package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/masker"
	"github.com/JetManiack/log-sentinel/internal/metrics"
	"github.com/JetManiack/log-sentinel/internal/state"
)

// Runner polls configured log sources at the configured interval, evaluates
// rules, and sends new Findings to the out channel.
type Runner struct {
	cfg     *config.Config
	db      *state.DB
	mask    *masker.Mask
	clients map[string]*VLClient // key = source name
	out     chan<- Finding
}

// New creates a Runner. The returned channel receives findings as they are produced.
// Returns an error if any log source fails to initialise (e.g. unreadable ca_file).
func New(cfg *config.Config, db *state.DB, mask *masker.Mask) (*Runner, <-chan Finding, error) {
	ch := make(chan Finding, 64)
	r := &Runner{
		cfg:     cfg,
		db:      db,
		mask:    mask,
		clients: make(map[string]*VLClient),
		out:     ch,
	}
	for _, src := range cfg.Logs {
		c, err := NewVLClient(src, mask)
		if err != nil {
			return nil, nil, fmt.Errorf("detector: init source %q: %w", src.Name, err)
		}
		r.clients[src.Name] = c
	}
	return r, ch, nil
}

// Run starts the polling loop. It blocks until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Detector.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.poll(ctx)
		}
	}
}

// pollOverlap is subtracted from the previous poll end to catch events that
// arrived in VictoriaLogs after the previous poll window closed (vlagent batch lag).
const pollOverlap = 5 * time.Second

func (r *Runner) poll(ctx context.Context) {
	now := time.Now()
	interval := r.cfg.Detector.Interval
	d := &r.cfg.Detector

	// Close any GroupWindows that expired since the last poll, emitting
	// group_closed findings for multi-event groups.
	r.closeExpiredWindows(now)

	for _, rule := range r.cfg.Detector.Rules {
		groupWindow := rule.GroupWindow
		if groupWindow == 0 {
			groupWindow = d.GroupWindowDefault
		}

		clients := r.clientsForRule(rule)
		for srcName, client := range clients {
			start := r.db.PollStart(rule.ID, srcName, interval, pollOverlap)
			ctxCfg := r.cfg.LLM
			entries, err := client.queryRaw(ctx, rule.Query, start, now, 200)
			if err != nil {
				slog.Error("detector query failed — rule may be producing no results",
					"rule", rule.ID, "source", srcName, "err", err)
				r.emitDetectorError(ctx, rule, srcName, err)
				continue
			}
			if err := r.db.SetPollEnd(rule.ID, srcName, now); err != nil {
				slog.Warn("db setpollend error", "err", err)
			}
			if len(entries) == 0 {
				continue
			}

			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Time < entries[j].Time
			})

			// --- Per-event dedup via SeenEvent ---
			var newEntries []vlEntry
			for _, e := range entries {
				evID := EventID(
					e.Tags[rule.AuditIDField],
					e.Time,
					e.Tags["_stream_id"],
					e.Msg,
				)
				seen, err := r.db.HasSeenEvent(rule.ID, srcName, evID, d.SeenEventTTL)
				if err != nil {
					slog.Warn("db HasSeenEvent error", "err", err)
					continue
				}
				if seen {
					metrics.EventsDedupedTotal.WithLabelValues(rule.ID, srcName).Inc()
					continue
				}
				if err := r.db.MarkEventSeen(rule.ID, srcName, evID); err != nil {
					slog.Warn("db MarkEventSeen error", "err", err)
				}
				newEntries = append(newEntries, e)
			}
			if len(newEntries) == 0 {
				continue
			}

			// --- Group by actor ---
			type actorGroup struct {
				actorKey string
				evidence []string
				msgs     []string // _msg only, for benign matching
				objects  map[string]struct{}
			}
			groupMap := map[string]*actorGroup{}
			objFields := objectFields(rule)
			for _, e := range newEntries {
				ak := actorKeyStr(rule, e)
				g, ok := groupMap[ak]
				if !ok {
					g = &actorGroup{
						actorKey: ak,
						objects:  make(map[string]struct{}),
					}
					groupMap[ak] = g
				}
				g.evidence = append(g.evidence, client.mask.Redact(entryLine(e)))
				g.msgs = append(g.msgs, client.mask.Redact(e.Msg))
				for _, f := range objFields {
					if v := e.Tags[f]; v != "" {
						g.objects[v] = struct{}{}
					}
				}
			}

			// Fetch context lines once per rule/source (uses first entry's stream).
			var ctxLines []string
			if streamSelector := buildStreamSelector(newEntries[0].Tags); streamSelector != "" {
				ctxStart := now.Add(-ctxCfg.ContextWindow)
				ctxEnd := now.Add(ctxCfg.ContextWindow)
				ctxEntries, ctxErr := client.queryRaw(ctx, streamSelector, ctxStart, ctxEnd, ctxCfg.ContextLines)
				if ctxErr == nil {
					sort.Slice(ctxEntries, func(i, j int) bool {
						return ctxEntries[i].Time < ctxEntries[j].Time
					})
					for _, ce := range ctxEntries {
						ctxLines = append(ctxLines, client.mask.Redact(entryLine(ce)))
					}
				}
			}

			for _, g := range groupMap {
				if isBenign(g.msgs, d.KnownBenign) {
					slog.Debug("suppressed by known-benign", "rule", rule.ID)
					continue
				}

				groupFP := GroupFP(rule.ID, srcName, g.actorKey)

				// Respect manual /quiet on this group.
				quiet, err := r.db.IsQuiet(groupFP)
				if err != nil {
					slog.Warn("db IsQuiet error", "err", err)
					continue
				}
				if quiet {
					continue
				}

				objSamples := samplesFromSet(g.objects, d.SampleObjectsMax)

				gw, err := r.db.ActiveGroupWindow(groupFP)
				if err != nil {
					slog.Warn("db ActiveGroupWindow error", "err", err)
					continue
				}

				if gw != nil {
					// Window already open: increment count and merge object samples.
					merged := mergeSamples(unmarshalSamples(gw.ObjectSamples), objSamples, d.SampleObjectsMax)
					gw, err = r.db.IncrGroupWindow(gw.ID, marshalSamples(merged))
					if err != nil {
						slog.Warn("db IncrGroupWindow error", "err", err)
						continue
					}
					metrics.GroupEventsTotal.WithLabelValues(rule.ID, srcName).Inc()
					r.out <- Finding{
						Fingerprint:   groupFP,
						RuleID:        rule.ID,
						Severity:      rule.Severity,
						Source:        srcName,
						Description:   rule.Description,
						Evidence:      truncate(g.evidence, 10),
						ContextLines:  truncate(ctxLines, ctxCfg.ContextLines),
						FiredAt:       now,
						GroupEvent:    GroupEventUpdate,
						GroupCount:    gw.Count,
						GroupActorKey: g.actorKey,
						GroupObjects:  unmarshalSamples(gw.ObjectSamples),
						GroupWindowID: gw.ID,
					}
				} else {
					// No active window: open a new one.
					openUntil := now.Add(groupWindow)
					gw, err = r.db.OpenGroupWindow(groupFP, rule.ID, rule.Severity, srcName,
						g.actorKey, openUntil, marshalSamples(objSamples))
					if err != nil {
						slog.Warn("db OpenGroupWindow error", "err", err)
						continue
					}
					// Upsert a Finding record so /quiet works on the group_fp.
					if _, err := r.db.Upsert(groupFP, rule.ID, rule.Severity, srcName); err != nil {
						slog.Warn("db Upsert error", "err", err)
					}
					metrics.FindingsTotal.WithLabelValues(rule.ID, srcName, rule.Severity).Inc()
					r.out <- Finding{
						Fingerprint:   groupFP,
						RuleID:        rule.ID,
						Severity:      rule.Severity,
						Source:        srcName,
						Description:   rule.Description,
						Evidence:      truncate(g.evidence, 10),
						ContextLines:  truncate(ctxLines, ctxCfg.ContextLines),
						FiredAt:       now,
						GroupEvent:    GroupEventOpen,
						GroupCount:    1,
						GroupActorKey: g.actorKey,
						GroupObjects:  objSamples,
						GroupWindowID: gw.ID,
					}
				}
			}
		}
	}

	// Fail-open pattern scan.
	if len(d.FailOpenPatterns) > 0 {
		start := now.Add(-interval)
		r.scanFailOpen(ctx, start, now)
	}

	// Periodic SeenEvent purge — keep the table small.
	if err := r.db.PurgeExpiredSeenEvents(d.SeenEventTTL); err != nil {
		slog.Warn("db PurgeExpiredSeenEvents error", "err", err)
	}
}

// closeExpiredWindows closes GroupWindows whose open_until has passed and emits
// group_closed findings for groups with more than one event.
func (r *Runner) closeExpiredWindows(now time.Time) {
	rows, err := r.db.ExpiredGroupWindows()
	if err != nil {
		slog.Warn("db ExpiredGroupWindows error", "err", err)
		return
	}
	for _, gw := range rows {
		if err := r.db.CloseGroupWindow(gw.ID); err != nil {
			slog.Warn("db CloseGroupWindow error", "err", err)
			continue
		}
		// Single-event groups are fully represented by their group_open finding.
		if gw.Count <= 1 {
			continue
		}
		metrics.GroupsClosedTotal.WithLabelValues(gw.RuleID, gw.Source).Inc()
		desc := ""
		if rule := r.ruleByID(gw.RuleID); rule != nil {
			desc = rule.Description
		}
		r.out <- Finding{
			Fingerprint:   gw.GroupFP,
			RuleID:        gw.RuleID,
			Severity:      gw.Severity,
			Source:        gw.Source,
			Description:   desc,
			FiredAt:       now,
			GroupEvent:    GroupEventClosed,
			GroupCount:    gw.Count,
			GroupActorKey: gw.ActorKey,
			GroupObjects:  unmarshalSamples(gw.ObjectSamples),
			GroupWindowID: gw.ID,
		}
	}
}

// entryLine returns the best human-readable representation of a log entry,
// always prefixed with the RFC3339 timestamp so the LLM and operator can
// determine event order without relying on query sort order.
//
// When _msg is non-empty (syslog, journald, text logs), returns "T _msg".
// When _msg is empty (structured JSON audit logs with pack_json or no _msg),
// serialises all non-_stream* tags as sorted key=value pairs.
func entryLine(e vlEntry) string {
	ts := e.Time
	if ts == "" {
		ts = "?"
	}
	if e.Msg != "" {
		return ts + " " + e.Msg
	}
	// Build sorted key=value string from all non-_stream* tags.
	keys := make([]string, 0, len(e.Tags))
	for k := range e.Tags {
		if !strings.HasPrefix(k, "_stream") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+1)
	parts = append(parts, ts)
	for _, k := range keys {
		parts = append(parts, k+"="+e.Tags[k])
	}
	return strings.Join(parts, " ")
}

// actorKeyStr returns a human-readable actor key for grouping. When
// actor_fields is empty, "" is returned (whole-rule group).
func actorKeyStr(rule config.Rule, e vlEntry) string {
	if len(rule.ActorFields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rule.ActorFields))
	for _, field := range rule.ActorFields {
		if v := e.Tags[field]; v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, "/")
}

// objectFields returns the key_fields that are NOT in actor_fields.
func objectFields(rule config.Rule) []string {
	if len(rule.KeyFields) == 0 {
		return nil
	}
	actorSet := make(map[string]struct{}, len(rule.ActorFields))
	for _, f := range rule.ActorFields {
		actorSet[f] = struct{}{}
	}
	out := make([]string, 0, len(rule.KeyFields))
	for _, f := range rule.KeyFields {
		if _, isActor := actorSet[f]; !isActor {
			out = append(out, f)
		}
	}
	return out
}

// samplesFromSet returns up to max unique strings from a set, sorted.
func samplesFromSet(s map[string]struct{}, max int) []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// mergeSamples merges existing and new sample lists, keeping up to max unique
// entries in stable order (existing first).
func mergeSamples(existing, newSamples []string, max int) []string {
	seen := make(map[string]struct{}, len(existing))
	out := make([]string, 0, len(existing)+len(newSamples))
	for _, v := range existing {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	for _, v := range newSamples {
		if len(out) >= max {
			break
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func marshalSamples(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func unmarshalSamples(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// logsqlQuote escapes backslashes and double-quotes in a literal string so it
// can be safely embedded in a LogsQL quoted-string filter: "pattern".
func logsqlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func (r *Runner) scanFailOpen(ctx context.Context, start, end time.Time) {
	for _, pattern := range r.cfg.Detector.FailOpenPatterns {
		query := logsqlQuote(pattern)
		for srcName, client := range r.clients {
			lines, err := client.Query(ctx, query, start, end, 20)
			if err != nil || len(lines) == 0 {
				continue
			}
			fp := Fingerprint("fail-open", srcName, pattern)
			quiet, _ := r.db.IsQuiet(fp)
			if quiet {
				continue
			}
			if isBenign(lines, r.cfg.Detector.KnownBenign) {
				continue
			}
			r.db.Upsert(fp, "fail-open", SeverityMedium, srcName) //nolint:errcheck
			metrics.FindingsTotal.WithLabelValues("fail-open", srcName, SeverityMedium).Inc()
			r.out <- Finding{
				Fingerprint: fp,
				RuleID:      "fail-open",
				Severity:    SeverityMedium,
				Source:      srcName,
				Description: "fail-open pattern: " + pattern,
				Evidence:    truncate(lines, 5),
				FiredAt:     end,
			}
		}
	}
}

// emitDetectorError fires a high-severity finding so that a broken rule query
// is visible in the stdout sink and on the board — not just a log line.
func (r *Runner) emitDetectorError(ctx context.Context, rule config.Rule, srcName string, queryErr error) {
	fp := Fingerprint("detector-error", srcName, rule.ID)
	quiet, _ := r.db.IsQuiet(fp)
	if quiet {
		return
	}
	r.db.Upsert(fp, "detector-error", SeverityHigh, srcName) //nolint:errcheck
	metrics.FindingsTotal.WithLabelValues("detector-error", srcName, SeverityHigh).Inc()
	r.out <- Finding{
		Fingerprint: fp,
		RuleID:      "detector-error",
		Severity:    SeverityHigh,
		Source:      srcName,
		Description: fmt.Sprintf("rule %q query returned an error — detector may be producing no results", rule.ID),
		Evidence:    []string{queryErr.Error()},
		FiredAt:     time.Now(),
	}
}

func (r *Runner) ruleByID(id string) *config.Rule {
	for i := range r.cfg.Detector.Rules {
		if r.cfg.Detector.Rules[i].ID == id {
			return &r.cfg.Detector.Rules[i]
		}
	}
	return nil
}

func (r *Runner) clientsForRule(rule config.Rule) map[string]*VLClient {
	if rule.Source == "" {
		return r.clients
	}
	c, ok := r.clients[rule.Source]
	if !ok {
		return nil
	}
	return map[string]*VLClient{rule.Source: c}
}

func isBenign(lines []string, entries []config.KnownBenignEntry) bool {
	for _, e := range entries {
		for _, l := range lines {
			if strings.Contains(l, e.Pattern) {
				return true
			}
		}
	}
	return false
}

func truncate(lines []string, max int) []string {
	if len(lines) <= max {
		return lines
	}
	return lines[:max]
}
