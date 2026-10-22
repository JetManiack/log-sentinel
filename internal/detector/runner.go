package detector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/masker"
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

	for _, rule := range r.cfg.Detector.Rules {
		clients := r.clientsForRule(rule)
		for srcName, client := range clients {
			// Use a per-(rule,source) high-water mark so events near the poll
			// boundary are never dropped (defect #3: gap between polls).
			start := r.db.PollStart(rule.ID, srcName, interval, pollOverlap)
			ctxCfg := r.cfg.LLM
			entries, err := client.queryRaw(ctx, rule.Query, start, now, 50)
			if err != nil {
				// Fail loud: a broken rule query must be visible as a finding,
				// not a silent warn. An operator watching stdout or the board
				// will see it immediately.
				slog.Error("detector query failed — rule may be producing no results",
					"rule", rule.ID, "source", srcName, "err", err)
				r.emitDetectorError(ctx, rule, srcName, err)
				continue
			}
			// Always advance the high-water mark, even on empty results.
			if err := r.db.SetPollEnd(rule.ID, srcName, now); err != nil {
				slog.Warn("db setpollend error", "err", err)
			}
			if len(entries) == 0 {
				continue
			}

			// Sort entries by _time ascending so evidence is chronological and the
			// LLM sees events in the correct order (VL does not guarantee order).
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Time < entries[j].Time
			})

			// Group entries by fingerprint key. key_fields → per-actor/object scope;
			// no key_fields → hash of _msg (fail-safe: unique events don't dedup,
			// identical events do — defect #1: unkeyed rules must not get 24h silence).
			type group struct {
				key      string
				evidence []string
				msgs     []string // _msg only, used for benign matching
			}
			groupMap := map[string]*group{}
			for _, e := range entries {
				key := ruleKey(rule, e)
				g, ok := groupMap[key]
				if !ok {
					g = &group{key: key}
					groupMap[key] = g
				}
				g.evidence = append(g.evidence, client.mask.Redact(entryLine(e)))
				// Benign matching uses _msg only: attacker-controlled fields such as
				// objectRef.name must not influence whether a finding is suppressed.
				g.msgs = append(g.msgs, client.mask.Redact(e.Msg))
			}

			// Fetch context lines once per rule/source (uses first entry's stream).
			var ctxLines []string
			if streamSelector := buildStreamSelector(entries[0].Tags); streamSelector != "" {
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
				// Benign check uses _msg only — not the full field dump — so that
				// an attacker cannot craft objectRef.name to match a benign pattern
				// and suppress a real finding.
				if isBenign(g.msgs, r.cfg.Detector.KnownBenign) {
					slog.Debug("suppressed by known-benign", "rule", rule.ID)
					continue
				}
				fp := Fingerprint(rule.ID, srcName, g.key)
				quiet, err := r.db.IsQuiet(fp)
				if err != nil {
					slog.Warn("db isquiet error", "err", err)
					continue
				}
				if quiet {
					continue
				}
				_, err = r.db.Upsert(fp, rule.ID, rule.Severity, srcName)
				if err != nil {
					slog.Warn("db upsert error", "err", err)
				}
				// Apply quiet window on every emit:
				// - With key_fields: use quiet_window_default (actor/object scope).
				// - Without key_fields (msg-hash key): use 2×interval+overlap to
				//   dedup across the poll overlap window without long-term silence.
				//   This prevents the same _msg from firing twice due to the 5s
				//   overlap, while new unique messages always produce fresh findings.
				var quietUntil time.Time
				if len(rule.KeyFields) > 0 && r.cfg.Detector.QuietWindowDefault > 0 {
					quietUntil = now.Add(r.cfg.Detector.QuietWindowDefault)
				} else if len(rule.KeyFields) == 0 {
					quietUntil = now.Add(2*interval + pollOverlap)
				}
				if !quietUntil.IsZero() {
					if err := r.db.SetQuiet(fp, quietUntil); err != nil {
						slog.Warn("db setquiet error", "err", err)
					}
				}
				r.out <- Finding{
					Fingerprint:  fp,
					RuleID:       rule.ID,
					Severity:     rule.Severity,
					Source:       srcName,
					Description:  rule.Description,
					Evidence:     truncate(g.evidence, 10),
					ContextLines: truncate(ctxLines, ctxCfg.ContextLines),
					FiredAt:      now,
				}
			}
		}
	}

	// Fail-open pattern scan over the full log tail.
	if len(r.cfg.Detector.FailOpenPatterns) > 0 {
		start := now.Add(-interval)
		r.scanFailOpen(ctx, start, now)
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

// ruleKey computes the fingerprint key component for one log entry.
//
// When key_fields is set, it hashes the values of those fields from the
// entry's tags, scoping quiet windows to a specific actor/object pair.
//
// When key_fields is empty (text rules, syslog), it falls back to hashing
// _msg. This is the fail-safe default: unique log lines produce distinct
// fingerprints (noisy but safe), while exact-duplicate lines dedup normally.
// The empty-key (whole-rule) scope is NOT used, because a single event would
// silence the whole rule for 24h — an attacker primitive.
//
// Note: key_fields reads e.Tags only; _msg is not in Tags (it is e.Msg).
// Use the special sentinel value "_msg" in key_fields only as an explicit
// override — it will always read as "" from Tags and collapse all events.
// The msg-hash fallback (no key_fields) is the correct way to key on content.
//
// Key field selection guidance: prefer fields controlled by the API server
// (user.username, verb) over fully attacker-controlled target identifiers
// (objectRef.name). Including target fields is still useful — a new target
// always produces a fresh finding — but does not confer suppression power.
func ruleKey(rule config.Rule, e vlEntry) string {
	if len(rule.KeyFields) == 0 {
		// Fail-safe default: key on _msg content so identical lines dedup but
		// new content always fires.
		h := sha256.New()
		fmt.Fprintf(h, "msg=%s", e.Msg)
		return fmt.Sprintf("%x", h.Sum(nil))[:12]
	}
	h := sha256.New()
	for _, field := range rule.KeyFields {
		fmt.Fprintf(h, "%s=%s\x00", field, e.Tags[field])
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
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
		// LogsQL: a quoted string is a substring filter against all streams.
		// Escape backslashes and double-quotes in the pattern before interpolation.
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
