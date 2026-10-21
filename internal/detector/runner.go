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

func (r *Runner) poll(ctx context.Context) {
	now := time.Now()
	window := time.Duration(r.cfg.Detector.Interval)
	start := now.Add(-window)

	for _, rule := range r.cfg.Detector.Rules {
		clients := r.clientsForRule(rule)
		for srcName, client := range clients {
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
			if len(entries) == 0 {
				continue
			}

			// Build per-entry fingerprint key from key_fields (defect #2: whole-rule
			// silencing was an attacker primitive). Group entries by key.
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
				existed, err := r.db.Upsert(fp, rule.ID, rule.Severity, srcName)
				if err != nil {
					slog.Warn("db upsert error", "err", err)
				}
				// Apply quiet_window_default on first fire, but only when key_fields
				// are configured. Whole-rule (empty-key) quiet windows would allow a
				// single event to silence every actor for 24h — an attacker primitive.
				if !existed && r.cfg.Detector.QuietWindowDefault > 0 && len(rule.KeyFields) > 0 {
					quietUntil := now.Add(r.cfg.Detector.QuietWindowDefault)
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
		r.scanFailOpen(ctx, start, now)
	}
}

// entryLine returns the best human-readable representation of a log entry.
// When _msg is empty (structured JSON audit logs), it serialises all non-stream
// fields as key=value pairs (defect #3: LLM received "missing _msg field").
func entryLine(e vlEntry) string {
	if e.Msg != "" {
		return e.Msg
	}
	// Build sorted key=value string from all non-_stream* tags.
	keys := make([]string, 0, len(e.Tags))
	for k := range e.Tags {
		if !strings.HasPrefix(k, "_stream") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+e.Tags[k])
	}
	return strings.Join(parts, " ")
}

// ruleKey computes the fingerprint key component for one log entry.
// When rule.KeyFields is configured, it hashes the values of those fields
// from the entry's tags, scoping quiet windows to that actor/object.
// Falls back to "" (whole-rule scope) when no key_fields are set; in that
// case quiet_window_default is intentionally NOT applied (see poll()).
//
// Key field selection guidance: prefer fields controlled by the API server
// (user.username, verb) over fully attacker-controlled target identifiers
// (objectRef.name). Including target fields is still useful — it makes a new
// target always produce a fresh finding — but does not confer suppression
// power to the attacker because quiet windows are only set on first-fire, and
// a new objectRef.name always produces a distinct fingerprint.
func ruleKey(rule config.Rule, e vlEntry) string {
	if len(rule.KeyFields) == 0 {
		return ""
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
