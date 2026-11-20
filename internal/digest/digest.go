// Package digest sends a daily summary of findings at a configured local time.
//
// The goroutine wakes exactly at the configured HH:MM in the configured IANA
// timezone (default 19:00 Asia/Nicosia). If there are no findings in the
// previous new_lookback window the digest is silently skipped. The summary is
// emitted as a structured JSON line to stdout (picked up by vlagent).
package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/state"
)

// Runner sends the daily digest.
type Runner struct {
	cfg config.DigestConfig
	db  *state.DB
}

// New creates a Runner.
func New(cfg config.DigestConfig, db *state.DB) *Runner {
	return &Runner{cfg: cfg, db: db}
}

// Run blocks until ctx is cancelled, firing the digest at the configured time
// each day.
func (r *Runner) Run(ctx context.Context) {
	loc, err := time.LoadLocation(r.cfg.Timezone)
	if err != nil {
		slog.Error("digest: invalid timezone, using UTC", "tz", r.cfg.Timezone, "err", err)
		loc = time.UTC
	}

	for {
		next := nextFire(time.Now().In(loc), r.cfg.Time, loc)
		slog.Debug("digest: next fire", "at", next)

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}

		if ctx.Err() != nil {
			return
		}

		r.fire(ctx, next)
	}
}

// nextFire returns the next wall-clock moment matching HH:MM in loc after now.
func nextFire(now time.Time, hhmm string, loc *time.Location) time.Time {
	h, m := parseHHMM(hhmm)
	candidate := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, loc)
	if !candidate.After(now) {
		candidate = candidate.Add(24 * time.Hour)
	}
	return candidate
}

func parseHHMM(s string) (hour, min int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 19, 0
	}
	fmt.Sscanf(parts[0], "%d", &hour)
	fmt.Sscanf(parts[1], "%d", &min)
	return
}

func (r *Runner) fire(ctx context.Context, fireTime time.Time) {
	since := fireTime.Add(-r.cfg.NewLookback)
	entries, err := r.db.DigestEntries(since)
	if err != nil {
		slog.Warn("digest: db query", "err", err)
		return
	}
	if len(entries) == 0 {
		slog.Debug("digest: no novel findings, skipping")
		return
	}

	title, body := buildDigest(entries, since, fireTime)

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]interface{}{
		"time":  fireTime.UTC().Format(time.RFC3339),
		"level": "INFO",
		"msg":   "daily-digest",
		"title": title,
		"body":  body,
	})

	// Mark all included findings as digested so they don't reappear tomorrow.
	fps := make([]string, len(entries))
	for i, e := range entries {
		fps[i] = e.Fingerprint
	}
	if err := r.db.MarkDigested(fps); err != nil {
		slog.Warn("digest: mark digested", "err", err)
	}
}

func buildDigest(entries []state.DigestEntry, since, until time.Time) (title, body string) {
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Severity]++
	}

	title = fmt.Sprintf("Дайджест %s — %d событий",
		until.Format("2006-01-02"), len(entries))

	var sb strings.Builder
	fmt.Fprintf(&sb, "**Период:** %s — %s\n\n",
		since.Format("15:04 MST 2006-01-02"), until.Format("15:04 MST 2006-01-02"))

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(&sb, "- **%s**: %d\n", strings.ToUpper(sev), n)
		}
	}
	sb.WriteString("\n")

	listed := entries
	truncated := false
	if len(listed) > 20 {
		listed = listed[:20]
		truncated = true
	}
	for _, e := range listed {
		sb.WriteString(formatEntry(e))
		sb.WriteByte('\n')
	}
	if truncated {
		fmt.Fprintf(&sb, "- _...и ещё %d событий_\n", len(entries)-20)
	}

	return title, sb.String()
}

func formatEntry(e state.DigestEntry) string {
	sev := strings.ToUpper(e.Severity)
	if e.GroupCount > 1 {
		// Grouped finding: show count and actor, use first→last range.
		timeRange := e.GroupFirstAt.Format("15:04") + "–" + e.GroupLastAt.Format("15:04")
		if e.GroupActorKey != "" {
			return fmt.Sprintf("- `[%s]` **%s** — %s — %d событий, актор: `%s` (%s)",
				sev, e.RuleID, e.Source, e.GroupCount, e.GroupActorKey, timeRange)
		}
		return fmt.Sprintf("- `[%s]` **%s** — %s — %d событий (%s)",
			sev, e.RuleID, e.Source, e.GroupCount, timeRange)
	}
	// Non-grouped or single-event finding.
	return fmt.Sprintf("- `[%s]` **%s** — %s (%s)",
		sev, e.RuleID, e.Source, e.LastFiredAt.Format("15:04"))
}
