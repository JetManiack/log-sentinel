// Package digest sends a daily summary of findings at a configured local time.
//
// The goroutine wakes exactly at the configured HH:MM in the configured IANA
// timezone (default 19:00 Asia/Nicosia). If there are no findings in the
// previous 24 h the digest is silently skipped — it never sends an empty
// message. The summary is emitted as a structured JSON line to stdout (picked
// up by vlagent) and, if the board sink is enabled, as a board thread reply or
// new thread.
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
	cfg         config.DigestConfig
	db          *state.DB
	boardEmit   func(ctx context.Context, title, body string)
}

// New creates a Runner. boardEmit may be nil if the board sink is disabled.
func New(cfg config.DigestConfig, db *state.DB, boardEmit func(context.Context, string, string)) *Runner {
	return &Runner{cfg: cfg, db: db, boardEmit: boardEmit}
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

		// Re-check after wakeup (ctx may have been cancelled while sleeping).
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
	since := fireTime.Add(-24 * time.Hour)
	findings, err := r.db.FindingsSince(since)
	if err != nil {
		slog.Warn("digest: db query", "err", err)
		return
	}
	if len(findings) == 0 {
		slog.Debug("digest: no findings, skipping")
		return
	}

	title, body := buildDigest(findings, since, fireTime)

	// Emit to stdout as a structured JSON line.
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]interface{}{
		"time":  fireTime.UTC().Format(time.RFC3339),
		"level": "INFO",
		"msg":   "daily-digest",
		"title": title,
		"body":  body,
	})

	// Post to board if configured.
	if r.boardEmit != nil {
		r.boardEmit(ctx, title, body)
	}
}

func buildDigest(findings []state.DigestFinding, since, until time.Time) (title, body string) {
	// Count by severity.
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	title = fmt.Sprintf("📋 Дайджест %s — %d событий",
		until.Format("2006-01-02"), len(findings))

	var sb strings.Builder
	fmt.Fprintf(&sb, "**Период:** %s — %s\n\n",
		since.Format("15:04"), until.Format("15:04 MST 2006-01-02"))

	// Severity summary table.
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(&sb, "- **%s**: %d\n", strings.ToUpper(sev), n)
		}
	}
	sb.WriteString("\n")

	// Per-finding lines (cap at 20 to keep the post readable).
	listed := findings
	truncated := false
	if len(listed) > 20 {
		listed = listed[:20]
		truncated = true
	}
	for _, f := range listed {
		fmt.Fprintf(&sb, "- `[%s]` **%s** — %s (%s)\n",
			strings.ToUpper(f.Severity), f.RuleID, f.Source,
			f.LastFiredAt.Format("15:04"))
	}
	if truncated {
		fmt.Fprintf(&sb, "- _...и ещё %d событий_\n", len(findings)-20)
	}

	return title, sb.String()
}
