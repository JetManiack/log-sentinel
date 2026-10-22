// Package commands parses board-thread reply commands issued by authorised actors.
//
// Grammar (exact, matched at line start, case-sensitive):
//
//	/quiet <duration> <reason…>   — suppress notifications for duration
//	/unquiet                      — cancel the active quiet window
//	/benign <reason…>             — add a known-benign entry for this pattern
//
// No LLM is involved in parsing. Parsing is regex-free and string-based so the
// grammar is audit-trivial. The functions are pure; callers enforce access control.
package commands

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Kind is the type of a parsed board command.
type Kind string

const (
	KindQuiet   Kind = "quiet"
	KindUnquiet Kind = "unquiet"
	KindBenign  Kind = "benign"
)

// Command is the result of parsing a single board reply line.
type Command struct {
	Kind     Kind
	Duration time.Duration // KindQuiet only
	Reason   string        // KindQuiet and KindBenign
}

// ErrNoCommand is returned when the text contains no command line.
var ErrNoCommand = fmt.Errorf("no command found")

// Parse scans text line-by-line for the first command at line-start and returns it.
// Returns ErrNoCommand if none found, a descriptive error for malformed commands.
func Parse(text string) (*Command, error) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRightFunc(raw, unicode.IsSpace)
		if !strings.HasPrefix(line, "/") {
			continue
		}
		cmd, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		if cmd != nil {
			return cmd, nil
		}
	}
	return nil, ErrNoCommand
}

// parseLine parses a single "/" prefixed line.  Returns a descriptive error
// for any unrecognised "/command" so the caller can reply with a warning.
func parseLine(line string) (*Command, error) {
	switch {
	case line == "/unquiet" || strings.HasPrefix(line, "/unquiet "):
		// Optional reason after /unquiet is stored but not used by the engine.
		reason := strings.TrimSpace(strings.TrimPrefix(line, "/unquiet"))
		return &Command{Kind: KindUnquiet, Reason: reason}, nil

	case strings.HasPrefix(line, "/quiet "):
		rest := strings.TrimPrefix(line, "/quiet ")
		return parseQuiet(rest)

	case strings.HasPrefix(line, "/benign "):
		reason := strings.TrimSpace(strings.TrimPrefix(line, "/benign "))
		if reason == "" {
			return nil, fmt.Errorf("commands: /benign requires a reason")
		}
		return &Command{Kind: KindBenign, Reason: reason}, nil
	}
	// Any "/" line that isn't a known command gets an explicit error so the
	// caller can send a ⚠️ reply instead of silently ignoring it.
	cmd := strings.Fields(line)[0]
	return nil, fmt.Errorf("commands: unknown command %q (known: /quiet, /unquiet, /benign)", cmd)
}

// parseQuiet parses "<duration> <reason…>".
// Duration is Go's time.ParseDuration format, plus shorthand d/w/mo.
func parseQuiet(rest string) (*Command, error) {
	idx := strings.IndexFunc(rest, unicode.IsSpace)
	if idx < 0 {
		return nil, fmt.Errorf("commands: /quiet requires duration and reason")
	}
	durStr := rest[:idx]
	reason := strings.TrimSpace(rest[idx:])
	if reason == "" {
		return nil, fmt.Errorf("commands: /quiet requires a reason after duration")
	}

	d, err := parseDuration(durStr)
	if err != nil {
		return nil, fmt.Errorf("commands: /quiet invalid duration %q: %w", durStr, err)
	}
	if d <= 0 {
		return nil, fmt.Errorf("commands: /quiet duration must be positive")
	}
	return &Command{Kind: KindQuiet, Duration: d, Reason: reason}, nil
}

// parseDuration extends time.ParseDuration with "d" (day), "w" (week), "mo" (30 days).
func parseDuration(s string) (time.Duration, error) {
	switch {
	case strings.HasSuffix(s, "mo"):
		n, err := parseNumber(strings.TrimSuffix(s, "mo"))
		return time.Duration(n) * 30 * 24 * time.Hour, err
	case strings.HasSuffix(s, "w"):
		n, err := parseNumber(strings.TrimSuffix(s, "w"))
		return time.Duration(n) * 7 * 24 * time.Hour, err
	case strings.HasSuffix(s, "d"):
		n, err := parseNumber(strings.TrimSuffix(s, "d"))
		return time.Duration(n) * 24 * time.Hour, err
	default:
		return time.ParseDuration(s)
	}
}

func parseNumber(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("missing number")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number %q", s)
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}
