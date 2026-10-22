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

// parseLine parses a single "/" prefixed line.
//
// A line is a command attempt only if its first word is ^/[a-z][a-z-]*$ —
// all lowercase letters and hyphens, no path separators, no dots, no digits.
// This lets lines like "/etc/sentinel/config.yaml is updated" pass through
// silently so that a path in a reply body doesn't suppress a real command on
// the next line.
//
// Returns (cmd, nil) on success, (nil, err) for malformed known commands and
// unrecognised command words, (nil, nil) for non-command lines.
func parseLine(line string) (*Command, error) {
	if len(line) == 0 || line[0] != '/' {
		return nil, nil
	}
	firstWord := strings.Fields(line)[0]
	if !isCommandWord(firstWord) {
		return nil, nil // path or uppercase line — skip, keep scanning
	}

	switch {
	case line == "/unquiet" || strings.HasPrefix(line, "/unquiet "):
		reason := strings.TrimSpace(strings.TrimPrefix(line, "/unquiet"))
		return &Command{Kind: KindUnquiet, Reason: reason}, nil

	case line == "/quiet":
		return nil, fmt.Errorf("commands: /quiet requires a duration and reason")

	case strings.HasPrefix(line, "/quiet "):
		rest := strings.TrimPrefix(line, "/quiet ")
		return parseQuiet(rest)

	case line == "/benign":
		return nil, fmt.Errorf("commands: /benign requires a reason")

	case strings.HasPrefix(line, "/benign "):
		reason := strings.TrimSpace(strings.TrimPrefix(line, "/benign "))
		if reason == "" {
			return nil, fmt.Errorf("commands: /benign requires a reason")
		}
		return &Command{Kind: KindBenign, Reason: reason}, nil
	}

	return nil, fmt.Errorf("commands: unknown command %q (known: /quiet, /unquiet, /benign)", firstWord)
}

// isCommandWord reports whether w looks like a command word: /[a-z][a-z-]*
// No path separators after the first character, no dots, no uppercase, no digits.
func isCommandWord(w string) bool {
	if len(w) < 2 || w[0] != '/' {
		return false
	}
	for _, c := range w[1:] {
		if !((c >= 'a' && c <= 'z') || c == '-') {
			return false
		}
	}
	return true
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
