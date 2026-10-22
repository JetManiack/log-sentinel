// Package masker replaces secret-shaped strings in log text before they are
// sent to the LLM or included in notifications.
package masker

import (
	"regexp"
	"strings"
)

// Mask is a compiled set of patterns.
type Mask struct {
	patterns []*regexp.Regexp
}

// defaultPatterns covers common secret shapes.
var defaultPatterns = []*regexp.Regexp{
	// OpenAI-style keys: sk-, Bearer tokens, API keys
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9_\-\.]{20,}`),
	regexp.MustCompile(`(?i)(api.?key[=:\s]+)[A-Za-z0-9_\-\.]{20,}`),
	regexp.MustCompile(`(?i)(secret[=:\s]+)[A-Za-z0-9_\-\.]{20,}`),
	regexp.MustCompile(`(?i)(password[=:\s]+)\S{8,}`),
	regexp.MustCompile(`(?i)(token[=:\s]+)[A-Za-z0-9_\-\.]{20,}`),

	// sudo ENV dump: strip everything between "ENV=" and " ; COMMAND=" (or EOL).
	// Group 1 = "ENV=", group 2 = "; COMMAND=" (optional, preserved as suffix).
	// Uses two-group convention so Redact emits: ENV=[REDACTED]; COMMAND=...
	// The terminator is optional so the block is still stripped when the line
	// ends before "; COMMAND=" (truncated journal entries).
	regexp.MustCompile(`(ENV=)[^;]+(; COMMAND=)?`),

	// sudo "(command continued)" lines: the entire content after the marker is
	// an env dump continuation and must be redacted wholesale.
	// Capture only the marker itself; do NOT capture the first word — it is
	// part of the env dump and could itself be sensitive.
	regexp.MustCompile(`(\(command continued\) ?)[^\x00]+`),

	// Any env variable whose name contains a sensitive keyword.
	// Redact to end of line to handle multi-word header values, intra-value
	// semicolons, and any other edge cases safely.  RE2 has no lookahead so
	// we cannot stop at the sudo ` ; ` separator without post-processing;
	// redacting to EOL is the safe default for these high-risk variables.
	regexp.MustCompile(`(?i)([A-Z0-9_]*(?:KEY|TOKEN|COOKIE|SECRET|SESSION|PASSWORD|AUTH|HEADERS|CONTEXT)[A-Z0-9_]*=['\"]?)[^\n\x00]+`),

	// sk- prefixed keys (LiteLLM, OpenAI)
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),
	// glsa_ (GitLab service account)
	regexp.MustCompile(`glsa_[A-Za-z0-9]{20,}`),
	// ghp_ (GitHub personal access token)
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
	// PEM private keys
	regexp.MustCompile(`-----BEGIN [A-Z ]+ KEY-----[^-]+-----END [A-Z ]+ KEY-----`),
	// Long base64 runs (likely encoded credentials)
	regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`),
}

// Default returns a Mask with the built-in patterns.
func Default() *Mask {
	return &Mask{patterns: defaultPatterns}
}

// New creates a Mask with additional custom patterns on top of the defaults.
func New(extra ...string) (*Mask, error) {
	m := &Mask{patterns: make([]*regexp.Regexp, len(defaultPatterns))}
	copy(m.patterns, defaultPatterns)
	for _, s := range extra {
		r, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, r)
	}
	return m, nil
}

const redacted = "[REDACTED]"

// Redact replaces all matched secret-shaped substrings with [REDACTED].
//
// Pattern conventions:
//   - No capture groups → entire match is replaced.
//   - One capture group → group 1 is a prefix to preserve; the rest is replaced.
//   - Two capture groups → group 1 is a prefix, group 2 is a suffix to preserve;
//     everything between them (the secret span) is replaced.
func (m *Mask) Redact(s string) string {
	for _, p := range m.patterns {
		s = p.ReplaceAllStringFunc(s, func(match string) string {
			subs := p.FindStringSubmatch(match)
			switch len(subs) {
			case 3:
				// prefix [REDACTED] suffix
				return subs[1] + redacted + subs[2]
			case 2:
				// prefix [REDACTED]
				return subs[1] + redacted
			default:
				return redacted
			}
		})
	}
	return s
}

// RedactLines applies Redact to each line individually (used on ±N context windows).
func (m *Mask) RedactLines(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = m.Redact(l)
	}
	return strings.Join(lines, "\n")
}
