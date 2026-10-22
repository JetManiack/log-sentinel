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

	// sudo ENV dump: strip everything between "ENV=" and " ; COMMAND=".
	// sudo writes the caller's full environment into the journal in this form,
	// including session tokens, cookies, and custom auth headers. Value-pattern
	// masking cannot cover all possible env var values (mixed-case alnum cookies,
	// UUIDs, proxy headers with spaces), so we drop the entire ENV block.
	// Note: long env dumps are split into "(command continued)" journal entries,
	// so this pattern only fires when both endpoints appear on the same line.
	regexp.MustCompile(`(ENV=)[^;]+?(; COMMAND=)`),

	// sudo "(command continued)" lines: the entire content after the marker is
	// an env dump continuation and must be redacted wholesale.
	regexp.MustCompile(`(\(command continued\) ?\S* ?)[^\x00]+`),

	// Any env variable whose name contains a sensitive keyword.
	// Masks the value up to " ; " (sudo separator) or end of string.
	// This is intentionally greedy so multi-word header values are fully covered
	// (e.g. ANTHROPIC_CUSTOM_HEADERS=proxy_key: <uuid> X-Header: <val>).
	// Re2 does not support lookahead, so we use [^;]* and trim " ; " in the
	// replacement logic: the capture group prefix is kept, the value is replaced.
	regexp.MustCompile(`(?i)([A-Z0-9_]*(?:KEY|TOKEN|COOKIE|SECRET|SESSION|PASSWORD|AUTH|HEADERS|CONTEXT)[A-Z0-9_]*=['\"]?)[^;]+`),

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
func (m *Mask) Redact(s string) string {
	for _, p := range m.patterns {
		// Preserve the capture group prefix (e.g. "Bearer ") and replace only the secret part.
		s = p.ReplaceAllStringFunc(s, func(match string) string {
			submatches := p.FindStringSubmatch(match)
			if len(submatches) > 1 {
				// Group 1 is the prefix; replace the rest.
				prefix := submatches[1]
				return prefix + redacted
			}
			return redacted
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
