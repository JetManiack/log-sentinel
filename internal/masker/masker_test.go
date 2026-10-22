package masker_test

import (
	"testing"

	"github.com/JetManiack/log-sentinel/internal/masker"
)

func TestRedact(t *testing.T) {
	m := masker.Default()

	cases := []struct {
		input string
		// must not appear in output
		mustAbsent string
	}{
		{
			input:      "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx",
			mustAbsent: "sk-abcdefghijklmnopqrstuvwx",
		},
		{
			input:      "API_KEY=supersecretvalue12345678",
			mustAbsent: "supersecretvalue12345678",
		},
		{
			input:      "no secrets here",
			mustAbsent: "",
		},
		{
			input:      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
			mustAbsent: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		},
		// sudo ENV= block: entire block between ENV= and ; COMMAND= is stripped.
		// COMMAND= suffix must be preserved (operator needs to know what ran).
		// Real sudo journal format; values are redacted in the fixture below.
		{
			input:      "ilazarev : PWD=/home/ilazarev ; USER=root ; ENV=SNAP_COOKIE=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh SNAP_CONTEXT=ZyXwVuTsRqPoNmLkJiHgFeDcBa0987654321zyxwvuts CLAUDE_CODE_SESSION_ID=12345678-1234-1234-1234-123456789abc ANTHROPIC_CUSTOM_HEADERS=proxy_key: sk-pr-00000000-0000-0000-0000-000000000000 ; COMMAND=/usr/bin/true",
			mustAbsent: "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh",
		},
		{
			// SNAP_CONTEXT value: mixed-case alnum, 52 chars (not hex, not base64-60)
			input:      "SNAP_CONTEXT=ZyXwVuTsRqPoNmLkJiHgFeDcBa0987654321zyxwvuts ; PATH=/usr/bin",
			mustAbsent: "ZyXwVuTsRqPoNmLkJiHgFeDcBa0987654321zyxwvuts",
		},
		{
			// CLAUDE_CODE_SESSION_ID: UUID format
			input:      "CLAUDE_CODE_SESSION_ID=12345678-1234-1234-1234-123456789abc",
			mustAbsent: "12345678-1234-1234-1234-123456789abc",
		},
		{
			// ANTHROPIC_CUSTOM_HEADERS: value contains spaces — stripped by ENV= block rule
			input:      "ENV=ANTHROPIC_CUSTOM_HEADERS=proxy_key: sk-pr-test1234 OTHER=x ; COMMAND=/bin/sh",
			mustAbsent: "proxy_key",
		},
		// Real sudo format: header value with spaces followed by another header.
		// The UUID after the space must not leak.
		{
			input:      "ANTHROPIC_CUSTOM_HEADERS=proxy_key: 12345678-1234-1234-1234-123456789abc X-IntelliJ-Proxy-Agent-ID: deadbeef-dead-beef-dead-beefdeadbeef",
			mustAbsent: "12345678-1234-1234-1234-123456789abc",
		},
		// sudo "(command continued)" line — everything after the marker is env dump.
		{
			input:      "(command continued) ANTHROPIC_API_KEY=sk-pr-00000000-0000-0000-0000-000000000000 SNAP_COOKIE=AbCdEfGhIjKlMnOpQrStUvWxYz ; COMMAND=/usr/bin/true",
			mustAbsent: "sk-pr-00000000-0000-0000-0000-000000000000",
		},
	}

	for _, c := range cases {
		out := m.Redact(c.input)
		if c.mustAbsent != "" && containsSubstring(out, c.mustAbsent) {
			t.Errorf("Redact(%q) = %q; should not contain %q", c.input, out, c.mustAbsent)
		}
	}
}

// TestRedactPreservesCommandSuffix verifies that "COMMAND=/path" is not lost
// when the ENV= block is stripped — the operator must see what command ran.
func TestRedactPreservesCommandSuffix(t *testing.T) {
	m := masker.Default()
	line := "ilazarev : PWD=/home/ilazarev ; ENV=SECRET=abc123 SNAP_COOKIE=xyz789 ; COMMAND=/usr/bin/true"
	out := m.Redact(line)
	if !containsSubstring(out, "COMMAND=/usr/bin/true") {
		t.Errorf("COMMAND= suffix lost after redaction: %q", out)
	}
	if containsSubstring(out, "abc123") || containsSubstring(out, "xyz789") {
		t.Errorf("secret values not redacted: %q", out)
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) > 0 && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
