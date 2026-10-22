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
		// sudo journal env dump: bare hex session tokens (no Bearer prefix)
		{
			input:      "USER=root ; COMMAND=/usr/bin/true ; ENV=CLAUDE_CODE_MESSAGING_TOKEN=aabbccddeeff00112233445566778899 OTHER=x",
			mustAbsent: "aabbccddeeff00112233445566778899",
		},
		{
			input:      "SNAP_COOKIE=deadbeef01234567deadbeef01234567 PATH=/usr/bin",
			mustAbsent: "deadbeef01234567deadbeef01234567",
		},
		{
			input:      "SESSION=0123456789abcdef0123456789abcdef ; SHELL=/bin/bash",
			mustAbsent: "0123456789abcdef0123456789abcdef",
		},
	}

	for _, c := range cases {
		out := m.Redact(c.input)
		if c.mustAbsent != "" && containsSubstring(out, c.mustAbsent) {
			t.Errorf("Redact(%q) = %q; should not contain %q", c.input, out, c.mustAbsent)
		}
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
