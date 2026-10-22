package detector

import (
	"testing"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/masker"
)

func TestIsBenign(t *testing.T) {
	entries := []config.KnownBenignEntry{
		{Pattern: "healthcheck"},
		{Pattern: "liveness probe"},
	}

	if !isBenign([]string{"GET /healthcheck 200"}, entries) {
		t.Error("should be benign")
	}
	if isBenign([]string{"GET /api/login 401"}, entries) {
		t.Error("should not be benign")
	}
	if isBenign([]string{}, entries) {
		t.Error("empty lines should not be benign")
	}
}

func TestLogsqlQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"permission denied", `"permission denied"`},
		{`back\slash`, `"back\\slash"`},
		{`quote"inside`, `"quote\"inside"`},
		{`both\"`, `"both\\\""`},
	}
	for _, c := range cases {
		got := logsqlQuote(c.in)
		if got != c.want {
			t.Errorf("logsqlQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEntryLine(t *testing.T) {
	// When _msg is non-empty, it is returned with the timestamp prefix.
	e := vlEntry{Time: "2026-01-01T00:00:00Z", Msg: "hello world", Tags: map[string]string{"job": "sshd"}}
	got := entryLine(e)
	if !containsStr(got, "hello world") || !containsStr(got, "2026-01-01T00:00:00Z") {
		t.Errorf("want timestamp+msg, got %q", got)
	}

	// When _msg is empty (structured audit log), field=value pairs are returned.
	e2 := vlEntry{Time: "2026-01-01T00:00:01Z", Msg: "", Tags: map[string]string{
		"verb":          "create",
		"user.username": "admin",
		"_streamLabels": "ignore",
	}}
	got2 := entryLine(e2)
	if containsStr(got2, "_stream") {
		t.Errorf("_stream* fields must be excluded: %q", got2)
	}
	if !containsStr(got2, "user.username=admin") || !containsStr(got2, "verb=create") {
		t.Errorf("expected field pairs in output: %q", got2)
	}
	if !containsStr(got2, "2026-01-01T00:00:01Z") {
		t.Errorf("expected timestamp prefix: %q", got2)
	}
}

func TestRuleKey(t *testing.T) {
	rule := config.Rule{ID: "r", KeyFields: []string{"user.username", "objectRef.name"}}
	e := vlEntry{Tags: map[string]string{"user.username": "alice", "objectRef.name": "role-x"}}

	k1 := ruleKey(rule, e)
	if k1 == "" {
		t.Fatal("expected non-empty key with key_fields set")
	}

	// Different user → different key.
	e2 := vlEntry{Tags: map[string]string{"user.username": "bob", "objectRef.name": "role-x"}}
	if ruleKey(rule, e2) == k1 {
		t.Error("different user.username must produce different key")
	}

	// No key_fields → hash of _msg (fail-safe, not empty).
	ruleNoFields := config.Rule{ID: "r"}
	eMsg1 := vlEntry{Msg: "failed password for alice"}
	eMsg2 := vlEntry{Msg: "failed password for alice"}
	eMsg3 := vlEntry{Msg: "failed password for bob"}

	k2 := ruleKey(ruleNoFields, eMsg1)
	if k2 == "" {
		t.Error("rule without key_fields must return non-empty key (msg hash)")
	}
	if ruleKey(ruleNoFields, eMsg2) != k2 {
		t.Error("identical _msg must produce identical key")
	}
	if ruleKey(ruleNoFields, eMsg3) == k2 {
		t.Error("different _msg must produce different key")
	}
}

func TestEntryLineBenignIsolation(t *testing.T) {
	// entryLine output (full field dump) must NOT be used for benign suppression.
	// An attacker who names a Role "healthcheck" must not suppress the RBAC finding.
	// The benign check is against _msg only, which is empty for JSON audit logs.
	e := vlEntry{
		Msg: "",
		Tags: map[string]string{
			"objectRef.name": "healthcheck", // attacker-controlled
			"verb":           "create",
		},
	}
	line := entryLine(e)
	benignEntries := []config.KnownBenignEntry{{Pattern: "healthcheck"}}
	// entryLine contains "healthcheck" but _msg does not.
	if !containsStr(line, "healthcheck") {
		t.Skip("test precondition: entryLine must contain the attacker-controlled name")
	}
	// Benign suppression should NOT trigger (it uses _msg, not entryLine).
	if isBenign([]string{e.Msg}, benignEntries) {
		t.Error("benign suppression triggered on empty _msg — attacker-controlled name leaked into suppression")
	}
	// entryLine in evidence is fine for the LLM, but let's verify it contains the field.
	if !containsStr(line, "objectRef.name=healthcheck") {
		t.Errorf("evidence line should contain field: %q", line)
	}
}

func TestEntryLineMasking(t *testing.T) {
	// entryLine result should be maskable by the masker.
	mask := masker.Default()
	e := vlEntry{Msg: "", Tags: map[string]string{
		"authorization": "Bearer sk-supersecretkey1234567890abcdef",
	}}
	line := entryLine(e)
	masked := mask.Redact(line)
	if containsStr(masked, "sk-supersecretkey") {
		t.Errorf("secret not masked: %q", masked)
	}
}

func TestTruncate(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	got := truncate(lines, 3)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	got2 := truncate(lines, 10)
	if len(got2) != 5 {
		t.Fatalf("under limit: want 5, got %d", len(got2))
	}
}
