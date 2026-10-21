package prompt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLoadsBuiltin(t *testing.T) {
	mgr, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sys, user, err := mgr.Execute("triage", map[string]any{
		"RuleID":               "sshd-failure",
		"Severity":             "medium",
		"Description":          "SSH auth failure",
		"Evidence":             []string{"Failed password for root"},
		"ContextLines":         []string{},
		"ContextWindowMinutes": 2,
		"KnownBenign":          nil,
	})
	if err != nil {
		t.Fatalf("Execute triage: %v", err)
	}
	if sys == "" {
		t.Error("system prompt should not be empty")
	}
	if !strings.Contains(user, "sshd-failure") {
		t.Errorf("user prompt missing rule id:\n%s", user)
	}
	if !strings.Contains(user, "Failed password") {
		t.Errorf("user prompt missing evidence:\n%s", user)
	}
}

func TestOverrideDir(t *testing.T) {
	dir := t.TempDir()
	override := `name: triage
version: "99.0.0"
critical: true
system: |
  custom system
user: |
  custom user {{ .RuleID }}
`
	if err := os.WriteFile(filepath.Join(dir, "triage.yaml"), []byte(override), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := New(dir)
	if err != nil {
		t.Fatalf("New with override: %v", err)
	}
	sys, user, err := mgr.Execute("triage", map[string]any{"RuleID": "test-rule"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(sys, "custom system") {
		t.Errorf("override system not applied: %q", sys)
	}
	if !strings.Contains(user, "test-rule") {
		t.Errorf("override user not applied: %q", user)
	}
}

func TestMissingBlueprintError(t *testing.T) {
	mgr, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = mgr.Execute("nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for missing blueprint")
	}
}

func TestMissingOverrideDirIsNotError(t *testing.T) {
	_, err := New("/nonexistent/prompts/dir")
	if err != nil {
		t.Fatalf("missing override dir should not be fatal: %v", err)
	}
}

func TestContextLinesInPrompt(t *testing.T) {
	mgr, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, user, err := mgr.Execute("triage", map[string]any{
		"RuleID":               "r",
		"Severity":             "high",
		"Description":          "d",
		"Evidence":             []string{"line1"},
		"ContextLines":         []string{"ctx-before", "ctx-after"},
		"ContextWindowMinutes": 2,
		"KnownBenign":          nil,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(user, "ctx-before") {
		t.Errorf("context lines not in prompt:\n%s", user)
	}
}
