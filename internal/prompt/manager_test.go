package prompt

import (
	"encoding/json"
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

func TestBuiltinTriageHasSchema(t *testing.T) {
	mgr, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, name, ok := mgr.Schema("triage")
	if !ok {
		t.Fatal("triage blueprint should declare a schema")
	}
	if name == "" {
		t.Error("schema name should not be empty")
	}
	// Verify it round-trips as valid JSON.
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if v["type"] != "object" {
		t.Errorf("expected schema type=object, got %v", v["type"])
	}
}

func TestSchemaAbsentForMissingBlueprint(t *testing.T) {
	mgr, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, ok := mgr.Schema("nonexistent")
	if ok {
		t.Error("Schema() should return ok=false for a missing blueprint")
	}
}

func TestOverrideDirCanAddSchema(t *testing.T) {
	dir := t.TempDir()
	override := `name: triage
version: "99.0.0"
critical: true
schema:
  name: custom_verdict
  schema:
    type: object
    additionalProperties: false
    properties:
      result:
        type: string
    required: [result]
system: |
  sys
user: |
  user {{ .RuleID }}
`
	if err := os.WriteFile(filepath.Join(dir, "triage.yaml"), []byte(override), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, err := New(dir)
	if err != nil {
		t.Fatalf("New with override: %v", err)
	}
	raw, name, ok := mgr.Schema("triage")
	if !ok {
		t.Fatal("override blueprint should have schema")
	}
	if name != "custom_verdict" {
		t.Errorf("expected schema name 'custom_verdict', got %q", name)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("schema not valid JSON: %v", err)
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
