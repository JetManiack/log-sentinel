package triage

import (
	"os"
	"testing"

	"github.com/JetManiack/log-sentinel/internal/prompt"
)

func TestCapSeverityRaiseNoChange(t *testing.T) {
	// LLM agrees with detector — keep rule severity.
	got := capSeverityRaise("high", "high")
	if got != "high" {
		t.Fatalf("want high, got %q", got)
	}
}

func TestCapSeverityRaiseLower(t *testing.T) {
	// LLM says lower — rule wins (never downgrade).
	got := capSeverityRaise("high", "low")
	if got != "high" {
		t.Fatalf("LLM must not downgrade: want high, got %q", got)
	}
}

func TestCapSeverityRaiseByOne(t *testing.T) {
	// LLM raises by exactly one — allowed.
	got := capSeverityRaise("medium", "high")
	if got != "high" {
		t.Fatalf("want high, got %q", got)
	}
}

func TestCapSeverityRaiseCapped(t *testing.T) {
	// LLM tries to skip two levels — capped to rule+1.
	got := capSeverityRaise("low", "critical")
	if got != "medium" {
		t.Fatalf("want medium (low+1), got %q", got)
	}
}

func TestCapSeverityRaiseUnknown(t *testing.T) {
	// Unknown severity from LLM → rule severity wins.
	got := capSeverityRaise("high", "extreme")
	if got != "high" {
		t.Fatalf("unknown LLM severity should return rule severity, got %q", got)
	}
}

func TestCapSeverityRaiseAtCeiling(t *testing.T) {
	// Already critical — can't go higher.
	got := capSeverityRaise("critical", "critical")
	if got != "critical" {
		t.Fatalf("want critical, got %q", got)
	}
}

func TestBuildResponseFormatUsesJSONSchema(t *testing.T) {
	mgr, err := prompt.New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rf := buildResponseFormat(mgr, "triage")
	if rf == nil {
		t.Fatal("response format should not be nil")
	}
	if rf.Type != "json_schema" {
		t.Errorf("expected json_schema, got %q", rf.Type)
	}
	if rf.JSONSchema == nil {
		t.Error("json_schema wrapper should be set")
	}
	if rf.JSONSchema.Name == "" {
		t.Error("schema name should not be empty")
	}
	if !rf.JSONSchema.Strict {
		t.Error("strict should be true")
	}
}

func TestBuildResponseFormatFallsBackToJSONObject(t *testing.T) {
	// A blueprint without a schema should fall back to json_object.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/triage.yaml", []byte("name: triage\ncritical: true\nsystem: sys\nuser: usr\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, err := prompt.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rf := buildResponseFormat(mgr, "triage")
	if rf.Type != "json_object" {
		t.Errorf("expected json_object fallback, got %q", rf.Type)
	}
	if rf.JSONSchema != nil {
		t.Error("json_schema should be nil for fallback")
	}
}
