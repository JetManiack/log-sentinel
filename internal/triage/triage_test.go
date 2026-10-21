package triage

import (
	"testing"
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
