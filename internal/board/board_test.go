package board

import (
	"testing"

	"github.com/JetManiack/log-sentinel/internal/detector"
	"github.com/JetManiack/log-sentinel/internal/sink"
)

func TestMeetsMinSeverity(t *testing.T) {
	cases := []struct {
		actual, min string
		want        bool
	}{
		{"critical", "medium", true},
		{"high", "high", true},
		{"low", "medium", false},
		{"medium", "high", false},
		{"critical", "", true},  // empty min defaults to medium
		{"low", "", false},
		// Unknown actual → fail-closed (above critical = meets any threshold)
		{"extreme", "critical", true},
		// Unknown min → let everything through (0)
		{"low", "bogus", true},
	}
	for _, tc := range cases {
		got := meetsMinSeverity(tc.actual, tc.min)
		if got != tc.want {
			t.Errorf("meetsMinSeverity(%q, %q) = %v, want %v", tc.actual, tc.min, got, tc.want)
		}
	}
}

func TestFormatBodyNoEnrichment(t *testing.T) {
	f := detector.Finding{
		RuleID:      "sshd-failure",
		Severity:    "medium",
		Source:      "local",
		Description: "SSH auth failure",
		Evidence:    []string{"Failed password for root"},
	}
	body := formatBody(f, nil)
	if body == "" {
		t.Fatal("body should not be empty")
	}
	// Should mention the rule and source.
	for _, want := range []string{"sshd-failure", "local", "MEDIUM", "Failed password"} {
		if !containsStr(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	// Should include command instructions.
	if !containsStr(body, "/quiet") {
		t.Errorf("body missing command instructions:\n%s", body)
	}
}

func TestFormatBodyWithEnrichment(t *testing.T) {
	f := detector.Finding{
		RuleID:   "k8s-exec-attach",
		Severity: "high",
		Source:   "prod",
	}
	e := &sink.Enrichment{
		WhatHappenedRU: "выполнен exec в под",
		ImpactRU:       "возможная компрометация",
		Confidence:     0.8,
	}
	body := formatBody(f, e)
	if !containsStr(body, "выполнен exec") {
		t.Errorf("body missing enrichment:\n%s", body)
	}
}

func containsStr(s, sub string) bool {
	return len(sub) <= len(s) && func() bool {
		for i := range s {
			if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
