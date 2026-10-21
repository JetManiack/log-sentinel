package sink

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/JetManiack/log-sentinel/internal/detector"
)

func TestSlogLevel(t *testing.T) {
	cases := []struct{ sev, want string }{
		{"low", "INFO"},
		{"medium", "WARN"},
		{"high", "ERROR"},
		{"critical", "ERROR"},
		{"unknown", "INFO"},
	}
	for _, tc := range cases {
		got := slogLevel(tc.sev)
		if got != tc.want {
			t.Errorf("slogLevel(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestEmitJSON(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	s := &Stdout{enc: enc}

	f := detector.Finding{
		Fingerprint: "deadbeef01234567",
		RuleID:      "sshd-failure",
		Severity:    "medium",
		Source:      "local",
		Description: "SSH auth failure",
		Evidence:    []string{"Failed password for root"},
		FiredAt:     time.Now(),
	}
	s.Emit(f, nil)

	var out FindingJSON
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if out.RuleID != "sshd-failure" {
		t.Errorf("rule_id mismatch: %q", out.RuleID)
	}
	if out.Level != "WARN" {
		t.Errorf("level mismatch: %q", out.Level)
	}
	if out.Enrichment != nil {
		t.Error("enrichment should be nil")
	}
}

func TestEmitJSONWithEnrichment(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	s := &Stdout{enc: enc}

	f := detector.Finding{
		RuleID:   "k8s-exec-attach",
		Severity: "high",
		Source:   "prod",
	}
	enrich := &Enrichment{
		WhatHappenedRU: "что-то случилось",
		ImpactRU:       "критический импакт",
		Confidence:     0.9,
		Severity:       "high",
	}
	s.Emit(f, enrich)

	var out FindingJSON
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Enrichment == nil {
		t.Fatal("enrichment should not be nil")
	}
	if out.Enrichment.Confidence != 0.9 {
		t.Errorf("confidence mismatch: %v", out.Enrichment.Confidence)
	}
}

func TestEmitNoHTMLEscape(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	s := &Stdout{enc: enc}

	f := detector.Finding{
		RuleID:      "r",
		Severity:    "low",
		Source:      "s",
		Description: "url with <special> & chars",
		Evidence:    []string{"GET /search?q=a&b=c"},
	}
	s.Emit(f, nil)

	raw := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("&")) {
		t.Errorf("& should not be HTML-escaped, got: %s", raw)
	}
}
