package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesDir(t *testing.T) {
	dir := t.TempDir()

	// Write two rule files.
	file1 := `rules:
  - id: rule-a
    severity: high
    description: A
    query: '{job="x"}'
  - id: rule-b
    severity: medium
    description: B
    query: '{job="y"}'
`
	file2 := `rules:
  - id: rule-c
    severity: low
    description: C
    query: '{job="z"}'
`
	if err := os.WriteFile(filepath.Join(dir, "file1.yaml"), []byte(file1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file2.yaml"), []byte(file2), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Detector: DetectorConfig{RulesDir: dir}}
	if err := loadRulesDir(cfg); err != nil {
		t.Fatalf("loadRulesDir: %v", err)
	}
	if len(cfg.Detector.Rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(cfg.Detector.Rules))
	}
}

func TestLoadRulesDirInlineOverride(t *testing.T) {
	dir := t.TempDir()
	file := `rules:
  - id: rule-a
    severity: low
    description: from file
    query: '{job="y"}'
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Detector: DetectorConfig{
			RulesDir: dir,
			Rules: []Rule{
				{ID: "rule-a", Severity: "critical", Description: "inline", Query: `{job="inline"}`},
			},
		},
	}
	if err := loadRulesDir(cfg); err != nil {
		t.Fatalf("loadRulesDir: %v", err)
	}
	// Inline rule must survive; file rule must be skipped.
	if len(cfg.Detector.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(cfg.Detector.Rules))
	}
	if cfg.Detector.Rules[0].Severity != "critical" {
		t.Fatalf("inline rule was overridden: %s", cfg.Detector.Rules[0].Severity)
	}
}

func TestLoadRulesDirMissing(t *testing.T) {
	cfg := &Config{Detector: DetectorConfig{RulesDir: "/nonexistent/path"}}
	// An empty glob (no matches) is not an error; only a bad path expression is.
	if err := loadRulesDir(cfg); err != nil {
		t.Fatalf("unexpected error for empty dir: %v", err)
	}
}

func TestLoadRulesDirSkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	// Write a valid file and a malformed file; only the valid one should load.
	valid := `rules:
  - id: rule-good
    severity: high
    description: Good
    query: '{job="x"}'
`
	bad := `rules: [unclosed`
	if err := os.WriteFile(filepath.Join(dir, "a_valid.yaml"), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b_bad.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Detector: DetectorConfig{RulesDir: dir}}
	if err := loadRulesDir(cfg); err != nil {
		t.Fatalf("loadRulesDir should not fail on a malformed file: %v", err)
	}
	if len(cfg.Detector.Rules) != 1 || cfg.Detector.Rules[0].ID != "rule-good" {
		t.Fatalf("expected 1 valid rule, got %+v", cfg.Detector.Rules)
	}
}

func TestValidateRuleRejectsUnknownSeverity(t *testing.T) {
	r := Rule{ID: "x", Query: `{job="x"}`, Severity: "critical"}
	if err := validateRule(r, "test"); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	r.Severity = "extreme"
	if err := validateRule(r, "test"); err == nil {
		t.Fatal("expected error for unknown severity, got nil")
	}
}

func TestLoadRulesDirDuplicateCrossFile(t *testing.T) {
	dir := t.TempDir()
	// Same ID in two files — only the first (alphabetically) should be kept.
	f1 := `rules:
  - id: dup-rule
    severity: high
    description: First
    query: '{job="a"}'
`
	f2 := `rules:
  - id: dup-rule
    severity: low
    description: Second
    query: '{job="b"}'
`
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(f1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(f2), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Detector: DetectorConfig{RulesDir: dir}}
	if err := loadRulesDir(cfg); err != nil {
		t.Fatalf("loadRulesDir: %v", err)
	}
	if len(cfg.Detector.Rules) != 1 {
		t.Fatalf("want 1 rule (dup suppressed), got %d", len(cfg.Detector.Rules))
	}
	if cfg.Detector.Rules[0].Severity != "high" {
		t.Fatalf("first file should win, got severity %s", cfg.Detector.Rules[0].Severity)
	}
}
