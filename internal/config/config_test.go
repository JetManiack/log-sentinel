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
				{ID: "rule-a", Severity: "critical", Description: "inline"},
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
