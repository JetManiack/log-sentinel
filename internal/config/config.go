// Package config loads and validates the sentinel configuration.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	// State is the SQLite database path or Postgres DSN for baselines and dedup.
	State string `yaml:"state"`

	// Logs lists the VictoriaLogs / Loki endpoints the sentinel queries.
	Logs []LogSource `yaml:"logs"`

	// LLM configures the optional triage layer.
	LLM LLMConfig `yaml:"llm"`

	// Detector configures the deterministic detection layer.
	Detector DetectorConfig `yaml:"detector"`

	// Digest configures the daily low-severity digest.
	Digest DigestConfig `yaml:"digest"`
}

// LogSource is a single log backend.
type LogSource struct {
	// Name is a short human label used in findings.
	Name string `yaml:"name"`
	// URL is the base URL, e.g. "http://victorialogs:9428".
	URL string `yaml:"url"`
	// Token is an optional Bearer token.
	Token string `yaml:"token"`
	// CAFile is an optional path to a PEM CA certificate to trust for TLS.
	// Useful when the VictoriaLogs endpoint uses a private CA.
	CAFile string `yaml:"ca_file"`
}

// LLMConfig configures the optional triage model.
type LLMConfig struct {
	// Enabled turns the triage layer on or off.
	Enabled bool `yaml:"enabled"`
	// BaseURL is the OpenAI-compatible endpoint base URL.
	BaseURL string `yaml:"base_url"`
	// APIKey is the key for the endpoint.
	APIKey string `yaml:"api_key"`
	// Model is the model identifier, e.g. "gemma-4-26b-a4b-it".
	Model string `yaml:"model"`
	// MaxTokensStep is the token budget for each tool step reply (default 256).
	MaxTokensStep int `yaml:"max_tokens_step"`
	// MaxTokensFinal is the budget for the final JSON answer (default 1200).
	MaxTokensFinal int `yaml:"max_tokens_final"`
	// StepTimeout is the per-step deadline (default 60s).
	StepTimeout time.Duration `yaml:"step_timeout"`
	// TotalTimeout is the whole-investigation deadline (default 240s).
	TotalTimeout time.Duration `yaml:"total_timeout"`
	// ContextWindow is the ±window around the matched event used to fetch
	// surrounding log lines for the LLM prompt (default 2m).
	ContextWindow time.Duration `yaml:"context_window"`
	// ContextLines is the max number of surrounding lines to include (default 20).
	ContextLines int `yaml:"context_lines"`
	// PromptsDir is an optional directory of YAML blueprint overrides.
	// Files here replace built-in prompts by their `name` field.
	PromptsDir string `yaml:"prompts_dir"`
}

// DetectorConfig controls the deterministic detection layer.
type DetectorConfig struct {
	// Interval is how often the detector polls (default 1m).
	Interval time.Duration `yaml:"interval"`
	// WindowBefore is the look-back window around a change event (default 30m).
	WindowBefore time.Duration `yaml:"window_before"`
	// WindowAfter is the look-forward window (default 15m).
	WindowAfter time.Duration `yaml:"window_after"`
	// QuietWindowDefault is the dedup quiet window after a finding fires (default 24h).
	QuietWindowDefault time.Duration `yaml:"quiet_window_default"`
	// RulesDir is a directory of *.yaml rule files (optional, merged with Rules).
	RulesDir string `yaml:"rules_dir"`
	// Rules are inline rule definitions.
	Rules []Rule `yaml:"rules"`
	// FailOpenPatterns are substrings that always trigger a finding in watched logs.
	FailOpenPatterns []string `yaml:"fail_open_patterns"`
	// KnownBenign lists patterns that are never escalated to a notification.
	KnownBenign []KnownBenignEntry `yaml:"known_benign"`
	// GroupWindowDefault is the tumbling burst-grouping window for all rules
	// that don't set their own group_window (default 10m).
	GroupWindowDefault time.Duration `yaml:"group_window_default"`
	// SampleObjectsMax is the max number of distinct objectRef.name values to
	// collect per GroupWindow row (default 5). Extra values are dropped to keep
	// DB size predictable.
	SampleObjectsMax int `yaml:"sample_objects_max"`
	// SeenEventTTL controls how long a seen event_id is retained for dedup
	// (default 1h). Events older than the poll overlap don't need to be retained.
	SeenEventTTL time.Duration `yaml:"seen_event_ttl"`
}

// Rule is a single LogsQL-based detection rule.
type Rule struct {
	// ID is a unique stable identifier for this rule.
	ID string `yaml:"id"`
	// Query is a LogsQL expression.
	Query string `yaml:"query"`
	// Severity is one of "low", "medium", "high", "critical".
	Severity string `yaml:"severity"`
	// Description explains what the rule catches (used in findings and docs).
	Description string `yaml:"description"`
	// Source names the LogSource(s) this rule applies to (empty = all).
	Source string `yaml:"source"`
	// KeyFields are VictoriaLogs field names whose values are shown in evidence.
	// They no longer drive the grouping fingerprint — ActorFields does.
	// Example: [user.username, objectRef.namespace, objectRef.name]
	KeyFields []string `yaml:"key_fields"`
	// ActorFields are the subset of key_fields that identify the actor for
	// burst grouping. Events with the same rule + actor within group_window
	// collapse into one finding. If empty, the whole rule is one group per
	// window (safe fallback for rules that caused burst noise).
	ActorFields []string `yaml:"actor_fields"`
	// AuditIDField is the VictoriaLogs field holding the unique audit event
	// ID (e.g. "auditID" for Kubernetes audit logs). Used for exact dedup
	// across poll overlaps and pod restarts. If empty, dedup falls back to
	// hash(_time + _stream_id + _msg).
	AuditIDField string `yaml:"audit_id_field"`
	// GroupWindow overrides the detector-level group_window_default for this
	// rule. Zero means use the default.
	GroupWindow time.Duration `yaml:"group_window"`
}

// KnownBenignEntry is a log-pattern + reason that suppresses notifications.
type KnownBenignEntry struct {
	// Pattern is a substring match against the log line.
	Pattern string `yaml:"pattern"`
	// Reason explains why it is benign (required).
	Reason string `yaml:"reason"`
	// Severity is the threshold at which this suppression applies (default "low").
	Severity string `yaml:"severity"`
}

// DigestConfig controls the daily digest.
type DigestConfig struct {
	// Time is "HH:MM" in the given timezone.
	Time string `yaml:"time"`
	// Timezone is an IANA timezone name, e.g. "Asia/Nicosia".
	Timezone string `yaml:"timezone"`
	// NewLookback is how far back the digest looks for "new" findings that
	// haven't appeared in a previous digest (default 14d). Longer means more
	// catch-up after an outage; shorter means less noise from old data.
	NewLookback time.Duration `yaml:"new_lookback"`
}

// Load reads and parses the YAML config at path, then merges any rules from
// detector.rules_dir (directory-file rules never override inline rules).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	setDefaults(&cfg)
	if cfg.Detector.RulesDir != "" {
		if err := loadRulesDir(&cfg); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

// ruleFile is the top-level structure expected in each *.yaml under rules_dir.
type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// validSeverities lists the accepted rule severity values.
var validSeverities = map[string]struct{}{
	"low": {}, "medium": {}, "high": {}, "critical": {},
}

// validateRule returns an error if a rule is missing required fields or has an
// unrecognised severity.
func validateRule(r Rule, source string) error {
	if r.ID == "" {
		return fmt.Errorf("config: %s: rule missing id", source)
	}
	if r.Query == "" {
		return fmt.Errorf("config: %s: rule %q missing query", source, r.ID)
	}
	if _, ok := validSeverities[r.Severity]; !ok {
		return fmt.Errorf("config: %s: rule %q has unknown severity %q (want low/medium/high/critical)", source, r.ID, r.Severity)
	}
	return nil
}

// loadRulesDir globs cfg.Detector.RulesDir for *.yaml files and appends their
// rules to cfg.Detector.Rules.
//
//   - Inline rules always take precedence over directory rules (same ID is skipped
//     with a warning).
//   - A malformed or unreadable file is skipped with a warning, not a fatal error,
//     so one bad file cannot disable all detection.
//   - Duplicate IDs across directory files are also warned, and the first-seen
//     definition wins (alphabetical file order).
func loadRulesDir(cfg *Config) error {
	dir := cfg.Detector.RulesDir

	// Validate inline rules first.
	inlineIDs := make(map[string]struct{}, len(cfg.Detector.Rules))
	for _, r := range cfg.Detector.Rules {
		if err := validateRule(r, "inline"); err != nil {
			return err
		}
		inlineIDs[r.ID] = struct{}{}
	}

	pattern := filepath.Join(dir, "*.yaml")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("config: rules_dir glob %s: %w", pattern, err)
	}

	// seen tracks all IDs including inline ones, for cross-file duplicate detection.
	seen := make(map[string]struct{}, len(inlineIDs))
	for id := range inlineIDs {
		seen[id] = struct{}{}
	}

	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("config: rules_dir: skipping unreadable file", "path", path, "err", err)
			continue
		}
		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			slog.Warn("config: rules_dir: skipping malformed file", "path", path, "err", err)
			continue
		}
		for _, r := range rf.Rules {
			if err := validateRule(r, path); err != nil {
				slog.Warn("config: rules_dir: skipping invalid rule", "path", path, "err", err)
				continue
			}
			if _, isInline := inlineIDs[r.ID]; isInline {
				slog.Warn("config: rules_dir: rule ID shadowed by inline rule, skipping", "id", r.ID, "file", path)
				continue
			}
			if _, dup := seen[r.ID]; dup {
				slog.Warn("config: rules_dir: duplicate rule ID across directory files, keeping first", "id", r.ID, "file", path)
				continue
			}
			cfg.Detector.Rules = append(cfg.Detector.Rules, r)
			seen[r.ID] = struct{}{}
		}
	}
	return nil
}

func setDefaults(cfg *Config) {
	if cfg.State == "" {
		cfg.State = "data/sentinel.db"
	}
	d := &cfg.Detector
	if d.Interval == 0 {
		d.Interval = time.Minute
	}
	if d.WindowBefore == 0 {
		d.WindowBefore = 30 * time.Minute
	}
	if d.WindowAfter == 0 {
		d.WindowAfter = 15 * time.Minute
	}
	if d.QuietWindowDefault == 0 {
		d.QuietWindowDefault = 24 * time.Hour
	}
	if d.GroupWindowDefault == 0 {
		d.GroupWindowDefault = 10 * time.Minute
	}
	if d.SampleObjectsMax == 0 {
		d.SampleObjectsMax = 5
	}
	if d.SeenEventTTL == 0 {
		d.SeenEventTTL = time.Hour
	}
	l := &cfg.LLM
	if l.MaxTokensStep == 0 {
		l.MaxTokensStep = 256
	}
	if l.MaxTokensFinal == 0 {
		l.MaxTokensFinal = 1200
	}
	if l.StepTimeout == 0 {
		l.StepTimeout = 60 * time.Second
	}
	if l.TotalTimeout == 0 {
		l.TotalTimeout = 240 * time.Second
	}
	if l.ContextWindow == 0 {
		l.ContextWindow = 2 * time.Minute
	}
	if l.ContextLines == 0 {
		l.ContextLines = 20
	}
	if cfg.Digest.Time == "" {
		cfg.Digest.Time = "19:00"
	}
	if cfg.Digest.Timezone == "" {
		cfg.Digest.Timezone = "UTC"
	}
	if cfg.Digest.NewLookback == 0 {
		cfg.Digest.NewLookback = 14 * 24 * time.Hour
	}
}
