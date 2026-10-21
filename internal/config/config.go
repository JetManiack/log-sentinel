// Package config loads and validates the sentinel configuration.
package config

import (
	"fmt"
	"os"
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

	// Sinks configure where findings are sent.
	Sinks SinksConfig `yaml:"sinks"`

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
}

// SinksConfig lists the output channels.
type SinksConfig struct {
	// StdoutJSON writes every finding as a JSON line to stdout (always on).
	StdoutJSON bool `yaml:"stdout_json"`

	// Board configures the coordination board sink.
	Board BoardSinkConfig `yaml:"board"`

	// Webhook is an optional generic HTTP sink.
	Webhook WebhookSinkConfig `yaml:"webhook"`
}

// BoardSinkConfig configures the board MCP client.
type BoardSinkConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Token   string `yaml:"token"`
	// MinSeverity is the minimum severity to post; below this → digest only.
	MinSeverity string `yaml:"min_severity"`
}

// WebhookSinkConfig is a generic HTTP POST sink.
type WebhookSinkConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Token   string `yaml:"token"`
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
}

// Commands controls the /quiet /benign /unquiet command parser.
type CommandsConfig struct {
	// AllowedActors is a list of board actor nicknames allowed to issue commands.
	AllowedActors []string `yaml:"allowed_actors"`
	// CriticalMuteActors can mute critical findings (subset of AllowedActors).
	CriticalMuteActors []string `yaml:"critical_mute_actors"`
	// MaxAgentQuietDays is the max quiet duration an agent (non-critical-mute actor)
	// can set via /quiet (default 7).
	MaxAgentQuietDays int `yaml:"max_agent_quiet_days"`
	// MaxAgentBenignDays is how long an agent's /benign entry lasts without
	// operator confirmation (default 30).
	MaxAgentBenignDays int `yaml:"max_agent_benign_days"`
}

// Load reads and parses the YAML config at path.
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
	return &cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.State == "" {
		cfg.State = "data/sentinel.db"
	}
	if cfg.Sinks.StdoutJSON {
		// always-on; nothing to default
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
	if cfg.Digest.Time == "" {
		cfg.Digest.Time = "19:00"
	}
	if cfg.Digest.Timezone == "" {
		cfg.Digest.Timezone = "UTC"
	}
}
