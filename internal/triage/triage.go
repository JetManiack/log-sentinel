// Package triage implements the optional LLM enrichment layer.
//
// A finding produced by the detector is always published; triage only adds
// the Enrichment field. If the LLM is unavailable or times out, the finding
// is sent unenriched.
package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/detector"
	"github.com/JetManiack/log-sentinel/internal/masker"
	"github.com/JetManiack/log-sentinel/internal/prompt"
	"github.com/JetManiack/log-sentinel/internal/sink"
)

// Triager calls the LLM for enrichment.
type Triager struct {
	cfg     config.LLMConfig
	mask    *masker.Mask
	client  *http.Client
	prompts *prompt.Manager
}

// New creates a Triager. Returns nil if LLM is disabled.
func New(cfg config.LLMConfig, m *masker.Mask) *Triager {
	if !cfg.Enabled {
		return nil
	}
	mgr, err := prompt.New(cfg.PromptsDir)
	if err != nil {
		slog.Error("triage: failed to load prompt blueprints", "err", err)
		return nil
	}
	return &Triager{
		cfg:  cfg,
		mask: m,
		client: &http.Client{
			Timeout: cfg.TotalTimeout + 10*time.Second,
		},
		prompts: mgr,
	}
}

type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiRequest struct {
	Model          string       `json:"model"`
	Messages       []oaiMessage `json:"messages"`
	MaxTokens      int          `json:"max_tokens"`
	Temperature    float64      `json:"temperature"`
	ResponseFormat *respFormat  `json:"response_format,omitempty"`
}

// respFormat selects between json_object (basic) and json_schema (structured output).
// When Schema is non-nil the provider is asked for strict structured output.
type respFormat struct {
	Type       string         `json:"type"`
	JSONSchema *jsonSchemaWrap `json:"json_schema,omitempty"`
}

type jsonSchemaWrap struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type oaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// triageOutput is the expected JSON shape from the model.
type triageOutput struct {
	Severity         string   `json:"severity"`
	WhatHappenedRU   string   `json:"what_happened_ru"`
	ImpactRU         string   `json:"impact_ru"`
	Evidence         []string `json:"evidence"`
	LikelyBenign     string   `json:"likely_benign_reason,omitempty"`
	RecommendedCheck string   `json:"recommended_check_ru,omitempty"`
	Confidence       float64  `json:"confidence"`
}

// Enrich calls the LLM and returns an Enrichment, or nil on any failure.
// The finding is never suppressed by this call.
func (t *Triager) Enrich(ctx context.Context, f detector.Finding, knownBenign []config.KnownBenignEntry) *sink.Enrichment {
	if t == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, t.cfg.TotalTimeout)
	defer cancel()

	systemContent, userContent, err := buildPrompt(t.prompts, t.mask, f, knownBenign, t.cfg.ContextWindow)
	if err != nil {
		slog.Warn("triage: build prompt", "err", err)
		return nil
	}

	rf := buildResponseFormat(t.prompts, "triage")
	reqBody := oaiRequest{
		Model: t.cfg.Model,
		Messages: []oaiMessage{
			{Role: "system", Content: systemContent},
			{Role: "user", Content: userContent},
		},
		MaxTokens:      t.cfg.MaxTokensFinal,
		Temperature:    0,
		ResponseFormat: rf,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		slog.Warn("triage: marshal request", "err", err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.cfg.BaseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		slog.Warn("triage: build request", "err", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if t.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.cfg.APIKey)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		slog.Warn("triage: http call failed", "err", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		slog.Warn("triage: non-200 response", "status", resp.StatusCode, "body", string(body))
		return nil
	}

	var oaiResp oaiResponse
	if err := json.NewDecoder(resp.Body).Decode(&oaiResp); err != nil {
		slog.Warn("triage: decode response", "err", err)
		return nil
	}

	if len(oaiResp.Choices) == 0 {
		return nil
	}

	choice := oaiResp.Choices[0]
	if choice.FinishReason == "length" {
		slog.Warn("triage: finish_reason=length, dropping enrichment", "rule", f.RuleID)
		return nil
	}

	content := strings.TrimSpace(choice.Message.Content)
	var out triageOutput
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		slog.Warn("triage: parse json output", "err", err, "content", content[:min(200, len(content))])
		return nil
	}

	// Enforce: LLM may only raise severity by at most one level.
	out.Severity = capSeverityRaise(f.Severity, out.Severity)

	return &sink.Enrichment{
		WhatHappenedRU:   out.WhatHappenedRU,
		ImpactRU:         out.ImpactRU,
		Evidence:         out.Evidence,
		LikelyBenign:     out.LikelyBenign,
		RecommendedCheck: out.RecommendedCheck,
		Confidence:       out.Confidence,
		Severity:         out.Severity,
	}
}

// triageData is the template data struct passed to the triage blueprint.
type triageData struct {
	RuleID               string
	Severity             string
	Description          string
	Evidence             []string
	ContextLines         []string
	ContextWindowMinutes int
	KnownBenign          []config.KnownBenignEntry
}

func buildPrompt(
	mgr *prompt.Manager,
	m *masker.Mask,
	f detector.Finding,
	benign []config.KnownBenignEntry,
	ctxWindow time.Duration,
) (system, user string, err error) {
	// Mask evidence and context before passing to the LLM.
	evidence := make([]string, len(f.Evidence))
	for i, e := range f.Evidence {
		evidence[i] = m.Redact(e)
	}
	ctxLines := make([]string, len(f.ContextLines))
	for i, l := range f.ContextLines {
		ctxLines[i] = m.Redact(l)
	}
	data := triageData{
		RuleID:               f.RuleID,
		Severity:             f.Severity,
		Description:          f.Description,
		Evidence:             evidence,
		ContextLines:         ctxLines,
		ContextWindowMinutes: int(ctxWindow.Minutes()),
		KnownBenign:          benign,
	}
	return mgr.Execute("triage", data)
}

// buildResponseFormat returns the response_format to request from the provider.
// When the blueprint declares a JSON Schema, json_schema (strict) is used;
// otherwise json_object is the fallback so the model still returns valid JSON.
func buildResponseFormat(mgr *prompt.Manager, name string) *respFormat {
	raw, schemaName, ok := mgr.Schema(name)
	if ok && len(raw) > 0 {
		return &respFormat{
			Type: "json_schema",
			JSONSchema: &jsonSchemaWrap{
				Name:   schemaName,
				Schema: raw,
				Strict: true,
			},
		}
	}
	return &respFormat{Type: "json_object"}
}

var severityOrder = map[string]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

const (
	SeverityLow      = detector.SeverityLow
	SeverityMedium   = detector.SeverityMedium
	SeverityHigh     = detector.SeverityHigh
	SeverityCritical = detector.SeverityCritical
)

// capSeverityRaise allows the LLM to raise severity by at most one level.
func capSeverityRaise(rule, llm string) string {
	ruleIdx, ok1 := severityOrder[rule]
	llmIdx, ok2 := severityOrder[llm]
	if !ok1 || !ok2 {
		return rule
	}
	if llmIdx <= ruleIdx {
		return rule
	}
	// Raise by one at most.
	if llmIdx > ruleIdx+1 {
		return severityByIdx(ruleIdx + 1)
	}
	return llm
}

func severityByIdx(idx int) string {
	for k, v := range severityOrder {
		if v == idx {
			return k
		}
	}
	return SeverityLow
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
