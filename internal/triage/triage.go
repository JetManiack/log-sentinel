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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/detector"
	"github.com/JetManiack/log-sentinel/internal/masker"
	"github.com/JetManiack/log-sentinel/internal/sink"
)

const systemPrompt = `Ты — security-аналитик, получаешь подозрительное событие из логов.
Проанализируй и верни compact single-line JSON без пробелов между полями:
{"severity":"low|medium|high|critical","what_happened_ru":"...","impact_ru":"...","evidence":["..."],"likely_benign_reason":"...","recommended_check_ru":"...","confidence":0.0}
Поля likely_benign_reason и recommended_check_ru — опциональные, оставь пустыми если неприменимо.
Severity не может быть ниже той, что определил детектор.
Если не хватает данных — честно укажи.`

// Triager calls the LLM for enrichment.
type Triager struct {
	cfg    config.LLMConfig
	mask   *masker.Mask
	client *http.Client
}

// New creates a Triager. Returns nil if LLM is disabled.
func New(cfg config.LLMConfig, m *masker.Mask) *Triager {
	if !cfg.Enabled {
		return nil
	}
	return &Triager{
		cfg:  cfg,
		mask: m,
		client: &http.Client{
			Timeout: cfg.TotalTimeout + 10*time.Second,
		},
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

type respFormat struct {
	Type string `json:"type"`
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

	userContent := buildPrompt(f, knownBenign, t.mask)

	reqBody := oaiRequest{
		Model: t.cfg.Model,
		Messages: []oaiMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userContent},
		},
		MaxTokens:   t.cfg.MaxTokensFinal,
		Temperature: 0,
		ResponseFormat: &respFormat{Type: "json_object"},
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

func buildPrompt(f detector.Finding, benign []config.KnownBenignEntry, m *masker.Mask) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Правило: %s (%s)\nОписание: %s\n\nСобытия:\n",
		f.RuleID, f.Severity, f.Description)
	for _, e := range f.Evidence {
		sb.WriteString(m.Redact(e))
		sb.WriteByte('\n')
	}
	if len(benign) > 0 {
		sb.WriteString("\nИзвестные штатные ситуации (не считать подозрительными):\n")
		for _, b := range benign {
			fmt.Fprintf(&sb, "- %s: %s\n", b.Pattern, b.Reason)
		}
	}
	return sb.String()
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
