// Package sink contains the output channel implementations.
package sink

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/JetManiack/log-sentinel/internal/detector"
)

// FindingJSON is the structured JSON shape written to stdout.
// vlagent picks these up and ships them to VictoriaLogs, where a Grafana rule
// fires on msg:"finding". group_update lines use msg:"group_update" deliberately
// so they do NOT trigger Grafana — they are informational count updates only.
type FindingJSON struct {
	Time        string   `json:"time"`
	Level       string   `json:"level"`
	Msg         string   `json:"msg"`
	Severity    string   `json:"severity"`
	RuleID      string   `json:"rule_id"`
	Source      string   `json:"source"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence,omitempty"`
	// Grouping fields — only set when GroupEvent != GroupEventNone.
	// group_event: "group_open" | "group_update" | "group_closed"
	// Grafana rule matches msg:"finding" AND group_event to distinguish open vs closed.
	GroupEvent    string   `json:"group_event,omitempty"`
	GroupFP       string   `json:"group_fp,omitempty"`
	GroupActor    string   `json:"actor,omitempty"`
	GroupCount    int      `json:"group_count,omitempty"`
	GroupObjects  []string `json:"group_objects,omitempty"`
	// Enrichment is set after the optional triage step.
	Enrichment *Enrichment `json:"enrichment,omitempty"`
}

// Enrichment holds the optional LLM triage output.
type Enrichment struct {
	WhatHappenedRU  string   `json:"what_happened_ru"`
	ImpactRU        string   `json:"impact_ru"`
	Evidence        []string `json:"evidence"`
	LikelyBenign    string   `json:"likely_benign_reason,omitempty"`
	RecommendedCheck string  `json:"recommended_check_ru,omitempty"`
	Confidence      float64  `json:"confidence"`
	Severity        string   `json:"severity"`
}

// Stdout writes findings as JSON lines to os.Stdout.
type Stdout struct {
	enc *json.Encoder
}

// NewStdout creates a Stdout sink.
func NewStdout() *Stdout {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return &Stdout{enc: enc}
}

// Emit writes a finding to stdout.
//
// GroupEventUpdate (group_update) writes msg:"group_update" — Grafana does NOT
// match this, so no alert fires. All other events write msg:"finding" so Grafana
// can alert on them.
func (s *Stdout) Emit(f detector.Finding, enrichment *Enrichment) {
	msg := "finding"
	groupEvent := ""
	switch f.GroupEvent {
	case detector.GroupEventOpen:
		groupEvent = "group_open"
	case detector.GroupEventUpdate:
		msg = "group_update"
		groupEvent = "group_update"
	case detector.GroupEventClosed:
		groupEvent = "group_closed"
	}
	out := FindingJSON{
		Time:         time.Now().UTC().Format(time.RFC3339),
		Level:        slogLevel(f.Severity),
		Msg:          msg,
		Severity:     f.Severity,
		RuleID:       f.RuleID,
		Source:       f.Source,
		Description:  f.Description,
		Evidence:     f.Evidence,
		GroupEvent:   groupEvent,
		GroupFP:      f.GroupFingerprint,
		GroupActor:   f.GroupActorKey,
		GroupCount:   f.GroupCount,
		GroupObjects: f.GroupObjects,
		Enrichment:   enrichment,
	}
	if err := s.enc.Encode(out); err != nil {
		slog.Error("stdout sink encode error", "err", err)
	}
}

func slogLevel(severity string) string {
	switch severity {
	case detector.SeverityLow:
		return "INFO"
	case detector.SeverityMedium:
		return "WARN"
	case detector.SeverityHigh, detector.SeverityCritical:
		return "ERROR"
	default:
		return "INFO"
	}
}
