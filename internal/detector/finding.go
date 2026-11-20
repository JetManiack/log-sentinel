// Package detector implements the deterministic detection layer.
package detector

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// Severity levels, ordered lowest to highest.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding is a candidate produced by the detector.
type Finding struct {
	// Fingerprint is a stable hash of (RuleID, source, key fields).
	Fingerprint string
	// RuleID identifies which rule fired.
	RuleID string
	// Severity is one of the Severity* constants.
	Severity string
	// Source is the LogSource name.
	Source string
	// Description is the human-readable rule description.
	Description string
	// Evidence holds masked log lines that matched the rule.
	Evidence []string
	// ContextLines holds surrounding log lines fetched from the same stream
	// in a ±window around the event time, for LLM enrichment only.
	// These are masked but not used for detection decisions.
	ContextLines []string
	// FiredAt is when the detector produced this finding.
	FiredAt time.Time

	// GroupEvent indicates what kind of burst-grouping event this is.
	// Zero value (GroupEventNone) means the old non-grouped path.
	GroupEvent GroupEvent
	// GroupCount is the total number of events in the group at this point.
	GroupCount int
	// GroupActorKey is the human-readable actor key
	// (e.g. "system:kube-controller-manager" or "" for whole-rule groups).
	GroupActorKey string
	// GroupObjects is the sampled list of object names (key_fields minus actor_fields).
	GroupObjects []string
	// GroupWindowID is the DB row ID of the GroupWindow; non-zero when grouped.
	GroupWindowID uint
}

// GroupEvent classifies a grouped finding for the sinks.
type GroupEvent uint8

const (
	// GroupEventNone is a non-grouped finding (old path, GroupWindowID == 0).
	GroupEventNone GroupEvent = iota
	// GroupEventOpen is emitted when the first event opens a new GroupWindow.
	// stdout emits a "finding" line (triggers Grafana alert).
	GroupEventOpen
	// GroupEventUpdate is emitted when events arrive in an already-open window.
	// stdout emits "group_update" (NOT a "finding" line — no Grafana alert).
	GroupEventUpdate
	// GroupEventClosed is emitted when a GroupWindow expires.
	// stdout emits a "finding" line with final count + time range.
	GroupEventClosed
)

// Fingerprint computes a stable fingerprint for a (ruleID, source, key) triple.
func Fingerprint(ruleID, source, key string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", ruleID, source, key)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// GroupFP computes the burst-grouping fingerprint for a (ruleID, source, actorKey)
// triple. When actorKey is empty (no actor_fields configured), the group covers
// the whole rule+source, preventing burst storms from opening one finding per object.
func GroupFP(ruleID, source, actorKey string) string {
	h := sha256.New()
	fmt.Fprintf(h, "group\x00%s\x00%s\x00%s", ruleID, source, actorKey)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// EventID computes a dedup event ID from raw log fields. When auditID is
// non-empty it is used directly (Kubernetes audit log path). Otherwise a hash
// of (_time, streamID, msg) is returned to prevent collapsing identical messages
// from different streams or times.
func EventID(auditID, eventTime, streamID, msg string) string {
	if auditID != "" {
		return auditID
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", eventTime, streamID, msg)
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}
