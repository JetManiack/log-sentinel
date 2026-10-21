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
	// Evidence holds masked log lines or other supporting text.
	Evidence []string
	// FiredAt is when the detector produced this finding.
	FiredAt time.Time
}

// Fingerprint computes a stable fingerprint for a (ruleID, source, key) triple.
func Fingerprint(ruleID, source, key string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", ruleID, source, key)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
