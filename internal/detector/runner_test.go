package detector

import (
	"testing"

	"github.com/JetManiack/log-sentinel/internal/config"
)

func TestIsBenign(t *testing.T) {
	entries := []config.KnownBenignEntry{
		{Pattern: "healthcheck"},
		{Pattern: "liveness probe"},
	}

	if !isBenign([]string{"GET /healthcheck 200"}, entries) {
		t.Error("should be benign")
	}
	if isBenign([]string{"GET /api/login 401"}, entries) {
		t.Error("should not be benign")
	}
	if isBenign([]string{}, entries) {
		t.Error("empty lines should not be benign")
	}
}

func TestTruncate(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	got := truncate(lines, 3)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	got2 := truncate(lines, 10)
	if len(got2) != 5 {
		t.Fatalf("under limit: want 5, got %d", len(got2))
	}
}
