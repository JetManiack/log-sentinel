package digest

import (
	"strings"
	"testing"
	"time"

	"github.com/JetManiack/log-sentinel/internal/state"
)

func TestNextFire(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Nicosia")

	// 18:59 local → next fire is today at 19:00.
	now := time.Date(2026, 10, 22, 18, 59, 0, 0, loc)
	next := nextFire(now, "19:00", loc)
	want := time.Date(2026, 10, 22, 19, 0, 0, 0, loc)
	if !next.Equal(want) {
		t.Errorf("before: want %v got %v", want, next)
	}

	// 19:01 local → next fire is tomorrow at 19:00.
	now2 := time.Date(2026, 10, 22, 19, 1, 0, 0, loc)
	next2 := nextFire(now2, "19:00", loc)
	want2 := time.Date(2026, 10, 23, 19, 0, 0, 0, loc)
	if !next2.Equal(want2) {
		t.Errorf("after: want %v got %v", want2, next2)
	}

	// Exactly 19:00 → next is tomorrow (not today, since "after" is required).
	now3 := time.Date(2026, 10, 22, 19, 0, 0, 0, loc)
	next3 := nextFire(now3, "19:00", loc)
	if !next3.Equal(want2) {
		t.Errorf("exact: want %v got %v", want2, next3)
	}
}

func TestBuildDigestEmpty(t *testing.T) {
	since := time.Date(2026, 10, 22, 19, 0, 0, 0, time.UTC)
	until := since.Add(24 * time.Hour)
	title, body := buildDigest(nil, since, until)
	_ = title
	_ = body
	// Just ensure it doesn't panic on empty input.
}

func TestBuildDigestCounts(t *testing.T) {
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()
	findings := []state.DigestFinding{
		{RuleID: "r1", Severity: "critical", Source: "local", LastFiredAt: until.Add(-1 * time.Hour)},
		{RuleID: "r2", Severity: "high", Source: "local", LastFiredAt: until.Add(-2 * time.Hour)},
		{RuleID: "r3", Severity: "high", Source: "remote", LastFiredAt: until.Add(-3 * time.Hour)},
	}
	title, body := buildDigest(findings, since, until)
	if !strings.Contains(title, "3 событий") {
		t.Errorf("title should mention count: %s", title)
	}
	if !strings.Contains(body, "CRITICAL") {
		t.Errorf("body should mention critical: %s", body)
	}
	if !strings.Contains(body, "HIGH") {
		t.Errorf("body should mention high: %s", body)
	}
}

func TestBuildDigestTruncation(t *testing.T) {
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()
	findings := make([]state.DigestFinding, 25)
	for i := range findings {
		findings[i] = state.DigestFinding{RuleID: "r", Severity: "low", Source: "s", LastFiredAt: until}
	}
	_, body := buildDigest(findings, since, until)
	if !strings.Contains(body, "ещё") {
		t.Errorf("body should mention truncation: %s", body)
	}
}

func TestParseHHMM(t *testing.T) {
	cases := []struct{ input string; h, m int }{
		{"19:00", 19, 0},
		{"08:30", 8, 30},
		{"00:00", 0, 0},
		{"bad",   19, 0}, // fallback
	}
	for _, tc := range cases {
		h, m := parseHHMM(tc.input)
		if h != tc.h || m != tc.m {
			t.Errorf("parseHHMM(%q) = %d:%d, want %d:%d", tc.input, h, m, tc.h, tc.m)
		}
	}
}
