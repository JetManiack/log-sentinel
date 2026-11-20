package state

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}

func TestUpsertAndIsQuiet(t *testing.T) {
	db := openTestDB(t)

	fp := "deadbeef01234567"
	// First upsert — not existed.
	existed, err := db.Upsert(fp, "rule-a", "high", "local")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if existed {
		t.Error("first upsert should return existed=false")
	}

	// Second upsert — existed.
	existed, err = db.Upsert(fp, "rule-a", "high", "local")
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if !existed {
		t.Error("second upsert should return existed=true")
	}

	// Not quiet yet.
	q, err := db.IsQuiet(fp)
	if err != nil {
		t.Fatalf("is_quiet: %v", err)
	}
	if q {
		t.Error("should not be quiet before SetQuiet")
	}

	// Set quiet.
	if err := db.SetQuiet(fp, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("set_quiet: %v", err)
	}
	q, err = db.IsQuiet(fp)
	if err != nil {
		t.Fatalf("is_quiet after set: %v", err)
	}
	if !q {
		t.Error("should be quiet after SetQuiet")
	}
}

func TestSetQuietExpired(t *testing.T) {
	db := openTestDB(t)
	fp := "aabbccdd01234567"
	if _, err := db.Upsert(fp, "r", "low", "s"); err != nil {
		t.Fatal(err)
	}
	// Set quiet in the past.
	if err := db.SetQuiet(fp, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	q, err := db.IsQuiet(fp)
	if err != nil {
		t.Fatal(err)
	}
	if q {
		t.Error("expired quiet should not be active")
	}
}


func TestDNSBaseline(t *testing.T) {
	db := openTestDB(t)

	seen, err := db.SeenDomain("default", "myapp", "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Error("should not be seen yet")
	}

	if err := db.RecordDomain("default", "myapp", "api.example.com"); err != nil {
		t.Fatal(err)
	}
	// RecordDomain is idempotent.
	if err := db.RecordDomain("default", "myapp", "api.example.com"); err != nil {
		t.Fatal(err)
	}

	seen, err = db.SeenDomain("default", "myapp", "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("should be seen after record")
	}
}

func TestBenignOverride(t *testing.T) {
	db := openTestDB(t)

	// No overrides yet.
	overrides, err := db.ActiveBenignOverrides()
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 0 {
		t.Errorf("want 0, got %d", len(overrides))
	}

	// Add a future-expiring override.
	if err := db.AddBenignOverride("rule-a@local", "routine backup", "operator", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Add an expired override.
	if err := db.AddBenignOverride("rule-b@remote", "old stuff", "operator", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	overrides, err = db.ActiveBenignOverrides()
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 1 {
		t.Errorf("want 1 active override, got %d", len(overrides))
	}
}


func TestMarkReplyProcessed(t *testing.T) {
	db := openTestDB(t)

	// First call → fresh.
	fresh, err := db.MarkReplyProcessed("reply-001")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Error("first call should be fresh")
	}

	// Second call → already seen.
	fresh, err = db.MarkReplyProcessed("reply-001")
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Error("second call should not be fresh")
	}
}

func TestDigestEntries(t *testing.T) {
	db := openTestDB(t)

	now := time.Now()
	fp1 := "aa00000000000001"
	fp2 := "bb00000000000002"
	db.Upsert(fp1, "r1", "critical", "local") //nolint:errcheck
	db.Upsert(fp2, "r2", "low", "remote")     //nolint:errcheck

	results, err := db.DigestEntries(now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 entries, got %d", len(results))
	}
	// First result should be critical (ordered by severity).
	if results[0].Severity != "critical" {
		t.Errorf("want critical first, got %q", results[0].Severity)
	}

	// Entries without a GroupWindow should have zero GroupCount.
	for _, r := range results {
		if r.GroupCount != 0 {
			t.Errorf("fp %s: want GroupCount=0 (no window), got %d", r.Fingerprint, r.GroupCount)
		}
	}
}

func TestMarkDigested(t *testing.T) {
	db := openTestDB(t)

	now := time.Now()
	fp1 := "dd00000000000001"
	fp2 := "ee00000000000002"
	fp3 := "ff00000000000003"
	db.Upsert(fp1, "r1", "high", "local")   //nolint:errcheck
	db.Upsert(fp2, "r2", "medium", "local") //nolint:errcheck
	db.Upsert(fp3, "r3", "low", "local")    //nolint:errcheck

	// All three are novel initially.
	results, err := db.DigestEntries(now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("before mark: want 3 novel entries, got %d", len(results))
	}

	// Mark fp1 and fp2 as digested.
	if err := db.MarkDigested([]string{fp1, fp2}); err != nil {
		t.Fatalf("MarkDigested: %v", err)
	}

	// Now only fp3 should be novel.
	results, err = db.DigestEntries(now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("after mark: want 1 novel entry, got %d", len(results))
	}
	if results[0].Fingerprint != fp3 {
		t.Errorf("want fp3 remaining, got %q", results[0].Fingerprint)
	}

	// MarkDigested with empty slice is a no-op.
	if err := db.MarkDigested(nil); err != nil {
		t.Errorf("MarkDigested(nil): %v", err)
	}
	if err := db.MarkDigested([]string{}); err != nil {
		t.Errorf("MarkDigested([]): %v", err)
	}
}

func TestDigestEntriesEmpty(t *testing.T) {
	db := openTestDB(t)

	results, err := db.DigestEntries(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("want 0, got %d", len(results))
	}
}

func TestDigestEntriesGrouped(t *testing.T) {
	db := openTestDB(t)

	fp := "cc00000000000003"
	db.Upsert(fp, "r1", "high", "local") //nolint:errcheck

	// Open a GroupWindow for this finding.
	now := time.Now()
	gw, err := db.OpenGroupWindow(fp, "r1", "high", "local", "alice", now.Add(10*time.Minute), `["role-x"]`)
	if err != nil {
		t.Fatal(err)
	}
	gw, err = db.IncrGroupWindow(gw.ID, `["role-x","role-y"]`)
	if err != nil {
		t.Fatal(err)
	}
	gw, err = db.IncrGroupWindow(gw.ID, `["role-x","role-y","role-z"]`)
	if err != nil {
		t.Fatal(err)
	}

	results, err := db.DigestEntries(now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 entry, got %d", len(results))
	}
	r := results[0]
	if r.GroupCount != 3 {
		t.Errorf("want GroupCount=3, got %d", r.GroupCount)
	}
	if r.GroupActorKey != "alice" {
		t.Errorf("want GroupActorKey=alice, got %q", r.GroupActorKey)
	}
	_ = gw
}
