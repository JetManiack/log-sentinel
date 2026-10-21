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

func TestBoardThread(t *testing.T) {
	db := openTestDB(t)
	fp := "fp1234567890abcd"
	if _, err := db.Upsert(fp, "r", "medium", "s"); err != nil {
		t.Fatal(err)
	}

	// No thread yet.
	id, err := db.BoardThreadID(fp)
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Errorf("expected empty thread ID, got %q", id)
	}

	// Set thread.
	if err := db.SetBoardThread(fp, "thread-123"); err != nil {
		t.Fatal(err)
	}
	id, err = db.BoardThreadID(fp)
	if err != nil {
		t.Fatal(err)
	}
	if id != "thread-123" {
		t.Errorf("want thread-123, got %q", id)
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

func TestAllBoardThreadIDs(t *testing.T) {
	db := openTestDB(t)

	fp1, fp2 := "fp0000000000001a", "fp0000000000002b"
	db.Upsert(fp1, "r1", "high", "local")   //nolint:errcheck
	db.Upsert(fp2, "r2", "medium", "local") //nolint:errcheck
	db.SetBoardThread(fp1, "thread-A")       //nolint:errcheck
	// fp2 has no thread.

	ids, err := db.AllBoardThreadIDs()
	if err != nil {
		t.Fatal(err)
	}
	if ids[fp1] != "thread-A" {
		t.Errorf("fp1: want thread-A, got %q", ids[fp1])
	}
	if _, ok := ids[fp2]; ok {
		t.Error("fp2 should not appear (no thread set)")
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

func TestFindingsSince(t *testing.T) {
	db := openTestDB(t)

	now := time.Now()
	fp1 := "aa00000000000001"
	fp2 := "bb00000000000002"
	db.Upsert(fp1, "r1", "critical", "local") //nolint:errcheck
	db.Upsert(fp2, "r2", "low", "remote")     //nolint:errcheck

	results, err := db.FindingsSince(now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 findings, got %d", len(results))
	}
	// First result should be critical (ordered by severity).
	if results[0].Severity != "critical" {
		t.Errorf("want critical first, got %q", results[0].Severity)
	}
}

func TestFindingsSinceEmpty(t *testing.T) {
	db := openTestDB(t)

	// No findings at all.
	results, err := db.FindingsSince(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("want 0, got %d", len(results))
	}
}
