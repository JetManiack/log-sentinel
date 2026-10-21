package detector

import "testing"

func TestFingerprintStable(t *testing.T) {
	fp1 := Fingerprint("rule-a", "local", "")
	fp2 := Fingerprint("rule-a", "local", "")
	if fp1 != fp2 {
		t.Fatalf("fingerprint not stable: %q vs %q", fp1, fp2)
	}
}

func TestFingerprintUnique(t *testing.T) {
	pairs := [][2]string{
		{"rule-a", "local"},
		{"rule-b", "local"},
		{"rule-a", "remote"},
	}
	seen := map[string]bool{}
	for _, p := range pairs {
		fp := Fingerprint(p[0], p[1], "")
		if seen[fp] {
			t.Fatalf("collision for %v", p)
		}
		seen[fp] = true
	}
}

func TestFingerprintLength(t *testing.T) {
	fp := Fingerprint("rule-x", "src", "key")
	if len(fp) != 16 {
		t.Fatalf("want 16 hex chars, got %d: %q", len(fp), fp)
	}
}
