package detector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/masker"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*VLClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	src := config.LogSource{Name: "test", URL: srv.URL}
	return NewVLClient(src, masker.Default()), srv
}

func TestVLClientQuery(t *testing.T) {
	lines := []map[string]string{
		{"_time": "2026-01-01T00:00:00Z", "_msg": "failed login for user root"},
		{"_time": "2026-01-01T00:00:01Z", "_msg": "failed login for user admin"},
	}
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		for _, l := range lines {
			enc.Encode(l) //nolint:errcheck
		}
	})

	got, err := client.Query(context.Background(), `{job="sshd"}`, time.Now().Add(-time.Minute), time.Now(), 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 lines, got %d", len(got))
	}
}

func TestVLClientQueryHTTPError(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	_, err := client.Query(context.Background(), `{job="x"}`, time.Now().Add(-time.Minute), time.Now(), 10)
	if err == nil {
		t.Fatal("expected error on HTTP 403, got nil")
	}
}

func TestVLClientMasksSecrets(t *testing.T) {
	secret := "Bearer sk-supersecretkey1234567890abcdef"
	lines := []map[string]string{
		{"_time": "2026-01-01T00:00:00Z", "_msg": "Authorization: " + secret},
	}
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(lines[0]) //nolint:errcheck
	})

	got, err := client.Query(context.Background(), `{job="x"}`, time.Now().Add(-time.Minute), time.Now(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one line")
	}
	for _, line := range got {
		if contains(line, "sk-supersecretkey") {
			t.Errorf("secret not masked in output: %q", line)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
