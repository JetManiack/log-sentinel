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
	rows := []map[string]string{
		{"_time": "2026-01-01T00:00:00Z", "_msg": "failed login for user root", "job": "sshd"},
		{"_time": "2026-01-01T00:00:01Z", "_msg": "failed login for user admin", "job": "sshd"},
	}
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		for _, l := range rows {
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
	row := map[string]string{
		"_time": "2026-01-01T00:00:00Z",
		"_msg":  "Authorization: " + secret,
		"job":   "app",
	}
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(row) //nolint:errcheck
	})

	got, err := client.Query(context.Background(), `{job="x"}`, time.Now().Add(-time.Minute), time.Now(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one line")
	}
	for _, line := range got {
		if containsStr(line, "sk-supersecretkey") {
			t.Errorf("secret not masked in output: %q", line)
		}
	}
}

func TestQueryWithContextDeduplicates(t *testing.T) {
	// The matched line should not appear in context lines.
	matchedMsg := "failed password for root"
	ctxMsg := "accepted password for alice"

	calls := 0
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		calls++
		if calls == 1 {
			// First call = rule query → matched event.
			enc.Encode(map[string]string{"_time": "2026-01-01T00:01:00Z", "_msg": matchedMsg, "job": "sshd"}) //nolint:errcheck
		} else {
			// Second call = context query → matched + surrounding.
			enc.Encode(map[string]string{"_time": "2026-01-01T00:00:59Z", "_msg": ctxMsg, "job": "sshd"})   //nolint:errcheck
			enc.Encode(map[string]string{"_time": "2026-01-01T00:01:00Z", "_msg": matchedMsg, "job": "sshd"}) //nolint:errcheck
		}
	})

	now := time.Now()
	matched, ctx, err := client.QueryWithContext(
		context.Background(), `{job="sshd"}`,
		now.Add(-time.Minute), now, now,
		2*time.Minute, 20, 50,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matched) != 1 || !containsStr(matched[0], "root") {
		t.Fatalf("wrong matched lines: %v", matched)
	}
	// matchedMsg must not appear in ctx.
	for _, line := range ctx {
		if containsStr(line, matchedMsg) {
			t.Errorf("matched line leaked into context: %q", line)
		}
	}
	if len(ctx) != 1 || !containsStr(ctx[0], "alice") {
		t.Fatalf("wrong context lines: %v", ctx)
	}
}

func TestBuildStreamSelectorPod(t *testing.T) {
	tags := map[string]string{
		"kubernetes_namespace_name": "prod",
		"kubernetes_pod_name":       "myapp-abc123",
	}
	sel := buildStreamSelector(tags)
	if !containsStr(sel, "myapp-abc123") || !containsStr(sel, "prod") {
		t.Errorf("stream selector missing expected labels: %q", sel)
	}
}

func TestBuildStreamSelectorJob(t *testing.T) {
	tags := map[string]string{"job": "sshd"}
	sel := buildStreamSelector(tags)
	if !containsStr(sel, "sshd") {
		t.Errorf("stream selector missing job: %q", sel)
	}
}

func TestBuildStreamSelectorEmpty(t *testing.T) {
	sel := buildStreamSelector(map[string]string{})
	if sel != "" {
		t.Errorf("expected empty selector, got %q", sel)
	}
}

func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
