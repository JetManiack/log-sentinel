package detector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/masker"
)

// VLClient queries a VictoriaLogs / Loki endpoint via the LogsQL HTTP API.
type VLClient struct {
	base   string
	token  string
	client *http.Client
	mask   *masker.Mask
}

// NewVLClient creates a client for the given base URL.
// When src.CAFile is set, the custom CA is trusted in addition to system roots.
func NewVLClient(src config.LogSource, m *masker.Mask) (*VLClient, error) {
	transport := http.DefaultTransport
	if src.CAFile != "" {
		pem, err := os.ReadFile(src.CAFile) // #nosec G304 -- operator-supplied CA path
		if err != nil {
			return nil, fmt.Errorf("logsql: read ca_file %q: %w", src.CAFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("logsql: no valid certificates in ca_file %q", src.CAFile)
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		}
	}
	return &VLClient{
		base:  src.URL,
		token: src.Token,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		mask: m,
	}, nil
}

// vlEntry is one result row from VictoriaLogs /select/logsql/query.
type vlEntry struct {
	Time string            `json:"_time"`
	Msg  string            `json:"_msg"`
	Tags map[string]string `json:"-"`
}

func (e *vlEntry) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.Time = raw["_time"]
	e.Msg = raw["_msg"]
	e.Tags = make(map[string]string, len(raw))
	for k, v := range raw {
		if k != "_time" && k != "_msg" {
			e.Tags[k] = v
		}
	}
	return nil
}

// queryRaw runs a LogsQL query and returns raw entries (with tags).
func (c *VLClient) queryRaw(ctx context.Context, query string, start, end time.Time, limit int) ([]vlEntry, error) {
	params := url.Values{
		"query": {query},
		"start": {strconv.FormatInt(start.UnixMilli(), 10)},
		"end":   {strconv.FormatInt(end.UnixMilli(), 10)},
		"limit": {strconv.Itoa(limit)},
	}
	reqURL := c.base + "/select/logsql/query?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("logsql query: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("logsql query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("logsql query: HTTP %d: %s", resp.StatusCode, body)
	}

	var entries []vlEntry
	dec := json.NewDecoder(resp.Body)
	for dec.More() {
		var entry vlEntry
		if err := dec.Decode(&entry); err != nil {
			slog.Warn("logsql decode error", "err", err)
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Query runs a LogsQL query over [start, end] and returns masked log lines.
func (c *VLClient) Query(ctx context.Context, query string, start, end time.Time, limit int) ([]string, error) {
	entries, err := c.queryRaw(ctx, query, start, end, limit)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		lines = append(lines, c.mask.Redact(e.Msg))
	}
	return lines, nil
}

// QueryWithContext runs query over [start, end], returns matched masked lines plus
// surrounding context lines from the same stream fetched over
// [firedAt-ctxWindow, firedAt+ctxWindow]. Context lines are masked and deduplicated
// against the matched lines. Returns (matched, context, error).
func (c *VLClient) QueryWithContext(
	ctx context.Context,
	query string,
	start, end time.Time,
	firedAt time.Time,
	ctxWindow time.Duration,
	ctxLimit int,
	limit int,
) (matched []string, context []string, err error) {
	entries, err := c.queryRaw(ctx, query, start, end, limit)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return nil, nil, nil
	}

	for _, e := range entries {
		matched = append(matched, c.mask.Redact(e.Msg))
	}

	// Build a stream selector from the first matched entry's tags.
	// We use the most specific stable labels: job, namespace, pod (if present).
	streamSelector := buildStreamSelector(entries[0].Tags)
	if streamSelector == "" {
		// No usable labels — skip context fetch.
		return matched, nil, nil
	}

	ctxStart := firedAt.Add(-ctxWindow)
	ctxEnd := firedAt.Add(ctxWindow)
	ctxEntries, err := c.queryRaw(ctx, streamSelector, ctxStart, ctxEnd, ctxLimit)
	if err != nil {
		// Context fetch failure is non-fatal.
		slog.Warn("logsql context fetch failed", "err", err)
		return matched, nil, nil
	}

	// Deduplicate: exclude lines already in matched.
	matchedSet := make(map[string]struct{}, len(matched))
	for _, m := range matched {
		matchedSet[m] = struct{}{}
	}
	for _, e := range ctxEntries {
		line := c.mask.Redact(e.Msg)
		if _, dup := matchedSet[line]; !dup {
			context = append(context, line)
		}
	}
	return matched, context, nil
}

// buildStreamSelector returns a LogsQL stream selector using the most specific
// stable labels from a VictoriaLogs entry's tag map.
// Priority: kubernetes_pod_name > kubernetes_namespace > job > (empty).
func buildStreamSelector(tags map[string]string) string {
	// Prefer pod-level scope (most specific).
	if pod, ok := tags["kubernetes_pod_name"]; ok && pod != "" {
		if ns, ok := tags["kubernetes_namespace_name"]; ok && ns != "" {
			return fmt.Sprintf(`{kubernetes_namespace_name=%q,kubernetes_pod_name=%q}`, ns, pod)
		}
		return fmt.Sprintf(`{kubernetes_pod_name=%q}`, pod)
	}
	// Namespace scope.
	if ns, ok := tags["kubernetes_namespace_name"]; ok && ns != "" {
		return fmt.Sprintf(`{kubernetes_namespace_name=%q}`, ns)
	}
	// Fall back to job label (syslog / host units).
	if job, ok := tags["job"]; ok && job != "" {
		return fmt.Sprintf(`{job=%q}`, job)
	}
	// Try unit (systemd).
	if unit, ok := tags["unit"]; ok && unit != "" {
		return fmt.Sprintf(`{unit=%q}`, unit)
	}
	return ""
}

// Count returns the number of log entries matching query in [start, end].
func (c *VLClient) Count(ctx context.Context, query string, start, end time.Time) (int64, error) {
	lines, err := c.Query(ctx, query, start, end, 1)
	if err != nil {
		return 0, err
	}
	return int64(len(lines)), nil
}

