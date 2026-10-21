package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"log/slog"

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
func NewVLClient(src config.LogSource, m *masker.Mask) *VLClient {
	return &VLClient{
		base:   src.URL,
		token:  src.Token,
		client: &http.Client{Timeout: 30 * time.Second},
		mask:   m,
	}
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
	e.Tags = raw
	delete(e.Tags, "_time")
	delete(e.Tags, "_msg")
	return nil
}

// Query runs a LogsQL query over [start, end] and returns masked log lines.
func (c *VLClient) Query(ctx context.Context, query string, start, end time.Time, limit int) ([]string, error) {
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

	var lines []string
	dec := json.NewDecoder(resp.Body)
	for dec.More() {
		var entry vlEntry
		if err := dec.Decode(&entry); err != nil {
			slog.Warn("logsql decode error", "err", err)
			continue
		}
		masked := c.mask.Redact(entry.Msg)
		lines = append(lines, masked)
	}
	return lines, nil
}

// Count returns the number of log entries matching query in [start, end].
func (c *VLClient) Count(ctx context.Context, query string, start, end time.Time) (int64, error) {
	lines, err := c.Query(ctx, query, start, end, 1)
	if err != nil {
		return 0, err
	}
	return int64(len(lines)), nil
}
