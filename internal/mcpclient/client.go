// Package mcpclient implements a general-purpose Streamable HTTP MCP client.
//
// Each Client is bound to one MCP server configuration. It enforces a
// per-server tool allowlist (anything not listed is refused before the
// network is touched), a call budget (call_cap), and a response size cap.
// Every response is treated as untrusted data and run through the masker.
package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/masker"
	"github.com/JetManiack/log-sentinel/internal/metrics"
)

const maxResponseBytes = 64 * 1024 // 64 KB hard cap on any MCP response

// Client is a single-server MCP client. It is NOT safe for concurrent use
// (session state is not protected by a mutex). Create one per goroutine or
// protect externally.
type Client struct {
	cfg     config.MCPServer
	token   string
	http    *http.Client
	session string
	calls   int
	tools   map[string]struct{} // allowed tool names
	mask    *masker.Mask
	id      int
}

// New creates a Client for the given server config.
// Token resolution order: Token literal → TokenFile → TokenEnv.
func New(cfg config.MCPServer, mask *masker.Mask) (*Client, error) {
	token, err := resolveToken(cfg)
	if err != nil {
		return nil, fmt.Errorf("mcpclient %q: resolve token: %w", cfg.Name, err)
	}
	tools := make(map[string]struct{}, len(cfg.Tools))
	for _, t := range cfg.Tools {
		tools[t] = struct{}{}
	}
	return &Client{
		cfg:   cfg,
		token: token,
		http:  &http.Client{Timeout: cfg.Timeout},
		tools: tools,
		mask:  mask,
	}, nil
}

// Call invokes tool on the server with args and returns the first text content
// block from the response. The response is masked and size-capped.
//
// Returns ErrDenied if tool is not in the allowlist.
// Returns ErrCapped if the per-request call cap has been reached.
func (c *Client) Call(ctx context.Context, tool string, args interface{}) (string, error) {
	// Allowlist check — before any network activity.
	if _, ok := c.tools[tool]; !ok {
		metrics.MCPCallsTotal.WithLabelValues(c.cfg.Name, tool, "denied").Inc()
		return "", fmt.Errorf("%w: tool %q not in allowlist for server %q", ErrDenied, tool, c.cfg.Name)
	}
	// Budget check.
	if c.calls >= c.cfg.CallCap {
		metrics.MCPCallsTotal.WithLabelValues(c.cfg.Name, tool, "capped").Inc()
		return "", fmt.Errorf("%w: call_cap %d reached for server %q", ErrCapped, c.cfg.CallCap, c.cfg.Name)
	}

	result, err := c.callWithRetry(ctx, tool, args)
	if err != nil {
		metrics.MCPCallsTotal.WithLabelValues(c.cfg.Name, tool, "error").Inc()
		return "", err
	}
	c.calls++
	metrics.MCPCallsTotal.WithLabelValues(c.cfg.Name, tool, "ok").Inc()
	return result, nil
}

// ResetBudget resets the per-request call counter. Call at the start of each
// new context-collection or verdict request.
func (c *Client) ResetBudget() { c.calls = 0 }

// callWithRetry executes a tools/call, re-initialising the session once on
// "unknown session" errors (server restarted via Keel).
func (c *Client) callWithRetry(ctx context.Context, tool string, args interface{}) (string, error) {
	result, err := c.toolCall(ctx, tool, args)
	if err != nil && isUnknownSession(err) {
		slog.Warn("mcpclient: unknown session, re-initialising", "server", c.cfg.Name)
		c.session = ""
		result, err = c.toolCall(ctx, tool, args)
	}
	return result, err
}

func (c *Client) toolCall(ctx context.Context, tool string, args interface{}) (string, error) {
	if err := c.connect(ctx); err != nil {
		return "", err
	}
	type params struct {
		Name      string      `json:"name"`
		Arguments interface{} `json:"arguments"`
	}
	raw, err := c.rpc(ctx, "tools/call", params{Name: tool, Arguments: args})
	if err != nil {
		c.session = "" // reset on any error so next call reconnects
		return "", err
	}
	return c.extractText(raw), nil
}

func (c *Client) connect(ctx context.Context) error {
	if c.session != "" {
		return nil
	}
	_, err := c.rpc(ctx, "initialize", map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]string{"name": "log-sentinel", "version": "1"},
	})
	return err
}

type rpcReq struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type rpcResp struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *Client) rpc(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	c.id++
	body, err := json.Marshal(rpcReq{JSONRPC: "2.0", ID: c.id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "log-sentinel/1")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcpclient %q %s: %w", c.cfg.Name, method, err)
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session = sid
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("mcpclient %q %s: read body: %w", c.cfg.Name, method, err)
	}

	// Parse SSE or plain JSON (server may return either).
	for _, line := range strings.Split(string(rawBody), "\n") {
		line = strings.TrimPrefix(line, "data:")
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r rpcResp
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("mcpclient %q %s: decode: %w", c.cfg.Name, method, err)
		}
		if r.Error != nil {
			return nil, fmt.Errorf("mcpclient %q %s: %s", c.cfg.Name, method, r.Error.Message)
		}
		return r.Result, nil
	}
	return nil, fmt.Errorf("mcpclient %q %s: empty response (HTTP %d)", c.cfg.Name, method, resp.StatusCode)
}

// extractText pulls the first text content block out of a tools/call result
// and applies masking. The result is treated as untrusted data.
func (c *Client) extractText(raw json.RawMessage) string {
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Content) == 0 {
		return ""
	}
	for _, item := range r.Content {
		if item.Type == "text" && item.Text != "" {
			return c.mask.Redact(item.Text)
		}
	}
	return ""
}

func resolveToken(cfg config.MCPServer) (string, error) {
	if cfg.Token != "" {
		return cfg.Token, nil
	}
	if cfg.TokenFile != "" {
		data, err := os.ReadFile(cfg.TokenFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	if cfg.TokenEnv != "" {
		return os.Getenv(cfg.TokenEnv), nil
	}
	return "", nil
}

func isUnknownSession(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unknown session")
}

// ErrDenied is returned when the requested tool is not in the allowlist.
var ErrDenied = fmt.Errorf("mcpclient: tool denied")

// ErrCapped is returned when the call budget for this request is exhausted.
var ErrCapped = fmt.Errorf("mcpclient: call cap reached")
