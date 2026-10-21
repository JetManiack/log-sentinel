// Package board implements the coordination-board sink for the sentinel.
//
// The sentinel creates one board thread per unique finding fingerprint
// (identified by external_id) and replies to it on repeats. Resolving the
// thread acts as an ack and starts the quiet window.
package board

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/detector"
	"github.com/JetManiack/log-sentinel/internal/sink"
	"github.com/JetManiack/log-sentinel/internal/state"
)

// Client posts findings to the board via the MCP HTTP transport.
type Client struct {
	cfg     config.BoardSinkConfig
	db      *state.DB
	http    *http.Client
	session string
	id      int
}

// New creates a board Client. Returns nil if board sink is disabled.
func New(cfg config.BoardSinkConfig, db *state.DB) *Client {
	if !cfg.Enabled {
		return nil
	}
	return &Client{
		cfg:  cfg,
		db:   db,
		http: &http.Client{Timeout: 30 * time.Second},
	}
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

func (c *Client) call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	c.id++
	body, err := json.Marshal(rpcReq{
		JSONRPC: "2.0",
		ID:      c.id,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("User-Agent", "log-sentinel/1")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session = sid
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	// VictoriaLogs / board returns SSE or plain JSON.
	content := string(rawBody)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimPrefix(line, "data:")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			var r rpcResp
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, err
			}
			if r.Error != nil {
				return nil, fmt.Errorf("board rpc %s: %s", method, r.Error.Message)
			}
			return r.Result, nil
		}
	}
	return nil, fmt.Errorf("board rpc %s: empty response", method)
}

// connect performs MCP handshake if no session exists.
func (c *Client) connect(ctx context.Context) error {
	if c.session != "" {
		return nil
	}
	_, err := c.call(ctx, "initialize", map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]string{"name": "log-sentinel", "version": "1"},
	})
	return err
}

func (c *Client) toolCall(ctx context.Context, name string, args interface{}) (json.RawMessage, error) {
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	type params struct {
		Name      string      `json:"name"`
		Arguments interface{} `json:"arguments"`
	}
	res, err := c.call(ctx, "tools/call", params{Name: name, Arguments: args})
	if err != nil {
		// Reset session on error so next call reconnects.
		c.session = ""
	}
	return res, err
}

// toolText extracts the text content from a tools/call result.
func toolText(raw json.RawMessage) string {
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}

// Emit posts a finding to the board. It upserts by external_id (fingerprint):
// creates a new thread on first occurrence, replies on repeats.
func (c *Client) Emit(ctx context.Context, f detector.Finding, enrichment *sink.Enrichment) {
	if c == nil || !meetsMinSeverity(f.Severity, c.cfg.MinSeverity) {
		return
	}

	existingThread, err := c.db.BoardThreadID(f.Fingerprint)
	if err != nil {
		slog.Warn("board: db lookup", "err", err)
		return
	}

	body := formatBody(f, enrichment)

	if existingThread == "" {
		c.createThread(ctx, f, body)
	} else {
		c.replyThread(ctx, existingThread, body)
	}
}

func (c *Client) createThread(ctx context.Context, f detector.Finding, body string) {
	args := map[string]interface{}{
		"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Description),
		"body":        body,
		"external_id": f.Fingerprint,
		"tags":        []string{"log-sentinel", f.Severity, f.Source},
	}
	raw, err := c.toolCall(ctx, "create_thread", args)
	if err != nil {
		slog.Warn("board: create_thread", "err", err)
		return
	}
	threadID := extractThreadID(raw)
	if threadID == "" {
		return
	}
	if err := c.db.SetBoardThread(f.Fingerprint, threadID); err != nil {
		slog.Warn("board: set thread id", "err", err)
	}
}

func (c *Client) replyThread(ctx context.Context, threadID, body string) {
	args := map[string]interface{}{
		"thread_id": threadID,
		"body":      body,
	}
	if _, err := c.toolCall(ctx, "reply", args); err != nil {
		slog.Warn("board: reply", "err", err)
	}
}

// EmitDigest posts a daily digest as a new board thread. It is a best-effort
// call; errors are logged but not returned.
func (c *Client) EmitDigest(ctx context.Context, title, body string) {
	if c == nil {
		return
	}
	args := map[string]interface{}{
		"title": title,
		"body":  body,
		"tags":  []string{"log-sentinel", "digest"},
	}
	if _, err := c.toolCall(ctx, "create_thread", args); err != nil {
		slog.Warn("board: emit digest", "err", err)
	}
}

func extractThreadID(raw json.RawMessage) string {
	text := toolText(raw)
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return ""
	}
	id, _ := m["id"].(string)
	return id
}

func formatBody(f detector.Finding, enrichment *sink.Enrichment) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**Источник:** %s  \n**Правило:** %s  \n**Серьёзность:** %s\n\n",
		f.Source, f.RuleID, strings.ToUpper(f.Severity))

	if len(f.Evidence) > 0 {
		sb.WriteString("**Улики:**\n```\n")
		for _, e := range f.Evidence {
			sb.WriteString(e)
			sb.WriteByte('\n')
		}
		sb.WriteString("```\n\n")
	}

	if enrichment != nil {
		fmt.Fprintf(&sb, "**Что произошло:** %s\n\n**Чем грозит:** %s\n\n",
			enrichment.WhatHappenedRU, enrichment.ImpactRU)
		if enrichment.RecommendedCheck != "" {
			fmt.Fprintf(&sb, "**Рекомендуемые проверки:** %s\n\n", enrichment.RecommendedCheck)
		}
		if enrichment.LikelyBenign != "" {
			fmt.Fprintf(&sb, "_Возможно штатная ситуация: %s_\n\n", enrichment.LikelyBenign)
		}
	} else {
		sb.WriteString("_Обогащение от LLM недоступно._\n\n")
	}

	sb.WriteString("---\n*Используй `/quiet <duration> <reason>`, `/benign <reason>` или `/unquiet` в ответе для управления.*")
	return sb.String()
}

var severityLevels = map[string]int{
	detector.SeverityLow:      0,
	detector.SeverityMedium:   1,
	detector.SeverityHigh:     2,
	detector.SeverityCritical: 3,
}

const severityUnknown = 4 // above critical → always meets threshold (fail-closed)

func meetsMinSeverity(actual, min string) bool {
	if min == "" {
		min = detector.SeverityMedium
	}
	aLevel, aOK := severityLevels[actual]
	if !aOK {
		aLevel = severityUnknown
	}
	mLevel, mOK := severityLevels[min]
	if !mOK {
		mLevel = 0 // unknown min → let everything through
	}
	return aLevel >= mLevel
}
