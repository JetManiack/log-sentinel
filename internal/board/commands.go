package board

// commands.go — board reply command poller.
//
// The sentinel polls its own board threads for replies containing /quiet,
// /unquiet, or /benign commands.
//
// Authorization model:
//   - The allowlist (AllowedActors / CriticalMuteActors) is matched against the
//     stable actor ID returned by the board, not the mutable display nickname.
//   - Processed reply IDs are persisted in the state DB so restarts do not replay
//     commands.
//   - Critical findings require CriticalMuteActors membership for both /quiet and
//     /benign.
//   - Benign overrides are scoped to ruleID+source (not bare ruleID) to prevent
//     one ack from blanket-suppressing an entire rule across all sources.
//
// No LLM is involved in parsing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/commands"
	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/state"
)

// PollCommands starts a goroutine that polls all known board threads for new
// replies containing commands. It ticks at interval. Blocks until ctx is cancelled.
func (c *Client) PollCommands(ctx context.Context, cfg config.CommandsConfig, db *state.DB, interval time.Duration) {
	if c == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pollOnce(ctx, cfg, db)
		}
	}
}

func (c *Client) pollOnce(ctx context.Context, cfg config.CommandsConfig, db *state.DB) {
	threads, err := db.AllBoardThreadIDs()
	if err != nil {
		slog.Warn("board: commands: list thread ids", "err", err)
		return
	}
	for fingerprint, threadID := range threads {
		if threadID == "" {
			continue
		}
		c.checkThread(ctx, cfg, db, fingerprint, threadID)
	}
}

func (c *Client) checkThread(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID string,
) {
	raw, err := c.toolCall(ctx, "get_thread", map[string]interface{}{"thread_id": threadID})
	if err != nil {
		slog.Warn("board: commands: get_thread", "thread_id", threadID, "err", err)
		return
	}

	thread, err := parseThread(raw)
	if err != nil {
		slog.Warn("board: commands: parse thread", "thread_id", threadID, "err", err)
		return
	}

	for _, reply := range thread.Replies {
		// Persist-and-check: skip if already processed (survives restarts).
		fresh, err := db.MarkReplyProcessed(reply.ID)
		if err != nil {
			slog.Warn("board: commands: mark processed", "reply_id", reply.ID, "err", err)
			continue
		}
		if !fresh {
			continue
		}

		// Authorize before parsing so unauthorized actors get no reply at all.
		if !isAllowedActor(reply.ActorID, cfg.AllowedActors) {
			slog.Debug("board: commands: actor not allowed, ignoring", "actor_id", reply.ActorID, "reply", reply.ID)
			continue
		}

		cmd, err := commands.Parse(reply.Body)
		if err != nil {
			if !errors.Is(err, commands.ErrNoCommand) {
				slog.Warn("board: commands: parse error", "reply_id", reply.ID, "err", err)
				c.replyThread(ctx, threadID, fmt.Sprintf("⚠️ Ошибка разбора команды: %v", err))
			}
			continue
		}

		c.applyCommand(ctx, cfg, db, fingerprint, threadID, reply.ActorID, cmd)
	}
}

func (c *Client) applyCommand(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID, actorID string,
	cmd *commands.Command,
) {
	switch cmd.Kind {
	case commands.KindQuiet:
		c.applyQuiet(ctx, cfg, db, fingerprint, threadID, actorID, cmd)
	case commands.KindUnquiet:
		c.applyUnquiet(ctx, cfg, db, fingerprint, threadID, actorID, cmd)
	case commands.KindBenign:
		c.applyBenign(ctx, cfg, db, fingerprint, threadID, actorID, cmd)
	}
}

func (c *Client) applyQuiet(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID, actorID string,
	cmd *commands.Command,
) {
	severity, err := db.FindingSeverity(fingerprint)
	if err != nil {
		slog.Warn("board: commands: quiet: db severity lookup", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось применить /quiet: ошибка БД.")
		return
	}

	isCritical := strings.EqualFold(severity, "critical")
	if isCritical && !isAllowedActor(actorID, cfg.CriticalMuteActors) {
		c.replyThread(ctx, threadID, fmt.Sprintf("⛔ `%s`: quiet critical-уровня разрешён только для critical_mute_actors.", actorID))
		return
	}

	// Cap for actors not in CriticalMuteActors.
	if !isAllowedActor(actorID, cfg.CriticalMuteActors) && cfg.MaxAgentQuietDays > 0 {
		cap := time.Duration(cfg.MaxAgentQuietDays) * 24 * time.Hour
		if cmd.Duration > cap {
			c.replyThread(ctx, threadID, fmt.Sprintf("⛔ `%s`: максимум %dd. Запрошено: %s.", actorID, cfg.MaxAgentQuietDays, cmd.Duration))
			return
		}
	}

	until := time.Now().Add(cmd.Duration)
	if err := db.SetQuiet(fingerprint, until); err != nil {
		slog.Warn("board: commands: quiet: db set", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось установить quiet: ошибка БД.")
		return
	}
	label := cfg.ActorLabel(actorID)
	untilStr := until.UTC().Format("2006-01-02 15:04 UTC")
	msg := fmt.Sprintf("✅ `%s`: тихий режим до %s. Причина: %s", label, untilStr, cmd.Reason)
	slog.Info("board: command accepted", "kind", "quiet", "actor", label, "until", until, "fp", fingerprint)
	emitCommandAccepted("quiet", label, fingerprint, fmt.Sprintf("until=%s reason=%s", untilStr, cmd.Reason))
	c.replyThread(ctx, threadID, msg)
}

func (c *Client) applyUnquiet(ctx context.Context, cfg config.CommandsConfig, db *state.DB, fingerprint, threadID, actorID string, cmd *commands.Command) {
	if err := db.SetQuiet(fingerprint, time.Time{}); err != nil {
		slog.Warn("board: commands: unquiet db", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось снять quiet: ошибка БД.")
		return
	}
	label := cfg.ActorLabel(actorID)
	slog.Info("board: command accepted", "kind", "unquiet", "actor", label, "fp", fingerprint)
	emitCommandAccepted("unquiet", label, fingerprint, cmd.Reason)
	c.replyThread(ctx, threadID, fmt.Sprintf("✅ `%s`: тихий режим отменён.", label))
}

func (c *Client) applyBenign(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID, actorID string,
	cmd *commands.Command,
) {
	severity, err := db.FindingSeverity(fingerprint)
	if err != nil {
		slog.Warn("board: commands: benign: db severity lookup", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось применить /benign: ошибка БД.")
		return
	}

	// Critical findings require critical_mute_actors membership.
	isCritical := strings.EqualFold(severity, "critical")
	if isCritical && !isAllowedActor(actorID, cfg.CriticalMuteActors) {
		c.replyThread(ctx, threadID, fmt.Sprintf("⛔ `%s`: /benign для critical-уровня разрешён только для critical_mute_actors.", actorID))
		return
	}

	// Scope to ruleID+source to prevent one ack from suppressing an entire rule
	// across all sources.
	ruleID, err := db.FindingRuleID(fingerprint)
	if err != nil {
		slog.Warn("board: commands: benign: db rule lookup", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось применить /benign: ошибка БД.")
		return
	}
	source, err := db.FindingSource(fingerprint)
	if err != nil {
		slog.Warn("board: commands: benign: db source lookup", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось применить /benign: ошибка БД.")
		return
	}
	// Pattern is ruleID+source so it is scoped to this exact detection context.
	pattern := ruleID + "@" + source

	expiresAt := time.Now().Add(time.Duration(cfg.MaxAgentBenignDays) * 24 * time.Hour)
	if err := db.AddBenignOverride(pattern, cmd.Reason, actorID, expiresAt); err != nil {
		slog.Warn("board: commands: benign: db insert", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось сохранить benign override: ошибка БД.")
		return
	}
	label := cfg.ActorLabel(actorID)
	expiresStr := expiresAt.Format("2006-01-02")
	msg := fmt.Sprintf("✅ `%s`: `%s` помечено как benign до %s (требует подтверждения оператора). Причина: %s",
		label, pattern, expiresStr, cmd.Reason)
	slog.Info("board: command accepted", "kind", "benign", "actor", label, "pattern", pattern, "fp", fingerprint)
	emitCommandAccepted("benign", label, fingerprint, fmt.Sprintf("pattern=%s expires=%s reason=%s", pattern, expiresStr, cmd.Reason))
	c.replyThread(ctx, threadID, msg)
}

// emitCommandAccepted writes a structured JSON line to stdout so that
// vlagent / Grafana can alert on command-accepted events (audit trail,
// and effectively a Telegram notification via the existing Grafana rule).
func emitCommandAccepted(kind, actorLabel, fingerprint, detail string) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]interface{}{
		"time":        time.Now().UTC().Format(time.RFC3339),
		"level":       "INFO",
		"msg":         "command-accepted",
		"kind":        kind,
		"actor":       actorLabel,
		"fingerprint": fingerprint,
		"detail":      detail,
	})
}

func isAllowedActor(actorID string, list []string) bool {
	for _, a := range list {
		if strings.EqualFold(a, actorID) {
			return true
		}
	}
	return false
}

// boardThread is the portion of a get_thread result we care about.
type boardThread struct {
	Replies []boardReply
}

// boardReply carries the fields we read from a board thread reply.
type boardReply struct {
	ID      string
	ActorID string // stable board-assigned ID, not the mutable display nickname
	Body    string
}

func parseThread(raw json.RawMessage) (*boardThread, error) {
	text := toolText(raw)
	if text == "" {
		return nil, fmt.Errorf("empty thread result")
	}
	// The board API returns author_id as a top-level field on each reply,
	// not nested under an actor object. We try both shapes for resilience.
	var v struct {
		Replies []struct {
			ID       string `json:"id"`
			AuthorID string `json:"author_id"` // actual board API field
			Actor    struct {
				ID       string `json:"id"`
				Nickname string `json:"nickname"`
			} `json:"actor"` // fallback for hypothetical future shape
			Body string `json:"body"`
		} `json:"replies"`
	}
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil, err
	}
	t := &boardThread{}
	for _, r := range v.Replies {
		actorID := r.AuthorID
		if actorID == "" {
			actorID = r.Actor.ID
		}
		if actorID == "" {
			actorID = r.Actor.Nickname
		}
		t.Replies = append(t.Replies, boardReply{
			ID:      r.ID,
			ActorID: actorID,
			Body:    r.Body,
		})
	}
	return t, nil
}
