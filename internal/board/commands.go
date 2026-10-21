package board

// commands.go — board reply command poller.
//
// The sentinel polls its own board threads for replies containing /quiet,
// /unquiet, or /benign commands. Only actors listed in cfg.Commands.AllowedActors
// may issue commands; /quiet on a critical finding additionally requires the actor
// to be in CriticalMuteActors.
//
// Every accepted command generates its own board reply so the issuer has an
// audit trail visible on the board. Commands are exact-match grammar parsed by
// the commands package — no LLM involvement.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/JetManiack/log-sentinel/internal/commands"
	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/state"
)

// PollCommands starts a goroutine that polls all known board threads for new
// replies containing commands. It ticks at interval (suggested: same as detector
// interval). Blocks until ctx is cancelled.
func (c *Client) PollCommands(ctx context.Context, cfg config.CommandsConfig, db *state.DB, interval time.Duration) {
	if c == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// seenReplies tracks reply IDs already processed to avoid reprocessing.
	seenReplies := make(map[string]struct{})
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pollOnce(ctx, cfg, db, seenReplies)
		}
	}
}

func (c *Client) pollOnce(ctx context.Context, cfg config.CommandsConfig, db *state.DB, seen map[string]struct{}) {
	// Enumerate known board threads from the state DB.
	threads, err := db.AllBoardThreadIDs()
	if err != nil {
		slog.Warn("board: commands: list thread ids", "err", err)
		return
	}
	for fingerprint, threadID := range threads {
		if threadID == "" {
			continue
		}
		c.checkThread(ctx, cfg, db, fingerprint, threadID, seen)
	}
}

func (c *Client) checkThread(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID string,
	seen map[string]struct{},
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
		if _, already := seen[reply.ID]; already {
			continue
		}
		seen[reply.ID] = struct{}{}

		cmd, err := commands.Parse(reply.Body)
		if err != nil {
			if !errors.Is(err, commands.ErrNoCommand) {
				slog.Warn("board: commands: parse error", "reply_id", reply.ID, "err", err)
				c.replyThread(ctx, threadID, fmt.Sprintf("⚠️ Ошибка разбора команды: %v", err))
			}
			continue
		}

		if !isAllowedActor(reply.ActorNickname, cfg.AllowedActors) {
			slog.Warn("board: commands: actor not allowed", "actor", reply.ActorNickname, "reply", reply.ID)
			c.replyThread(ctx, threadID, fmt.Sprintf("⛔ @%s не в списке allowed_actors, команда отклонена.", reply.ActorNickname))
			continue
		}

		c.applyCommand(ctx, cfg, db, fingerprint, threadID, reply.ActorNickname, cmd)
	}
}

func (c *Client) applyCommand(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID, actor string,
	cmd *commands.Command,
) {
	switch cmd.Kind {
	case commands.KindQuiet:
		c.applyQuiet(ctx, cfg, db, fingerprint, threadID, actor, cmd)

	case commands.KindUnquiet:
		if err := db.SetQuiet(fingerprint, time.Time{}); err != nil {
			slog.Warn("board: commands: unquiet db", "err", err)
			c.replyThread(ctx, threadID, "⚠️ Не удалось снять quiet: ошибка БД.")
			return
		}
		msg := fmt.Sprintf("✅ @%s: тихий режим отменён.", actor)
		slog.Info("board: command accepted", "kind", "unquiet", "actor", actor, "fingerprint", fingerprint)
		c.replyThread(ctx, threadID, msg)

	case commands.KindBenign:
		c.applyBenign(ctx, cfg, db, fingerprint, threadID, actor, cmd)
	}
}

func (c *Client) applyQuiet(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID, actor string,
	cmd *commands.Command,
) {
	// Determine the finding severity so we can enforce mute caps.
	severity, err := db.FindingSeverity(fingerprint)
	if err != nil {
		slog.Warn("board: commands: quiet: db severity lookup", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось применить /quiet: ошибка БД.")
		return
	}

	isCritical := strings.EqualFold(severity, "critical")
	if isCritical && !isAllowedActor(actor, cfg.CriticalMuteActors) {
		msg := fmt.Sprintf("⛔ @%s: quiet critical-уровня разрешён только для critical_mute_actors.", actor)
		c.replyThread(ctx, threadID, msg)
		return
	}

	// Non-critical-mute actors are capped at MaxAgentQuietDays.
	maxDays := cfg.MaxAgentQuietDays
	if isAllowedActor(actor, cfg.CriticalMuteActors) {
		maxDays = 0 // no cap for critical-mute actors
	}
	if maxDays > 0 {
		cap := time.Duration(maxDays) * 24 * time.Hour
		if cmd.Duration > cap {
			msg := fmt.Sprintf("⛔ @%s: максимальный quiet для агента — %dd. Запрошено: %s.", actor, maxDays, cmd.Duration)
			c.replyThread(ctx, threadID, msg)
			return
		}
	}

	until := time.Now().Add(cmd.Duration)
	if err := db.SetQuiet(fingerprint, until); err != nil {
		slog.Warn("board: commands: quiet: db set", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось установить quiet: ошибка БД.")
		return
	}
	msg := fmt.Sprintf("✅ @%s: тихий режим до %s. Причина: %s", actor, until.Format("2006-01-02 15:04 MST"), cmd.Reason)
	slog.Info("board: command accepted", "kind", "quiet", "actor", actor, "until", until, "fingerprint", fingerprint)
	c.replyThread(ctx, threadID, msg)
}

func (c *Client) applyBenign(
	ctx context.Context,
	cfg config.CommandsConfig,
	db *state.DB,
	fingerprint, threadID, actor string,
	cmd *commands.Command,
) {
	// Use the finding's rule_id as the benign pattern (exact match on rule scope).
	ruleID, err := db.FindingRuleID(fingerprint)
	if err != nil {
		slog.Warn("board: commands: benign: db lookup", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось применить /benign: ошибка БД.")
		return
	}

	maxDays := cfg.MaxAgentBenignDays
	expiresAt := time.Now().Add(time.Duration(maxDays) * 24 * time.Hour)

	if err := db.AddBenignOverride(ruleID, cmd.Reason, actor, expiresAt); err != nil {
		slog.Warn("board: commands: benign: db insert", "err", err)
		c.replyThread(ctx, threadID, "⚠️ Не удалось сохранить benign override: ошибка БД.")
		return
	}
	msg := fmt.Sprintf("✅ @%s: правило %q помечено как benign до %s (требует подтверждения оператора). Причина: %s",
		actor, ruleID, expiresAt.Format("2006-01-02"), cmd.Reason)
	slog.Info("board: command accepted", "kind", "benign", "actor", actor, "rule", ruleID, "fingerprint", fingerprint)
	c.replyThread(ctx, threadID, msg)
}

func isAllowedActor(actor string, list []string) bool {
	for _, a := range list {
		if strings.EqualFold(a, actor) {
			return true
		}
	}
	return false
}

// boardThread is the portion of a get_thread result we care about.
type boardThread struct {
	Replies []boardReply
}

type boardReply struct {
	ID            string
	ActorNickname string
	Body          string
}

func parseThread(raw json.RawMessage) (*boardThread, error) {
	text := toolText(raw)
	if text == "" {
		return nil, fmt.Errorf("empty thread result")
	}
	// The board returns a JSON object with a "replies" array.
	var v struct {
		Replies []struct {
			ID    string `json:"id"`
			Actor struct {
				Nickname string `json:"nickname"`
			} `json:"actor"`
			Body string `json:"body"`
		} `json:"replies"`
	}
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil, err
	}
	t := &boardThread{}
	for _, r := range v.Replies {
		t.Replies = append(t.Replies, boardReply{
			ID:            r.ID,
			ActorNickname: r.Actor.Nickname,
			Body:          r.Body,
		})
	}
	return t, nil
}
