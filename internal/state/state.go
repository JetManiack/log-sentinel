// Package state manages persistent state: fingerprint dedup, quiet windows,
// known-benign overrides, and DNS/template baselines.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Finding records a fired detector finding for dedup / quiet-window tracking.
type Finding struct {
	ID           uint      `gorm:"primarykey"`
	Fingerprint  string    `gorm:"uniqueIndex;not null"`
	Severity     string    `gorm:"not null"`
	RuleID       string    `gorm:"not null"`
	Source       string    `gorm:"not null"`
	FirstFiredAt time.Time `gorm:"not null"`
	LastFiredAt  time.Time `gorm:"not null"`
	QuietUntil   time.Time `gorm:"index"`
	// ResolvedAt is set when the board thread for this finding is resolved.
	ResolvedAt *time.Time
	// BoardThreadID is the external_id used when creating board threads.
	BoardThreadID string
}

// BenignOverride is an operator- or agent-acknowledged benign pattern.
type BenignOverride struct {
	ID        uint      `gorm:"primarykey"`
	Pattern   string    `gorm:"not null"`
	Reason    string    `gorm:"not null"`
	Author    string    `gorm:"not null"`
	CreatedAt time.Time `gorm:"not null"`
	ExpiresAt time.Time `gorm:"index"`
	// ConfirmedAt is set when a critical-mute actor confirms it.
	ConfirmedAt *time.Time
}

// DNSBaseline records the first time a pod resolved a domain (for new-domain detection).
type DNSBaseline struct {
	ID        uint      `gorm:"primarykey"`
	Namespace string    `gorm:"uniqueIndex:idx_dns;not null"`
	Workload  string    `gorm:"uniqueIndex:idx_dns;not null"`
	Domain    string    `gorm:"uniqueIndex:idx_dns;not null"`
	FirstSeen time.Time `gorm:"not null"`
}

// TemplateBaseline records the set of known log templates per container.
type TemplateBaseline struct {
	ID        uint      `gorm:"primarykey"`
	Source    string    `gorm:"uniqueIndex:idx_tmpl;not null"`
	Namespace string    `gorm:"uniqueIndex:idx_tmpl;not null"`
	Workload  string    `gorm:"uniqueIndex:idx_tmpl;not null"`
	Container string    `gorm:"uniqueIndex:idx_tmpl;not null"`
	Template  string    `gorm:"uniqueIndex:idx_tmpl;not null;type:text"`
	Count     int64     `gorm:"not null;default:0"`
	LastSeen  time.Time `gorm:"not null"`
}

// ProcessedReply records board reply IDs that have already been acted on,
// so commands are not replayed across sentinel restarts.
type ProcessedReply struct {
	ID      uint   `gorm:"primarykey"`
	ReplyID string `gorm:"uniqueIndex;not null"`
}

// PollHighWater tracks the end timestamp of the last successful poll per
// (rule_id, source_name). Used to implement poll overlap: the next poll
// queries [last_end - overlap, now] so events that arrived after the
// previous poll window closed are never missed.
type PollHighWater struct {
	ID         uint      `gorm:"primarykey"`
	RuleID     string    `gorm:"uniqueIndex:idx_hwm;not null"`
	SourceName string    `gorm:"uniqueIndex:idx_hwm;not null"`
	LastEnd    time.Time `gorm:"not null"`
}

// GroupWindow is a tumbling burst-grouping window. It is keyed by (group_fp),
// a hash of (rule_id + actor_key) or (rule_id + source) when actor_fields is
// empty. All events matching the same group_fp within [first_at, open_until]
// belong to this group. A new row is created when no active window exists.
type GroupWindow struct {
	ID            uint       `gorm:"primarykey"`
	GroupFP       string     `gorm:"uniqueIndex:idx_gw_active;not null"`
	RuleID        string     `gorm:"not null"`
	Severity      string     `gorm:"not null"`
	Source        string     `gorm:"not null"`
	ActorKey      string     `gorm:"not null"`
	OpenUntil     time.Time  `gorm:"uniqueIndex:idx_gw_active;not null"`
	Count         int        `gorm:"not null;default:1"`
	ObjectSamples string     `gorm:"type:text"` // JSON array, capped at SampleObjectsMax
	FirstAt       time.Time  `gorm:"not null"`
	LastAt        time.Time  `gorm:"not null"`
	BoardThreadID string
	ClosedAt      *time.Time
}

// SeenEvent records event IDs for cross-restart exact dedup within a rolling TTL.
// EventID is either the audit ID field or hash(_time + _stream_id + _msg).
type SeenEvent struct {
	ID     uint      `gorm:"primarykey"`
	RuleID string    `gorm:"uniqueIndex:idx_seen;not null"`
	Source string    `gorm:"uniqueIndex:idx_seen;not null"`
	// EventID is the dedup key; hashed to a fixed-length string.
	EventID string    `gorm:"uniqueIndex:idx_seen;not null"`
	SeenAt  time.Time `gorm:"index;not null"`
}

// DB wraps a gorm.DB with sentinel-specific helpers.
type DB struct {
	g *gorm.DB
}

// Open opens (or creates) the state database at the given DSN.
// A path ending in .db is treated as SQLite; anything else is assumed Postgres.
func Open(dsn string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dsn), 0o750); err != nil {
		return nil, fmt.Errorf("state: mkdir %s: %w", filepath.Dir(dsn), err)
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("state: open %s: %w", dsn, err)
	}
	if err := db.AutoMigrate(
		&Finding{},
		&BenignOverride{},
		&DNSBaseline{},
		&TemplateBaseline{},
		&ProcessedReply{},
		&PollHighWater{},
		&GroupWindow{},
		&SeenEvent{},
	); err != nil {
		return nil, fmt.Errorf("state: migrate: %w", err)
	}
	return &DB{g: db}, nil
}

// GORM returns the underlying *gorm.DB (for health checks).
func (d *DB) GORM() *gorm.DB { return d.g }

// IsQuiet returns true if the given fingerprint has an active quiet window.
func (d *DB) IsQuiet(fingerprint string) (bool, error) {
	var f Finding
	err := d.g.Where("fingerprint = ? AND quiet_until > ?", fingerprint, time.Now()).First(&f).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	return err == nil, err
}

// Upsert creates or updates the Finding record for fingerprint, returning whether
// it already existed (true = existing, fire is a repeat).
func (d *DB) Upsert(fingerprint, ruleID, severity, source string) (existed bool, err error) {
	var f Finding
	err = d.g.Where("fingerprint = ?", fingerprint).First(&f).Error
	if err == gorm.ErrRecordNotFound {
		f = Finding{
			Fingerprint:  fingerprint,
			RuleID:       ruleID,
			Severity:     severity,
			Source:       source,
			FirstFiredAt: time.Now(),
			LastFiredAt:  time.Now(),
		}
		return false, d.g.Create(&f).Error
	}
	if err != nil {
		return false, err
	}
	f.LastFiredAt = time.Now()
	f.Severity = severity
	return true, d.g.Save(&f).Error
}

// SetQuiet sets a quiet window for fingerprint.
func (d *DB) SetQuiet(fingerprint string, until time.Time) error {
	return d.g.Model(&Finding{}).
		Where("fingerprint = ?", fingerprint).
		Update("quiet_until", until).Error
}

// SetBoardThread sets the board thread external_id for a fingerprint.
func (d *DB) SetBoardThread(fingerprint, threadID string) error {
	return d.g.Model(&Finding{}).
		Where("fingerprint = ?", fingerprint).
		Update("board_thread_id", threadID).Error
}

// BoardThreadID returns the board thread external_id for a fingerprint, or "".
func (d *DB) BoardThreadID(fingerprint string) (string, error) {
	var f Finding
	err := d.g.Select("board_thread_id").Where("fingerprint = ?", fingerprint).First(&f).Error
	if err == gorm.ErrRecordNotFound {
		return "", nil
	}
	return f.BoardThreadID, err
}

// SeenDomain returns true if the domain has been seen for this pod before.
func (d *DB) SeenDomain(namespace, workload, domain string) (bool, error) {
	var b DNSBaseline
	err := d.g.Where("namespace = ? AND workload = ? AND domain = ?", namespace, workload, domain).First(&b).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	return err == nil, err
}

// RecordDomain records a new domain for a pod (no-op if already seen).
func (d *DB) RecordDomain(namespace, workload, domain string) error {
	b := DNSBaseline{
		Namespace: namespace,
		Workload:  workload,
		Domain:    domain,
		FirstSeen: time.Now(),
	}
	return d.g.Where(DNSBaseline{Namespace: namespace, Workload: workload, Domain: domain}).
		FirstOrCreate(&b).Error
}

// ActiveBenignOverrides returns all non-expired benign overrides.
func (d *DB) ActiveBenignOverrides() ([]BenignOverride, error) {
	var out []BenignOverride
	err := d.g.Where("expires_at > ?", time.Now()).Find(&out).Error
	return out, err
}

// AddBenignOverride inserts a new benign override.
func (d *DB) AddBenignOverride(pattern, reason, author string, expiresAt time.Time) error {
	b := BenignOverride{
		Pattern:   pattern,
		Reason:    reason,
		Author:    author,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	return d.g.Create(&b).Error
}

// AllBoardThreadIDs returns a map of fingerprint → boardThreadID for all findings
// that have a board thread assigned.
func (d *DB) AllBoardThreadIDs() (map[string]string, error) {
	var findings []Finding
	err := d.g.Select("fingerprint, board_thread_id").
		Where("board_thread_id != ''").Find(&findings).Error
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(findings))
	for _, f := range findings {
		m[f.Fingerprint] = f.BoardThreadID
	}
	return m, nil
}

// FindingSeverity returns the severity stored for a fingerprint.
func (d *DB) FindingSeverity(fingerprint string) (string, error) {
	var f Finding
	err := d.g.Select("severity").Where("fingerprint = ?", fingerprint).First(&f).Error
	if err != nil {
		return "", err
	}
	return f.Severity, nil
}

// FindingRuleID returns the rule_id stored for a fingerprint.
func (d *DB) FindingRuleID(fingerprint string) (string, error) {
	var f Finding
	err := d.g.Select("rule_id").Where("fingerprint = ?", fingerprint).First(&f).Error
	if err != nil {
		return "", err
	}
	return f.RuleID, nil
}

// FindingSource returns the log source name stored for a fingerprint.
func (d *DB) FindingSource(fingerprint string) (string, error) {
	var f Finding
	err := d.g.Select("source").Where("fingerprint = ?", fingerprint).First(&f).Error
	if err != nil {
		return "", err
	}
	return f.Source, nil
}

// DigestFinding is a read-only projection used by the daily digest.
type DigestFinding struct {
	Fingerprint string
	RuleID      string
	Severity    string
	Source      string
	LastFiredAt time.Time
}

// FindingsSince returns all findings that fired at or after since, ordered by
// severity (critical first) then last_fired_at descending.
func (d *DB) FindingsSince(since time.Time) ([]DigestFinding, error) {
	var rows []Finding
	err := d.g.
		Select("fingerprint, rule_id, severity, source, last_fired_at").
		Where("last_fired_at >= ?", since).
		Order("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, last_fired_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]DigestFinding, len(rows))
	for i, r := range rows {
		out[i] = DigestFinding{
			Fingerprint: r.Fingerprint,
			RuleID:      r.RuleID,
			Severity:    r.Severity,
			Source:      r.Source,
			LastFiredAt: r.LastFiredAt,
		}
	}
	return out, nil
}

// PollStart returns the start time for the next poll of (ruleID, sourceName).
// It is max(lastEnd - overlap, fallback), where fallback = now - interval.
// On first call (no record) it returns fallback.
func (d *DB) PollStart(ruleID, sourceName string, interval, overlap time.Duration) time.Time {
	var hw PollHighWater
	err := d.g.Where("rule_id = ? AND source_name = ?", ruleID, sourceName).First(&hw).Error
	fallback := time.Now().Add(-interval)
	if err != nil {
		return fallback
	}
	start := hw.LastEnd.Add(-overlap)
	if start.Before(fallback) {
		return fallback
	}
	return start
}

// SetPollEnd records that a poll for (ruleID, sourceName) ended at end.
func (d *DB) SetPollEnd(ruleID, sourceName string, end time.Time) error {
	hw := PollHighWater{RuleID: ruleID, SourceName: sourceName, LastEnd: end}
	return d.g.Where(PollHighWater{RuleID: ruleID, SourceName: sourceName}).
		Assign(PollHighWater{LastEnd: end}).
		FirstOrCreate(&hw).Error
}

// MarkReplyProcessed records that a board reply has been acted on.
// Returns (true, nil) if this is the first time (caller should process it),
// (false, nil) if already seen, or (false, err) on DB error.
func (d *DB) MarkReplyProcessed(replyID string) (bool, error) {
	result := d.g.Create(&ProcessedReply{ReplyID: replyID})
	if result.Error != nil {
		// SQLite unique-constraint violation means already processed.
		if strings.Contains(result.Error.Error(), "UNIQUE constraint failed") {
			return false, nil
		}
		return false, result.Error
	}
	return true, nil
}

// ActiveGroupWindow returns the open GroupWindow for groupFP whose window has
// not yet expired. Returns (nil, nil) when none exists.
func (d *DB) ActiveGroupWindow(groupFP string) (*GroupWindow, error) {
	var gw GroupWindow
	err := d.g.Where("group_fp = ? AND open_until > ? AND closed_at IS NULL", groupFP, time.Now()).
		First(&gw).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &gw, nil
}

// OpenGroupWindow creates a new GroupWindow for the given groupFP.
func (d *DB) OpenGroupWindow(groupFP, ruleID, severity, source, actorKey string, openUntil time.Time, objectSamples string) (*GroupWindow, error) {
	now := time.Now()
	gw := GroupWindow{
		GroupFP:       groupFP,
		RuleID:        ruleID,
		Severity:      severity,
		Source:        source,
		ActorKey:      actorKey,
		OpenUntil:     openUntil,
		Count:         1,
		ObjectSamples: objectSamples,
		FirstAt:       now,
		LastAt:        now,
	}
	if err := d.g.Create(&gw).Error; err != nil {
		return nil, err
	}
	return &gw, nil
}

// IncrGroupWindow increments count, updates last_at, and merges new object
// samples (up to max) into an existing GroupWindow row. Returns the updated row.
func (d *DB) IncrGroupWindow(id uint, objectSamples string) (*GroupWindow, error) {
	updates := map[string]any{
		"count":          gorm.Expr("count + 1"),
		"last_at":        time.Now(),
		"object_samples": objectSamples,
	}
	if err := d.g.Model(&GroupWindow{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, err
	}
	var gw GroupWindow
	if err := d.g.First(&gw, id).Error; err != nil {
		return nil, err
	}
	return &gw, nil
}

// SetGroupWindowThread stores the board thread ID on a GroupWindow row.
func (d *DB) SetGroupWindowThread(id uint, threadID string) error {
	return d.g.Model(&GroupWindow{}).Where("id = ?", id).
		Update("board_thread_id", threadID).Error
}

// CloseGroupWindow marks a GroupWindow as closed.
func (d *DB) CloseGroupWindow(id uint) error {
	now := time.Now()
	return d.g.Model(&GroupWindow{}).Where("id = ?", id).
		Update("closed_at", now).Error
}

// ExpiredGroupWindows returns all GroupWindow rows whose open_until has passed
// and that have not yet been closed.
func (d *DB) ExpiredGroupWindows() ([]GroupWindow, error) {
	var rows []GroupWindow
	err := d.g.Where("open_until <= ? AND closed_at IS NULL", time.Now()).Find(&rows).Error
	return rows, err
}

// HasSeenEvent returns true if (ruleID, source, eventID) has been recorded
// within the given TTL.
func (d *DB) HasSeenEvent(ruleID, source, eventID string, ttl time.Duration) (bool, error) {
	var se SeenEvent
	cutoff := time.Now().Add(-ttl)
	err := d.g.Where("rule_id = ? AND source = ? AND event_id = ? AND seen_at > ?",
		ruleID, source, eventID, cutoff).First(&se).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	return err == nil, err
}

// MarkEventSeen records eventID so future calls to HasSeenEvent return true.
// If the event was already recorded (outside the TTL), it updates seen_at.
func (d *DB) MarkEventSeen(ruleID, source, eventID string) error {
	se := SeenEvent{RuleID: ruleID, Source: source, EventID: eventID, SeenAt: time.Now()}
	return d.g.
		Where(SeenEvent{RuleID: ruleID, Source: source, EventID: eventID}).
		Assign(SeenEvent{SeenAt: time.Now()}).
		FirstOrCreate(&se).Error
}

// PurgeExpiredSeenEvents deletes SeenEvent rows older than the given TTL.
func (d *DB) PurgeExpiredSeenEvents(ttl time.Duration) error {
	cutoff := time.Now().Add(-ttl)
	return d.g.Where("seen_at < ?", cutoff).Delete(&SeenEvent{}).Error
}
