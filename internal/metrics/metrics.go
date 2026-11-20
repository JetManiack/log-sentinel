// Package metrics registers Prometheus counters for the sentinel.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// FindingsTotal counts group_open and non-grouped (fail-open, detector-error)
	// findings. group_update and group_closed are NOT counted here — they
	// represent events inside an already-counted group, not new distinct alerts.
	FindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sentinel_findings_total",
		Help: "New findings (group_open + non-grouped) by rule, source and severity.",
	}, []string{"rule", "source", "severity"})

	// GroupEventsTotal counts individual log events that were added to an open
	// GroupWindow (group_update events). Divided by GroupsOpenedTotal it gives
	// the average burst size per group.
	GroupEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sentinel_group_events_total",
		Help: "Log events merged into an open GroupWindow (group_update).",
	}, []string{"rule", "source"})

	// GroupsClosedTotal counts GroupWindow expiry events (group_closed).
	GroupsClosedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sentinel_groups_closed_total",
		Help: "GroupWindows that expired (group_closed), by rule and source.",
	}, []string{"rule", "source"})

	// EventsDedupedTotal counts events skipped by the SeenEvent dedup layer.
	EventsDedupedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sentinel_events_deduped_total",
		Help: "Log events skipped because their event_id was already seen.",
	}, []string{"rule", "source"})
)
