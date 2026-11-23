package findings

import (
	"context"
	"sync"
	"time"
)

// The counts of other modules Home's overview carries (GET /findings/overview, overview.go).

// alertDays is the window of the "alerts sent" count.
const alertDays = 7

// NotifyModule is the id of the module whose sent messages Home counts.
const NotifyModule = "notify"

// HomeSources are the counts of other modules GET /findings/overview carries, wired by the binary (findings imports neither inventory
// nor notify). Devices is inventory's "All" and "To review" counts; Alerts is notify's sent and failed alert messages since a time;
// Incidents is notify's open and urgent (high, critical) incidents; FirstRun is notify's first-run summary of the newest load made at or
// after a time (nil when there is none). A nil Devices counts the devices from Inventory.AssetIDs with no "to review"; a nil Alerts,
// Incidents or FirstRun, or notify off, answers null for it.
type HomeSources struct {
	Devices   func(ctx context.Context) (total, pending int, err error)
	Alerts    func(ctx context.Context, since time.Time) (sent, failed int, err error)
	Incidents func(ctx context.Context) (open, urgent int, err error)
	FirstRun  func(ctx context.Context, since time.Time) (*FirstRunSummary, error)
}

// firstRunDays is how long Home shows a first-run summary after it was made.
const firstRunDays = 7

// FirstRunSummary is Overview.first_run_summary: the summary notify sent (or could not send) when a load first rated findings urgent,
// the box's own first look above all. Times are UTC (store.FormatTS); the binary converts notify's answer.
type FirstRunSummary struct {
	ID         string   `json:"id"`
	Load       string   `json:"load"`
	Title      string   `json:"title"`
	MadeAt     string   `json:"made_at"`
	State      string   `json:"state"`
	SentAt     *string  `json:"sent_at"`
	Channels   []string `json:"channels"`
	DueAt      *string  `json:"due_at"`
	Quiet      bool     `json:"quiet"`
	NotSent    *string  `json:"not_sent"`
	Reason     *string  `json:"reason"`
	Link       string   `json:"link"`
	Later      int      `json:"later"`
	LaterTitle *string  `json:"later_title"`
}

// SetHome registers the sources of the device and alert counts (the binary, at start-up).
func (h *FindingHandlers) SetHome(src HomeSources) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.home = src
	h.ov.val = nil
}

// SummaryAlerts is notify's counts over the last Days days.
type SummaryAlerts struct {
	Sent   int `json:"sent"`
	Failed int `json:"failed"`
	Days   int `json:"days"`
}

// SummaryIncidents is notify's open incidents (new or acknowledged) and, of them, the high and critical ones.
type SummaryIncidents struct {
	Open   int `json:"open"`
	Urgent int `json:"urgent"`
}

// summaryState is the part of FindingHandlers that holds Home's overview: sumMu serialises the computations.
type summaryState struct {
	sumMu sync.Mutex
	ov    overviewCache
	home  HomeSources
}
