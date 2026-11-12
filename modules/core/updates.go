package core

import (
	"errors"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// Software updates of Vedette itself (S-CORE-2, D-340, update-manifest.md §5–§10). Two halves on OSHandlers:
// the check side (updates_check.go: fetch and verify the signed index and manifest, channel, mode, cohort, what is
// offered, GET/PATCH /core/updates, POST /core/updates/check) and the run side (updates_run.go: apply and rollback
// as one run over every service, core last, kept across core's own restart, history). This file is the seam between them.

// core_setting keys of the software update. Every value is one JSON object (or array) written in a transaction.
const (
	keyUpdates        = "core_updates"        // check side: channel, mode, last_check
	keyUpdateRelease  = "core_update_release" // check side: the stored verified index (sequence floor, revocations) and the offered manifest
	keyUpdateRun      = "core_update_run"     // run side: the run in progress or the latest one
	keyUpdateHistory  = "core_update_history" // run side: the latest 100 history entries, newest first
	softwareComponent = "software"            // the one component of the release (D-340)
)

// errNoUpdate: nothing is offered right now (no check yet, up to date, not in the rollout cohort, or the offer
// no longer verifies). The run side answers it with 404 no_update.
var errNoUpdate = errors.New("core: no software update is offered")

// verifiedRelease is a release whose index and manifest core verified with internal/release. The raw bytes go to
// the host as they are (container.pull verifies them again, host-api 6.7); M is the parsed manifest.
type verifiedRelease struct {
	Index, IndexSig, Manifest, ManifestSig []byte
	M                                      *release.Manifest
}

// updateRunView is UpdatesState.run (contract.ts UpdateRun). Steps and Step use "download", "start", "restore", "restart".
type updateRunView struct {
	ID         string     `json:"id"`
	Action     string     `json:"action"` // update | rollback
	Component  string     `json:"component"`
	From       *string    `json:"from"`
	To         string     `json:"to"`
	Status     string     `json:"status"` // running | done | failed | reverted
	Steps      []string   `json:"steps"`
	Step       *string    `json:"step"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	User       string     `json:"user"`
	Error      *string    `json:"error"`
}

// updateHistoryView is one UpdatesState.history entry (contract.ts UpdateHistory).
type updateHistoryView struct {
	ID        string    `json:"id"`
	TS        time.Time `json:"ts"`
	Component string    `json:"component"`
	From      *string   `json:"from"`
	To        string    `json:"to"`
	Action    string    `json:"action"` // update | rollback | bundle
	User      string    `json:"user"`
}

// asOAS (osview.go) turns these views into the generated type of each operation: ogen makes a separate copy of
// UpdatesState for every operation, with the same JSON.

// The seam. Each half implements its own functions in its own file; the other half only calls them.
//
// Check side (updates_check.go):
//
//	func (h *OSHandlers) offered(ctx context.Context) (*verifiedRelease, error)   // the release Apply installs; errNoUpdate when none
//	func (h *OSHandlers) runningRestoresData(ctx context.Context) (bool, error)  // the running release says rollback.safe=false
//	func (h *OSHandlers) updatesView(ctx context.Context) (any, error)           // the whole UpdatesState, run and history included
//	func (h *OSHandlers) setManual(ctx context.Context, tx *sql.Tx, by string) error  // mode -> manual in the caller's transaction (rollback)
//
// Run side (updates_run.go):
//
//	func (h *OSHandlers) runView(ctx context.Context) (*updateRunView, error)     // nil when none or ended more than 24 h ago
//	func (h *OSHandlers) historyView(ctx context.Context) ([]updateHistoryView, error) // newest first, at most 20
