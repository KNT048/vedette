package core

import (
	"context"
	"database/sql"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// TEMPORARY: deleted when updates_check.go lands. The check side of the seam (updates.go) with obviously fake
// bodies, so the run side compiles and its tests run on their own branch. Nothing here is the real behaviour:
// nothing is ever offered, no release restores data, the mode is not stored.

func (h *OSHandlers) offered(context.Context) (*verifiedRelease, error) { return nil, errNoUpdate }

func (h *OSHandlers) runningRestoresData(context.Context) (bool, error) { return false, nil }

func (h *OSHandlers) setManual(context.Context, *sql.Tx, string) error { return nil }

// updatesView: the fixed parts are placeholders; run and history are the run side's.
func (h *OSHandlers) updatesView(ctx context.Context) (any, error) {
	run, err := h.runView(ctx)
	if err != nil {
		return nil, err
	}
	hist, err := h.historyView(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"channel": "stable", "mode": "manual", "check_enabled": true, "last_check": time.Time{},
		"components": []any{}, "available": []any{}, "history": hist, "advisories": []any{}, "managed": []any{}, "run": run,
	}, nil
}

// CoreGetCoreUpdates implements GET /core/updates for now: the check side owns it; here it only shows the run side's part.
func (h *OSHandlers) CoreGetCoreUpdates(ctx context.Context) (*oas.CoreGetCoreUpdatesOK, error) {
	v, err := h.updatesView(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CoreGetCoreUpdatesOK](v)
}
