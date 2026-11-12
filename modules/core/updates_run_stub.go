package core

import "context"

// TEMPORARY: deleted when updates_run.go lands (the run side of the software update, D-340). Until then the page
// shows no run and no history, and apply, rollback and bundle answer 501 (not implemented).

func (h *OSHandlers) runView(context.Context) (*updateRunView, error) { return nil, nil } //nolint:nilnil // stub

func (h *OSHandlers) historyView(context.Context) ([]updateHistoryView, error) { return nil, nil } //nolint:nilnil // stub
