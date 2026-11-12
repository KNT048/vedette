package core

import (
	"context"
)

// OfferedVersionForTest is the version offered() hands the run side ("" with the error when nothing is offered).
func (h *OSHandlers) OfferedVersionForTest(ctx context.Context) (string, error) {
	v, err := h.offered(ctx)
	if err != nil {
		return "", err
	}
	return v.M.Version, nil
}

// RunningRestoresDataForTest is runningRestoresData.
func (h *OSHandlers) RunningRestoresDataForTest(ctx context.Context) (bool, error) {
	return h.runningRestoresData(ctx)
}

// ErrNoUpdate is errNoUpdate for the external tests.
var ErrNoUpdate = errNoUpdate

// HoldFollowerForTest makes the run side believe a follower is going (one that is about to end).
func HoldFollowerForTest(h *OSHandlers) { h.urun.following.Store(true) }

// EndFollowerForTest is the end of that follower: it hands off, and follows a run still running.
func EndFollowerForTest(h *OSHandlers) {
	if h.handOff() {
		h.goFollow()
	}
}
