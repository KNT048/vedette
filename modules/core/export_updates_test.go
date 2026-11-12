package core

import (
	"context"
	"time"
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

// SetUpdateRetryForTest shortens the follower's wait between two tries (followRetry); set it before the run starts.
func SetUpdateRetryForTest(h *OSHandlers, d time.Duration) { h.urun.retry = d }

// HostWhyForTest is the sentence of the host step's end code for a run of release that takes the helper from running to v.
func HostWhyForTest(code, v, running, release string) string {
	return hostWhy(context.Background(), &updateRunRec{To: release, Host: &runHost{From: running, To: v}}, code)
}

// RetryWaitForTest is retryWait.
func RetryWaitForTest(err error, base time.Duration, refused int) time.Duration {
	return retryWait(err, base, refused)
}
