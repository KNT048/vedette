package core

import "context"

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
