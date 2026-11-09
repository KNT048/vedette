package api_test

import (
	"testing"

	"github.com/knt048/vedette/host/api"
)

func TestStatusTerminal(t *testing.T) {
	t.Parallel()
	for st, want := range map[api.Status]bool{
		api.StatusQueued: false, api.StatusRunning: false, api.StatusAwaitingConfirm: false,
		api.StatusSucceeded: true, api.StatusFailed: true, api.StatusReverted: true, api.StatusRefused: true,
		"unknown": false,
	} {
		if st.Terminal() != want {
			t.Errorf("%s.Terminal() = %v", st, !want)
		}
	}
}
