package main

import (
	"errors"
	"net/http"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/findings"
)

// A hook that stops one identification call is about that call's names: the call fails and the run goes on with the next names. Only
// a missing profile or a budget stops the whole run.
func TestIdentifyStop(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  error
		stop bool
	}{
		{apierr.New(http.StatusConflict, "ai_unavailable", "no profile"), true},
		{apierr.New(http.StatusTooManyRequests, "budget_reached", "used up"), true},
		{apierr.New(http.StatusTooManyRequests, "rate_limited", "later"), true},
		{apierr.New(http.StatusConflict, "blocked_by_hook", "a hook stopped the answer"), false},
		{apierr.New(http.StatusBadGateway, "ai_bad_format", "bad format"), false},
		{errors.New("network"), false},
	} {
		var stop *findings.CheckStop
		if got := errors.As(identifyErr(tc.err), &stop); got != tc.stop {
			t.Errorf("identifyErr(%v) stops the run = %v, want %v", tc.err, got, tc.stop)
		}
	}
}
