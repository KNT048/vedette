package ops

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The box's own public IP stays the box's for 90 days from its latest sighting as the box's egress, also while the box goes out
// through another line. Core sends that sighting with the page (proven_at), and the host's own ownership re-check takes the page on
// it while it holds; without a proof that holds, its own sighting right before the run decides as before.

var zapTestNow = time.Date(2026, 11, 26, 6, 27, 0, 0, time.UTC)

func zapProvenPage(t *testing.T, at time.Time) zapPage {
	t.Helper()
	p, err := zapArgs(api.ZapBaselineArgs{URL: "http://" + zapTestIP + ":8080/", Host: zapTestIP, IP: zapTestIP, Port: 8080, Kind: api.ZapKindIP,
		ProvenAt: at.Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// refusalCode is the code of a refusal or failure of zapBaseline, "" when it ran.
func refusalCode(err error) string {
	var ref *server.Refusal
	var f *server.Failure
	switch {
	case errors.As(err, &ref):
		return ref.Code
	case errors.As(err, &f):
		return f.Code
	}
	return ""
}

func TestZapBaseline_AProvenIPPageRunsWhileTheBoxGoesOutThroughAnotherLine(t *testing.T) {
	t.Parallel()
	asked := 0
	other := func(context.Context) (netip.Addr, error) { asked++; return netip.MustParseAddr("1.1.1.1"), nil }
	w := newZapWorld(t, Deps{ZapEgress: other, Now: func() time.Time { return zapTestNow }})
	if _, err := w.o.zapBaseline(t.Context(), nolog, zapProvenPage(t, zapTestNow.Add(-30*24*time.Hour))); refusalCode(err) != "" || err != nil {
		t.Fatalf("a page of a proven IP: %v", err)
	}
	if asked != 0 || !slices.Contains(w.Calls(), "podman run") {
		t.Fatalf("egress asked %d times, calls %q", asked, w.Calls())
	}
	w.cleanedUp(t)
}

// A proof older than 90 days, or dated in the future, is no proof: the host's sighting decides, with the codes it had.
func TestZapBaseline_AProofThatDoesNotHoldIsTheSightingAgain(t *testing.T) {
	t.Parallel()
	other := func(context.Context) (netip.Addr, error) { return netip.MustParseAddr("1.1.1.1"), nil }
	down := func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no answer") }
	for name, c := range map[string]struct {
		egress func(context.Context) (netip.Addr, error)
		at     time.Time
		code   string
	}{
		"older than 90 days":    {other, zapTestNow.Add(-egressip.ProofValid - time.Second), api.CodeTargetNotOwned},
		"in the future":         {other, zapTestNow.Add(time.Hour), api.CodeTargetNotOwned},
		"older, no service":     {down, zapTestNow.Add(-100 * 24 * time.Hour), api.CodeOwnershipUnchecked},
		"older, seen again now": {nil, zapTestNow.Add(-100 * 24 * time.Hour), ""},
	} {
		w := newZapWorld(t, Deps{ZapEgress: c.egress, Now: func() time.Time { return zapTestNow }})
		_, err := w.o.zapBaseline(t.Context(), nolog, zapProvenPage(t, c.at))
		if got := refusalCode(err); got != c.code || c.code == "" && err != nil {
			t.Errorf("%s: %v, want %q", name, err, c.code)
		}
	}
}

// proven_at is for the box's own IP only, and an RFC 3339 time: a domain page, a typed IP page or another format is refused at the edge.
func TestZapArgs_ProvenAtIsForTheBoxsOwnIPOnly(t *testing.T) {
	t.Parallel()
	at := zapTestNow.Format(time.RFC3339)
	for name, a := range map[string]api.ZapBaselineArgs{
		"a domain page": {URL: "https://www.example.com/", Host: "www.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: zapTestTok, ProvenAt: at},
		"a typed IP": {URL: "http://" + zapTestIP + ":8080/", Host: zapTestIP, IP: zapTestIP, Port: 8080, Kind: api.ZapKindIP, TXTToken: zapTestTok,
			Typed: &api.ExposureTyped{Method: "file"}, ProvenAt: at},
		"not RFC 3339": {URL: "http://" + zapTestIP + ":8080/", Host: zapTestIP, IP: zapTestIP, Port: 8080, Kind: api.ZapKindIP, ProvenAt: "26 Nov 2026"},
	} {
		if _, err := zapArgs(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
