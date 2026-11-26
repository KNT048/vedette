package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/egressip"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The box's own public IP stays proven for 90 days from its latest sighting as the box's egress (exposure's box_egress proof),
// also while the box goes out through another line. Core's fence passes on the time of that sighting with the job, and the
// worker accepts the job on it instead of asking for a sighting right before nmap or nuclei.

// provenFence is exposure's gate with the proof it rests on: yes for the addresses in ok, proven at at.
type provenFence struct {
	deepFence
	at time.Time
}

func (f *provenFence) OwnProof(ctx context.Context, ip netip.Addr) (time.Time, bool, error) {
	ok, err := f.OwnEgress(ctx, ip)
	return f.at, ok, err
}

var otherLine = netip.MustParseAddr("1.1.1.1") // the line the box goes out through now

// The owner's case: the box's own IP was proven a month ago, and every round of the worker's public-IP check now sees the other
// line. The default scan and the deep scan both run through the real worker.
func TestScanExternalOfAProvenIPWhileTheBoxGoesOutThroughAnotherLine(t *testing.T) {
	t.Parallel()
	month := time.Now().Add(-30 * 24 * time.Hour)
	t.Run("external", func(t *testing.T) {
		t.Parallel()
		e := externalEnvWithNmap(t, otherLine, fakeOpts{always: svXML(t, false, svPort(22, "ssh", "OpenSSH")), topPorts: discoveryFixture(t, boxIP)})
		own := &provenFence{deepFence: deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}}, at: month}
		got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own)
		if err != nil {
			t.Fatal(err)
		}
		if got.Ports < 1000 || len(got.Services) == 0 || got.Services[0].Product != "OpenSSH" || len(e.nm.calls(t)) < 2 || own.ownFence.asked != len(e.nm.calls(t)) {
			t.Fatalf("probed %d ports in %d nmap runs", got.Ports, len(e.nm.calls(t)))
		}
	})
	t.Run("external_full", func(t *testing.T) {
		t.Parallel()
		e := externalEnvWith(t, otherLine, "external_full.xml")
		own := &provenFence{deepFence: deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalFull}, at: month}
		got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.ExternalFull, own)
		if err != nil {
			t.Fatal(err)
		}
		if got.Ports != 65535 || len(got.Services) != 3 || len(e.nm.calls(t)) != 1 {
			t.Fatalf("got %d ports %d services", got.Ports, len(got.Services))
		}
	})
}

// A proof that no longer holds when it reaches the worker (older than 90 days) is no proof: the worker's own sighting decides and
// refuses (ErrNotOwnIP, nothing run). Core's own refusal is unchanged: a gate that says no sends nothing.
func TestScanExternalWithAProofThatDoesNotHoldIsRefused(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, otherLine)
	old := &provenFence{deepFence: deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}}, at: time.Now().Add(-egressip.ProofValid - time.Hour)}
	if _, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, old); !errors.Is(err, sa.ErrNotOwnIP) || !errors.Is(err, sa.ErrWorkerRefused) {
		t.Fatalf("an expired proof: %v", err)
	}
	no := &provenFence{deepFence: deepFence{ownFence: ownFence{}}, at: time.Now()}
	if _, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, no); !errors.Is(err, sa.ErrNotOwnIP) || errors.Is(err, sa.ErrWorkerRefused) {
		t.Fatalf("core's gate said no: %v", err)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Fatalf("nmap ran %d times", n)
	}
}
