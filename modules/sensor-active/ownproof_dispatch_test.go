package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The proof goes on the wire only to a worker whose heartbeat says own_proof; an older worker gets the job in the shape it knows and
// its own sighting decides.
func TestTheProofGoesOnlyToAWorkerThatSaysOwnProof(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 27, 3, 53, 0, 0, time.UTC)
	argv, err := nmapargv.Build(nmapargv.External, nmapargv.ExternalRate, []netip.Addr{boxIP})
	if err != nil {
		t.Fatal(err)
	}
	for name, says := range map[string]bool{"own_proof": true, "an older worker": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
			hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.95"}, OwnProof: says}
			if _, err := d.ActiveHeartbeat(t.Context(), hb); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := d.ProbeProven(ctx, argv, at); done <- err }()
			rep, _ := d.Jobs(t.Context(), 5*time.Second, nil)
			if len(rep.Jobs) != 1 || !slices.Equal(rep.Jobs[0].Targets, []string{"8.8.8.8"}) {
				t.Fatalf("jobs %+v", rep.Jobs)
			}
			got := rep.Jobs[0].ProvenAt
			if says && (got == nil || !got.Equal(at)) || !says && got != nil {
				t.Fatalf("proven_at %v", got)
			}
			_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "refused", Reason: "not_own_ip", ExitCode: -1})
			if err := <-done; !errors.Is(err, sa.ErrNotOwnIP) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("not on a LAN shape", func(t *testing.T) {
		t.Parallel()
		d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
		if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true}, OwnProof: true}); err != nil {
			t.Fatal(err)
		}
		lan, err := nmapargv.Build(nmapargv.Normal, 100, []netip.Addr{netip.MustParseAddr("192.168.10.20")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.ProbeProven(t.Context(), lan, at); err == nil {
			t.Fatal("a LAN job carried a proof")
		}
	})
}

// An own_ip nuclei job carries the proof the same way; a LAN job cannot carry one.
func TestOwnIPNucleiCarriesTheProof(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 27, 3, 53, 0, 0, time.UTC)
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
	hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true},
		Nuclei: sensorlink.HeartbeatNuclei{Present: true, Version: "v3.11.1", Pack: sensorlink.HeartbeatPack{Version: "2026.11.10", SHA256: packSHA}, OwnIP: true}, OwnProof: true}
	if _, err := d.ActiveHeartbeat(t.Context(), hb); err != nil {
		t.Fatal(err)
	}
	lan := nreq()
	lan.ProvenAt = at
	if _, err := d.RunNuclei(t.Context(), lan); err == nil {
		t.Fatal("a LAN nuclei job carried a proof")
	}
	req := ownIPReq()
	req.ProvenAt = at
	ch := runNuclei(t.Context(), d, req)
	rep, _ := d.Jobs(t.Context(), 5*time.Second, nil)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Nuclei.ProvenAt == nil || !rep.Jobs[0].Nuclei.ProvenAt.Equal(at) {
		t.Fatalf("jobs %+v", rep.Jobs)
	}
	_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "done"})
	awaitN(t, ch)
}
