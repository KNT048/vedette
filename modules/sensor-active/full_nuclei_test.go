package sensoractive_test

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// FULL-4 (D-527): a nuclei job of depth full goes only to a worker whose heartbeat said full, and carries its depth and tick on the
// wire. The Dispatcher is driven directly: nothing reaches a network.
func TestFullNucleiOnlyToAWorkerThatSaidFull(t *testing.T) {
	t.Parallel()
	full := ownIPReq()
	full.Rate, full.Depth, full.Disruptive = nucleiargv.FullRate, nucleiargv.DepthFull, true
	beat := func(d *sa.Dispatcher, f bool) {
		hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true},
			Nuclei: sensorlink.HeartbeatNuclei{Present: true, Version: "v3.11.1", Pack: sensorlink.HeartbeatPack{Version: "2026.11.10", SHA256: packSHA}, OwnIP: true, Full: f}}
		if _, err := d.ActiveHeartbeat(t.Context(), hb); err != nil {
			t.Fatal(err)
		}
	}
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
	beat(d, false)
	if _, err := d.RunNuclei(t.Context(), full); !errors.Is(err, sa.ErrNucleiFullUnsupported) {
		t.Fatalf("%v", err)
	}
	if rep, _ := d.Jobs(t.Context(), 10*time.Millisecond, nil); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out: %+v", rep.Jobs)
	}
	beat(d, true)
	bad := full
	bad.Rate = nucleiargv.OwnIPRate
	if _, err := d.RunNuclei(t.Context(), bad); err == nil {
		t.Fatal("a full job at the own_ip rate was accepted")
	}
	ch := runNuclei(t.Context(), d, full)
	rep, _ := d.Jobs(t.Context(), 5*time.Second, nil)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Nuclei.Depth != nucleiargv.DepthFull || !rep.Jobs[0].Nuclei.Disruptive || rep.Jobs[0].Nuclei.Rate != nucleiargv.FullRate {
		t.Fatalf("jobs %+v", rep.Jobs)
	}
	_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "done"})
	awaitN(t, ch)
}
