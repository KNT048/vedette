package sensoractive_test

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// D-520: a nuclei job of scope own_ip (exposure's safe checks on the box's own public IP) goes only to a worker whose heartbeat
// said own_ip, never waits behind another nuclei job, carries its scope on the wire, and the worker's own-IP refusals
// come back as ErrNotOwnIP and ErrEgressUnverified. The Dispatcher is driven directly: nothing reaches a network.

func ownIPReq() sa.NucleiRequest {
	return sa.NucleiRequest{PackVersion: "2026.11.10", PackSHA256: packSHA, Templates: []string{"CVE-2021-41773"},
		Targets: []nucleiargv.Target{{Host: "8.8.8.8", Port: 18443, Scheme: "http"}}, Rate: nucleiargv.OwnIPRate, MaxHostErrors: 3, Scope: nucleiargv.ScopeOwnIP}
}

func beatOwnIP(t *testing.T, d *sa.Dispatcher, ownIP bool) {
	t.Helper()
	hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true},
		Nuclei: sensorlink.HeartbeatNuclei{Present: true, Version: "v3.11.1", Pack: sensorlink.HeartbeatPack{Version: "2026.11.10", SHA256: packSHA}, OwnIP: ownIP}}
	if _, err := d.ActiveHeartbeat(t.Context(), hb); err != nil {
		t.Fatal(err)
	}
}

func TestOwnIPNucleiNeverGoesToAWorkerWithoutOwnIP(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
	beatOwnIP(t, d, false)
	if _, err := d.RunNuclei(t.Context(), ownIPReq()); !errors.Is(err, sa.ErrOwnIPUnsupported) {
		t.Fatalf("%v", err)
	}
	if rep, _ := d.Jobs(t.Context(), 10*time.Millisecond, nil); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out: %+v", rep.Jobs)
	}
	// A LAN job to the same worker keeps the shape it had: no scope on the wire.
	ch := runNuclei(t.Context(), d, nreq())
	rep, _ := d.Jobs(t.Context(), 5*time.Second, nil)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Nuclei.Scope != "" {
		t.Fatalf("jobs %+v", rep.Jobs)
	}
	_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "done"})
	awaitN(t, ch)
}

func TestOwnIPNucleiGoesOutWithItsScopeAndTheFenceComesBack(t *testing.T) {
	t.Parallel()
	for reason, want := range map[string]error{"not_own_ip": sa.ErrNotOwnIP, "egress_unverified": sa.ErrEgressUnverified} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
			beatOwnIP(t, d, true)
			ch := runNuclei(t.Context(), d, ownIPReq())
			rep, _ := d.Jobs(t.Context(), 5*time.Second, nil)
			if len(rep.Jobs) != 1 {
				t.Fatalf("jobs %+v", rep.Jobs)
			}
			n := rep.Jobs[0].Nuclei
			if n.Scope != nucleiargv.ScopeOwnIP || n.Rate != nucleiargv.OwnIPRate || len(n.Targets) != 1 || n.Targets[0].Host != "8.8.8.8" {
				t.Fatalf("job %+v", n)
			}
			// a second own_ip job does not queue behind the first: nothing is sent
			if _, err := d.RunNuclei(t.Context(), ownIPReq()); !errors.Is(err, sa.ErrNucleiBusy) {
				t.Fatalf("second job: %v", err)
			}
			_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "refused", Reason: reason, ExitCode: -1})
			if got := awaitN(t, ch); !errors.Is(got.err, want) || !errors.Is(got.err, sa.ErrWorkerRefused) {
				t.Fatalf("result %+v", got)
			}
		})
	}
}

// The core-side grammar of the scope: a private target, two targets or another rate in own_ip, a public target without the scope,
// and "lan" spelled out (the wire says LAN by leaving the scope out) are refused before anything is sent.
func TestOwnIPNucleiGrammarBeforeDispatch(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
	beatOwnIP(t, d, true)
	for name, mut := range map[string]func(*sa.NucleiRequest){
		"private":       func(r *sa.NucleiRequest) { r.Targets[0].Host = "192.168.10.20" },
		"two targets":   func(r *sa.NucleiRequest) { r.Targets = append(r.Targets, nucleiargv.Target{Host: "8.8.4.4", Port: 80}) },
		"rate 20":       func(r *sa.NucleiRequest) { r.Rate = 20 },
		"public in lan": func(r *sa.NucleiRequest) { r.Scope = "" },
		"lan spelled":   func(r *sa.NucleiRequest) { r.Scope = nucleiargv.ScopeLAN },
	} {
		r := ownIPReq()
		mut(&r)
		if _, err := d.RunNuclei(t.Context(), r); err == nil || errors.Is(err, sa.ErrNucleiBusy) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if rep, _ := d.Jobs(t.Context(), 10*time.Millisecond, nil); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out: %+v", rep.Jobs)
	}
}
