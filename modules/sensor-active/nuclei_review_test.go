package sensoractive_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// M1: the pack the request needs is compared with the pack the worker's heartbeat reports before anything goes out: a different
// pack is its own error, naming both, and is not "the scanner is unavailable, try again".
func TestRunNucleiComparesThePackWithTheHeartbeatBeforeDispatch(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true) // the image has packSHA
	for name, mut := range map[string]func(*sa.NucleiRequest){
		"another hash":    func(q *sa.NucleiRequest) { q.PackSHA256 = strings.Repeat("b", 64) },
		"another version": func(q *sa.NucleiRequest) { q.PackVersion = "2026.11.9" },
	} {
		q := nreq()
		mut(&q)
		_, err := r.d.RunNuclei(t.Context(), q)
		if !errors.Is(err, sa.ErrPackMismatch) || errors.Is(err, sa.ErrScannerUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
		if msg := err.Error(); !strings.Contains(msg, "the scan image has template pack 2026.11.10") || !strings.Contains(msg, "the request needs") {
			t.Errorf("%s: message %q", name, msg)
		}
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out for another pack: %+v", rep.Jobs)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond) // the right pack goes out, and nobody answers
	defer cancel()
	if _, err := r.d.RunNuclei(ctx, nreq()); errors.Is(err, sa.ErrPackMismatch) {
		t.Fatalf("the right pack: %v", err)
	}
}

// The worker's own refusals: pack_mismatch is the same error; pack_invalid (a hash that does not match or a link in the image: a
// sign of tampering) is its own error that is not retried, with an error-level health message until the image's pack changes.
func TestPackInvalidIsAnIntegrityErrorOfItsOwn(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ch := runNuclei(t.Context(), r.d, nreq())
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	_ = r.worker.PostResult(t.Context(), j.ID, &sensorlink.JobResult{Status: "refused", Reason: "pack_mismatch", ExitCode: -1})
	if got := awaitN(t, ch); !errors.Is(got.err, sa.ErrPackMismatch) {
		t.Fatalf("pack_mismatch: %v", got.err)
	}
	ch = runNuclei(t.Context(), r.d, nreq())
	rep := r.poll(t, "", 5*time.Second)
	if len(rep.Jobs) != 1 {
		t.Fatalf("reply = %+v", rep)
	}
	_ = r.worker.PostResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "refused", Reason: "pack_invalid", ExitCode: -1})
	got := awaitN(t, ch)
	if !errors.Is(got.err, sa.ErrPackInvalid) || errors.Is(got.err, sa.ErrScannerUnavailable) || errors.Is(got.err, sa.ErrPackMismatch) {
		t.Fatalf("pack_invalid: %v", got.err)
	}
	if msg := r.d.NucleiHealth(); !strings.Contains(msg, "integrity") {
		t.Fatalf("health = %q", msg)
	}
	if err := r.d.Ready(t.Context()); !errors.Is(err, sa.ErrPackInvalid) {
		t.Fatalf("Ready = %v", err)
	}
	if _, err := r.d.RunNuclei(t.Context(), nreq()); !errors.Is(err, sa.ErrPackInvalid) {
		t.Fatalf("RunNuclei = %v", err)
	}
	r.beatNuclei(t, true, true, true) // the same pack again: still not trusted
	if err := r.d.Ready(t.Context()); !errors.Is(err, sa.ErrPackInvalid) {
		t.Fatalf("Ready after the same pack = %v", err)
	}
	hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true}, Nuclei: sensorlink.HeartbeatNuclei{Present: true, Version: "v3.3.7",
		Pack: sensorlink.HeartbeatPack{Version: "2026.11.11", SHA256: strings.Repeat("c", 64)}}}
	if _, err := r.worker.ActiveHeartbeat(t.Context(), hb); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Ready(t.Context()); err != nil {
		t.Fatalf("a different pack in the image: %v", err)
	}
}

// L: a poll that names a job that has just finished in one slot still handles the other slot's job in the same poll (its lease,
// its cancel).
func TestJustFinishedJobDoesNotHideTheOtherSlotsCancel(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	nm := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	nmapJob := r.poll(t, "", 5*time.Second).Jobs[0]
	ctx, cancel := probeCtx(t, time.Minute)
	ch := runNuclei(ctx, r.d, nreq())
	nucJob := r.poll(t, nmapJob.ID, 5*time.Second).Jobs[0]
	_ = r.worker.PostResult(t.Context(), nmapJob.ID, okResult("<nmaprun/>"))
	await(t, nm)
	cancel()
	<-time.After(100 * time.Millisecond)
	// the nmap id comes first and is the one just finished; the nuclei job's cancel must be in the same reply
	rep := r.poll(t, nmapJob.ID+","+nucJob.ID, 5*time.Second)
	if len(rep.Cancel) != 1 || rep.Cancel[0] != nucJob.ID {
		t.Fatalf("reply = %+v", rep)
	}
	_ = r.worker.PostResult(t.Context(), nucJob.ID, &sensorlink.JobResult{Status: "stopped", Reason: "cancelled", ExitCode: -1})
	awaitN(t, ch)
}

// L: a running id core does not know holds both slots; both health messages say so, and stop saying it when the worker is free.
func TestUnknownRunningIDIsInTheHealthMessages(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	r.poll(t, strings.Repeat("e", 32), 0)
	for name, msg := range map[string]string{"nmap": r.d.NmapHealth(), "nuclei": r.d.NucleiHealth()} {
		if !strings.Contains(msg, "does not know") {
			t.Errorf("%s health = %q", name, msg)
		}
	}
	r.poll(t, "", 0)
	if r.d.NmapHealth() != "" || r.d.NucleiHealth() != "" {
		t.Fatalf("health after the worker is free: %q %q", r.d.NmapHealth(), r.d.NucleiHealth())
	}
}
