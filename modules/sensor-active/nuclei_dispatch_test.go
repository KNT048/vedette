package sensoractive_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The nuclei slot of the Dispatcher (D-125 (3), (5)). The worker is played by hand over the real mutual-TLS link, like the nmap
// tests of dispatch_test.go.

const packSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func (r *drig) beatNuclei(t *testing.T, nmap, nuclei, pack bool) {
	t.Helper()
	hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: nmap}, Nuclei: sensorlink.HeartbeatNuclei{Present: nuclei}}
	if nuclei {
		hb.Nuclei.Version = "v3.3.7"
	}
	if pack {
		hb.Nuclei.Pack = sensorlink.HeartbeatPack{Version: "2026.11.10", SHA256: packSHA}
	}
	if _, err := r.worker.ActiveHeartbeat(t.Context(), hb); err != nil {
		t.Fatal(err)
	}
}

func nreq() sa.NucleiRequest {
	return sa.NucleiRequest{
		PackVersion: "2026.11.10", PackSHA256: packSHA,
		Templates:     []string{"CVE-2024-1", "CVE-2024-2"},
		Targets:       []nucleiargv.Target{{Host: "192.168.10.20", Port: 8080, Scheme: "http"}, {Host: "10.0.0.7", Port: 22}},
		Rate:          5,
		MaxHostErrors: 3,
	}
}

type nucResult struct {
	res []nucleiout.Result
	he  []nucleiout.HostError
	err error
}

func runNuclei(ctx context.Context, d *sa.Dispatcher, req sa.NucleiRequest) <-chan nucResult {
	ch := make(chan nucResult, 1)
	go func() {
		out, err := d.RunNuclei(ctx, req)
		ch <- nucResult{out.Results, out.HostErrors, err}
	}()
	return ch
}

func awaitN(t *testing.T, ch <-chan nucResult) nucResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(45 * time.Second):
		t.Fatal("RunNuclei did not return")
		return nucResult{}
	}
}

func notYetN(t *testing.T, ch <-chan nucResult) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("RunNuclei returned early: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
}

func jsonlResult(b []byte) *sensorlink.JobResult {
	r := &sensorlink.JobResult{Status: "done"}
	r.SetJSONL(b)
	return r
}

func withHostErrors(jsonl []byte, he ...sensorlink.HostError) *sensorlink.JobResult {
	r := jsonlResult(jsonl)
	r.HostErrors = he
	return r
}

// D-165: the host errors the worker counted come back with the lines, checked against the request.
func TestNucleiHostErrorsComeBackWithTheResult(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ch := runNuclei(t.Context(), r.d, nreq())
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	he := []sensorlink.HostError{{Target: "10.0.0.7:22", Errors: 3, Unreachable: true}, {Target: "192.168.10.20:8080", Errors: 1}}
	if err := r.worker.PostResult(t.Context(), j.ID, withHostErrors(nil, he...)); err != nil {
		t.Fatal(err)
	}
	got := awaitN(t, ch)
	want := []nucleiout.HostError{{Target: "10.0.0.7:22", Errors: 3, Unreachable: true}, {Target: "192.168.10.20:8080", Errors: 1}}
	if got.err != nil || len(got.res) != 0 || !slices.Equal(got.he, want) {
		t.Fatalf("result = %+v", got)
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) //nolint:gosec // a fixture of this package
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The job on the wire is what protocol 2 says: kind, pack, template ids, targets with host, port and scheme, rate, max_host_errors
// and a timeout of the probe's deadline up to an hour; no argv, no path (D-111 (3)). The result's JSONL is parsed in core.
func TestNucleiJobGoesOutAndItsResultComesBackParsed(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ctx, cancel := probeCtx(t, 2*time.Hour)
	defer cancel()
	ch := runNuclei(ctx, r.d, nreq())
	rep := r.poll(t, "", 5*time.Second)
	if len(rep.Jobs) != 1 {
		t.Fatalf("reply = %+v", rep)
	}
	j := rep.Jobs[0]
	n := j.Nuclei
	if j.Kind != sensorlink.KindNuclei || !hex32.MatchString(j.ID) || n == nil || j.TimeoutS < 3590 || j.TimeoutS > 3600 ||
		n.Pack.Version != "2026.11.10" || n.Pack.SHA256 != packSHA || strings.Join(n.Templates, ",") != "CVE-2024-1,CVE-2024-2" ||
		len(n.Targets) != 2 || n.Targets[0] != (sensorlink.NucleiTarget{Host: "192.168.10.20", Port: 8080, Scheme: "http"}) || n.Rate != 5 || n.MaxHostErrors != 3 {
		t.Fatalf("job = %+v %+v", j, n)
	}
	notYetN(t, ch)
	if err := r.worker.PostResult(t.Context(), j.ID, jsonlResult(fixture(t, "nuclei_host_port.jsonl"))); err != nil {
		t.Fatal(err)
	}
	got := awaitN(t, ch)
	if got.err != nil || len(got.res) != 3 || !got.res[0].Matched || got.res[0].Template != "CVE-2024-1" || got.res[0].Target != "192.168.10.20:8080" || got.res[2].Target != "10.0.0.7:22" || got.res[2].Error == "" {
		t.Fatalf("result = %+v", got)
	}
}

// Extra (a) of the #138 review: the pinned nuclei v3.11.1 writes "host" as the bare address with "port" and "url" apart (lab VM,
// 2026-11-12, modules/scan/nucleiout/testdata/matched.jsonl); older versions wrote host:port. Both shapes must parse.
func TestNucleiOutputShapesOfTheLabLine(t *testing.T) {
	t.Parallel()
	tpl, tg := []string{"CVE-2024-1", "CVE-2024-2"}, []string{"192.168.10.20:8080", "10.0.0.7:22"}
	for _, f := range []string{"nuclei_host_port.jsonl", "nuclei_bare_host.jsonl"} {
		if res, err := nucleiout.Parse(fixture(t, f), tpl, tg); err != nil || len(res) != 3 || res[0].Target != "192.168.10.20:8080" || res[2].Target != "10.0.0.7:22" {
			t.Fatalf("%s: %v %+v", f, err, res)
		}
	}
}

func TestScannerUnavailableFollowsTheHeartbeat(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	if err := r.d.Ready(t.Context()); !errors.Is(err, sa.ErrScannerUnavailable) {
		t.Fatalf("no heartbeat: Ready = %v", err)
	}
	if msg := r.d.NucleiHealth(); !strings.Contains(msg, "has not reported") {
		t.Fatalf("no heartbeat: %q", msg)
	}
	if _, err := r.d.RunNuclei(t.Context(), nreq()); !errors.Is(err, sa.ErrScannerUnavailable) {
		t.Fatalf("RunNuclei without a heartbeat: %v", err)
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 {
		t.Fatalf("a job was created without a worker: %+v", rep)
	}
	r.beatNuclei(t, true, true, true)
	if err := r.d.Ready(t.Context()); err != nil || r.d.NucleiHealth() != "" {
		t.Fatalf("with a heartbeat: %v %q", err, r.d.NucleiHealth())
	}
	r.clk.Advance(91 * time.Second)
	if err := r.d.Ready(t.Context()); !errors.Is(err, sa.ErrScannerUnavailable) {
		t.Fatalf("91 s without a heartbeat: %v", err)
	}
	r.beatNuclei(t, true, false, false) // nmap is there, nuclei is not
	if msg := r.d.NucleiHealth(); !strings.Contains(msg, "nuclei is not installed") {
		t.Fatalf("nuclei missing: %q", msg)
	}
	if _, err := r.d.RunNuclei(t.Context(), nreq()); !errors.Is(err, sa.ErrNucleiMissing) || !errors.Is(err, sa.ErrScannerUnavailable) {
		t.Fatalf("RunNuclei with nuclei missing: %v", err)
	}
	if msg := r.d.NmapHealth(); msg != "" {
		t.Fatalf("nmap is fine and said so: %q", msg)
	}
	r.beatNuclei(t, true, true, false) // nuclei runs, the image has no pack
	if msg := r.d.NucleiHealth(); !strings.Contains(msg, "template pack") {
		t.Fatalf("no pack: %q", msg)
	}
	r.beatNuclei(t, false, true, true) // nuclei fine, nmap missing: the other way round
	if err := r.d.Ready(t.Context()); err != nil {
		t.Fatalf("nuclei is fine and nmap is missing: %v", err)
	}
	if msg := r.d.NmapHealth(); !strings.Contains(msg, "nmap is not installed") {
		t.Fatalf("nmap missing: %q", msg)
	}
}

// Core checks the grammar before anything leaves (D-125 (1), D-136 (4)); the worker checks it again.
func TestRunNucleiRefusesWhatTheGrammarForbidsBeforeDispatch(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	many := func(n int) []nucleiargv.Target {
		var ts []nucleiargv.Target
		for i := range n {
			ts = append(ts, nucleiargv.Target{Host: "10.0." + string(rune('0'+i/200)) + "." + itoa(i%200+1), Port: 80})
		}
		return ts
	}
	ids := make([]string, 33)
	for i := range ids {
		ids[i] = "CVE-2024-" + itoa(i+1)
	}
	tg := func(h string) []nucleiargv.Target { return []nucleiargv.Target{{Host: h, Port: 80, Scheme: "http"}} }
	cases := map[string]func(*sa.NucleiRequest){
		"a domain":           func(q *sa.NucleiRequest) { q.Targets = tg("printer.lan") },
		"a public address":   func(q *sa.NucleiRequest) { q.Targets = tg("8.8.8.8") },
		"loopback":           func(q *sa.NucleiRequest) { q.Targets = tg("127.0.0.1") },
		"link-local":         func(q *sa.NucleiRequest) { q.Targets = tg("169.254.169.254") },
		"CGNAT":              func(q *sa.NucleiRequest) { q.Targets = tg("100.64.0.1") },
		"benchmark":          func(q *sa.NucleiRequest) { q.Targets = tg("198.18.0.1") },
		"240/4":              func(q *sa.NucleiRequest) { q.Targets = tg("240.0.0.1") },
		"a flag as a host":   func(q *sa.NucleiRequest) { q.Targets = tg("-u") },
		"17 targets":         func(q *sa.NucleiRequest) { q.Targets = many(17) },
		"33 templates":       func(q *sa.NucleiRequest) { q.Templates = ids },
		"no template":        func(q *sa.NucleiRequest) { q.Templates = nil },
		"a template path":    func(q *sa.NucleiRequest) { q.Templates = []string{"../x"} },
		"a template flag":    func(q *sa.NucleiRequest) { q.Templates = []string{"-code"} },
		"a repeated id":      func(q *sa.NucleiRequest) { q.Templates = []string{"CVE-2024-1", "CVE-2024-1"} },
		"rate 0":             func(q *sa.NucleiRequest) { q.Rate = 0 },
		"rate 21":            func(q *sa.NucleiRequest) { q.Rate = 21 },
		"host errors 1":      func(q *sa.NucleiRequest) { q.MaxHostErrors = 1 },
		"host errors 21":     func(q *sa.NucleiRequest) { q.MaxHostErrors = 21 },
		"no pack hash":       func(q *sa.NucleiRequest) { q.PackSHA256 = "" },
		"a bad pack hash":    func(q *sa.NucleiRequest) { q.PackSHA256 = "XYZ" },
		"a bad pack version": func(q *sa.NucleiRequest) { q.PackVersion = "latest" },
	}
	for name, mut := range cases {
		q := nreq()
		mut(&q)
		if _, err := r.d.RunNuclei(t.Context(), q); err == nil || errors.Is(err, sa.ErrScannerUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out for a request the grammar forbids: %+v", rep.Jobs)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// D-125 (3): one nmap job and one nuclei job run at once, and a second nuclei job waits for the first. A long nmap sweep never
// holds a "Scan now" back.
func TestNmapAndNucleiRunAtOnceAndASecondNucleiWaits(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	nm := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	rep := r.poll(t, "", 5*time.Second)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Kind != sensorlink.KindNmap {
		t.Fatalf("reply = %+v", rep)
	}
	nmapJob := rep.Jobs[0]

	// the worker, busy with nmap, names it and gets the nuclei job
	n1 := runNuclei(t.Context(), r.d, nreq())
	rep = r.poll(t, nmapJob.ID, 5*time.Second)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Kind != sensorlink.KindNuclei {
		t.Fatalf("a nuclei job was not handed to a worker that runs nmap: %+v", rep)
	}
	nucJob := rep.Jobs[0]

	// a second nuclei job waits, however often the worker polls
	n2 := runNuclei(t.Context(), r.d, nreq())
	for range 2 {
		if rep = r.poll(t, nmapJob.ID+","+nucJob.ID, 0); len(rep.Jobs) != 0 || len(rep.Cancel) != 0 {
			t.Fatalf("the second nuclei job was handed out: %+v", rep)
		}
	}
	// the nmap job finishes first: the slots are separate
	if err := r.worker.PostResult(t.Context(), nmapJob.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	if got := await(t, nm); got.err != nil {
		t.Fatalf("nmap: %v", got.err)
	}
	if rep = r.poll(t, nucJob.ID, 0); len(rep.Jobs) != 0 {
		t.Fatalf("the second nuclei job was handed out while the first runs: %+v", rep)
	}
	notYetN(t, n1)
	notYetN(t, n2)
	if err := r.worker.PostResult(t.Context(), nucJob.ID, jsonlResult(nil)); err != nil {
		t.Fatal(err)
	}
	if got := awaitN(t, n1); got.err != nil || len(got.res) != 0 {
		t.Fatalf("first nuclei: %+v", got)
	}
	// the poll that still names the finished job is answered at once, then the second goes out
	rep = r.poll(t, nucJob.ID, 5*time.Second)
	rep = r.poll(t, "", 5*time.Second)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Kind != sensorlink.KindNuclei || rep.Jobs[0].ID == nucJob.ID {
		t.Fatalf("the second nuclei job did not go out: %+v", rep)
	}
	if err := r.worker.PostResult(t.Context(), rep.Jobs[0].ID, jsonlResult(nil)); err != nil {
		t.Fatal(err)
	}
	if got := awaitN(t, n2); got.err != nil {
		t.Fatalf("second nuclei: %v", got.err)
	}
}

// Both kinds can be handed out in one reply, and the worker's poll names both.
func TestOneReplyCanCarryOneJobOfEachKind(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	nm := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	n := runNuclei(t.Context(), r.d, nreq())
	<-time.After(100 * time.Millisecond)
	rep := r.poll(t, "", 5*time.Second)
	if len(rep.Jobs) < 1 {
		t.Fatalf("reply = %+v", rep)
	}
	if len(rep.Jobs) == 1 { // the nuclei one was queued a moment after: the next poll has it
		rep.Jobs = append(rep.Jobs, r.poll(t, rep.Jobs[0].ID, 5*time.Second).Jobs...)
	}
	kinds := map[string]string{}
	for _, j := range rep.Jobs {
		kinds[j.Kind] = j.ID
	}
	if len(kinds) != 2 {
		t.Fatalf("jobs = %+v", rep.Jobs)
	}
	_ = r.worker.PostResult(t.Context(), kinds[sensorlink.KindNmap], okResult("<nmaprun/>"))
	_ = r.worker.PostResult(t.Context(), kinds[sensorlink.KindNuclei], jsonlResult(nil))
	await(t, nm)
	awaitN(t, n)
}

// D-125 (3): the end of the probe's context wakes the open long poll, so Stop lands within seconds; the job is cancelled by id,
// and the other slot's job is not touched.
func TestNucleiCancelWakesTheLongPollWithinFiveSeconds(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	nm := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	nmapJob := r.poll(t, "", 5*time.Second).Jobs[0]
	ctx, cancel := context.WithCancel(t.Context())
	ch := runNuclei(ctx, r.d, nreq())
	nucJob := r.poll(t, nmapJob.ID, 5*time.Second).Jobs[0]
	polled := make(chan sensorlink.JobsReply, 1)
	go func() { polled <- r.poll(t, nmapJob.ID+","+nucJob.ID, 25*time.Second) }() // held open
	<-time.After(150 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case rep := <-polled:
		if time.Since(start) > 5*time.Second {
			t.Fatalf("the long poll answered after %v", time.Since(start))
		}
		if len(rep.Cancel) != 1 || rep.Cancel[0] != nucJob.ID || len(rep.Jobs) != 0 {
			t.Fatalf("reply = %+v", rep)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the long poll was not woken by the cancel")
	}
	notYetN(t, ch)
	notYet(t, nm, 50*time.Millisecond)
	if err := r.worker.PostResult(t.Context(), nucJob.ID, &sensorlink.JobResult{Status: "stopped", Reason: "cancelled", ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	if got := awaitN(t, ch); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v", got.err)
	}
	_ = r.worker.PostResult(t.Context(), nmapJob.ID, okResult("<nmaprun/>"))
	await(t, nm)
}

// A cancel before the worker fetched the nuclei job drops it; nothing is handed out afterwards.
func TestNucleiCancelBeforePickupDropsTheJob(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ctx, cancel := context.WithCancel(t.Context())
	ch := runNuclei(ctx, r.d, nreq())
	notYetN(t, ch)
	cancel()
	if got := awaitN(t, ch); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v", got.err)
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 || len(rep.Cancel) != 0 {
		t.Fatalf("the worker was told of a job that was dropped: %+v", rep)
	}
}

// SP-3 rules hold for the nuclei slot: pickup timeout, a worker that stops naming the job (worker_lost), the core-side cap of
// timeout plus grace, and a cancel for a job core does not know.
func TestNucleiSlotKeepsTheLeaseRulesOfSP3(t *testing.T) {
	t.Parallel()
	t.Run("pickup", func(t *testing.T) {
		t.Parallel()
		r := newDRig(t)
		r.beatNuclei(t, true, true, true)
		ch := runNuclei(t.Context(), r.d, nreq())
		notYetN(t, ch)
		r.clk.Advance(61 * time.Second)
		r.beatNuclei(t, true, true, true)
		if got := awaitN(t, ch); !errors.Is(got.err, sa.ErrScanWorkerUnavailable) || !errors.Is(got.err, sa.ErrScannerUnavailable) {
			t.Fatalf("err = %v", got.err)
		}
	})
	t.Run("the worker no longer names it", func(t *testing.T) {
		t.Parallel()
		r := newDRig(t)
		r.beatNuclei(t, true, true, true)
		ch := runNuclei(t.Context(), r.d, nreq())
		j := r.poll(t, "", 5*time.Second).Jobs[0]
		rep := r.poll(t, "", 0) // it restarted and runs nothing
		if len(rep.Jobs) != 0 {
			t.Fatalf("reply = %+v", rep)
		}
		if got := awaitN(t, ch); !errors.Is(got.err, sa.ErrWorkerLost) {
			t.Fatalf("err = %v", got.err)
		}
		if err := r.worker.PostResult(t.Context(), j.ID, jsonlResult(nil)); err == nil {
			t.Fatal("a result for a job that was given up was accepted")
		}
	})
	t.Run("a job that runs past timeout plus grace", func(t *testing.T) {
		t.Parallel()
		r := newDRig(t)
		r.beatNuclei(t, true, true, true)
		ctx, cancel := probeCtx(t, 20*time.Second)
		defer cancel()
		ch := runNuclei(ctx, r.d, nreq())
		j := r.poll(t, "", 5*time.Second).Jobs[0]
		r.clk.Advance(time.Duration(j.TimeoutS)*time.Second + 29*time.Second)
		r.beatNuclei(t, true, true, true)
		r.poll(t, j.ID, 0) // alive: it polls
		notYetN(t, ch)
		r.clk.Advance(2 * time.Second)
		r.beatNuclei(t, true, true, true)
		if got := awaitN(t, ch); !errors.Is(got.err, sa.ErrWorkerLost) {
			t.Fatalf("err = %v", got.err)
		}
		if msg := r.d.NucleiHealth(); !strings.Contains(msg, "past its time limit") {
			t.Fatalf("health = %q", msg)
		}
		if msg := r.d.NmapHealth(); msg != "" {
			t.Fatalf("nmap health = %q: the overrun is nuclei's", msg)
		}
		rep := r.poll(t, j.ID, 0)
		if len(rep.Cancel) != 1 || rep.Cancel[0] != j.ID {
			t.Fatalf("the worker was not told to stop it: %+v", rep)
		}
		r.poll(t, "", 0)
		if msg := r.d.NucleiHealth(); msg != "" {
			t.Fatalf("health after the worker is free = %q", msg)
		}
	})
	t.Run("a running id core does not know is cancelled at once", func(t *testing.T) {
		t.Parallel()
		r := newDRig(t)
		r.beatNuclei(t, true, true, true)
		unknown := strings.Repeat("e", 32)
		start := time.Now()
		rep := r.poll(t, unknown, 20*time.Second)
		if len(rep.Cancel) != 1 || rep.Cancel[0] != unknown || time.Since(start) > 5*time.Second {
			t.Fatalf("reply = %+v after %v", rep, time.Since(start))
		}
		// while the worker still names it, no job of either kind goes out
		ch := runNuclei(t.Context(), r.d, nreq())
		if rep = r.poll(t, unknown, 0); len(rep.Jobs) != 0 {
			t.Fatalf("a job went out to a worker that still runs a job nobody knows: %+v", rep)
		}
		rep = r.poll(t, "", 5*time.Second)
		if len(rep.Jobs) != 1 || rep.Jobs[0].Kind != sensorlink.KindNuclei {
			t.Fatalf("nothing went out to a free worker: %+v", rep)
		}
		_ = r.worker.PostResult(t.Context(), rep.Jobs[0].ID, jsonlResult(nil))
		awaitN(t, ch)
	})
}

// The result is the worker's word and core believes none of it but the bytes, which are parsed fail closed. What the worker says
// about itself explains a failure and never excuses one.
func TestNucleiResultsAreChecked(t *testing.T) {
	t.Parallel()
	good := fixture(t, "nuclei_host_port.jsonl")
	type tc struct {
		res  *sensorlink.JobResult
		want func(error) bool
	}
	trunc := jsonlResult(good)
	trunc.Truncated = true
	exit1 := &sensorlink.JobResult{Status: "failed", ExitCode: 1}
	notDone := &sensorlink.JobResult{Status: "stopped", Reason: "deadline", ExitCode: -1}
	xmlOnNuclei := okResult("<nmaprun/>")
	cases := map[string]tc{
		"truncated output is discarded": {trunc, func(e error) bool { return errors.Is(e, sa.ErrOutputTruncated) }},
		"exit code 1": {exit1, func(e error) bool {
			var ee *exec.ExitError
			return errors.As(e, &ee) && ee.Name == "nuclei" && ee.ExitCode == 1
		}},
		"a deadline is not a result":     {notDone, func(e error) bool { return e != nil }},
		"nmap output on a nuclei job":    {xmlOnNuclei, func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"nuclei_missing":                 {&sensorlink.JobResult{Status: "failed", Reason: "nuclei_missing", ExitCode: -1}, func(e error) bool { return errors.Is(e, sa.ErrNucleiMissing) }},
		"refused: pack_mismatch":         {&sensorlink.JobResult{Status: "refused", Reason: "pack_mismatch", ExitCode: -1}, func(e error) bool { return errors.Is(e, sa.ErrPackMismatch) && !errors.Is(e, sa.ErrScannerUnavailable) }},
		"refused: pack_invalid":          {&sensorlink.JobResult{Status: "refused", Reason: "pack_invalid", ExitCode: -1}, func(e error) bool { return errors.Is(e, sa.ErrPackInvalid) }},
		"refused: invalid_job":           {&sensorlink.JobResult{Status: "refused", Reason: "invalid_job", ExitCode: -1}, func(e error) bool { return errors.Is(e, sa.ErrWorkerRefused) }},
		"a template the job did not ask": {jsonlResult([]byte(`{"template-id":"CVE-2099-1","host":"192.168.10.20:8080","matcher-status":true}` + "\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"a target the job did not name":  {jsonlResult([]byte(`{"template-id":"CVE-2024-1","host":"192.168.10.99:8080","matcher-status":true}` + "\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"the right host, another port":   {jsonlResult([]byte(`{"template-id":"CVE-2024-1","host":"192.168.10.20:22","matcher-status":true}` + "\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"one hostile line among good":    {jsonlResult(append(append([]byte{}, good...), []byte("not json\n")...)), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"a repeated key":                 {jsonlResult([]byte(`{"template-id":"CVE-2024-1","template-id":"CVE-2024-2","host":"10.0.0.7:22","matcher-status":true}` + "\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"a match with an error":          {jsonlResult([]byte(`{"template-id":"CVE-2024-1","host":"10.0.0.7:22","matcher-status":true,"error":"x"}` + "\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"a line that is an array":        {jsonlResult([]byte("[1,2]\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"a line with no matcher-status":  {jsonlResult([]byte(`{"template-id":"CVE-2024-1","host":"10.0.0.7:22"}` + "\n")), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		// D-165: host_errors is checked against the request, fail closed.
		"host_errors names another target":     {withHostErrors(good, sensorlink.HostError{Target: "192.168.10.99:80", Errors: 1}), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"unreachable below the job's limit":    {withHostErrors(good, sensorlink.HostError{Target: "10.0.0.7:22", Errors: 2, Unreachable: true}), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
		"reachable at or over the job's limit": {withHostErrors(good, sensorlink.HostError{Target: "10.0.0.7:22", Errors: 3}), func(e error) bool { return errors.Is(e, sa.ErrResultRejected) }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newDRig(t)
			r.beatNuclei(t, true, true, true)
			ch := runNuclei(t.Context(), r.d, nreq())
			j := r.poll(t, "", 5*time.Second).Jobs[0]
			if err := r.worker.PostResult(t.Context(), j.ID, c.res); err != nil {
				t.Fatal(err)
			}
			got := awaitN(t, ch)
			if got.res != nil || !c.want(got.err) {
				t.Fatalf("result = %+v", got)
			}
		})
	}
}

// nuclei_missing from the worker makes the scanner unavailable until the next heartbeat says otherwise.
func TestNucleiMissingResultMakesTheScannerUnavailableUntilTheNextHeartbeat(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ch := runNuclei(t.Context(), r.d, nreq())
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	_ = r.worker.PostResult(t.Context(), j.ID, &sensorlink.JobResult{Status: "failed", Reason: "nuclei_missing", ExitCode: -1})
	if got := awaitN(t, ch); !errors.Is(got.err, sa.ErrNucleiMissing) {
		t.Fatalf("err = %v", got.err)
	}
	if err := r.d.Ready(t.Context()); !errors.Is(err, sa.ErrScannerUnavailable) {
		t.Fatalf("Ready = %v", err)
	}
	r.beatNuclei(t, true, true, true)
	if err := r.d.Ready(t.Context()); err != nil {
		t.Fatalf("Ready after a heartbeat = %v", err)
	}
}

// The core-side cap: a result over 4 MiB of JSONL is 413 and the run fails at once (the worker never sends it twice).
func TestOversizeNucleiResultIsRejectedAndFailsTheRun(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ch := runNuclei(t.Context(), r.d, nreq())
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	res := &sensorlink.JobResult{Status: "done"}
	res.SetJSONL([]byte(strings.Repeat("a", sensorlink.MaxResultJSONL+1)))
	if err := r.worker.PostResult(t.Context(), j.ID, res); err == nil {
		t.Fatal("an oversize result was accepted")
	}
	got := awaitN(t, ch)
	if !errors.Is(got.err, sa.ErrResultRejected) || !strings.Contains(got.err.Error(), "nuclei output") {
		t.Fatalf("err = %v", got.err)
	}
}

// The cap of the wire and the cap of nucleiargv are one number.
func TestNucleiOutputCapsAgree(t *testing.T) {
	t.Parallel()
	if sensorlink.MaxResultJSONL != nucleiargv.MaxOutput {
		t.Fatalf("wire cap %d, nucleiargv cap %d", sensorlink.MaxResultJSONL, nucleiargv.MaxOutput)
	}
}

// An nmap job's result with nuclei output is not believed either.
func TestNmapResultWithJSONLIsRejected(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beatNuclei(t, true, true, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	_ = r.worker.PostResult(t.Context(), j.ID, jsonlResult([]byte("{}\n")))
	if got := await(t, ch); !errors.Is(got.err, sa.ErrResultRejected) {
		t.Fatalf("err = %v", got.err)
	}
}
