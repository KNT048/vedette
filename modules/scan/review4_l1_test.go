package scan

import (
	"fmt"
	"testing"
	"time"
)

// #164 review L1: while a run is live the rescan job waits before it reads anything (no findings, no devices).
func TestReview4_L1_NoReadsWhileARunIsLive(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	started := r.eng.blockRuns()
	v := r.start("a-nas02")
	<-started
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	before := r.findings.listCalls()
	if err := r.svc.RunRescans(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := r.findings.listCalls() - before; n != 0 {
		t.Fatalf("%d findings reads while a run is live; the job should wait first", n)
	}
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
}

// L1: one pass of the rescan job handles at most a page of the queue.
func TestReview4_L1_OnePassHandlesAPage(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{AutoRescan: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	for i := range 250 {
		r.exec(`INSERT INTO scan_event (id, ts, cve, product) VALUES (?, '2026-11-10T09:00:00.000Z', ?, 'x')`, fmt.Sprintf("e-%d", i), fmt.Sprintf("CVE-2020-1%04d", i))
	}
	if err := r.svc.RunRescans(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := r.count(`SELECT count(*) FROM scan_event WHERE result IS NOT NULL`); n != 100 {
		t.Fatalf("one pass closed %d events, want a page of 100", n)
	}
}
