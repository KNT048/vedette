package exposure

import (
	"fmt"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// A stored open service whose newest verdicts are unreached, lost or unknown says since when the scans have not reached it: the start
// of the newest unbroken streak of those verdicts. Any other newest verdict (open, closed, filtered, network), no verdict at all and a
// closed row say nothing.
func TestServices_NotReachedSince(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.addVerifiedDomain()
	day := func(n int) string { return store.FormatTS(t0.Add(time.Duration(n) * 24 * time.Hour)) }
	runs := 0
	// run adds an ended run of the target started at, with the verdict of each port of ipA.
	run := func(at string, verdicts map[int]string) {
		runs++
		id := fmt.Sprintf("run-nr-%03d", runs)
		e.exec(`INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, subject_label,
			status, queued_at, started_at, ended_at, updated_at) VALUES (?, ?, ?, ?, 'External scan', 'manual', 'admin@acme.example', 'target', ?, ?, 'done', ?, ?, ?, ?)`,
			id, ModuleID, RunKind, RunLane, d.ID, d.Value, at, at, at, at)
		seq := 0
		for port, v := range verdicts {
			seq++
			k := portKey(ipA, port)
			e.exec(`INSERT INTO core_run_item (run_id, seq, subject_kind, subject_id, label, outcome) VALUES (?, ?, ?, ?, ?, ?)`, id, seq, itemVerdict, k, k, v)
		}
	}
	service := func(port int, state string) {
		e.exec(`INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id)
			VALUES (?, ?, ?, ?, 'tcp', 'table', ?, ?, ?, 'run-nr-001')`, fmt.Sprintf("xs-%d", port), d.ID, ipA, port, state, day(-30), day(-20))
	}
	for _, p := range []int{21, 22, 25, 80, 443, 993, 8080, 8443} {
		state := ServiceOpen
		if p == 21 {
			state = ServiceClosed
		}
		service(p, state)
	}
	run(day(-20), map[int]string{22: verdictOpen, 80: verdictOpen, 443: verdictOpen, 25: verdictOpen, 993: verdictOpen})
	run(day(-10), map[int]string{21: verdictUnreached, 22: verdictUnreached, 80: verdictUnreached, 443: verdictUnreached, 25: verdictUnreached})
	run(day(-6), map[int]string{22: verdictLost, 443: verdictUnreached, 993: verdictUnreached}) // a scan that did not probe 80 or 25
	run(day(-4), map[int]string{22: verdictUnknown, 443: verdictNetwork, 25: verdictFiltered})
	run(day(-3), map[int]string{80: verdictOpen, 993: itemOpenUnchecked})
	run(day(-1), map[int]string{21: verdictUnreached, 22: verdictUnreached, 443: verdictLost})
	// 8443: a longer streak than the bounded read; the date is that of the oldest verdict read.
	for i := 150; i >= 1; i-- {
		run(store.FormatTS(t0.Add(-time.Duration(i)*time.Hour)), map[int]string{8443: verdictUnreached})
	}

	got, err := e.svc.Services(e.ctx(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	since := map[int]string{}
	for _, s := range got {
		if s.NotReachedSince != nil {
			since[s.Port] = *s.NotReachedSince
		}
	}
	want := map[int]string{
		22:   day(-10), // unreached, lost, unknown, unreached: one streak
		443:  day(-1),  // the network's verdict broke the streak
		8443: store.FormatTS(t0.Add(-time.Duration(priorVerdictsMax) * time.Hour)),
	}
	if len(since) != len(want) {
		t.Fatalf("not reached since = %v, want %v", since, want)
	}
	for p, w := range want {
		if since[p] != w {
			t.Errorf("port %d: not reached since %q, want %q", p, since[p], w)
		}
	}
}
