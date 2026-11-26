package exposure

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// obs is one address of a verdicts input: open ports, the ports open before, and the coverage of an IP target's deep scan whose sweep
// ran to its end.
func obs(open []int, stored ...int) *addrObs {
	a := &addrObs{class: coverAll, listed: true, sweep: &sweepFacts{ran: true, trusted: true}, open: map[int]bool{}, storedOpen: stored}
	for _, p := range open {
		a.open[p] = true
	}
	return a
}

// verdictsOf is the verdict of each port of ipA, as "port:verdict/reason".
func verdictsOf(o observation) map[int]string {
	out := map[int]string{}
	for _, v := range verdicts(o).sorted() {
		out[v.port] = v.v + "/" + v.reason
	}
	return out
}

// verdicts is the one decision of a run: each case is what the probes of one run got on one address, and the verdict of each port.
func TestVerdicts_OneVerdictPerAddressAndPort(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		a     *addrObs
		calib map[int]string
		want  map[int]string
	}{
		"seen open": {a: obs([]int{22, 80}, 22), want: map[int]string{22: "open/", 80: "open/"}},
		"missed while the address answered, no re-check": {a: obs([]int{22}, 22, 443),
			want: map[int]string{22: "open/", 443: "closed/"}},
		"no answer at all to the re-check while 22 answered": {a: func() *addrObs {
			a := obs([]int{22}, 22, 443)
			a.recheck = map[int]string{443: PortSilent}
			return a
		}(), want: map[int]string{22: "open/", 443: "filtered/blocked"}},
		"the re-check got an answer": {a: func() *addrObs {
			a := obs([]int{22}, 22, 443)
			a.recheck = map[int]string{443: PortOpen}
			return a
		}(), want: map[int]string{22: "open/", 443: "open/"}},
		"nothing answered at all": {a: obs(nil, 22, 443), want: map[int]string{22: "unreached/blocked", 443: "unreached/blocked"}},
		"resets of a host elsewhere, nothing open": {a: func() *addrObs {
			a := obs(nil, 22, 443)
			a.resets = true
			return a
		}(), want: map[int]string{22: "closed/", 443: "closed/"}},
		"resets through the box's own NAT loopback, nothing open": {a: func() *addrObs {
			a := obs(nil, 22, 443)
			a.resets, a.loopback = true, true
			return a
		}(), want: map[int]string{22: "unreached/loopback", 443: "unreached/loopback"}},
		"a port that stopped answering in the run": {a: func() *addrObs {
			a := obs([]int{22, 443}, 22, 443, 8443)
			a.lost = []int{443}
			return a
		}(), want: map[int]string{22: "open/", 443: "lost/blocked", 8443: "lost/blocked"}},
		"the network accepts 5060 for every address": {a: func() *addrObs {
			a := obs([]int{22}, 22, 5060)
			a.leftOut = []int{5060}
			return a
		}(), calib: map[int]string{22: PortSilent, 5060: PortOpen}, want: map[int]string{22: "open/", 5060: "network/synack"}},
		"the network refuses 25 for every address, and those resets are not the target's": {a: func() *addrObs {
			a := obs(nil, 22, 25)
			a.resets = true
			return a
		}(), calib: map[int]string{22: PortSilent, 25: PortClosed}, want: map[int]string{22: "unreached/blocked", 25: "network/reset"}},
		"the check of the network failed": {a: obs([]int{5060}, 22), calib: map[int]string{22: calibFailed, 5060: calibFailed},
			want: map[int]string{22: "unknown/path", 5060: "unknown/path"}},
		"a sweep that was cut": {a: func() *addrObs {
			a := obs([]int{22}, 22, 32400)
			a.class, a.sweep, a.stepCut = coverList, &sweepFacts{cut: "cut"}, "cut"
			return a
		}(), want: map[int]string{22: "open/", 32400: "unknown/step"}},
		"a port the run did not probe": {a: func() *addrObs {
			a := obs([]int{80}, 80, 8443)
			a.class, a.sweep, a.listed = coverWeb, nil, false
			return a
		}(), want: map[int]string{80: "open/"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := observation{addrs: map[string]*addrObs{ipA: tc.a}, calib: tc.calib, checked: tc.calib != nil}
			got := verdictsOf(o)
			for p, w := range tc.want {
				if got[p] != w {
					t.Errorf("port %d: %q, want %q", p, got[p], w)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("verdicts %v, want %v", got, tc.want)
			}
		})
	}
}

// Two probes of one run that agree close at once: the runner and a trusted sweep on the fixed list, or one of them and a reset to the
// re-check. One probe needs the scan before.
func TestVerdicts_ProbesThatMissedAClosedPort(t *testing.T) {
	t.Parallel()
	a := obs([]int{22}, 22, 443, 32400)
	a.recheck = map[int]string{32400: PortClosed}
	vs := verdicts(observation{addrs: map[string]*addrObs{ipA: a}})
	for port, want := range map[int]int{443: 2, 32400: 2} {
		if v, _ := vs.of(ipA, port); v.v != verdictClosed || v.probes != want {
			t.Errorf("port %d: %s with %d probes, want closed with %d", port, v.v, v.probes, want)
		}
	}
	a = obs([]int{22}, 22, 32400)
	if v, _ := verdicts(observation{addrs: map[string]*addrObs{ipA: a}}).of(ipA, 32400); v.probes != 1 {
		t.Errorf("32400 missed by the sweep only: %d probes, want 1", v.probes)
	}
}

// Through a network that accepts a web port for every address, a target whose own answer differs (its certificate, its page) is open
// on that port, seen over a checked path; one whose answer is the network's is not.
func TestVerdicts_ATargetsOwnAnswerThroughAProxyIsOpen(t *testing.T) {
	t.Parallel()
	a := obs([]int{22, 443}, 22)
	a.leftOut = []int{80}
	o := observation{addrs: map[string]*addrObs{ipA: a}, checked: true, calib: map[int]string{22: PortSilent, 80: PortOpen, 443: PortOpen},
		distinct: map[string]bool{portKey(ipA, 443): true}}
	vs := verdicts(o)
	if v, _ := vs.of(ipA, 443); v.v != verdictOpen || !v.clean {
		t.Errorf("443, the target's own answer: %+v", v)
	}
	if v, _ := vs.of(ipA, 80); v.v != verdictNetwork {
		t.Errorf("80, the proxy's answer: %+v", v)
	}
}

// The rows' memory: a filtered port closes on the third filtered scan in a row since it was last seen, a day after the first; a row of
// a port the network answers is retired only when no scan saw it open over a checked clean path.
func TestVerdicts_FilteredStreakAndCleanSighting(t *testing.T) {
	t.Parallel()
	seen := "2026-11-01T00:00:00.000Z"
	prior := []priorVerdict{{at: "2026-11-02T12:00:00.000Z", outcome: verdictFiltered}, {at: "2026-11-02T00:00:00.000Z", outcome: verdictFiltered}}
	if !filteredStreak(prior, seen, "2026-11-03T00:00:00.000Z") {
		t.Error("three filtered scans over a day did not close")
	}
	if filteredStreak(prior, seen, "2026-11-02T20:00:00.000Z") {
		t.Error("three filtered scans within a day closed")
	}
	if filteredStreak(append([]priorVerdict{{at: "2026-11-02T18:00:00.000Z", outcome: verdictOpen}}, prior...), seen, "2026-11-03T00:00:00.000Z") {
		t.Error("an answer in between did not start the count again")
	}
	if seenClean([]priorVerdict{{outcome: itemOpenUnchecked}, {outcome: verdictNetwork}}) {
		t.Error("a sighting over a path that was not checked counts as clean")
	}
	if !seenClean([]priorVerdict{{outcome: verdictNetwork}, {outcome: verdictOpen}}) {
		t.Error("a clean sighting was missed")
	}
}

// The customer's words come from the verdict's reason, in one place: the box's own IP reached from inside gets the NAT-loopback hint,
// any other address what to allow (with "deep" only in a deep scan), and the network's ports their own line that is not a problem.
func TestVerdicts_TheLinesSayTheReason(t *testing.T) {
	t.Parallel()
	own := obs(nil, 22)
	elsewhere := obs(nil, 443)
	net := obs([]int{22}, 22)
	net.leftOut = []int{5060}
	o := observation{addrs: map[string]*addrObs{ipA: own, ipC: elsewhere, ipB: net}, deep: true, checked: true,
		calib: map[int]string{22: PortSilent, 443: PortSilent, 5060: PortOpen}, names: map[string][]string{ipC: {"www.acme.example"}}}
	own.loopback = true
	lines := vantageLines(o, verdicts(o), "198.51.100.7")
	find := func(prefix string) (vantageLine, bool) {
		for _, l := range lines {
			if strings.HasPrefix(l.row.Text, prefix) {
				return l, true
			}
		}
		return vantageLine{}, false
	}
	if l, ok := find("No port of " + ipA + " answered this box."); !ok || !strings.Contains(l.row.Text, "NAT loopback") || !l.problem || l.row.Kind != "unanswered" {
		t.Errorf("the box's own IP: %+v (%v)", l, ok)
	}
	if l, ok := find("No port of " + ipC + " (www.acme.example) answered this box."); !ok ||
		!strings.Contains(l.row.Text, "allow this box's public IP 198.51.100.7 during deep scans") || strings.Contains(l.row.Text, "NAT") {
		t.Errorf("an address elsewhere: %+v (%v)", l, ok)
	}
	if l, ok := find("Port 5060 is answered by your own network"); !ok || l.problem || l.row.Kind != "network_path" {
		t.Errorf("the network's port: %+v (%v)", l, ok)
	}
	for _, l := range lines {
		if len([]rune(l.row.Text)) > maxLineText {
			t.Errorf("a line longer than a line may be: %q", l.row.Text)
		}
	}
}

// The verdicts of the runs before are read up to a bound, newest first, however many runs a target has; a clean sighting older than
// the bound is still known (a row seen open over a clean path is never retired as the network's).
func TestPriorVerdicts_AreBoundedAndKeepTheCleanSighting(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	port := portKey(ipA, 5060)
	start := t0.Add(-400 * 24 * time.Hour)
	add := func(i int, outcome string) string {
		id := fmt.Sprintf("run-%04d", i)
		at := store.FormatTS(start.Add(time.Duration(i) * 6 * time.Hour))
		err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, subject_label,
				status, queued_at, started_at, ended_at, updated_at) VALUES (?, ?, ?, ?, 'External scan', 'manual', 'admin@acme.example', 'target', 'tgt', 'tgt', 'done', ?, ?, ?, ?)`,
				id, ModuleID, RunKind, RunLane, at, at, at, at); err != nil {
				return err
			}
			if outcome == "" {
				return nil
			}
			_, err := tx.ExecContext(e.ctx(), `INSERT INTO core_run_item (run_id, seq, subject_kind, subject_id, label, outcome) VALUES (?, 1, ?, ?, ?, ?)`,
				id, itemVerdict, port, port, outcome)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	add(0, verdictOpen)
	for i := 1; i <= 300; i++ {
		add(i, verdictNetwork)
	}
	now := add(301, "")
	prior, err := priorVerdicts(e.ctx(), e.db.Reader(), "tgt", now, port)
	if err != nil {
		t.Fatal(err)
	}
	if len(prior) > 101 {
		t.Fatalf("%d verdicts read for one port, want a bounded number", len(prior))
	}
	if prior[0].outcome != verdictNetwork || prior[0].at != store.FormatTS(start.Add(300*6*time.Hour)) {
		t.Fatalf("the newest verdict before: %+v", prior[0])
	}
	if !seenClean(prior) {
		t.Fatal("the clean sighting of the first run is forgotten")
	}
}
