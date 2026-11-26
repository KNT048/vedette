package exposure

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakePath answers that the box's own network answers ports for any destination; asked records each call's ports.
type fakePath struct {
	mu    sync.Mutex
	ports []int
	asked [][]int
}

func (f *fakePath) AnsweredByPath(_ context.Context, ports []int) ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, slices.Clone(ports))
	var out []int
	for _, p := range ports {
		if slices.Contains(f.ports, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// INV-44: from a network whose firewall answers the SYN on 2000 and 5060 for any destination (its SCCP and SIP helpers), the runner
// and nmap both see those ports open on every target. A connect to a never-routed address answers there too, so they are the
// network's: no service row, no issue, nothing for the engines, and one plain line on the target and in the run's log. The check is
// asked only about the ports that came back open, each once a run.
func TestNetworkPath_APortAnsweredForANeverRoutedAddressIsLeftOut(t *testing.T) {
	t.Parallel()
	e, scan, _ := deepScans(t)
	path := &fakePath{ports: []int{2000, 5060}}
	e.svc.cfg.Path = path
	sweep := swept(80, 2000, 5060)
	sweep.Scripts = []ScriptRow{{IP: ipA, Port: 5060, ID: "sip-methods", Output: "OPTIONS"}, {IP: ipA, Port: 80, ID: "http-title", Output: "Home"}}
	r := scan([]int{80, 5060}, sweep, nil)
	if n := e.count(`SELECT count(*) FROM exp_service WHERE port IN (2000, 5060)`); n != 0 {
		t.Fatalf("%d service rows for the ports the network answers", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_service WHERE port = 80 AND state = 'open'`); n != 1 {
		t.Fatalf("port 80, the target's own: %d open rows", n)
	}
	if slices.ContainsFunc(r.Scripts, func(s ScriptRow) bool { return s.Port == 5060 }) {
		t.Fatalf("a script result on a port the network answers was kept: %+v", r.Scripts)
	}
	want := "Ports 2000 and 5060 are answered by your own network (a firewall helper or a proxy), not by " + ipA
	i := slices.IndexFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "network_path" })
	if i < 0 || !strings.HasPrefix(r.NotChecked[i].Text, want) || !strings.Contains(r.NotChecked[i].Text, "they were left out") {
		t.Fatalf("the target's line: %+v", r.NotChecked)
	}
	if n := e.count(`SELECT count(*) FROM core_run_log WHERE run_id = ? AND text LIKE '%answered by your own network, not by `+ipA+`%'`, r.RunID); n < 1 {
		t.Fatal("the run's log does not say which ports the network answered")
	}
	var all []int
	for _, a := range path.asked {
		all = append(all, a...)
	}
	slices.Sort(all)
	if !slices.Equal(all, []int{80, 2000, 5060}) {
		t.Fatalf("the check was asked about %v: want each open port once (80, 2000, 5060)", path.asked)
	}
}

// failingPath is a PathChecker whose check fails every time.
type failingPath struct{}

func (failingPath) AnsweredByPath(context.Context, []int) ([]int, error) {
	return nil, errors.New("no route to the documentation addresses")
}

// INV-44 with INV-22: rows that earlier scans stored for ports the network answers (scans from before the check, or with a check
// that failed) are retired by the first scan in which the check ran and flagged that port on that address: no longer listed as
// open, not counted as closed by the target, their issues gone, and the save step says why. A check that fails retires nothing.
func TestNetworkPath_EarlierRowsOfAPortTheNetworkAnswersAreRetired(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{80, 5060}, swept(80, 2000, 5060), nil) // no check: the network's 2000 and 5060 were stored as the target's
	var svc5060 string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM exp_service WHERE ip = ? AND port = 5060`, ipA).Scan(&svc5060); err != nil {
		t.Fatal(err)
	}
	ts := "2026-01-01T00:00:00.000Z"
	e.exec(`INSERT INTO exp_issue (id, target_id, service_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id)
		SELECT 'i5060', target_id, id, 'openvas', 'sip', 'SIP answers', 'medium', 'open', ?, ?, 'r0' FROM exp_service WHERE id = ?`, ts, ts, svc5060)

	e.svc.cfg.Path = failingPath{}
	scan([]int{80, 5060}, swept(80, 2000, 5060), nil)
	if state(2000) != ServiceOpen || state(5060) != ServiceOpen {
		t.Fatalf("a failed check retired a row: 2000 %s, 5060 %s", state(2000), state(5060))
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE id = 'i5060' AND state = 'open'`); n != 1 {
		t.Fatal("a failed check made the issue of 5060 gone")
	}

	e.svc.cfg.Path = &fakePath{ports: []int{2000, 5060}}
	r := scan([]int{80, 5060}, swept(80, 2000, 5060), nil)
	if state(2000) != ServiceClosed || state(5060) != ServiceClosed || state(80) != ServiceOpen {
		t.Fatalf("after a scan whose check flagged 2000 and 5060: 2000 %s, 5060 %s, 80 %s", state(2000), state(5060), state(80))
	}
	if n := closedByNewest(e); n != 0 {
		t.Fatalf("the scan counts %d services closed by the target; the retired rows were the network's", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE id = 'i5060' AND state = 'gone'`); n != 1 {
		t.Fatal("the issue of a retired row is still open")
	}
	save := stepOf(t, e.runDetail(e.ctx(), r.RunID), stepNameSave)
	if note := noteOf(save); !strings.HasPrefix(note, "1 open service (0 new, 0 closed)") ||
		!strings.Contains(note, "Ports 2000 and 5060 of "+ipA+" are no longer listed: they are answered by your own network, not by "+ipA+".") {
		t.Fatalf("the save step: %q", note)
	}
	if n := e.count(`SELECT count(*) FROM core_run_log WHERE run_id = ? AND text LIKE '%are no longer listed: they are answered by your own network%'`, r.RunID); n < 1 {
		t.Fatal("the run's log does not say why the rows are no longer listed")
	}

	// From a clean network the target's real 5060 is seen again: a new open service, as for any port that comes back.
	e.svc.cfg.Path = &fakePath{}
	scan([]int{80, 5060}, swept(80, 5060), nil)
	if state(5060) != ServiceOpen || state(2000) != ServiceClosed {
		t.Fatalf("from a clean network: 5060 %s, 2000 %s", state(5060), state(2000))
	}
}

// INV-44: a check that is not wired, or that fails, leaves the results as they were.
func TestNetworkPath_NoCheckKeepsTheOpenPorts(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{80, 5060}, swept(80, 5060), nil)
	if state(5060) != ServiceOpen {
		t.Fatalf("5060 without a check: %s", state(5060))
	}
	if n := e.count(`SELECT count(*) FROM core_run_item WHERE subject_kind = 'path_port'`); n != 0 {
		t.Fatalf("%d path items without a check", n)
	}
}

// A network that answers many ports (a SYN proxy in front of the box) still gets its line on the target: a line longer than a
// "Not checked" line may be is dropped when the results are written, so it names a few ports and counts the rest.
func TestNetworkPath_ManyPortsKeepTheirLine(t *testing.T) {
	t.Parallel()
	e, scan, _ := deepScans(t)
	var many []int
	for p := 10001; p <= 10035; p++ {
		many = append(many, p)
	}
	e.svc.cfg.Path = &fakePath{ports: many}
	r := scan([]int{80}, swept(append([]int{80}, many...)...), nil)
	i := slices.IndexFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "network_path" })
	if i < 0 || !strings.Contains(r.NotChecked[i].Text, "answered by your own network") {
		t.Fatalf("the target's line about 35 ports the network answers: %+v", r.NotChecked)
	}
}
