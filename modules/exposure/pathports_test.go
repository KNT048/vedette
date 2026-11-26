package exposure

import (
	"context"
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

// INV-44 with INV-22: a port the network answers is neither seen nor missed. A real 2000 (outside the fixed list) and 5060 (on it)
// found open before keep their rows and their last sighting through scans from such a network; the first scan from a clean network
// that misses them closes 5060 (the runner's connect and a trusted sweep both missed it) and not 2000, whose miss needs the scan
// before to have checked it too: the scans from the network that answered it did not.
func TestNetworkPath_APortTheNetworkAnswersIsNeitherSeenNorMissed(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{80, 5060}, swept(80, 2000, 5060), nil)
	seen := func(port int) string {
		t.Helper()
		var at string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT last_seen FROM exp_service WHERE ip = ? AND port = ?`, ipA, port).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := seen(2000)
	e.svc.cfg.Path = &fakePath{ports: []int{2000, 5060}}
	for i := range 3 {
		scan([]int{80, 5060}, swept(80, 2000, 5060), nil)
		if state(2000) != ServiceOpen || state(5060) != ServiceOpen || seen(2000) != before {
			t.Fatalf("scan %d from the network that answers 2000 and 5060: 2000 %s (last seen %s, was %s), 5060 %s", i+1, state(2000), seen(2000), before, state(5060))
		}
	}
	e.svc.cfg.Path = &fakePath{}
	scan([]int{80}, swept(80), nil)
	if state(5060) != ServiceClosed {
		t.Fatalf("5060, missed by the runner and a trusted sweep from a clean network: %s", state(5060))
	}
	if state(2000) != ServiceOpen {
		t.Fatalf("2000 after one clean miss, the scans before did not check it: %s", state(2000))
	}
	scan([]int{80}, swept(80), nil)
	if state(2000) != ServiceClosed {
		t.Fatalf("2000 after two clean misses in a row: %s", state(2000))
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
