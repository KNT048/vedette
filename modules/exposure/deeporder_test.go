package exposure

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corerun "github.com/knt048/vedette/core/run"
)

// fakeAlive is Config.Liveness: up says which ports of an address still accept a connection at the n-th check of the run (n from 0).
type fakeAlive struct {
	mu    sync.Mutex
	up    func(n int, ip netip.Addr, port int) bool
	calls int
	asked [][]int
}

func (f *fakeAlive) Alive(_ context.Context, ip netip.Addr, ports []int) (map[int]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.calls
	f.calls++
	f.asked = append(f.asked, slices.Clone(ports))
	out := map[int]bool{}
	for _, p := range ports {
		out[p] = f.up(n, ip, p)
	}
	return out, nil
}

// downFrom is a target that answers every check before the n-th, and none from it on.
func downFrom(n int) *fakeAlive {
	return &fakeAlive{up: func(i int, _ netip.Addr, _ int) bool { return i < n }}
}

// disruptiveServices is a ServiceScanner that also runs the disruptive scripts: it records the ports it was asked for.
type disruptiveServices struct {
	fakeServices
	mu      sync.Mutex
	ports   [][]int
	scripts []ScriptRow
	err     error
}

func (f *disruptiveServices) ScanDisruptive(_ context.Context, t ScanTarget, ip netip.Addr, ports []int) (ServiceScan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip.String() != t.Value || !t.Mode.Disruptive {
		return ServiceScan{}, errors.New("asked for another address, or without the disruptive checks")
	}
	f.ports = append(f.ports, slices.Clone(ports))
	return ServiceScan{Ports: len(ports), Probed: ports, Scripts: f.scripts}, f.err
}

// startedOrder is the order of the "Started: <step>" lines of a run's log.
func startedOrder(d corerun.Detail) []string {
	var out []string
	for _, l := range d.Log {
		if name, ok := strings.CutPrefix(l.Text, "Started: "); ok {
			out = append(out, name)
		}
	}
	return out
}

func stepOf(t *testing.T, d corerun.Detail, name string) corerun.Step {
	t.Helper()
	for _, s := range d.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no step %q", name)
	return corerun.Step{}
}

func noteOf(s corerun.Step) string {
	if s.Note == nil {
		return ""
	}
	return *s.Note
}

// The deep scan's order: the light checks (templates, the passive then the active web scan) before the heavy ones (OpenVAS), and
// nmap's disruptive scripts last, so a ban or an overloaded firewall costs only the last steps. The plan is the one source of that
// order: a deep scan of an IP and of a domain end with the disruptive scripts; a standard scan has no such step.
func TestScanPlan_TheDisruptiveScriptsRunLast(t *testing.T) {
	t.Parallel()
	keys := func(defs ...[]stepDef) []string {
		var out []string
		for _, d := range defs {
			for _, s := range d {
				out = append(out, s.key)
			}
		}
		return out
	}
	head, tail := scanPlan(KindIP, ScanMode{Full: true, Disruptive: true})
	want := []string{stepKeySurface, stepKeyPorts, stepKeyServices, stepKeyNuclei, stepKeyZAP, stepKeyZAPActive, stepKeySave, stepKeyOpenVAS, stepKeyDisruptive}
	if got := keys(head, tail); !slices.Equal(got, want) {
		t.Fatalf("deep IP plan = %q\nwant %q", got, want)
	}
	head, tail = scanPlan(KindIP, ScanMode{Full: true})
	if got := keys(head, tail); !slices.Equal(got, want) {
		t.Fatalf("a deep plan lists the disruptive step (skipped with why when the run may not run it): %q", got)
	}
	head, tail = scanPlan(KindDomain, ScanMode{Full: true, Disruptive: true})
	if got := keys(head, tail); got[len(got)-1] != stepKeyDisruptive {
		t.Fatalf("deep domain plan = %q", got)
	}
	head, tail = scanPlan(KindIP, ScanMode{})
	if got := keys(head, tail); slices.Contains(got, stepKeyDisruptive) || slices.Contains(got, stepKeyZAPActive) {
		t.Fatalf("standard plan = %q", got)
	}
}

// A person's deep scan with the disruptive checks: the early nmap run is the deep scan without the disruptive scripts, and they run as
// the last step of the run, after OpenVAS, on the open ports this scan found. What they confirm is an issue.
func TestDisruptive_TheScriptsRunLastOnTheOpenPorts(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	*e.terms = true
	svc := &disruptiveServices{fakeServices: *e.svc.cfg.Services.(*fakeServices), scripts: []ScriptRow{{IP: ipA, Port: 22, ID: "ssh-brute", Output: "Output not stored: it can hold credentials.",
		Findings: []ScriptFinding{{State: "vulnerable", Title: "Weak SSH password", CVEs: nil}}}}}
	e.svc.cfg.Services = svc
	s := e.scanIP(gbOpen())
	d := e.runDetail(e.ctx(), s.RunID)
	order := startedOrder(d)
	want := []string{stepNameCheck, stepNameSurfaceIP, stepNamePortsDeep, stepNameServiceDeep, stepNameNuclei, stepNameZAP, stepNameZAPAct, stepNameSave, stepNameOpenVAS, stepNameDisruptive}
	if !slices.Equal(order, want) {
		t.Fatalf("steps started in the order %q\nwant %q", order, want)
	}
	if len(svc.ports) != 1 || !slices.Equal(svc.ports[0], []int{22, 80, 443}) {
		t.Fatalf("the disruptive scripts ran on %v, want the open ports [22 80 443]", svc.ports)
	}
	st := stepOf(t, d, stepNameDisruptive)
	if st.Status != corerun.Done || !strings.Contains(noteOf(st), "3 open ports") {
		t.Fatalf("disruptive step = %s %q", st.Status, noteOf(st))
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'surface' AND title = 'Weak SSH password' AND state = 'open'`); n != 1 {
		t.Fatalf("the disruptive scripts' finding is %d open issues", n)
	}
	if d.Status != corerun.Done {
		t.Fatalf("run = %s %q", d.Status, d.Summary)
	}
}

// Without the disruptive checks (terms without them, or a scheduled scan) the step is listed and skipped with why, and the
// disruptive scripts are never asked for.
func TestDisruptive_SkippedWhenTheRunMayNotRunThem(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t) // the terms without the disruptive checks
	svc := &disruptiveServices{fakeServices: *e.svc.cfg.Services.(*fakeServices)}
	e.svc.cfg.Services = svc
	s := e.scanIP(gbOpen())
	d := e.runDetail(e.ctx(), s.RunID)
	st := stepOf(t, d, stepNameDisruptive)
	if st.Status != corerun.Skipped || !strings.Contains(noteOf(st), "disruptive checks") {
		t.Fatalf("disruptive step = %s %q", st.Status, noteOf(st))
	}
	if len(svc.ports) != 0 {
		t.Fatalf("the disruptive scripts ran: %v", svc.ports)
	}
	if d.Steps[len(d.Steps)-1].Name != stepNameDisruptive {
		t.Fatalf("the disruptive step is not the last: %q", d.Steps[len(d.Steps)-1].Name)
	}
}

// The box's own public IP stops answering in the middle of a deep scan (the router lost its NAT loopback, so the box cannot reach
// its own address from inside the network): the steps after it are skipped with that in plain words, the run ends partly done
// (never "Done"), and the scan does not count as a miss of any port, even one a trusted sweep and the runner both missed.
func TestLiveness_ATargetThatStopsAnsweringIsSaidAndIsNotAMiss(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", Ident: IdentProbed}, {IP: ipA, Port: 22, Service: "ssh", Ident: IdentProbed}}})
	e.advance(ScanEvery + time.Minute)
	if state := e.svcState(22); state != ServiceOpen {
		t.Fatalf("22 after the first scan: %s", state)
	}
	// The second scan: the runner and a trusted sweep both miss 22; the address stops answering before the templates.
	alive := downFrom(0)
	e.svc.cfg.Liveness = alive
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 65535, Services: []ServiceRow{{IP: ipA, Port: 443, Name: "https", Product: "nginx", Method: "probed"}}}}
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", Ident: IdentProbed}}}})
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", e.ipTargetID())
	if err != nil {
		t.Fatal(err)
	}
	d := e.runDetail(e.ctx(), s.RunID)
	if d.Status != corerun.Partial || !strings.Contains(d.Summary, "stopped answering") {
		t.Fatalf("run = %s %q, want partly done saying the target stopped answering", d.Status, d.Summary)
	}
	for _, name := range []string{stepNameNuclei, stepNameZAP, stepNameZAPAct, stepNameOpenVAS} {
		st := stepOf(t, d, name)
		note := noteOf(st)
		if st.Status != corerun.Skipped || !strings.Contains(note, ipA+":443 stopped answering during the scan") || !strings.Contains(note, "NAT loopback") {
			t.Errorf("%s = %s %q", name, st.Status, note)
		}
		if strings.Contains(note, "IPS") {
			t.Errorf("%s claims an IPS without evidence: %q", name, note)
		}
	}
	if state := e.svcState(22); state != ServiceOpen {
		t.Fatalf("22 after a scan whose target stopped answering: %s, want still open (not a miss)", state)
	}
	if n := e.count(`SELECT count(*) FROM core_run_item WHERE run_id = ? AND subject_kind = 'address' AND subject_id = ? AND outcome IN (?, ?, ?, ?, ?)`,
		s.RunID, ipA, coverAll, coverList, coverTop, coverWeb, coverEmpty); n != 0 {
		t.Fatalf("the scan counts as having checked %s: %d coverage items", ipA, n)
	}
	if save := stepOf(t, d, stepNameSave); save.Status != corerun.Done || !strings.Contains(noteOf(save), "does not count as a miss") {
		t.Fatalf("the save step = %s %q: its rows are written (done), and it says the scan is not a miss", save.Status, noteOf(save))
	}
	if recent, err := e.svc.RecentScans(e.ctx(), 10); err != nil || len(recent) == 0 || recent[0].RunID != s.RunID {
		t.Fatalf("the scan that wrote its rows is not among the recent scans: %+v %v", recent, err)
	}
	if len(alive.asked) == 0 || !slices.Equal(alive.asked[0], []int{443}) {
		t.Fatalf("the liveness check asked %v, want the port seen open in this run", alive.asked)
	}
}

// One port stops answering while the others still do: the engines skip that port, the step that lost it says so (partly done), and
// so does the run. nuclei's own answers count too: a port where most templates got no answer at all makes the template step
// incomplete.
func TestLiveness_APortThatStopsAnsweringMakesTheStepIncomplete(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	e.svc.cfg.Liveness = &fakeAlive{up: func(n int, _ netip.Addr, port int) bool { return port != 443 || n == 0 }}
	var results []TemplateResult
	for i := range 40 {
		results = append(results, TemplateResult{Port: 80, Template: "tpl-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Outcome: OutcomeNoMatch, Elsewhere: true})
	}
	e.svc.cfg.Templates = &fakeTemplates{log: &fakeProbeLog{}, results: results}
	s := e.scanIP(gbOpen())
	d := e.runDetail(e.ctx(), s.RunID)
	if d.Status != corerun.Partial {
		t.Fatalf("run = %s %q", d.Status, d.Summary)
	}
	nuc := stepOf(t, d, stepNameNuclei)
	if nuc.Status != corerun.Partial || !strings.Contains(noteOf(nuc), "no answer from "+ipA+":80") {
		t.Fatalf("nuclei step = %s %q", nuc.Status, noteOf(nuc))
	}
	gb := stepOf(t, d, stepNameOpenVAS)
	if gb.Status != corerun.Partial || !strings.Contains(noteOf(gb), ipA+":443 stopped answering during the scan") {
		t.Fatalf("OpenVAS step = %s %q", gb.Status, noteOf(gb))
	}
}

// The ZAP image is not on the box yet (it is still downloading): the web step is skipped with that note, and the run is partly
// done, never a silent Done.
func TestEngineImage_AStepWhoseImageIsDownloadingIsSkippedAndTheRunSaysSo(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	e.svc.cfg.Web = &fakeWeb{report: cleanReport, err: &Unavailable{Reason: "the ZAP image is still downloading; it will run in the next scan.", Pending: true}}
	s := e.scanIP(gbOpen())
	d := e.runDetail(e.ctx(), s.RunID)
	zap := stepOf(t, d, stepNameZAP)
	if zap.Status != corerun.Skipped || !strings.Contains(noteOf(zap), "still downloading; it will run in the next scan") {
		t.Fatalf("ZAP step = %s %q", zap.Status, noteOf(zap))
	}
	if d.Status != corerun.Partial || !strings.Contains(d.Summary, "still downloading") {
		t.Fatalf("run = %s %q", d.Status, d.Summary)
	}
}

// fakePreparer is a WebScanner that fetches its engine's image when asked.
type fakePreparer struct {
	fakeWeb
	mu    sync.Mutex
	asked int
	calls chan struct{} // one value per call
}

func (f *fakePreparer) PrepareImage(context.Context) error {
	f.mu.Lock()
	f.asked++
	f.mu.Unlock()
	f.calls <- struct{}{}
	return nil
}

func (f *fakePreparer) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.asked }

// Turning the External exposure module on, and the box's start with the module on (after an install or an update), fetch the engine
// images, so the first scan does not find them missing; with the module off nothing is fetched.
func TestEngineImage_TheModuleOnFetchesTheImages(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &fakePreparer{calls: make(chan struct{}, 4)}
	e.svc.cfg.Web = p
	e.svc.ModuleSwitched(false)
	e.svc.PrepareEngines(e.ctx())
	if p.count() != 0 {
		t.Fatalf("the image was fetched with the module off: %d", p.count())
	}
	e.svc.ModuleSwitched(true)
	select { // the switch fetches in the background
	case <-p.calls:
	case <-time.After(5 * time.Second):
		t.Fatal("switching the module on fetched nothing")
	}
	e.svc.PrepareEngines(e.ctx())
	if p.count() != 2 {
		t.Fatalf("the start with the module on fetched %d times", p.count()-1)
	}
}

func (e *env) svcState(port int) string {
	e.t.Helper()
	var st string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT state FROM exp_service WHERE ip = ? AND port = ?`, ipA, port).Scan(&st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

func (e *env) ipTargetID() string {
	e.t.Helper()
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM exp_target WHERE value = ?`, ipA).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}
