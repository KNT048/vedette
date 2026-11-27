package exposure

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// A domain's deep scan reuses the address-level layer (port discovery, nmap -sV and its scripts, OpenVAS, nmap's disruptive scripts)
// of a deep scan of the same address that finished within the last 24 hours at an equal or wider scope; the web layer of the domain
// (the templates, ZAP by name, the certificates) always runs. Fixture data only: the seams are fakes, nothing is sent anywhere.

// reuseEnv is newDeepEnv with a domain fence, the box's own IP target (ipA) and the domain both with accepted terms.
type reuseEnv struct {
	*deepEnv
	box string // the id of the box's own IP target, ipA
}

func newReuseEnv(t *testing.T) *reuseEnv {
	t.Helper()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	v, ok, err := loadTargetByValue(d.ctx(), d.db.Reader(), ipA)
	if err != nil || !ok {
		t.Fatalf("box target: %v %v", ok, err)
	}
	r := &reuseEnv{deepEnv: d, box: v.ID}
	d.acceptTerms(r.box, false)
	d.acceptTerms(d.dom.ID, false)
	return r
}

// scanBox runs a person's deep scan of the box's own IP target and returns it; the runner sees the address's web port only.
func (r *reuseEnv) scanBox() ScanResult {
	r.t.Helper()
	keep := r.run.content
	r.run.content = Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}
	defer func() { r.run.content = keep }()
	s, err := r.svc.Scan(r.ctx(), "admin@acme.example", r.box)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// servicesCalls counts the service-identification calls sent to ip so far.
func (r *reuseEnv) servicesCalls(ip string) int {
	return len(slices.DeleteFunc(r.seams.serviceIPs(), func(x string) bool { return x != ip }))
}

func (r *reuseEnv) templateCalls(ip string) int {
	r.seams.mu.Lock()
	defer r.seams.mu.Unlock()
	n := 0
	for _, c := range r.seams.templates {
		if c.ip == ip {
			n++
		}
	}
	return n
}

// addressStep is the step of one of the domain run's addresses.
func addressStep(d corerun.Detail, ip string) (corerun.Step, bool) {
	for _, s := range d.Steps {
		if strings.HasPrefix(s.Name, "Deep scan of "+ip+" ") {
			return s, true
		}
	}
	return corerun.Step{}, false
}

func reuseNote(s corerun.Step) string {
	if s.Note == nil {
		return ""
	}
	return *s.Note
}

// wantReused: the domain run reused the box's scan for ipA (no second service identification there, the step says where its results
// come from and links that run) and scanned the other addresses itself.
func (r *reuseEnv) wantReused(s ScanResult, source string, before int) {
	r.t.Helper()
	if got := r.servicesCalls(ipA); got != before {
		r.t.Fatalf("service identification of %s sent %d more times by the domain's run, want reused", ipA, got-before)
	}
	d := r.runDetail(r.ctx(), s.RunID)
	st, ok := addressStep(d, ipA)
	if !ok || st.Status != corerun.Done || !strings.Contains(reuseNote(st), "Reused from the deep scan of "+ipA+" at ") {
		r.t.Fatalf("step of %s = %+v %q", ipA, st, reuseNote(st))
	}
	if !slices.ContainsFunc(d.Items, func(it corerun.ItemRow) bool {
		return it.SubjectKind == "run" && it.SubjectID != nil && *it.SubjectID == source && it.Outcome == "reused"
	}) {
		r.t.Fatalf("no item links the source run %s: %+v", source, d.Items)
	}
	if !slices.ContainsFunc(s.Services, func(x ServiceRow) bool { return x.IP == ipA && x.Port == 443 && x.Product == "nginx" }) {
		r.t.Fatalf("the reused services are not the domain's: %+v", s.Services)
	}
}

// wantScanned: the domain run identified ipA's services itself, and its step says nothing of a reuse.
func (r *reuseEnv) wantScanned(s ScanResult, before int) {
	r.t.Helper()
	if got := r.servicesCalls(ipA); got != before+1 {
		r.t.Fatalf("service identification of %s sent %d times by the domain's run, want once (no reuse)", ipA, got-before)
	}
	d := r.runDetail(r.ctx(), s.RunID)
	if st, _ := addressStep(d, ipA); strings.Contains(reuseNote(st), "Reused") {
		r.t.Fatalf("step of %s says %q", ipA, reuseNote(st))
	}
	if slices.ContainsFunc(d.Items, func(it corerun.ItemRow) bool { return it.SubjectKind == "run" }) {
		r.t.Fatalf("a source run is linked: %+v", d.Items)
	}
}

// The measured case: the box's own IP was deep-scanned an hour ago at the same scope; the domain that points at it reuses that
// address's ports, services and scripts, says so with a link to that run, and still runs its own web layer there (the templates with
// the domain's step, ZAP by name). Another address of the domain is scanned as before.
func TestDomainReuse_AFreshEqualScopeAddressRunIsReused(t *testing.T) {
	t.Parallel()
	r := newReuseEnv(t)
	src := r.scanBox()
	if d := r.runDetail(r.ctx(), src.RunID); d.Status != corerun.Done {
		t.Fatalf("the box's scan ended %s %q", d.Status, d.Summary)
	}
	r.advance(time.Hour)
	before, tplBefore := r.servicesCalls(ipA), r.templateCalls(ipA)
	pagesBefore := len(r.seams.pages)
	s := r.scan()
	r.wantReused(s, src.RunID, before)
	if r.servicesCalls(ipB) != 1 || r.servicesCalls(ipC) != 1 { // a different address is never reused from it
		t.Fatalf("services of the other addresses: %v", r.seams.serviceIPs())
	}
	if r.templateCalls(ipA) != tplBefore+1 { // the web layer of the domain runs on the reused address
		t.Fatalf("templates on %s: %d new calls, want 1", ipA, r.templateCalls(ipA)-tplBefore)
	}
	if !slices.ContainsFunc(r.seams.pages[pagesBefore:], func(p WebPage) bool { return strings.HasSuffix(p.Host, "acme.example") }) {
		t.Fatalf("no page by name in the domain's run: %+v", r.seams.pages[pagesBefore:])
	}
	if deepOf(s, ipA).Deep != DeepScanned {
		t.Fatalf("ipA = %+v", deepOf(s, ipA))
	}
}

// What is never reused: a source older than 24 hours, a run that did not finish, a source whose settings were narrower than the
// domain's step now allows (fewer ports skipped now, the gentle speed then, DoS off then and on now), and a domain whose stored rows
// a reuse would close or reopen. Each scans the address itself.
func TestDomainReuse_NoReuse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		before func(r *reuseEnv) // before the box's scan
		after  func(r *reuseEnv) // between the box's scan and the domain's
	}{
		{name: "the source is older than 24 hours", after: func(r *reuseEnv) { r.advance(25 * time.Hour) }},
		{name: "the source did not finish", before: func(r *reuseEnv) {
			r.seams.mu.Lock()
			r.seams.errFor = map[string]error{ipA: errors.New("nmap failed")}
			r.seams.mu.Unlock()
		}, after: func(r *reuseEnv) {
			r.seams.mu.Lock()
			r.seams.errFor = nil
			r.seams.mu.Unlock()
		}},
		{name: "fewer ports skipped now than then", before: func(r *reuseEnv) {
			r.deepRow(r.box, false, true, true, true, true, SpeedNormal, "[8443]", "[]")
		}, after: func(r *reuseEnv) {
			r.deepRow(r.box, false, true, true, true, true, SpeedNormal, "[]", "[]")
			r.exec(`UPDATE exp_deep_setting SET updated_at = ? WHERE target_id = ?`, store.FormatTS(r.clock.Now()), r.box)
		}},
		{name: "the gentle speed then, normal now", before: func(r *reuseEnv) {
			r.deepRow(r.box, false, true, true, true, true, SpeedGentle, "[]", "[]")
		}, after: func(r *reuseEnv) {
			r.deepRow(r.box, false, true, true, true, true, SpeedNormal, "[]", "[]")
			r.exec(`UPDATE exp_deep_setting SET updated_at = ? WHERE target_id = ?`, store.FormatTS(r.clock.Now()), r.box)
		}},
		{name: "a skipped port the stored summary keeps that the settings no longer have", before: func(r *reuseEnv) {
			r.deepRow(r.box, false, true, true, true, true, SpeedNormal, "[8443]", "[]")
		}, after: func(r *reuseEnv) { // a settings row rewritten without its time moving: the summary of the run still says what it skipped
			r.deepRow(r.box, false, true, true, true, true, SpeedNormal, "[]", "[]")
		}},
		{name: "the domain holds an open script finding the source did not report", after: func(r *reuseEnv) {
			r.exec(`INSERT INTO exp_issue (id, target_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id)
				VALUES ('xi-old', ?, 'surface', ?, 'Old finding', 'high', 'open', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`,
				r.dom.ID, keyScript+ipA+" old-script:Old finding")
		}},
		{name: "the domain holds an open port the source did not see", after: func(r *reuseEnv) {
			r.exec(`INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id)
				VALUES ('xs-old', ?, ?, 2222, 'tcp', 'probed', 'open', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`, r.dom.ID, ipA)
		}},
		{name: "a finding the source reported is gone on the domain", after: func(r *reuseEnv) {
			r.exec(`INSERT INTO exp_issue (id, target_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id)
				VALUES ('xi-gone', ?, 'surface', ?, 'Weak finding', 'high', 'gone', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`,
				r.dom.ID, keyScript+ipA+" ssl-x:Weak finding")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newReuseEnv(t)
			r.seams.mu.Lock()
			r.seams.scripts = []ScriptRow{{IP: ipA, Port: 443, ID: "ssl-x", Output: "VULNERABLE", Findings: []ScriptFinding{{Title: "Weak finding", State: "vulnerable"}}}}
			r.seams.mu.Unlock()
			if tc.before != nil {
				tc.before(r)
			}
			r.scanBox()
			r.advance(time.Hour)
			if tc.after != nil {
				tc.after(r)
			}
			before := r.servicesCalls(ipA)
			r.wantScanned(r.scan(), before)
		})
	}
}

// The control of the cases above: the same fixtures without the change reuse.
func TestDomainReuse_ScriptFindingsOfTheSourceAreTheDomains(t *testing.T) {
	t.Parallel()
	r := newReuseEnv(t)
	r.seams.mu.Lock()
	r.seams.scripts = []ScriptRow{{IP: ipA, Port: 443, ID: "ssl-x", Output: "VULNERABLE", Findings: []ScriptFinding{{Title: "Weak finding", State: "vulnerable"}}}}
	r.seams.mu.Unlock()
	src := r.scanBox()
	r.advance(time.Hour)
	before := r.servicesCalls(ipA)
	s := r.scan()
	r.wantReused(s, src.RunID, before)
	if n := r.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND engine = 'surface' AND key = ? AND state = 'open'`,
		r.dom.ID, keyScript+ipA+" ssl-x:Weak finding"); n != 1 {
		t.Fatalf("the source's script finding on the domain: %d open rows, want 1", n)
	}
	// a second reuse keeps it open and closes nothing
	r.advance(time.Hour)
	before = r.servicesCalls(ipA)
	r.wantReused(r.scan(), src.RunID, before)
	if n := r.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND state = 'open' AND key = ?`, r.dom.ID, keyScript+ipA+" ssl-x:Weak finding"); n != 1 {
		t.Fatalf("after a second reuse: %d open rows", n)
	}
}

// The disruptive checks: a source that ran them with DoS off reuses for a domain step without DoS, never for one with DoS on now.
func TestDomainReuse_DisruptiveScopeMustBeCovered(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		dosNow bool
		reuse  bool
	}{{"DoS off then and now", false, true}, {"DoS off then, on now", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newReuseEnv(t)
			ds := &disruptiveSeams{deepSeams: r.seams}
			r.svc.cfg.Services = ds
			r.acceptTerms(r.box, true)
			r.acceptTerms(r.dom.ID, true)
			r.deepRow(r.box, false, true, true, true, true, SpeedNormal, "[]", "[]") // DoS off for the box's scan
			r.deepRow(r.dom.ID, false, true, true, true, true, SpeedNormal, "[]", "[]")
			src := r.scanBox()
			if ds.calls(ipA) != 1 {
				t.Fatalf("the box's scan ran the disruptive scripts %d times", ds.calls(ipA))
			}
			r.advance(time.Hour)
			if tc.dosNow {
				r.deepRow(r.box, true, true, true, true, true, SpeedNormal, "[]", "[]")
				r.deepRow(r.dom.ID, true, true, true, true, true, SpeedNormal, "[]", "[]")
				r.exec(`UPDATE exp_deep_setting SET updated_at = ? WHERE target_id = ?`, store.FormatTS(r.clock.Now()), r.box)
			}
			before := r.servicesCalls(ipA)
			s := r.scan()
			if tc.reuse {
				r.wantReused(s, src.RunID, before)
				if ds.calls(ipA) != 1 {
					t.Fatalf("the domain's run sent the disruptive scripts again (%d)", ds.calls(ipA))
				}
				d := r.runDetail(r.ctx(), s.RunID)
				for _, st := range d.Steps {
					if st.Name == stepNameDisruptive && !strings.Contains(reuseNote(st), "Reused from the deep scan of "+ipA) {
						t.Fatalf("disruptive step %+v %q", st, reuseNote(st))
					}
				}
				return
			}
			r.wantScanned(s, before)
		})
	}
}

// disruptiveSeams adds nmap's disruptive scripts to the deep seams.
type disruptiveSeams struct {
	*deepSeams
	sent []string
}

func (d *disruptiveSeams) ScanDisruptive(_ context.Context, _ ScanTarget, ip netip.Addr, _ []int) (ServiceScan, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, ip.String())
	return ServiceScan{}, nil
}

func (d *disruptiveSeams) calls(ip string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, x := range d.sent {
		if x == ip {
			n++
		}
	}
	return n
}
