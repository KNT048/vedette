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
	r.advance(time.Minute) // the terms and settings were set before the scan started
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
	// a template job's host is the address itself, never a name (TemplateJob): the step must not say they ran with the domain's name
	if st, _ := addressStep(r.runDetail(r.ctx(), s.RunID), ipA); strings.Contains(reuseNote(st), "name") {
		t.Fatalf("step of %s says %q", ipA, reuseNote(st))
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
		{name: "the domain's settings turn off a group whose scripts the source's sweep ran", before: func(r *reuseEnv) {
			r.deepRow(r.dom.ID, false, false, true, true, true, SpeedNormal, "[]", "[]") // password guessing and default logins off for the domain
		}},
		{name: "this run finds an open port there that the source did not see", after: func(r *reuseEnv) {
			r.run.content.Ports = append(slices.Clone(r.run.content.Ports), PortRow{IP: ipA, Port: 8080, Service: "http", HTTP: true})
		}},
		{name: "a finding the source reported is gone on the domain", after: func(r *reuseEnv) {
			r.exec(`INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id)
				VALUES ('xs-443', ?, ?, 443, 'tcp', 'probed', 'open', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`, r.dom.ID, ipA)
			r.exec(`INSERT INTO exp_issue (id, target_id, service_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id)
				VALUES ('xi-gone', ?, 'xs-443', 'surface', ?, 'Weak finding', 'high', 'gone', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`,
				r.dom.ID, keyScript+ipA+" ssl-x:Weak finding")
		}},
		{name: "a finding the source reported is marked patched on the domain", after: func(r *reuseEnv) {
			r.exec(`INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id)
				VALUES ('xs-443', ?, ?, 443, 'tcp', 'probed', 'open', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`, r.dom.ID, ipA)
			r.exec(`INSERT INTO exp_issue (id, target_id, service_id, engine, key, title, severity, state, resolution, resolved_by, resolved_at, first_seen, last_seen, last_run_id)
				VALUES ('xi-fixed', ?, 'xs-443', 'surface', ?, 'Weak finding', 'high', 'handled', 'patched', 'admin@acme.example', '2026-11-02T00:00:00.000Z',
				'2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', 'r-old')`, r.dom.ID, keyScript+ipA+" ssl-x:Weak finding")
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
			if ds.calls() != 1 {
				t.Fatalf("the box's scan ran the disruptive scripts %d times", ds.calls())
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
				if ds.calls() != 1 {
					t.Fatalf("the domain's run sent the disruptive scripts again (%d)", ds.calls())
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

// calls counts the disruptive jobs sent to the box's own IP.
func (d *disruptiveSeams) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, x := range d.sent {
		if x == ipA {
			n++
		}
	}
	return n
}

// scopeCovers is the settings rule alone: the source's settings must allow at least what the domain's step allows now.
func TestDomainReuse_ScopeCovers(t *testing.T) {
	t.Parallel()
	all := DeepSettings{DoS: true, Logins: true, WebActive: true, DataChange: true, OpenVAS: true, Speed: SpeedNormal}
	step := ScanTarget{Mode: ScanMode{Full: true, Disruptive: true, Logins: true, Change: true, WebActive: true, OpenVAS: true}, Groups: all.Groups() &^ GroupDoS,
		SkipPorts: []int{25, 8443}, SkipPaths: []string{"/admin"}}
	for _, tc := range []struct {
		name string
		sum  settingsSummary
		d    DeepSettings
		step func(ScanTarget) ScanTarget
		ok   bool
	}{
		{name: "equal", sum: settingsSummary{Speed: SpeedNormal, SkipPorts: []int{25}}, d: all, ok: true},
		{name: "the source wider: it skipped nothing", sum: settingsSummary{Speed: SpeedNormal}, d: all, ok: true},
		{name: "a skipped path under one the step skips", sum: settingsSummary{Speed: SpeedNormal, SkipPaths: []string{"/admin/x"}}, d: all, ok: true},
		{name: "the gentle step takes a normal source", sum: settingsSummary{Speed: SpeedNormal}, d: all, step: func(s ScanTarget) ScanTarget { s.Gentle = true; return s }, ok: true},
		{name: "DoS off then, on now", sum: settingsSummary{Off: GroupDoS.Names(), Speed: SpeedNormal}, d: all,
			step: func(s ScanTarget) ScanTarget { s.Mode.DoS, s.Groups = true, s.Groups|GroupDoS; return s }},
		{name: "logins off then", sum: settingsSummary{Off: GroupLogins.Names(), Speed: SpeedNormal}, d: all},
		{name: "OpenVAS off in the source's settings", sum: settingsSummary{Speed: SpeedNormal}, d: DeepSettings{Logins: true, WebActive: true, DataChange: true, Speed: SpeedNormal}},
		{name: "a port skipped then is scanned now", sum: settingsSummary{Speed: SpeedNormal, SkipPorts: []int{22}}, d: all},
		{name: "a path skipped then is scanned now", sum: settingsSummary{Speed: SpeedNormal, SkipPaths: []string{"/api"}}, d: all},
		{name: "gentle then, normal now", sum: settingsSummary{Speed: SpeedGentle}, d: all},
		{name: "an unknown group name", sum: settingsSummary{Off: []string{"something new"}, Speed: SpeedNormal}, d: all},
	} {
		st := step
		if tc.step != nil {
			st = tc.step(st)
		}
		if why := scopeCovers(tc.sum, tc.d, st); (why == "") != tc.ok {
			t.Errorf("%s: scopeCovers = %q, want reuse %v", tc.name, why, tc.ok)
		}
	}
}

// OpenVAS: a domain whose address had its own deep scan with OpenVAS a moment ago does not start a second OpenVAS task there. The
// address's OpenVAS findings become the domain's, its OpenVAS step says where they come from, and a second reuse closes none of them.
func TestDomainReuse_OpenVASResultsComeWithTheAddress(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.terms = nil
	e.enable()
	dns := &deepDNS{fakeResolver: e.dns, a: map[string][]string{"acme.example": {ipA}}}
	e.svc.cfg.Resolver, e.svc.cfg.DomainFence, e.svc.cfg.Services, e.svc.cfg.Matcher = dns, &fakeFence{}, &deepSeams{}, &fakeMatcher{}
	box := e.detect(ipA)
	if _, err := e.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(box[0].ID, false)
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, false)
	run := &fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}}
	e.svc.SetRunner(run)
	e.advance(time.Minute)
	src, err := e.svc.Scan(e.ctx(), "admin@acme.example", box[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := e.runDetail(e.ctx(), src.RunID); d.Status != corerun.Done {
		t.Fatalf("the box's scan ended %s %q", d.Status, d.Summary)
	}
	found := e.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND engine = 'openvas' AND state = 'open'`, box[0].ID)
	if found == 0 {
		t.Fatal("the box's scan found no OpenVAS result to reuse")
	}
	tasks := len(h.gvm.log.rows)
	run.content = Content{Hosts: []HostRow{{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassBox}}}},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}
	for range 2 {
		e.advance(time.Hour)
		s, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(h.gvm.log.rows) != tasks {
			t.Fatalf("the domain's run started OpenVAS again: %+v", h.gvm.log.rows[tasks:])
		}
		if got := e.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND engine = 'openvas' AND state = 'open'`, dom.ID); got != found {
			t.Fatalf("the domain holds %d open OpenVAS findings, the address's scan %d", got, found)
		}
		d := e.runDetail(e.ctx(), s.RunID)
		i := slices.IndexFunc(d.Steps, func(st corerun.Step) bool { return st.Name == stepNameOpenVAS })
		if i < 0 || d.Steps[i].Status != corerun.Skipped || !strings.Contains(reuseNote(d.Steps[i]), "Reused from the deep scan of "+ipA) {
			t.Fatalf("OpenVAS step %+v", d.Steps)
		}
		if d.Status != corerun.Done {
			t.Fatalf("the domain's run ended %s %q", d.Status, d.Summary)
		}
	}
}

// OpenVAS's config follows the disruptive groups of the scan (levelOf): a source run with the disruptive terms checked the address with
// the brute force, default accounts and denial-of-service families, which a domain step without them would not run. Its results are
// never the domain's: the domain starts its own OpenVAS task.
func TestDomainReuse_OpenVASOfAWiderSourceIsNotReused(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.terms = nil
	e.enable()
	dns := &deepDNS{fakeResolver: e.dns, a: map[string][]string{"acme.example": {ipA}}}
	e.svc.cfg.Resolver, e.svc.cfg.DomainFence, e.svc.cfg.Services, e.svc.cfg.Matcher = dns, &fakeFence{}, &deepSeams{}, &fakeMatcher{}
	box := e.detect(ipA)
	if _, err := e.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(box[0].ID, true) // the address's own scan: the disruptive checks allowed
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, false) // the domain: the deep scan without them
	run := &fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}}
	e.svc.SetRunner(run)
	e.advance(time.Minute)
	src, err := e.svc.Scan(e.ctx(), "admin@acme.example", box[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := e.runDetail(e.ctx(), src.RunID); d.Status != corerun.Done {
		t.Fatalf("the box's scan ended %s %q", d.Status, d.Summary)
	}
	if e.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND engine = 'openvas' AND state = 'open'`, box[0].ID) == 0 {
		t.Fatal("the box's scan found no OpenVAS result")
	}
	tasks := len(h.gvm.log.rows)
	run.content = Content{Hosts: []HostRow{{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassBox}}}},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}
	e.advance(time.Hour)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.gvm.log.rows) == tasks {
		t.Fatal("the domain's run reused the OpenVAS results of a scan with the disruptive checks; want its own OpenVAS task")
	}
	d := e.runDetail(e.ctx(), s.RunID)
	if slices.ContainsFunc(d.Items, func(it corerun.ItemRow) bool { return it.SubjectKind == "run" }) {
		t.Fatalf("a source run is linked: %+v", d.Items)
	}
}

// reuseNarrower alone: a finding of a check the domain's step would not run (a script group its settings turn off, a disruptive
// group of the source's run it does not have) is never taken; equal groups are.
func TestDomainReuse_Narrower(t *testing.T) {
	t.Parallel()
	def := DefaultDeepSettings() // DoS off: logins and the checks that may change data on
	script := issueIn{engine: EngineSurface, key: keyScript + ipA + " ssl-x:Weak finding"}
	vas := issueIn{engine: EngineOpenVAS, key: "1.3.6.1.4.1.25623.1.0.1:443@" + ipA}
	dis := issueIn{engine: EngineSurface, key: keyScriptDisruptive + ipA + " ftp-brute:Weak password"}
	plain := ScanTarget{Mode: ScanMode{Full: true, WebActive: true, OpenVAS: true}, Groups: def.Groups()}
	withD := plain
	withD.Mode.Disruptive, withD.Mode.Logins, withD.Mode.Change = true, true, true
	noLogins := plain
	noLogins.Groups &^= GroupLogins
	for _, tc := range []struct {
		name       string
		step       ScanTarget
		disruptive bool
		ins        []issueIn
		ok         bool
	}{
		{"equal, no disruptive checks", plain, false, []issueIn{script, vas}, true},
		{"equal, with the disruptive checks", withD, true, []issueIn{script, vas, dis}, true},
		{"the source's run had the disruptive checks, the step not: OpenVAS", plain, true, []issueIn{vas}, false},
		{"the source's run had the disruptive checks, the step not: no finding to take", plain, true, nil, true},
		{"the step's settings turn logins off: a script finding", noLogins, false, []issueIn{script}, false},
		{"the step's settings turn logins off: only OpenVAS of a run without the disruptive checks", noLogins, false, []issueIn{vas}, true},
	} {
		if why := reuseNarrower(tc.step, def, tc.disruptive, tc.ins); (why == "") != tc.ok {
			t.Errorf("%s: reuseNarrower = %q, want reuse %v", tc.name, why, tc.ok)
		}
	}
}

// The address's own settings turn OpenVAS off: its scan ran no OpenVAS, so the domain's OpenVAS step must not say that OpenVAS's
// results were reused from it; it says what a normal scan says (turned off in the settings), and nothing is sent.
func TestDomainReuse_OpenVASOffForTheAddressIsNotCalledReused(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.terms = nil
	e.enable()
	dns := &deepDNS{fakeResolver: e.dns, a: map[string][]string{"acme.example": {ipA}}}
	e.svc.cfg.Resolver, e.svc.cfg.DomainFence, e.svc.cfg.Services, e.svc.cfg.Matcher = dns, &fakeFence{}, &deepSeams{}, &fakeMatcher{}
	box := e.detect(ipA)
	if _, err := e.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(box[0].ID, false)
	e.deepRow(box[0].ID, false, true, true, true, false, SpeedNormal, "[]", "[]") // OpenVAS off for the address
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, false)
	run := &fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}}
	e.svc.SetRunner(run)
	e.advance(time.Minute)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", box[0].ID); err != nil {
		t.Fatal(err)
	}
	tasks := len(h.gvm.log.rows)
	run.content = Content{Hosts: []HostRow{{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassBox}}}},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}}}
	e.advance(time.Hour)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.gvm.log.rows) != tasks {
		t.Fatalf("OpenVAS was sent to an address whose settings turn it off: %+v", h.gvm.log.rows[tasks:])
	}
	d := e.runDetail(e.ctx(), s.RunID)
	if !slices.ContainsFunc(d.Items, func(it corerun.ItemRow) bool { return it.SubjectKind == "run" }) {
		t.Fatalf("the address layer was not reused: %+v", d.Items)
	}
	i := slices.IndexFunc(d.Steps, func(st corerun.Step) bool { return st.Name == stepNameOpenVAS })
	if i >= 0 && strings.Contains(reuseNote(d.Steps[i]), "Reused") {
		t.Fatalf("OpenVAS step says its results were reused from a scan that ran no OpenVAS: %q", reuseNote(d.Steps[i]))
	}
	for _, it := range d.Items {
		if it.SubjectKind == "run" && it.Note != nil && strings.Contains(*it.Note, "OpenVAS") {
			t.Fatalf("the source run's item says its OpenVAS was reused: %q", *it.Note)
		}
	}
}
