package exposure

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// alertLog keeps the alerts a test's service sent.
type alertLog struct {
	mu  sync.Mutex
	got []Alert
}

func (l *alertLog) send(_ context.Context, a Alert) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, a)
	return nil
}

func (l *alertLog) all() []Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Alert(nil), l.got...)
}

// A newly open port and a new issue each alert once: the first scan is the baseline (no alert), the scan that finds them sends one
// alert with both, and the scan after that finds nothing new and sends nothing.
func TestAlerts_ANewPortAndANewIssueAlertOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	base := Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", Ident: IdentProbed}}}
	ip := e.scanIP(base).RunID
	if len(log.all()) != 0 {
		t.Fatalf("the baseline alerted: %+v", log.all())
	}
	target := e.count(`SELECT count(*) FROM exp_target`)
	if target != 1 {
		t.Fatalf("targets: %d", target)
	}
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, ip).Scan(&id); err != nil {
		t.Fatal(err)
	}
	now := base
	now.Ports = append(now.Ports, PortRow{IP: ipA, Port: 8443, Service: "https-alt", Ident: IdentProbed})
	now.AdminPanels = []AdminRow{{URL: "https://" + ipA + ":8443/admin", Product: "Example Router", IP: ipA, Port: 8443, Risk: "danger"}}
	scan := func() {
		t.Helper()
		e.advance(ScanEvery)
		e.svc.SetRunner(&fakeRunner{content: now})
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	got := log.all()
	if len(got) != 1 {
		t.Fatalf("alerts after the change: %+v", got)
	}
	a := got[0]
	if a.TargetID != id || a.Severity != AlertHigh || !strings.Contains(a.Text, "New open port: "+ipA+":8443") ||
		!strings.Contains(a.Text, "New high issue: Admin page of Example Router open to the Internet on "+ipA+":8443") || strings.Contains(a.Text, ":443 ") {
		t.Fatalf("the alert: %+v", a)
	}
	scan()
	if n := len(log.all()); n != 1 {
		t.Fatalf("the same port and issue alerted again: %+v", log.all())
	}
}

// A port that a domain's scan finds new on a name its child target took over while the scan ran alerts once, on the child that holds it
// now, saying which scan found it; the child's own next scan does not announce it again. The event names the child too.
func TestAlerts_AMovedPortAlertsOnceOnTheTargetThatHoldsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	apex, git := e.proveTree()
	off, on := false, true
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	host := func(name, ip string) HostRow {
		return HostRow{Name: name, IP: ip, Source: "ct", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}}
	}
	run := &planRunner{content: Content{Hosts: []HostRow{host("acme.example", ipA), host("git.acme.example", ipB)},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}, {IP: ipB, Port: 22, Service: "ssh"}}}}
	e.svc.SetRunner(run)
	scan := func(id string) {
		t.Helper()
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	scan(apex.ID) // the apex's baseline, git's name its own while git is off
	if len(log.all()) != 0 {
		t.Fatalf("the baseline alerted: %+v", log.all())
	}
	run.content.Ports = append(run.content.Ports, PortRow{IP: ipB, Port: 3389, Service: "ms-wbt-server"})
	run.during = func() {
		if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &on}); err != nil {
			t.Error(err)
		}
	}
	scan(apex.ID)
	w := e.lastWritten(apex.ID)
	if len(w.Opened) != 1 || w.Opened[0].Port != 3389 || w.Opened[0].TargetID != git.ID {
		t.Fatalf("the event of the apex's scan: %+v", w.Opened)
	}
	got := log.all()
	if len(got) != 1 || got[0].TargetID != git.ID || !strings.Contains(got[0].Text, "New open port: "+ipB+":3389") ||
		!strings.Contains(got[0].Text, "The scan of acme.example") || !strings.HasPrefix(got[0].Title, "git.acme.example") {
		t.Fatalf("the alert of the moved port: %+v", got)
	}
	scan(git.ID)
	if n := len(log.all()); n != 1 {
		t.Fatalf("the child's scan announced it again: %+v", log.all())
	}
}

// A first scan that finds nothing open is still the baseline: a port opened after it (a forward for 3389) is news, alerted once, and the
// event is not the baseline either.
func TestAlerts_APortAfterAnEmptyFirstScanAlerts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	run := e.scanIP(Content{}).RunID
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, run).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if !e.lastWritten(id).First || len(log.all()) != 0 {
		t.Fatalf("the empty first scan: first %v, alerts %+v", e.lastWritten(id).First, log.all())
	}
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 3389, Service: "ms-wbt-server", Ident: IdentProbed}}}})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	w := e.lastWritten(id)
	if w.First || len(w.Opened) != 1 || w.Opened[0].Port != 3389 {
		t.Fatalf("the event after the empty scan: %+v", w)
	}
	if got := log.all(); len(got) != 1 || !strings.Contains(got[0].Text, "New open port: "+ipA+":3389") {
		t.Fatalf("alerts after the empty scan: %+v", got)
	}
}

// An issue a person marked patched or mitigated that a later scan still reports opens again (the flaw is still there), with an audit row
// and one alert; accepted, not relevant and false positive keep the person's decision.
func TestAlerts_AFixThatDidNotTakeOpensAgainOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	content := Content{Ports: []PortRow{{IP: ipA, Port: 8443, Service: "https-alt", Ident: IdentProbed}, {IP: ipA, Port: 9443, Service: "https-alt", Ident: IdentProbed}},
		AdminPanels: []AdminRow{{URL: "https://" + ipA + ":8443/admin", Product: "Example Router", IP: ipA, Port: 8443, Risk: "danger"},
			{URL: "https://" + ipA + ":9443/admin", Product: "Example Switch", IP: ipA, Port: 9443, Risk: "warn"}}}
	run := e.scanIP(content).RunID
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, run).Scan(&id); err != nil {
		t.Fatal(err)
	}
	issue := func(product string) string {
		t.Helper()
		var x string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM exp_issue WHERE target_id = ? AND title LIKE ?`, id, "%"+product+"%").Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	router, sw := issue("Example Router"), issue("Example Switch")
	if _, err := e.svc.HandleIssues(e.ctx(), "it@acme.example", []string{router}, ResolvedPatched, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.HandleIssues(e.ctx(), "it@acme.example", []string{sw}, ResolvedAccepted, "only reachable from the office", e.clock.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	scan := func() {
		t.Helper()
		e.advance(ScanEvery)
		e.svc.SetRunner(&fakeRunner{content: content})
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	if state, res, _, _, _ := e.issueRow(router); state != IssueOpen || res != "" {
		t.Fatalf("the patched issue found again: %s %s", state, res)
	}
	if state, res, _, _, _ := e.issueRow(sw); state != IssueHandled || res != string(ResolvedAccepted) {
		t.Fatalf("the accepted issue: %s %s", state, res)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.issue_reopen' AND user = 'system' AND detail = 'found again by a scan (was patched by it@acme.example)'`); n != 1 {
		t.Fatalf("the audit of the reopen: %d", n)
	}
	got := log.all()
	if len(got) != 1 || !strings.Contains(got[0].Text, "Found again although marked patched: Admin page of Example Router") || strings.Contains(got[0].Text, "Example Switch") {
		t.Fatalf("the alert of the reopen: %+v", got)
	}
	scan()
	if n := len(log.all()); n != 1 {
		t.Fatalf("the reopened issue alerted again: %+v", log.all())
	}
}

// duringRunner runs a function while its scan runs, then reports its content.
type duringRunner struct {
	content Content
	during  func()
}

func (r *duringRunner) Scan(context.Context, ScanTarget) (Content, error) {
	if r.during != nil {
		r.during()
		r.during = nil
	}
	return r.content, nil
}

// An issue marked patched while a scan runs is newer than what that scan saw: the scan keeps the mark and alerts nothing; the next scan,
// started after the mark, still reporting it opens it again.
func TestAlerts_AMarkMadeDuringAScanStays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	content := Content{Ports: []PortRow{{IP: ipA, Port: 8443, Service: "https-alt", Ident: IdentProbed}},
		AdminPanels: []AdminRow{{URL: "https://" + ipA + ":8443/admin", Product: "Example Router", IP: ipA, Port: 8443, Risk: "danger"}}}
	run := e.scanIP(content).RunID
	var id, issue string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, run).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM exp_issue WHERE target_id = ?`, id).Scan(&issue); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery)
	e.svc.SetRunner(&duringRunner{content: content, during: func() {
		e.advance(time.Minute)
		if _, err := e.svc.HandleIssues(e.ctx(), "it@acme.example", []string{issue}, ResolvedPatched, "", ""); err != nil {
			t.Error(err)
		}
	}})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if state, res, _, _, _ := e.issueRow(issue); state != IssueHandled || res != string(ResolvedPatched) {
		t.Fatalf("marked patched during the scan: %s %s", state, res)
	}
	if len(log.all()) != 0 {
		t.Fatalf("a mark made during the scan alerted: %+v", log.all())
	}
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: content})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if state, _, _, _, _ := e.issueRow(issue); state != IssueOpen || len(log.all()) != 1 {
		t.Fatalf("the next scan: %s, alerts %+v", state, log.all())
	}
}
