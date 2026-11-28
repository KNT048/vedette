package exposure

import (
	"context"
	"database/sql"
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

// A new issue that carries a CVE exploited in the wild alerts once: the first scan is the baseline (no alert), the scan that finds it
// sends one alert, which counts the new ports and the other new issue it does not name (they are in the daily summary), and the scan
// after that finds nothing new and sends nothing.
func TestAlerts_AnExploitedIssueAlertsOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	e.svc.cfg.Exploited = onlyExploited("CVE-2021-41773")
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
	now.Ports = append(now.Ports, PortRow{IP: ipA, Port: 8443, Service: "https-alt", Ident: IdentProbed}, PortRow{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed})
	withCVEs(e, "CVE-2021-41773")
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
	if a.TargetID != id || a.Severity != AlertCritical || !strings.Contains(a.Text, "New critical issue: CVE-2021-41773") || !strings.Contains(a.Text, "exploited in the wild") ||
		!strings.Contains(a.Text, "and 3 other new things with no CVE exploited in the wild") || strings.Contains(a.Text, "New open port") || strings.Contains(a.Text, "Example Router") {
		t.Fatalf("the alert: %+v", a)
	}
	scan()
	if n := len(log.all()); n != 1 {
		t.Fatalf("the same port and issue alerted again: %+v", log.all())
	}
}

// A port that a domain's scan finds new on a name its child target took over while the scan ran is news of the child that holds it now
// (the event names the child); a port carries no CVE, so it sends no alert, there or on the child's own next scan: it is in the daily
// summary.
func TestAlerts_AMovedPortIsNewsOfTheTargetThatHoldsIt(t *testing.T) {
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
	if got := log.all(); len(got) != 0 {
		t.Fatalf("a moved port alerted: %+v", got)
	}
	scan(git.ID)
	if n := len(log.all()); n != 0 {
		t.Fatalf("the child's scan announced it again: %+v", log.all())
	}
}

// A first scan that finds nothing open is still the baseline: a port opened after it (a forward for 3389) is news (the event is not the
// baseline either), counted for the daily summary; with no CVE exploited in the wild it sends no alert.
func TestAlerts_APortAfterAnEmptyFirstScanIsNews(t *testing.T) {
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
	if got := log.all(); len(got) != 0 {
		t.Fatalf("alerts after the empty scan: %+v", got)
	}
	if _, ports, err := e.svc.NewSince(e.ctx(), e.clock.Now().Add(-time.Minute), e.clock.Now().Add(time.Second)); err != nil || ports != 1 {
		t.Fatalf("the daily summary's new ports: %d, %v", ports, err)
	}
}

// An issue a person marked patched or mitigated that a later scan still reports opens again (the flaw is still there), with an audit row
// and, as its CVE is exploited in the wild, one alert; accepted, not relevant and false positive keep the person's decision.
func TestAlerts_AFixThatDidNotTakeOpensAgainOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	e.svc.cfg.Exploited = onlyExploited("CVE-2021-41773")
	withCVEs(e, "CVE-2021-41773")
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
	router, sw := issue("CVE-2021-41773"), issue("Example Switch")
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
	if len(got) != 1 || !strings.Contains(got[0].Text, "Found again although marked patched: CVE-2021-41773") || strings.Contains(got[0].Text, "Example Switch") {
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
	e.svc.cfg.Exploited = onlyExploited("CVE-2021-41773")
	withCVEs(e, "CVE-2021-41773")
	content := Content{Ports: []PortRow{{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}}}
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

// onlyExploited is a Config.Exploited that says the given CVEs, and no other, are exploited in the wild.
func onlyExploited(cves ...string) func(context.Context, []string) (map[string]bool, error) {
	return func(_ context.Context, ask []string) (map[string]bool, error) {
		out := map[string]bool{}
		for _, c := range ask {
			for _, x := range cves {
				out[c] = out[c] || c == x
			}
		}
		return out, nil
	}
}

// withCVEs makes the next scans identify Apache on port 80 of ipA and match cves on it: issues that carry those CVEs.
func withCVEs(e *env, cves ...string) {
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 1, Services: []ServiceRow{{IP: ipA, Port: 80, Name: "http", Product: "Apache httpd", Version: "2.4.49"}}}}
	m := Matches{Compared: 1, Listed: 1500}
	for _, c := range cves {
		m.Vulns = append(m.Vulns, VulnRow{IP: ipA, Port: 80, CVE: c, Name: c, Basis: "version", Summary: "In range."})
	}
	e.svc.cfg.Matcher = &fakeMatcher{m: m}
}

// Only an issue that carries a CVE exploited in the wild alerts at once (the rule of a finding's alert); a new port, an admin page and an
// issue of a CVE nobody exploits send nothing and are counted for the daily summary (NewSince).
func TestAlerts_OnlyAnIssueWithAnExploitedCVEAlerts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	e.svc.cfg.Exploited = onlyExploited("CVE-2021-41773")
	base := Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", Ident: IdentProbed}}}
	run := e.scanIP(base).RunID
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, run).Scan(&id); err != nil {
		t.Fatal(err)
	}
	scan := func(c Content) {
		t.Helper()
		e.advance(ScanEvery)
		e.svc.SetRunner(&fakeRunner{content: c})
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	quiet := base
	quiet.Ports = append(quiet.Ports, PortRow{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}, PortRow{IP: ipA, Port: 3389, Service: "ms-wbt-server", Ident: IdentProbed})
	quiet.AdminPanels = []AdminRow{{URL: "https://" + ipA + ":443/admin", Product: "Example Router", IP: ipA, Port: 443, Risk: "danger"}}
	withCVEs(e, "CVE-2099-0002")           // a CVE nobody exploits
	from := e.clock.Now().Add(time.Second) // after the baseline
	scan(quiet)
	if got := log.all(); len(got) != 0 {
		t.Fatalf("news with no exploited CVE alerted: %+v", got)
	}
	withCVEs(e, "CVE-2099-0002", "CVE-2021-41773")
	scan(quiet)
	got := log.all()
	if len(got) != 1 || got[0].Severity != AlertCritical || !strings.Contains(got[0].Text, "CVE-2021-41773") || strings.Contains(got[0].Text, "New open port") ||
		strings.Contains(got[0].Text, "CVE-2099-0002") {
		t.Fatalf("the alert of the exploited CVE: %+v", got)
	}
	issues, ports, err := e.svc.NewSince(e.ctx(), from, e.clock.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if issues != 2 || ports != 2 { // the CVE nobody exploits and the admin page; 80 and 3389 (443 was the baseline)
		t.Fatalf("for the daily summary: %d issues, %d ports", issues, ports)
	}
}

// exploitedSet is a Config.Exploited whose answer a test changes: a CVE joins CISA's list after the scan.
type exploitedSet struct {
	mu  sync.Mutex
	set map[string]bool
}

func (x *exploitedSet) add(cve string) { x.mu.Lock(); defer x.mu.Unlock(); x.set[cve] = true }

func (x *exploitedSet) ask(_ context.Context, cves []string) (map[string]bool, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := map[string]bool{}
	for _, c := range cves {
		out[c] = x.set[c]
	}
	return out, nil
}

// An issue whose CVE becomes exploited in the wild after the scan alerts at that moment, once, as a finding whose urgency rises does: the
// exploited-check job finds it. One that was already told, or still is not exploited, sends nothing; an issue of the target's first scan
// (its baseline) alerts too once its CVE becomes exploited, since that is news.
func TestAlerts_AnIssueWhoseCVEBecomesExploitedLaterAlertsOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	ex := &exploitedSet{set: map[string]bool{}}
	e.svc.cfg.Exploited = ex.ask
	withCVEs(e, "CVE-2026-7001") // found by the baseline
	base := Content{Ports: []PortRow{{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}}}
	run := e.scanIP(base).RunID
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, run).Scan(&id); err != nil {
		t.Fatal(err)
	}
	withCVEs(e, "CVE-2026-7001", "CVE-2026-7002") // a later scan finds a second one, nobody exploits it yet
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: base})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		if err := e.svc.RunExploitedCheck(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	check()
	if got := log.all(); len(got) != 0 {
		t.Fatalf("nothing is exploited yet, yet: %+v", got)
	}
	ex.add("CVE-2026-7002") // joins CISA's list
	ex.add("CVE-2026-7001")
	check()
	got := log.all()
	if len(got) != 1 || got[0].Severity != AlertCritical || !strings.Contains(got[0].Text, "CVE-2026-7001") || !strings.Contains(got[0].Text, "CVE-2026-7002") ||
		!strings.Contains(got[0].Text, "now exploited in the wild") {
		t.Fatalf("the alert of the CVEs that became exploited: %+v", got)
	}
	check()
	if n := len(log.all()); n != 1 {
		t.Fatalf("told again: %d alerts", n)
	}
}

// An issue found again (a scan had closed it) and a port that opens again are news of the span they opened again in: counted for the
// daily summary when nobody exploits them; a re-found issue whose CVE is exploited alerts, once per re-open, as a reopened finding does.
func TestAlerts_FoundAgainIsNewsOncePerReopen(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := &alertLog{}
	e.svc.cfg.Alert = log.send
	e.svc.cfg.Exploited = onlyExploited("CVE-2021-41773")
	withCVEs(e, "CVE-2099-0002")
	open := Content{Ports: []PortRow{{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}, {IP: ipA, Port: 3389, Service: "ms-wbt-server", Ident: IdentProbed}}}
	run := e.scanIP(open).RunID
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT target_id FROM exp_scan WHERE run_id = ?`, run).Scan(&id); err != nil {
		t.Fatal(err)
	}
	scan := func(c Content, cves ...string) {
		t.Helper()
		withCVEs(e, cves...)
		e.advance(ScanEvery)
		e.svc.SetRunner(&fakeRunner{content: c})
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	closed := Content{Ports: []PortRow{{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}}}
	scan(closed) // the issue is gone
	// two probes missed 3389: closeVanished closed it (INV-22)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_service SET state = 'closed' WHERE port = 3389`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	from := e.clock.Now().Add(time.Second)
	scan(open, "CVE-2099-0002") // both are back
	issues, ports, err := e.svc.NewSince(e.ctx(), from, e.clock.Now().Add(time.Second))
	if err != nil || issues != 1 || ports != 1 {
		t.Fatalf("found again in the span: %d issues, %d ports, %v; want 1 and 1", issues, ports, err)
	}
	if n := len(log.all()); n != 0 {
		t.Fatalf("news nobody exploits alerted: %d", n)
	}
	for round := 1; round <= 2; round++ { // an exploited issue that goes and comes back alerts each time it comes back
		scan(open, "CVE-2021-41773")
		scan(closed)
		if n := len(log.all()); n != round {
			t.Fatalf("round %d: %d alerts, want %d", round, n, round)
		}
	}
}
