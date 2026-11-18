package exposure

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedWindow struct {
	mu  sync.Mutex
	w   Window
	err error
}

func (f *fixedWindow) ScanWindow(context.Context) (Window, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w, f.err
}

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

// schedEnv is an env whose queued scans start in place, with a scan window open 09:00 to 17:00 every day (t0 is Monday 10:00 UTC)
// and an alert log.
func schedEnv(t *testing.T) (*env, *fixedWindow, *alertLog) {
	t.Helper()
	e := newEnv(t)
	w := &fixedWindow{w: Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "09:00", To: "17:00"}}
	l := &alertLog{}
	e.svc.cfg.Window, e.svc.cfg.Alert = w, l.send
	e.svc.spawn = func(f func()) { f() }
	return e, w, l
}

// deepDomain is a verified, committed domain whose testing terms are accepted: the schedule may scan it.
func (e *env) termsDomain() TargetView {
	e.t.Helper()
	v := e.committedDomain()
	return e.acceptTerms(v.ID, false)
}

// waitBoxRun waits until the run of the box (if any) has ended.
func (e *env) waitBoxRun() *ScanRun {
	e.t.Helper()
	e.svc.runMu.Lock()
	r := e.svc.run
	e.svc.runMu.Unlock()
	if r == nil {
		return nil
	}
	<-r.done
	v := e.svc.runView(r)
	return &v
}

func (e *env) tick() {
	e.t.Helper()
	if err := e.svc.RunSchedule(e.ctx()); err != nil {
		e.t.Fatal(err)
	}
}

func TestSchedule_Window(t *testing.T) {
	t.Parallel()
	utc := time.UTC
	at := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, utc) } // 9 Nov 2026 is a Monday
	night := Window{Days: []int{1}, From: "22:00", To: "05:00"}                              // Monday night only
	cases := []struct {
		name string
		w    Window
		at   time.Time
		open bool
	}{
		{"before the start", night, at(9, 21, 59), false},
		{"at the start", night, at(9, 22, 0), true},
		{"after midnight it is Monday's window", night, at(10, 4, 59), true},
		{"at the end", night, at(10, 5, 0), false},
		{"Monday morning belongs to Sunday's window", night, at(9, 1, 0), false},
		{"a day window", Window{Days: []int{1, 2, 3, 4, 5}, From: "09:00", To: "17:00"}, at(9, 16, 59), true},
		{"a day window on a Saturday", Window{Days: []int{1, 2, 3, 4, 5}, From: "09:00", To: "17:00"}, at(14, 10, 0), false},
		{"no day", Window{From: "09:00", To: "17:00"}, at(9, 10, 0), false},
		{"a bad time", Window{Days: []int{1}, From: "9", To: "17:00"}, at(9, 10, 0), false},
	}
	for _, c := range cases {
		if got := c.w.open(c.at, utc); got != c.open {
			t.Errorf("%s: open = %v, want %v", c.name, got, c.open)
		}
	}
	if n, ok := night.nextOpen(at(10, 6, 0), utc); !ok || !n.Equal(at(16, 22, 0)) {
		t.Fatalf("next opening after Tuesday 06:00 = %v %v, want next Monday 22:00", n, ok)
	}
	if n, ok := night.nextOpen(at(10, 3, 0), utc); !ok || !n.Equal(at(10, 3, 0)) {
		t.Fatalf("an open window opens now: %v %v", n, ok)
	}
	if _, ok := (Window{From: "09:00", To: "17:00"}).nextOpen(at(9, 6, 0), utc); ok {
		t.Fatal("a window with no day opened")
	}
	month := EveryMonthly.after(time.Date(2026, 1, 31, 10, 0, 0, 0, utc), utc)
	if !month.Equal(time.Date(2026, 2, 28, 10, 0, 0, 0, utc)) { // the last day of February, never early March
		t.Fatalf("monthly = %v", month)
	}
	if m := EveryMonthly.after(time.Date(2026, 12, 31, 10, 0, 0, 0, utc), utc); !m.Equal(time.Date(2027, 1, 31, 10, 0, 0, 0, utc)) {
		t.Fatalf("monthly over the year's end = %v", m)
	}
}

// INV-36: every target starts weekly (also those stored before the schedule: the column's default); a due target with accepted terms
// is scanned by the box inside the window, then not again until a week after that scan started; off scans nothing.
func TestContract_INV36_ScheduledScanRunsWhenDue(t *testing.T) {
	t.Parallel()
	e, _, _ := schedEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.termsDomain()
	if v.Schedule == nil || v.Schedule.Every != EveryWeekly || v.Schedule.Note != nil || str(v.Schedule.NextAt) != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("a new target's schedule = %+v", v.Schedule)
	}
	e.tick()
	got := e.waitBoxRun()
	if got == nil || got.Status != RunDone || !got.Scheduled || got.By != SystemUser || run.calls != 1 || !run.last.Mode.Full {
		t.Fatalf("scheduled run = %+v, runner calls %d, mode %+v", got, run.calls, run.last.Mode)
	}
	v = e.target(v.ID)
	if want := "2026-11-16T10:00:00.000Z"; str(v.Schedule.NextAt) != want {
		t.Fatalf("next = %s, want %s", str(v.Schedule.NextAt), want)
	}
	e.advance(24 * time.Hour)
	e.tick()
	if run.calls != 1 {
		t.Fatal("scanned again before a week had passed")
	}
	e.advance(6 * 24 * time.Hour)
	e.tick()
	if e.waitBoxRun(); run.calls != 2 {
		t.Fatalf("a week later: %d scans, want 2", run.calls)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND user = ? AND detail LIKE '%subdomains%'`, SystemUser); n != 2 {
		t.Fatalf("%d scheduled scans audited as the box, want 2", n)
	}
	if _, err := e.svc.SetSchedule(e.ctx(), "admin@acme.example", v.ID, EveryOff); err != nil {
		t.Fatal(err)
	}
	e.advance(8 * 24 * time.Hour)
	e.tick()
	if v = e.target(v.ID); run.calls != 2 || v.Schedule.Every != EveryOff || v.Schedule.NextAt != nil {
		t.Fatalf("off: %d scans, schedule %+v", run.calls, v.Schedule)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.schedule' AND detail = 'off (was weekly)'`); n != 1 {
		t.Fatalf("%d audit rows of the change", n)
	}
	_, err := e.svc.SetSchedule(e.ctx(), "admin@acme.example", v.ID, Every("hourly"))
	wantAPI(t, err, 400, "bad_value")
}

// INV-36: a scheduled scan needs the testing terms of the current version: without them it is skipped, the target says why, and the
// skip is audited once, not every minute.
func TestContract_INV36_NoScheduledScanWithoutTerms(t *testing.T) {
	t.Parallel()
	e, _, _ := schedEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.committedDomain() // Scan now's commitment only
	e.tick()
	e.advance(time.Minute)
	e.tick()
	v = e.target(v.ID)
	if run.calls != 0 || v.Schedule.NextAt != nil || str(v.Schedule.Note) != "Not scanned on schedule: the testing terms are not accepted" {
		t.Fatalf("%d scans, schedule %+v", run.calls, v.Schedule)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail = 'scheduled scan not done: the testing terms are not accepted'`); n != 1 {
		t.Fatalf("%d audit rows of the skip, want 1", n)
	}
	e.acceptTerms(v.ID, false)
	// terms of an older version: confirming again is needed
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET terms_version = '2020-01-01' WHERE id = ?`, v.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.tick()
	if v = e.target(v.ID); run.calls != 0 || str(v.Schedule.Note) != "Not scanned on schedule: terms need confirming again" {
		t.Fatalf("old terms: %d scans, schedule %+v", run.calls, v.Schedule)
	}
}

// INV-36: nothing scheduled starts outside the scan window; the next time is the window's next opening, and an unreadable window starts
// nothing.
func TestContract_INV36_OnlyInsideTheScanWindow(t *testing.T) {
	t.Parallel()
	e, w, _ := schedEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	w.w = Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00"}
	v := e.termsDomain()
	e.tick()
	if v = e.target(v.ID); run.calls != 0 || str(v.Schedule.NextAt) != "2026-11-09T22:00:00.000Z" || v.Schedule.Note != nil {
		t.Fatalf("outside the window: %d scans, schedule %+v", run.calls, v.Schedule)
	}
	e.advance(12 * time.Hour) // 22:00
	w.mu.Lock()
	w.err = errors.New("the inventory is down")
	w.mu.Unlock()
	e.tick()
	if v = e.target(v.ID); run.calls != 0 || str(v.Schedule.Note) != "Not scanned on schedule: "+notWindowRead {
		t.Fatalf("unreadable window: %d scans, schedule %+v", run.calls, v.Schedule)
	}
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	e.tick()
	if e.waitBoxRun(); run.calls != 1 {
		t.Fatalf("inside the window: %d scans", run.calls)
	}
}

// INV-36: the gate runs again right before a scheduled scan: a TXT record gone skips it, the target says why, and the schedule tries
// again after ScheduleRetry, not every minute.
func TestContract_INV36_GateRefusalWaitsForTheRetry(t *testing.T) {
	t.Parallel()
	e, w, _ := schedEnv(t)
	w.w.From, w.w.To = "00:00", "00:00" // open all day
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.termsDomain()
	e.dns.put("acme.example") // the record is gone
	e.tick()
	v = e.target(v.ID)
	if run.calls != 0 || !strings.HasPrefix(str(v.Schedule.Note), "Not scanned on schedule: ") {
		t.Fatalf("%d scans, schedule %+v", run.calls, v.Schedule)
	}
	lookups := e.dns.lookups()
	e.dns.put("acme.example", txtRecord(v.Token))
	e.advance(time.Hour)
	e.tick()
	if run.calls != 0 || e.dns.lookups() != lookups {
		t.Fatalf("tried again within the retry time: %d scans, %d lookups (was %d)", run.calls, e.dns.lookups(), lookups)
	}
	e.advance(ScheduleRetry)
	e.tick()
	if e.waitBoxRun(); run.calls != 1 {
		t.Fatalf("after the retry time: %d scans", run.calls)
	}
}

// INV-36: one scan at a time: a Scan now of another target while one runs is queued (202 queued with its place), the target reads
// queued, it starts by itself when the first ends, and a queued scan can be taken out of the queue.
func TestContract_INV36_ScanNowWhileBusyIsQueued(t *testing.T) {
	t.Parallel()
	e, _, _ := schedEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	a := scanReady(t, e)
	b := e.detect(ipA)[0]
	if _, err := e.commit(b.ID); err != nil {
		t.Fatal(err)
	}
	op := Actor{Email: "operator@acme.example"}
	first, err := e.svc.StartScan(e.ctx(), op, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	<-r.in
	q, err := e.svc.StartScan(e.ctx(), op, b.ID, "")
	if err != nil || q.Status != RunQueued || q.TargetID != b.ID || len(q.Queue) != 1 || q.Queue[0].TargetID != b.ID {
		t.Fatalf("second scan = %+v %v", q, err)
	}
	again, err := e.svc.StartScan(e.ctx(), op, b.ID, "")
	if err != nil || again.ID != q.ID {
		t.Fatalf("pressing again keeps its place: %+v %v", again, err)
	}
	if _, err := e.svc.StartScan(e.ctx(), op, a.ID, ""); !errors.Is(err, ErrScanBusy) {
		t.Fatalf("the target that runs: %v", err)
	}
	if cur := e.svc.CurrentScan(); cur.ID != first.ID || len(cur.Queue) != 1 || cur.Queue[0].TargetValue != ipA {
		t.Fatalf("current = %+v", cur)
	}
	if v := e.target(b.ID); v.ScanState != "queued" {
		t.Fatalf("queued target state = %s", v.ScanState)
	}
	if err := e.svc.Unqueue(e.ctx(), "operator@acme.example", b.ID); err != nil {
		t.Fatal(err)
	}
	wantAPI(t, e.svc.Unqueue(e.ctx(), "operator@acme.example", b.ID), 409, "not_queued")
	if q, err = e.svc.StartScan(e.ctx(), op, b.ID, ""); err != nil || q.Status != RunQueued {
		t.Fatalf("queued again = %+v %v", q, err)
	}
	e.svc.SetRunner(&fakeRunner{content: sampleContent()}) // the queued scan's runner; a's run keeps its own
	close(r.hold)
	next := e.waitBoxRun()
	for next != nil && next.TargetID != b.ID { // a's run was still the box's run when we looked
		next = e.waitBoxRun()
	}
	if next == nil || next.ID != q.ID || next.Status != RunDone || next.Scheduled {
		t.Fatalf("queued run = %+v", next)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND target = ? AND detail LIKE 'queued:%'`, ipA); n != 3 { // every press is an attempt
		t.Fatalf("%d queued audit rows, want 3", n)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND target = ? AND detail = 'removed from the queue by operator@acme.example'`, ipA); n != 1 {
		t.Fatalf("%d removal rows, want 1", n)
	}
}

// INV-36: after a scheduled scan, what is new since the scan before goes to the alert channels in one message: a new open port, a new
// admin page, a certificate now under 30 days; no change, no message; the first scan of a target is not news.
func TestContract_INV36_ChangesAreAlerted(t *testing.T) {
	t.Parallel()
	e, _, l := schedEnv(t)
	c := sampleContent()
	c.Certs = []CertRow{certAt("acme.example", 62*day)}
	run := &fakeRunner{content: c}
	e.svc.SetRunner(run)
	v := e.termsDomain()
	e.tick()
	e.waitBoxRun()
	if len(l.all()) != 0 {
		t.Fatalf("the first scan sent %+v", l.all())
	}
	e.advance(7 * 24 * time.Hour)
	run.content = sampleContent()
	run.content.Certs = []CertRow{certAt("acme.example", 62*day)}
	e.tick()
	e.waitBoxRun()
	if len(l.all()) != 0 {
		t.Fatalf("no change sent %+v", l.all())
	}
	e.advance(7 * 24 * time.Hour)
	run.content = sampleContent()
	run.content.Ports = append(run.content.Ports, PortRow{IP: ipA, Port: 3389, Service: "ms-wbt-server"})
	run.content.AdminPanels = append(run.content.AdminPanels, AdminRow{URL: "https://acme.example:8443", Product: "Jenkins", IP: ipA, Port: 8443, Risk: "warn"})
	run.content.Certs = []CertRow{certAt("acme.example", 24*day)}
	e.tick()
	e.waitBoxRun()
	got := l.all()
	if len(got) != 1 {
		t.Fatalf("%d alerts, want 1", len(got))
	}
	a := got[0]
	for _, want := range []string{"New open port: " + ipA + ":3389", "Newly exposed admin page: https://acme.example:8443 (Jenkins)", "Certificate of acme.example expires within 30 days"} {
		if !strings.Contains(a.Text, want) {
			t.Errorf("alert lacks %q:\n%s", want, a.Text)
		}
	}
	if a.Severity != AlertHigh || !strings.HasPrefix(a.Title, v.Value) || strings.Contains(a.Text, ":443") {
		t.Fatalf("alert = %+v", a)
	}
}

// versionMatcher lists one exploited CVE on every service of a version it knows.
type versionMatcher map[string]string

func (m versionMatcher) Match(_ context.Context, svcs []ServiceRow) (Matches, error) {
	var out Matches
	for _, x := range svcs {
		if cve, ok := m[x.Product+" "+x.Version]; ok {
			out.Vulns = append(out.Vulns, VulnRow{IP: x.IP, Port: x.Port, CVE: cve, Name: x.Product, Basis: "version"})
		}
	}
	return out, nil
}

// INV-36: an exploited CVE newly matched on a service is critical; one matched before too is not news.
func TestSchedule_NewExploitedCVEIsCritical(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Matcher = versionMatcher{"Exchange 15.1": "CVE-2021-26855", "nginx 1.18": "CVE-2021-23017"}
	prev := Snapshot{StartedAt: "2026-11-02T10:00:00.000Z"}
	prev.Services = []ServiceRow{{IP: ipA, Port: 443, Name: "https", Product: "nginx", Version: "1.18"}}
	now := Snapshot{ID: "sn-2", StartedAt: "2026-11-09T10:00:00.000Z"}
	now.Services = []ServiceRow{{IP: ipA, Port: 443, Name: "https", Product: "nginx", Version: "1.18"}, {IP: ipA, Port: 8443, Name: "https", Product: "Exchange", Version: "15.1"}}
	a, ok := alertOf("acme.example", now.ID, e.svc.changes(e.ctx(), prev, now, t0, false))
	if !ok || a.Severity != AlertCritical || !strings.Contains(a.Text, "Newly matched exploited vulnerability: CVE-2021-26855 on "+ipA+":8443") || strings.Contains(a.Text, "CVE-2021-23017") || a.ID != "exp-sn-2" {
		t.Fatalf("alert = %+v %v", a, ok)
	}
	if _, ok := alertOf("acme.example", "sn-3", e.svc.changes(e.ctx(), now, now, t0, false)); ok {
		t.Fatal("no change sent a message")
	}
}

// INV-36 through the API: the schedule is on every target, PUT sets it (an unknown value is refused by the contract), and a queued
// Scan now answers 202 with status queued and the queue.
func TestHandlers_ScheduleAndQueue(t *testing.T) {
	t.Parallel()
	e0, _, _ := schedEnv(t)
	e := httpOn(e0)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	a := scanReady(t, e.env)
	b := e.detect(ipA)[0]
	if _, err := e.commit(b.ID); err != nil {
		t.Fatal(err)
	}
	code, body := e.call("GET", "/exposure/targets/"+a.ID, "viewer", "")
	sch, _ := body["schedule"].(map[string]any)
	if code != 200 || sch["every"] != "weekly" || sch["next_at"] != nil || sch["note"] != "Not scanned on schedule: the testing terms are not accepted" {
		t.Fatalf("schedule: %d %v", code, body)
	}
	code, body = e.call("PUT", "/exposure/targets/"+a.ID+"/schedule", "admin", `{"every":"monthly"}`)
	if sch, _ = body["schedule"].(map[string]any); code != 200 || sch["every"] != "monthly" {
		t.Fatalf("PUT schedule: %d %v", code, body)
	}
	if code, _ = e.call("PUT", "/exposure/targets/"+a.ID+"/schedule", "admin", `{"every":"hourly"}`); code != 400 {
		t.Fatalf("unknown value: %d", code)
	}
	if code, body = e.call("POST", "/exposure/targets/"+a.ID+"/scan", "operator", ""); code != 202 || body["status"] != "running" {
		t.Fatalf("first scan: %d %v", code, body)
	}
	<-r.in
	code, body = e.call("POST", "/exposure/targets/"+b.ID+"/scan", "operator", "")
	if q := list(body, "queue"); code != 202 || body["status"] != "queued" || len(q) != 1 {
		t.Fatalf("queued scan: %d %v", code, body)
	}
	code, body = e.call("GET", "/exposure/scan", "viewer", "")
	if q := list(body, "queue"); code != 200 || body["target_id"] != a.ID || len(q) != 1 || q[0].(map[string]any)["target_value"] != ipA {
		t.Fatalf("current with its queue: %d %v", code, body)
	}
	if code, body = e.call("GET", "/exposure/targets/"+b.ID, "viewer", ""); body["scan_state"] != "queued" {
		t.Fatalf("queued target: %d %v", code, body)
	}
	if code, _ = e.call("DELETE", "/exposure/targets/"+b.ID+"/queue", "operator", ""); code != 204 {
		t.Fatalf("unqueue: %d", code)
	}
	if code, body = e.call("DELETE", "/exposure/targets/"+b.ID+"/queue", "operator", ""); code != 409 || errCode(body) != "not_queued" {
		t.Fatalf("unqueue again: %d %v", code, body)
	}
	close(r.hold)
	e.waitBoxRun()
}
