package exposure

import (
	"database/sql"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
)

// replayFile is testdata/scans-anon.json: the scans of an anonymised test network (one public IP of the box, an apex domain and a
// name under it), each with the content its engines handed over, in the order they ran.
type replayFile struct {
	Targets []struct {
		ID, Kind, Value, Origin string
	} `json:"targets"`
	Scans []struct {
		Target    string        `json:"target"`
		StartedAt string        `json:"started_at"`
		Content   replayContent `json:"content"`
	} `json:"scans"`
}

// replayContent is a stored scan's content: Content with the script results, which Content keeps out of its JSON form.
type replayContent struct {
	Content
	Scripts []ScriptRow `json:"scripts"`
}

func (r replayContent) content() Content {
	c := r.Content
	c.Scripts = r.Scripts
	return c
}

func loadReplay(t *testing.T) replayFile {
	t.Helper()
	b, err := os.ReadFile("testdata/scans-anon.json")
	if err != nil {
		t.Fatal(err)
	}
	var f replayFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// replayEnv is an env with the replay's targets stored as they were on the box: proved, so the writer sees them as real targets.
func replayEnv(t *testing.T, f replayFile) *env {
	t.Helper()
	e := newEnv(t)
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		for _, x := range f.Targets {
			token, method, scope := "", "box_egress", any(nil)
			if x.Kind == "domain" {
				token, method, scope = "0123456789abcdef", "dns_txt", "all"
			}
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO exp_target (id, kind, value, origin, scope_mode, method, token, verified_at, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, x.ID, x.Kind, x.Value, x.Origin, scope, method, token, store.FormatTS(t0), store.FormatTS(t0)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// replay writes one scan of target at the time it started, as a finished run would: the rows of the scan (a deep scan in which nuclei
// and ZAP ran; ZAP's pages are the sites of its alerts unless the content names them), the run items of what it checked, then
// OpenVAS's rows when it has results or names the addresses it finished. It returns what the rows said after it.
func (e *env) replay(target, startedAt string, c Content, gbAddrs ...GreenboneAddr) written {
	e.t.Helper()
	at, err := parseTS(startedAt)
	if err != nil {
		e.t.Fatal(err)
	}
	e.clock.mu.Lock()
	e.clock.now = at
	e.clock.mu.Unlock()
	runID := store.NewID("run")
	err = e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, subject_label,
			status, queued_at, started_at, ended_at, updated_at) VALUES (?, 'exposure', ?, ?, 'External scan', 'manual', 'admin@acme.example', 'target', ?, ?, 'done', ?, ?, ?, ?)`,
			runID, RunKind, RunLane, target, target, startedAt, startedAt, startedAt, startedAt); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO exp_scan (run_id, target_id, mode) VALUES (?, ?, 'deep')`, runID, target)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	t, err := loadTarget(e.ctx(), e.db.Reader(), target)
	if err != nil {
		e.t.Fatal(err)
	}
	steps := &stepLog{}
	steps.set(StepNuclei, StepOK, "ran", at)
	steps.set(StepZAP, StepOK, "ran", at)
	gb := c.Greenbone
	c.Greenbone = nil
	if c.WebPages == nil {
		for _, w := range c.WebFindings {
			c.WebPages = append(c.WebPages, w.Site)
		}
	}
	out, err := e.svc.save(e.ctx(), runID, "admin@acme.example", t, ScanMode{Full: true}, c, steps)
	if err != nil {
		e.t.Fatal(err)
	}
	err = e.db.Write(e.ctx(), func(tx *sql.Tx) error { // what execute records through the run (recordCoverage)
		seq := 0
		for ip, class := range out.checked {
			seq++
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO core_run_item (run_id, seq, subject_kind, subject_id, label, outcome) VALUES (?, ?, 'address', ?, ?, ?)`,
				runID, seq, ip, ip, class); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if len(gb) > 0 || len(gbAddrs) > 0 {
		o := gbOutcome{rows: sanitizeGreenbone(gb), state: GBRunDone, addrs: gbAddrs}
		err = e.svc.write(e.ctx(), func(tx *sql.Tx, _ func(string, any)) error {
			return e.svc.writeOpenVAS(e.ctx(), tx, t, runID, at, o, openVASCoverage(t, o, c.Ports))
		})
		if err != nil {
			e.t.Fatal(err)
		}
	}
	return out
}

// serviceState is a service of the replay's IP target, by port.
type serviceState struct{ state, firstSeen, lastSeen string }

func (e *env) serviceStates() map[int]serviceState {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT port, state, first_seen, last_seen FROM exp_service WHERE target_id = 'xt-ip'`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int]serviceState{}
	for rows.Next() {
		var port int
		var s serviceState
		if err := rows.Scan(&port, &s.state, &s.firstSeen, &s.lastSeen); err != nil {
			e.t.Fatal(err)
		}
		out[port] = s
	}
	return out
}

// The stored scans of the test network, replayed in order, write the rows the box should hold: every name, address and service with
// when it was first and last seen, and the issues of each engine; and the invariants of the module hold on what they wrote.
func TestWriter_ReplayOfStoredScansWritesTheRows(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := replayEnv(t, f)
	var ipScans []string
	for _, s := range f.Scans {
		out := e.replay(s.Target, s.StartedAt, s.Content.content())
		if s.Target == "xt-ip" {
			ipScans = append(ipScans, s.StartedAt)
			if len(ipScans) == 2 && (out.counts.NewServices != 4 || out.counts.ClosedServices != 0 || out.counts.Services != 6) {
				t.Fatalf("second scan of the IP: %+v", out.counts)
			}
		}
	}
	// the box's public IP: six services, each first seen by the scan that first found it and last seen by the newest
	got := e.serviceStates()
	if len(got) != 6 {
		t.Fatalf("services of the IP: %+v", got)
	}
	for port, s := range got {
		first := ipScans[1]
		if port == 5060 || port == 10443 {
			first = ipScans[0]
		}
		if s.state != ServiceOpen || s.firstSeen != first || s.lastSeen != ipScans[len(ipScans)-1] {
			t.Errorf("port %d: %+v, want open, first seen %s", port, s, first)
		}
	}
	for _, c := range []struct {
		what  string
		query string
		want  int
	}{
		{"the IP's own address", `SELECT count(*) FROM exp_address WHERE target_id = 'xt-ip' AND host_id IS NULL AND class = 'box'`, 1},
		{"the admin page of the appliance", `SELECT count(*) FROM exp_issue WHERE target_id = 'xt-ip' AND engine = 'surface' AND key >= 'admin_page:' AND key < 'admin_page;' AND state = 'open' AND service_id IS NOT NULL`, 1},
		{"the web alerts", `SELECT count(*) FROM exp_issue WHERE target_id = 'xt-ip' AND engine = 'zap' AND state = 'open'`, 4},
		{"OpenVAS's results", `SELECT count(*) FROM exp_issue WHERE target_id = 'xt-ip' AND engine = 'openvas' AND state = 'open'`, 3},
		{"the names under the apex", `SELECT count(*) FROM exp_host WHERE target_id = 'xt-apex'`, 20},
		{"their addresses", `SELECT count(*) FROM exp_address WHERE target_id = 'xt-apex'`, 27},
		{"the apex's services", `SELECT count(*) FROM exp_service WHERE target_id = 'xt-apex' AND state = 'open'`, 18},
		{"the name under the apex", `SELECT count(*) FROM exp_host WHERE target_id = 'xt-git'`, 1},
		{"its services", `SELECT count(*) FROM exp_service WHERE target_id = 'xt-git' AND state = 'open'`, 9},
		{"issues without a run", `SELECT count(*) FROM exp_issue WHERE last_run_id NOT IN (SELECT run_id FROM exp_scan)`, 0},
	} {
		if n := e.count(c.query); n != c.want {
			t.Errorf("%s: %d, want %d", c.what, n, c.want)
		}
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'nuclei' AND state = 'open'`); n == 0 {
		t.Error("no matched template is an issue")
	}
	for _, inv := range selfcheck.Registered() {
		if inv.Name[:len(ModuleID)] != ModuleID {
			continue
		}
		if n := e.count(inv.Query); n != 0 {
			t.Errorf("invariant %s: %d rows break it", inv.Name, n)
		}
	}
}

// INV-22: a port a scan that probed it no longer finds is missed, not closed; the next scan that probes it and misses it too closes
// it, keeps first_seen of the rest and makes its issues gone. A port seen again after one miss was never closed: no "opened". A port
// that answers again after it was closed is open again with its first first_seen, and the scan names it as opened.
func TestWriter_TwoScansInARowCloseAVanishedPortAndKeepFirstSeen(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := replayEnv(t, f)
	var last Content
	var first string
	for _, s := range f.Scans {
		if s.Target == "xt-ip" {
			e.replay(s.Target, s.StartedAt, s.Content.content())
			last = s.Content.content()
			if first == "" {
				first = s.StartedAt
			}
		}
	}
	before := e.serviceStates()
	without := func(c Content, port int) Content {
		c.Ports = slices.DeleteFunc(slices.Clone(c.Ports), func(p PortRow) bool { return p.Port == port })
		c.Services = slices.DeleteFunc(slices.Clone(c.Services), func(r ServiceRow) bool { return r.Port == port })
		return c
	}
	// one miss: still open, as it was
	out := e.replay("xt-ip", "2026-11-19T02:00:00.000Z", without(last, 11080))
	if out.counts.ClosedServices != 0 || out.counts.Services != 6 || e.serviceStates()[11080] != before[11080] {
		t.Fatalf("one miss: counts %+v, 11080 %+v", out.counts, e.serviceStates()[11080])
	}
	// seen again after one miss: not opened
	out = e.replay("xt-ip", "2026-11-20T02:00:00.000Z", last)
	if len(out.opened) != 0 || out.counts.ClosedServices != 0 {
		t.Fatalf("seen again after one miss: counts %+v, opened %+v", out.counts, out.opened)
	}
	before = e.serviceStates()
	// two misses in a row: closed
	e.replay("xt-ip", "2026-11-21T02:00:00.000Z", without(last, 11080))
	out = e.replay("xt-ip", "2026-11-22T02:00:00.000Z", without(last, 11080))
	if out.counts.ClosedServices != 1 || out.counts.Services != 5 || len(out.opened) != 0 {
		t.Fatalf("two misses: counts %+v, opened %+v", out.counts, out.opened)
	}
	got := e.serviceStates()
	for port, s := range got {
		want := before[port]
		switch {
		case port == 11080 && (s.state != ServiceClosed || s.lastSeen != want.lastSeen || s.firstSeen != want.firstSeen):
			t.Errorf("the vanished port: %+v, was %+v", s, want)
		case port != 11080 && (s.state != ServiceOpen || s.firstSeen != want.firstSeen || s.lastSeen != "2026-11-22T02:00:00.000Z"):
			t.Errorf("port %d: %+v, was %+v", port, s, want)
		}
	}
	if got[10443].firstSeen != first {
		t.Errorf("10443 first seen %s, want %s", got[10443].firstSeen, first)
	}
	out = e.replay("xt-ip", "2026-11-23T02:00:00.000Z", last)
	if out.counts.ClosedServices != 0 || out.counts.Services != 6 || len(out.opened) != 1 || out.opened[0].Port != 11080 {
		t.Fatalf("back again: counts %+v, opened %+v", out.counts, out.opened)
	}
	if s := e.serviceStates()[11080]; s.state != ServiceOpen || s.firstSeen != before[11080].firstSeen {
		t.Fatalf("11080 back again: %+v", s)
	}
}

// A port closed by two misses takes its issues with it: whatever any engine found there is gone, not left open.
func TestWriter_TheIssuesOfAClosedPortAreGone(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := replayEnv(t, f)
	var last Content
	for _, s := range f.Scans {
		if s.Target == "xt-ip" {
			e.replay(s.Target, s.StartedAt, s.Content.content())
			last = s.Content.content()
		}
	}
	on := func(state string) int {
		return e.count(`SELECT count(*) FROM exp_issue i JOIN exp_service s ON s.id = i.service_id WHERE s.port = 10443 AND i.state = ?`, state)
	}
	open := on(IssueOpen)
	if open == 0 {
		t.Fatal("no issue on 10443 to start with")
	}
	without := last
	without.Ports = slices.DeleteFunc(slices.Clone(last.Ports), func(p PortRow) bool { return p.Port == 10443 })
	without.Services = slices.DeleteFunc(slices.Clone(last.Services), func(r ServiceRow) bool { return r.Port == 10443 })
	without.Templates = slices.DeleteFunc(slices.Clone(last.Templates), func(r TemplateRow) bool { return r.Port == 10443 })
	without.WebFindings, without.WebPages, without.Certs, without.Greenbone = nil, []string{}, nil, nil
	e.replay("xt-ip", "2026-11-19T02:00:00.000Z", without)
	if n := on(IssueOpen); n != open {
		t.Fatalf("after one miss: %d issues of 10443 open, want %d", n, open)
	}
	e.replay("xt-ip", "2026-11-20T02:00:00.000Z", without)
	if n := on(IssueOpen); n != 0 {
		t.Fatalf("after the port closed: %d issues of 10443 still open", n)
	}
	if n := on(IssueGone); n != open {
		t.Fatalf("%d issues of 10443 gone, want %d", n, open)
	}
}

// A domain's deep engines reach a few rotated addresses per run: an issue nuclei or OpenVAS no longer reports is gone only on an
// address that engine scanned this run; the issues of an address it did not reach stay open until a run reaches it again.
func TestWriter_DeepEnginesGoneOnlyWhereTheyRan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO exp_target (id, kind, value, origin, scope_mode, method, token, verified_at, created_at)
			VALUES ('xt-d', 'domain', 'example.com', 'person', 'all', 'dns_txt', '0123456789abcdef', ?, ?)`, store.FormatTS(t0), store.FormatTS(t0))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	const a, b = "198.51.100.21", "198.51.100.22"
	content := func(deep ...string) Content {
		host := func(name, ip string) HostRow {
			h := HostRow{Name: name, IP: ip, Source: "dns", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic, Contacted: true}}}
			if slices.Contains(deep, ip) {
				h.IPs[0].Deep = DeepScanned
			} else {
				h.IPs[0].Deep = DeepWaiting
			}
			return h
		}
		return Content{Hosts: []HostRow{host("a.example.com", a), host("b.example.com", b)},
			Ports:    []PortRow{{IP: a, Port: 443, Service: "https"}, {IP: b, Port: 443, Service: "https"}},
			Services: []ServiceRow{{IP: a, Port: 443, Name: "https", Method: "probed"}, {IP: b, Port: 443, Name: "https", Method: "probed"}}}
	}
	first := content(a, b)
	for _, ip := range []string{a, b} {
		first.Templates = append(first.Templates, TemplateRow{IP: ip, Port: 443, Template: "tls-weak", Outcome: OutcomeMatched, Name: "Weak TLS", Severity: "medium"})
		first.Greenbone = append(first.Greenbone, GreenboneRow{IP: ip, Port: "general/tcp", Severity: 5, Name: "OS end of life", OID: "1.3.6.1.4.1.25623.1.0.1", QoD: 80},
			GreenboneRow{IP: ip, Port: "443/tcp", Severity: 7.5, Name: "Weak cipher", OID: "1.3.6.1.4.1.25623.1.0.2", QoD: 80})
	}
	e.replay("xt-d", "2026-11-19T02:00:00.000Z", first, GreenboneAddr{IP: a, State: GBRunDone}, GreenboneAddr{IP: b, State: GBRunDone})
	openOn := func(engine, ip string) int {
		return e.count(`SELECT count(*) FROM exp_issue i LEFT JOIN exp_service s ON s.id = i.service_id
			WHERE i.engine = ? AND i.state = 'open' AND (s.ip = ? OR (i.service_id IS NULL AND i.key LIKE '%@' || ?))`, engine, ip, ip)
	}
	if openOn("nuclei", a) != 1 || openOn("nuclei", b) != 1 || openOn("openvas", a) != 2 || openOn("openvas", b) != 2 {
		t.Fatalf("first run: nuclei %d/%d, openvas %d/%d", openOn("nuclei", a), openOn("nuclei", b), openOn("openvas", a), openOn("openvas", b))
	}
	// the next run's rotation reaches b only, which is clean now
	e.replay("xt-d", "2026-11-20T02:00:00.000Z", content(b), GreenboneAddr{IP: b, State: GBRunDone}, GreenboneAddr{IP: a, State: GBRunNotRun})
	if openOn("nuclei", a) != 1 || openOn("openvas", a) != 2 {
		t.Errorf("a, not reached this run: nuclei %d, openvas %d open, want 1 and 2", openOn("nuclei", a), openOn("openvas", a))
	}
	if openOn("nuclei", b) != 0 || openOn("openvas", b) != 0 {
		t.Errorf("b, scanned and clean: nuclei %d, openvas %d still open", openOn("nuclei", b), openOn("openvas", b))
	}
}

// An engine that ran again and no longer reports an issue makes it gone; an engine that did not run leaves its issues as they were;
// a person's decision stays when the scan reports it again.
func TestWriter_IssuesGoOnlyWhenTheirEngineRanAgain(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := replayEnv(t, f)
	var last Content
	var at string
	for _, s := range f.Scans {
		if s.Target == "xt-ip" {
			e.replay(s.Target, s.StartedAt, s.Content.content())
			last, at = s.Content.content(), s.StartedAt
		}
	}
	zapOpen := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND state = 'open'`)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_issue SET state = 'handled', resolution = 'accepted', resolved_by = 'admin@acme.example', resolved_at = ?
			WHERE id = (SELECT id FROM exp_issue WHERE engine = 'zap' ORDER BY key LIMIT 1)`, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// ZAP ran and found nothing; OpenVAS did not run
	quiet := last
	quiet.WebFindings, quiet.Greenbone = nil, nil
	for _, w := range last.WebFindings { // ZAP scanned the same pages and found nothing
		quiet.WebPages = append(quiet.WebPages, w.Site)
	}
	e.replay("xt-ip", "2026-11-19T02:00:00.000Z", quiet)
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND state = 'gone'`); n != zapOpen-1 {
		t.Errorf("%d zap issues gone, want %d", n, zapOpen-1)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND state = 'handled'`); n != 1 {
		t.Errorf("%d zap issues handled, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'openvas' AND state = 'open'`); n != 3 {
		t.Errorf("%d OpenVAS issues open, want 3 (OpenVAS did not run)", n)
	}
	// reported again: open again, first seen kept
	var firstSeen string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT min(first_seen) FROM exp_issue WHERE engine = 'zap' AND state = 'gone'`).Scan(&firstSeen); err != nil {
		t.Fatal(err)
	}
	out := e.replay("xt-ip", "2026-11-20T02:00:00.000Z", last)
	if len(out.newIssues) != zapOpen-1 {
		t.Errorf("%d issues open again, want %d", len(out.newIssues), zapOpen-1)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND state = 'open' AND first_seen = ?`, firstSeen); n == 0 {
		t.Errorf("the issues open again lost their first seen")
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND state = 'handled'`); n != 1 {
		t.Errorf("the person's decision was undone: %d handled", n)
	}
}
