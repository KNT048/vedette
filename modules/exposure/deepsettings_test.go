package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// The deep-scan settings of a target: stored in exp_deep_setting, applied at one point (narrow, the end of runMode), honoured by every
// engine core feeds. They only narrow: each group off means no engine runs it, and with every setting on the scan's own rules still
// refuse what they refuse.

// modeAll is the mode of a person's scan of the box's own IP with every group allowed; modeDeepOnly the deep scan with no disruptive group.
var (
	modeAll = ScanMode{Full: true, Disruptive: true, DoS: true, Logins: true, Change: true, WebActive: true, OpenVAS: true}
	// modeDefault is that mode under the default settings: the denial-of-service checks off.
	modeDefault  = ScanMode{Full: true, Disruptive: true, Logins: true, Change: true, WebActive: true, OpenVAS: true, Off: GroupDoS}
	modeDeepOnly = ScanMode{Full: true, WebActive: true, OpenVAS: true}
)

// deepRow writes a target's settings row as given, bypassing the API (the tests of what the scan does with them).
func (e *env) deepRow(id string, dos, logins, web, change, openvas bool, speed, ports, paths string) {
	e.t.Helper()
	e.exec(`INSERT INTO exp_deep_setting (target_id, dos, logins, web_active, data_change, openvas, speed, skip_ports, skip_paths, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '2026-11-01T00:00:00.000Z', 'admin@acme.example')
		ON CONFLICT (target_id) DO UPDATE SET dos = excluded.dos, logins = excluded.logins, web_active = excluded.web_active, data_change = excluded.data_change,
		openvas = excluded.openvas, speed = excluded.speed, skip_ports = excluded.skip_ports, skip_paths = excluded.skip_paths`,
		id, boolInt(dos), boolInt(logins), boolInt(web), boolInt(change), boolInt(openvas), speed, ports, paths)
}

// allGroups turns every group of a target on (the denial-of-service checks too).
func (e *env) allGroups(id string) {
	e.deepRow(id, true, true, true, true, true, SpeedNormal, "[]", "[]")
}

// garble sets columns of a target's settings row past the table's CHECKs (a value the code could never write).
func (e *env) garble(id, set string) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.ctx(), `PRAGMA ignore_check_constraints = ON`); err != nil {
			return err
		}
		defer func() { _, _ = tx.ExecContext(e.ctx(), `PRAGMA ignore_check_constraints = OFF`) }()
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_deep_setting SET `+set+` WHERE target_id = ?`, id) //nolint:gosec // G202: the columns the test garbles, fixed in the test
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

// ---- storage ----

// The migration adds the table to a database shaped like a box's (targets of every kind, their consents, services, issues and scans),
// keeps every row, and every target then reads with the defaults.
func TestDeepSettings_MigrationUpOnABoxShapedDatabase(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateTo(ctx, db, "exposure", Migrations, 1); err != nil {
		t.Fatal(err)
	}
	ts := "2026-11-09T10:00:00.000Z"
	rows := []string{
		`INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, verified_at, created_at, method) VALUES ('d1', 'domain', 'acme.example', 'person', 'all', '0123456789abcdef', '` + ts + `', '` + ts + `', 'dns_txt')`,
		`INSERT INTO exp_target (id, parent_id, kind, value, origin, scope_mode, token, created_at) VALUES ('d2', 'd1', 'domain', 'git.acme.example', 'discovered', 'self', '0123456789abcdef', '` + ts + `')`,
		`INSERT INTO exp_target (id, kind, value, origin, token, verified_at, created_at, method) VALUES ('i1', 'ip', '198.51.100.7', 'box', '', '` + ts + `', '` + ts + `', 'box_egress')`,
		`INSERT INTO exp_target (id, kind, value, origin, token, ip_token, proof_method, verified_at, created_at) VALUES ('i2', 'ip', '203.0.113.9', 'person', '', 'fedcba9876543210', 'ip_file', '` + ts + `', '` + ts + `')`,
		`INSERT INTO exp_consent (target_id, kind, version, text, by_name, at) VALUES ('d1', 'commitment', '2026-11-01', 'sentence', 'admin@acme.example', '` + ts + `')`,
		`INSERT INTO exp_consent (target_id, kind, version, text, by_name, disruptive, at) VALUES ('i1', 'terms', '2026-11-18b', 'terms', 'admin@acme.example', 1, '` + ts + `')`,
		`INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id) VALUES ('s1', 'i1', '198.51.100.7', 443, 'tcp', 'probed', 'open', '` + ts + `', '` + ts + `', 'r1')`,
		`INSERT INTO exp_issue (id, target_id, service_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id) VALUES ('x1', 'i1', 's1', 'zap', 'k', 't', 'high', 'open', '` + ts + `', '` + ts + `', 'r1')`,
	}
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range rows {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "exposure", Migrations); err != nil {
		t.Fatalf("0002 on a box's data: %v", err)
	}
	var n int
	if err := db.Reader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM exp_target) * 100 + (SELECT count(*) FROM exp_consent) * 10 + (SELECT count(*) FROM exp_issue)`).Scan(&n); err != nil || n != 421 {
		t.Fatalf("rows after the migration: %d %v", n, err)
	}
	all, err := listTargets(ctx, db.Reader())
	if err != nil || len(all) != 4 {
		t.Fatalf("targets: %d %v", len(all), err)
	}
	for _, x := range all {
		if x.Deep.DoS || !x.Deep.Logins || !x.Deep.WebActive || !x.Deep.DataChange || !x.Deep.OpenVAS || x.Deep.Speed != SpeedNormal ||
			len(x.Deep.SkipPorts) != 0 || len(x.Deep.SkipPaths) != 0 || x.Deep.UpdatedAt != nil || x.Deep.Problem != nil {
			t.Errorf("%s reads %+v, want the defaults", x.Value, x.Deep)
		}
	}
}

// The table refuses what the settings cannot be, whatever the code does; a row goes with its target.
func TestDeepSettings_TheSchemaHoldsAndARowGoesWithItsTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	ins := func(cols, vals string) error {
		return e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(e.ctx(), `INSERT INTO exp_deep_setting (target_id, updated_at, updated_by`+cols+`) VALUES (?, '2026-11-09T10:00:00.000Z', 'admin@acme.example'`+vals+`)`, id) //nolint:gosec // G202: the columns of each refused row, fixed in the test
			return err
		})
	}
	bad := []struct{ name, cols, vals string }{
		{"a toggle of 2", ", dos", ", 2"},
		{"a toggle as text", ", logins", ", 'yes'"},
		{"an unknown speed", ", speed", ", 'fast'"},
		{"ports that are no JSON", ", skip_ports", ", '22,80'"},
		{"ports that are an object", ", skip_ports", `, '{"22":true}'`},
		{"paths that are a string", ", skip_paths", `, '"/admin"'`},
	}
	for _, b := range bad {
		if err := ins(b.cols, b.vals); err == nil {
			t.Errorf("%s: accepted", b.name)
		}
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO exp_deep_setting (target_id, updated_at, updated_by) VALUES ('nobody', '2026-11-09T10:00:00.000Z', 'a')`)
		return err
	}); err == nil {
		t.Error("a row of no target: accepted")
	}
	if err := ins("", ""); err != nil {
		t.Fatalf("a row of the defaults: %v", err)
	}
	if got := e.loadTarget(id).Deep; got.DoS || !got.Logins || got.Speed != SpeedNormal || got.UpdatedBy == nil || *got.UpdatedBy != "admin@acme.example" {
		t.Fatalf("the row of the defaults reads %+v", got)
	}
	if err := e.svc.Remove(e.ctx(), "admin@acme.example", id, false); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_deep_setting`); n != 0 {
		t.Fatalf("%d settings rows after the target was deleted", n)
	}
}

// A backup is a copy of the database file (VACUUM INTO); a restore puts it back and starts the box, which runs the migrations. The
// settings come back as they were.
func TestDeepSettings_BackupAndRestoreCarryTheTable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	e.deepRow(id, true, false, true, false, true, SpeedGentle, "[22,8443]", `["/admin","/api/reset"]`)
	before := e.loadTarget(id).Deep
	path := filepath.Join(t.TempDir(), "backup.db")
	if err := e.db.SnapshotTo(e.ctx(), path); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(e.ctx(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "exposure", FS: Migrations}} {
		if err := store.Migrate(e.ctx(), restored, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	x, err := loadTarget(e.ctx(), restored.Reader(), id)
	if err != nil {
		t.Fatal(err)
	}
	if settingsWords(x.Deep) != settingsWords(before) || *x.Deep.UpdatedAt != *before.UpdatedAt || *x.Deep.UpdatedBy != *before.UpdatedBy || !x.Deep.DoS || x.Deep.Logins || !slices.Equal(x.Deep.SkipPorts, []int{22, 8443}) ||
		!slices.Equal(x.Deep.SkipPaths, []string{"/admin", "/api/reset"}) || !x.Deep.Gentle() {
		t.Fatalf("restored %+v, before %+v", x.Deep, before)
	}
}

// What the box cannot read narrows: a toggle counts as off, the speed as gentle, and an exclusion list it cannot parse makes the
// scan refuse at its check step with a plain reason; nothing is sent without the person's exclusions.
func TestDeepSettings_GarbledValuesFailClosed(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	*e.terms = true
	ips := e.detect(ipA)
	id := ips[0].ID
	if _, err := e.commit(id); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(id, true)
	garble := func(set string) { t.Helper(); e.garble(id, set) }
	garble(`dos = 'yes', logins = 2, web_active = '', data_change = '1x', openvas = -1, speed = 'fast'`)
	d := e.loadTarget(id).Deep
	if d.DoS || d.Logins || d.WebActive || d.DataChange || d.OpenVAS || !d.Gentle() || d.Problem != nil {
		t.Fatalf("garbled toggles read %+v, want every one off and the speed gentle", d)
	}
	if m, err := e.svc.ModeNow(e.ctx(), "admin@acme.example", id); err != nil || m.Disruptive || m.WebActive || m.OpenVAS || !m.Full {
		t.Fatalf("mode with garbled toggles: %+v %v", m, err)
	}
	for _, lists := range []string{`skip_ports = '[22, "x"]'`, `skip_ports = '[70000]'`, `skip_paths = '["admin"]'`, `skip_paths = '[1]'`, `skip_ports = 'nope'`} {
		e.allGroups(id)
		garble(lists)
		if d := e.loadTarget(id).Deep; d.Problem == nil {
			t.Fatalf("%s reads %+v without a problem", lists, d)
		}
		e.svc.SetRunner(&fakeRunner{content: gbOpen()})
		calls := len(e.svc.cfg.Services.(*fakeServices).calls)
		e.advance(ScanEvery)
		_, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != "settings_unreadable" || !strings.Contains(ae.Message, "cannot be read") {
			t.Fatalf("%s: the scan %v", lists, err)
		}
		if n := len(e.svc.cfg.Services.(*fakeServices).calls); n != calls {
			t.Fatalf("%s: nmap was asked %d times", lists, n-calls)
		}
	}
}

// ---- the groups: each one off, no engine runs it ----

// matrixEnv is a deep scan of the box's own IP with every engine wired: nmap with its disruptive scripts, nuclei, both ZAP passes,
// OpenVAS and the liveness checks.
type matrixEnv struct {
	*env
	gb   *fakeGB
	svc  *disruptiveServices
	web  *activeWeb
	tpl  *matrixTemplates
	live *fakeAlive
	id   string
}

// matrixTemplates is the nuclei seam: it records the target (its mode and exclusions) and the jobs of each call.
type matrixTemplates struct {
	mu      sync.Mutex
	targets []ScanTarget
	jobs    []TemplateJob
}

func (f *matrixTemplates) ScanTemplates(_ context.Context, t ScanTarget, _ netip.Addr, jobs []TemplateJob) (TemplateScan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets, f.jobs = append(f.targets, t), append(f.jobs, jobs...)
	return TemplateScan{}, nil
}

func newMatrixEnv(t *testing.T) *matrixEnv {
	t.Helper()
	e, h := gbEnv(t)
	m := &matrixEnv{env: e, gb: h, tpl: &matrixTemplates{}, live: &fakeAlive{up: func(int, netip.Addr, int) bool { return true }}}
	m.svc = &disruptiveServices{fakeServices: fakeServices{scan: ServiceScan{Ports: 98, Services: []ServiceRow{
		{IP: ipA, Port: 22, Name: "ssh", Product: "OpenSSH", Method: "probed"},
		{IP: ipA, Port: 80, Name: "http", Product: "nginx", Method: "probed"},
		{IP: ipA, Port: 443, Name: "https", Product: "nginx", Method: "probed"}}}}}
	e.svc.cfg.Services, e.svc.cfg.Templates, e.svc.cfg.Liveness, e.svc.cfg.Matcher = m.svc, m.tpl, m.live, &fakeMatcher{}
	m.web = &activeWeb{fakeWeb: &fakeWeb{report: cleanReport}, active: emptyReport}
	wl := &webLog{}
	m.web.log = wl
	e.svc.cfg.Web = m.web
	e.svc.cfg.Probes = stepsProbeLog{gbLog: h.gvm.log, web: wl}
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Requested", "Running", "Done"} })
	ips := e.detect(ipA)
	m.id = ips[0].ID
	if _, err := e.commit(m.id); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(m.id, true)
	return m
}

// matrixOpen is what the runner finds: three web and ssh ports.
func matrixOpen() Content {
	return Content{Ports: []PortRow{{IP: ipA, Port: 22, Service: "ssh"}, {IP: ipA, Port: 80, Service: "http", HTTP: true}, {IP: ipA, Port: 443, Service: "https", HTTP: true}}}
}

// matrixRun is what one scan sent to each engine.
type matrixRun struct {
	r             ScanResult
	nmapDis       [][]int    // the ports of each call of nmap's disruptive scripts
	nmapModes     []ScanMode // the mode of each of those calls
	zapPassive    []string   // the pages of the passive pass
	zapActive     []ScanTarget
	zapActiveURLs []string
	nuclei        []ScanTarget
	nucleiJobs    []TemplateJob
	gbConfig      string // the config of OpenVAS's task, "" when it got none
	alive         [][]int
	steps         map[string]string // step name: status and note
}

func (m *matrixEnv) scan(user string) matrixRun {
	m.t.Helper()
	m.svc.ports, m.svc.modes, m.web.calls, m.web.urls, m.web.asked, m.tpl.targets, m.tpl.jobs, m.live.asked = nil, nil, nil, nil, nil, nil, nil, nil
	m.gb.gvm.with(func(g *fakeGVM) { g.taskConfig = "" })
	m.svc.scripts = nil
	m.SetRunner(&fakeRunner{content: matrixOpen()})
	m.advance(ScanEvery)
	r, err := m.env.svc.Scan(m.ctx(), user, m.id)
	if err != nil {
		m.t.Fatal(err)
	}
	out := matrixRun{r: r, nmapDis: m.svc.ports, nmapModes: m.svc.modes, zapPassive: m.web.asked, zapActive: m.web.calls, zapActiveURLs: m.web.urls, nuclei: m.tpl.targets, nucleiJobs: m.tpl.jobs, alive: m.live.asked, steps: map[string]string{}}
	_, out.gbConfig = m.gb.gvm.cfg("")
	for _, st := range m.runDetail(m.ctx(), r.RunID).Steps {
		out.steps[st.Name] = string(st.Status) + " " + noteOf(st)
	}
	return out
}

// SetRunner is the service's runner, for the matrix's scans.
func (m *matrixEnv) SetRunner(r Runner) { m.env.svc.SetRunner(r) }

// For each group off, no engine runs it: nuclei is told the group is off (its adapter leaves the group's templates out, see
// cmd/vedette), nmap's disruptive scripts do not run unless every disruptive group is on, ZAP's disruptive rules need both the
// denial-of-service and the data-changing groups, ZAP's active pass needs its own, OpenVAS's disruptive config needs every disruptive
// group. The step says "Turned off in this target's settings."
func TestDeepSettings_EachGroupOffNoEngineRunsIt(t *testing.T) {
	t.Parallel()
	type want struct {
		nmapDis, zapDis, zapActive, gbDisruptive bool
		dos, logins, change                      bool // the nuclei target's groups
	}
	rows := []struct {
		name                                string
		dos, logins, web, change, openvas   bool
		want                                want
		nmapStep, activeStep, check, gbStep string // a part of the step's note
	}{
		{name: "every group on", dos: true, logins: true, web: true, change: true, openvas: true,
			want: want{nmapDis: true, zapDis: true, zapActive: true, gbDisruptive: true, dos: true, logins: true, change: true}},
		{name: "the defaults: denial of service off", logins: true, web: true, change: true, openvas: true,
			want: want{nmapDis: true, zapDis: true, zapActive: true, logins: true, change: true}, check: "turned off: denial-of-service checks"},
		{name: "password guessing off", dos: true, web: true, change: true, openvas: true,
			want: want{nmapDis: true, zapDis: true, zapActive: true, dos: true, change: true}, check: "turned off: password guessing and default logins"},
		{name: "data change off", dos: true, logins: true, web: true, openvas: true,
			want: want{nmapDis: true, zapDis: true, zapActive: true, dos: true, logins: true}, check: "exploit checks that may change data"},
		{name: "active web scan off", dos: true, logins: true, change: true, openvas: true,
			want: want{nmapDis: true, gbDisruptive: true, dos: true, logins: true, change: true}, activeStep: NotBySettings, check: "the active web scan"},
		{name: "every disruptive group off", web: true, openvas: true,
			want: want{zapActive: true}, nmapStep: NotBySettings},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			m := newMatrixEnv(t)
			m.deepRow(m.id, row.dos, row.logins, row.web, row.change, row.openvas, SpeedNormal, "[]", "[]")
			got := m.scan("admin@acme.example")
			var g want
			g.nmapDis = len(got.nmapDis) > 0
			for _, nm := range got.nmapModes { // nmap's disruptive scripts get exactly the groups allowed
				if nm.DoS != row.want.dos || nm.Logins != row.want.logins || nm.Change != row.want.change {
					t.Errorf("nmap's disruptive scripts got mode %+v", nm)
				}
			}
			g.zapActive = len(got.zapActive) > 0
			for _, c := range got.zapActive {
				g.zapDis = g.zapDis || c.Mode.Disruptive && c.Mode.WebDisruptive()
				if c.Mode.Disruptive && (c.Mode.DoS != row.want.dos || c.Mode.Change != row.want.change) {
					t.Errorf("a ZAP page got mode %+v", c.Mode)
				}
			}
			wantGB := levelFor(row.want.dos, row.want.logins, row.want.change)
			g.gbDisruptive = got.gbConfig == gbDisruptive.name
			if got.gbConfig != wantGB.name {
				t.Errorf("OpenVAS used %q, want %q (%s)", got.gbConfig, wantGB.name, wantGB.text)
			}
			if got.gbConfig == "" {
				t.Fatalf("OpenVAS did not run: %q", got.steps[stepNameOpenVAS])
			}
			for _, n := range got.nuclei {
				if !n.Mode.Full {
					t.Fatalf("nuclei not deep: %+v", n.Mode)
				}
				g.dos, g.logins, g.change = n.Mode.Disruptive && n.Mode.DoS, n.Mode.Disruptive && n.Mode.Logins, n.Mode.Disruptive && n.Mode.Change
			}
			if len(got.nuclei) == 0 {
				t.Fatal("nuclei was not asked")
			}
			if g != row.want {
				t.Errorf("engines: %+v\nwant     %+v", g, row.want)
			}
			if row.nmapStep != "" && !strings.Contains(got.steps[stepNameDisruptive], row.nmapStep) {
				t.Errorf("nmap's disruptive step: %q", got.steps[stepNameDisruptive])
			}
			if row.activeStep != "" && got.steps[stepNameZAPAct] != "skipped "+row.activeStep {
				t.Errorf("the active web step: %q", got.steps[stepNameZAPAct])
			}
			cfg, _ := m.gb.gvm.cfg(got.gbConfig)
			for _, f := range gmpDisruptiveFamilies {
				on := slices.ContainsFunc(cfg.families, func(x string) bool { return x == f })
				want := f == gmpDoSFamily && row.want.dos || f != gmpDoSFamily && row.want.logins
				if on != want {
					t.Errorf("OpenVAS family %q on = %v, want %v", f, on, want)
				}
			}
			if v := cfg.prefs["safe_checks"]; v != map[bool]string{true: "no", false: "yes"}[row.want.dos && row.want.change] {
				t.Errorf("safe_checks = %q", v)
			}
			narrowed := lineWith(notChecked(got.r), "One OpenVAS option (safe checks) holds both")
			if w := row.want; narrowed != ((w.dos || w.logins || w.change) && (!w.dos || !w.change)) {
				t.Errorf("the safe checks line said: %v; lines %q", narrowed, notChecked(got.r))
			}
			if row.check != "" && !strings.Contains(got.steps[stepNameCheck], row.check) {
				t.Errorf("the check step does not name the settings: %q", got.steps[stepNameCheck])
			}
			var doc string
			if err := m.db.Reader().QueryRowContext(m.ctx(), `SELECT json_extract(summary, '$.settings') FROM exp_scan WHERE run_id = ?`, got.r.RunID).Scan(&doc); err != nil || !strings.Contains(doc, `"speed":"normal"`) {
				t.Errorf("the scan's summary does not record the settings: %q %v", doc, err)
			}
		})
	}
}

// OpenVAS off for the target: the step is skipped with the settings' sentence, whatever the global switch.
func TestDeepSettings_OpenVASOffForTheTarget(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t)
	m.deepRow(m.id, true, true, true, true, false, SpeedNormal, "[]", "[]")
	got := m.scan("admin@acme.example")
	if got.gbConfig != "" || !strings.HasPrefix(got.steps[stepNameOpenVAS], "skipped") || !strings.Contains(got.steps[stepNameOpenVAS], NotBySettings) {
		t.Fatalf("OpenVAS: config %q, step %q", got.gbConfig, got.steps[stepNameOpenVAS])
	}
}

// Gentle speed: OpenVAS's task runs one host and two checks at a time; the normal speed leaves Greenbone's defaults.
func TestDeepSettings_GentleSlowsOpenVAS(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t)
	task := func() string {
		var body string
		m.gb.gvm.with(func(g *fakeGVM) {
			for i, c := range g.cmds {
				if c == "create_task" {
					body = g.bodies[i]
				}
			}
		})
		return body
	}
	m.scan("admin@acme.example")
	if b := task(); b == "" || strings.Contains(b, "max_checks") {
		t.Fatalf("normal speed: %q", b)
	}
	m.deepRow(m.id, true, true, true, true, true, SpeedGentle, "[]", "[]")
	m.scan("admin@acme.example")
	if b := task(); !strings.Contains(b, "<scanner_name>max_checks</scanner_name><value>2</value>") || !strings.Contains(b, "<scanner_name>max_hosts</scanner_name><value>1</value>") {
		t.Fatalf("gentle: %q", b)
	}
}

// With every setting on, the scan's own rules still refuse what they refuse: a scheduled scan, carrier-grade NAT, terms without the
// disruptive checks, no terms at all, a typed IP, and a domain's address that is not the box's own.
func TestDeepSettings_EverySettingOnTheHardRulesStillRefuse(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t) // every group on (acceptTerms with the disruptive checks)
	if got := m.scan(SystemUser); len(got.nmapDis) != 0 || len(got.zapActive) != 0 || got.gbConfig != gbDeep.name {
		t.Fatalf("scheduled: nmap %v, ZAP active %d, OpenVAS %q", got.nmapDis, len(got.zapActive), got.gbConfig)
	}
	gw := &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	m.env.svc.cfg.Gateway = gw
	if got := m.scan("admin@acme.example"); len(got.nmapDis) != 0 || slices.ContainsFunc(got.zapActive, func(s ScanTarget) bool { return s.Mode.Disruptive }) || got.gbConfig != gbDeep.name {
		t.Fatalf("carrier-grade NAT: nmap %v, OpenVAS %q", got.nmapDis, got.gbConfig)
	}
	gw.g = GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}
	m.exec(`UPDATE exp_consent SET version = ?, disruptive = 0 WHERE target_id = ? AND kind = 'terms'`, keptTermsVersions[0], m.id)
	if mode, err := m.env.svc.ModeNow(m.ctx(), "admin@acme.example", m.id); err != nil || mode != modeDeepOnly {
		t.Fatalf("terms without the disruptive checks: %+v %v", mode, err)
	}
	m.exec(`DELETE FROM exp_consent WHERE target_id = ? AND kind = 'terms'`, m.id)
	if mode, err := m.env.svc.ModeNow(m.ctx(), "admin@acme.example", m.id); err != nil || mode.Full || mode.WebActive || mode.OpenVAS {
		t.Fatalf("no terms: %+v %v", mode, err)
	}
	// A typed IP and a domain's address that is not the box's: their deep steps never carry a disruptive group.
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, true)
	st := d.svc.scanTarget(d.ctx(), d.loadTarget(d.dom.ID), "admin@acme.example", modeAll)
	out, line, err := d.svc.deepGate(d.ctx(), st, netip.MustParseAddr(ipB), []string{"www.acme.example"})
	if err != nil || line != "" || out.Mode.Disruptive || out.Mode.DoS || out.Mode.Logins || out.Mode.Change || out.Domain == nil {
		t.Fatalf("a hosting address: %+v %q %v", out.Mode, line, err)
	}
	o := newOMEnv(t, omTyped)
	o.acceptTerms(o.id, true)
	if mode, err := o.svc.ModeNow(o.ctx(), "admin@acme.example", o.id); err != nil || !mode.Full {
		t.Fatalf("typed: %+v %v", mode, err)
	}
	ts := o.svc.scanTarget(o.ctx(), o.loadTarget(o.id), "admin@acme.example", modeAll)
	if ownProvenPage(ts, WebPage{IP: netip.MustParseAddr(ipC)}) {
		t.Fatal("a typed IP's page counts as the box's own")
	}
}

// ---- the exclusions ----

// The ports to skip reach every engine core feeds: nuclei's jobs, ZAP's pages (both passes), nmap's disruptive scripts, OpenVAS's port
// list and the liveness checks. A skipped port is not observed: its stored row is neither closed nor confirmed, its issues stay.
func TestDeepSettings_SkipPortsReachEveryEngine(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t)
	before := m.scan("admin@acme.example") // every port, stored open
	if len(before.nmapDis) == 0 || !slices.Contains(before.nmapDis[0], 443) {
		t.Fatalf("the first scan: %v", before.nmapDis)
	}
	issue := m.addIssue(m.id, "zap-443", "high")
	m.exec(`UPDATE exp_issue SET service_id = (SELECT id FROM exp_service WHERE port = 443), engine = 'zap', key = '40012@https://8.8.8.8:443' WHERE id = ?`, issue)
	m.deepRow(m.id, true, true, true, true, true, SpeedNormal, "[443]", "[]")
	got := m.scan("admin@acme.example") // the runner and nmap's sweep still report 443: core leaves it out
	for _, j := range got.nucleiJobs {
		if j.Port == 443 {
			t.Errorf("nuclei got a job on 443: %+v", j)
		}
	}
	for _, n := range got.nuclei {
		if !slices.Contains(n.SkipPorts, 443) {
			t.Errorf("nuclei's target does not carry the skipped ports: %v", n.SkipPorts)
		}
	}
	for _, u := range append(slices.Clone(got.zapPassive), got.zapActiveURLs...) {
		if strings.Contains(u, ":443") || strings.HasPrefix(u, "https://") {
			t.Errorf("ZAP got a page on 443: %s", u)
		}
	}
	for _, ps := range got.nmapDis {
		if slices.Contains(ps, 443) {
			t.Errorf("nmap's disruptive scripts got 443: %v", ps)
		}
	}
	for _, ps := range got.alive {
		if slices.Contains(ps, 443) {
			t.Errorf("the liveness check asked 443: %v", ps)
		}
	}
	var ports string
	m.gb.gvm.with(func(g *fakeGVM) { ports = g.portRange })
	if strings.Contains(ports, "443") || ports == "" {
		t.Errorf("OpenVAS's port list: %q", ports)
	}
	if st := m.svcState(443); st != ServiceOpen {
		t.Errorf("the skipped port's row is %q, want it left open as it was", st)
	}
	if st, _, _, _, _ := m.issueRow(issue); st != IssueOpen {
		t.Errorf("an issue of the skipped port is %q", st)
	}
	if !strings.Contains(got.steps[stepNameCheck], "ports skipped: 443") {
		t.Errorf("the check step: %q", got.steps[stepNameCheck])
	}
}

// Web paths to skip: ZAP's runs leave them out only through a scanner that says it can (PathExcluder); without one, no ZAP run goes
// to the target and the step says why. With one, both passes run.
func TestDeepSettings_WebPathsNeedAZAPThatKeepsThemOut(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t)
	m.deepRow(m.id, true, true, true, true, true, SpeedNormal, "[]", `["/admin"]`)
	got := m.scan("admin@acme.example")
	if len(got.zapPassive) != 0 || len(got.zapActive) != 0 {
		t.Fatalf("ZAP ran with paths to skip it cannot keep out: passive %v, active %d", got.zapPassive, len(got.zapActive))
	}
	if !lineWith(notChecked(got.r), notWebPaths) || !strings.Contains(got.steps[stepNameZAPAct], NotBySettings) {
		t.Fatalf("lines %q, active step %q", notChecked(got.r), got.steps[stepNameZAPAct])
	}
	m.env.svc.cfg.Web = pathWeb{m.web}
	got = m.scan("admin@acme.example")
	if len(got.zapPassive) == 0 || len(got.zapActive) == 0 || !slices.Equal(got.zapActive[0].SkipPaths, []string{"/admin"}) {
		t.Fatalf("with a scanner that keeps paths out: passive %v, active %+v", got.zapPassive, got.zapActive)
	}
}

// pathWeb is a web scanner that leaves the paths to skip out.
type pathWeb struct{ *activeWeb }

func (pathWeb) ExcludesPaths() bool { return true }

// A domain's address that is also an IP target of the box takes both targets' settings: the groups either turns off, and the ports
// either skips.
func TestDeepSettings_ADomainOnTheBoxIPTakesBothTargetsSettings(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.acceptTerms(d.dom.ID, true)
	box := d.loadTarget(d.idOfIP(ipA))
	d.deepRow(box.ID, false, true, false, true, true, SpeedGentle, "[8443]", `["/admin"]`)
	st := d.svc.scanTarget(d.ctx(), d.loadTarget(d.dom.ID), "admin@acme.example", modeAll)
	out, line, err := d.svc.deepGate(d.ctx(), st, netip.MustParseAddr(ipA), []string{"acme.example"})
	if err != nil || line != "" {
		t.Fatalf("the box's address: %q %v", line, err)
	}
	if out.Mode.DoS || out.Mode.WebActive || !out.Mode.Logins || !out.Mode.Change || !slices.Equal(out.SkipPorts, []int{8443}) ||
		!slices.Equal(out.SkipPaths, []string{"/admin"}) || !out.Gentle {
		t.Fatalf("the step: mode %+v, ports %v, paths %v, gentle %v", out.Mode, out.SkipPorts, out.SkipPaths, out.Gentle)
	}
	d.garble(box.ID, `skip_ports = 'x'`)
	if _, line, err := d.svc.deepGate(d.ctx(), st, netip.MustParseAddr(ipA), []string{"acme.example"}); err == nil && line != deepSettingsUnread {
		t.Fatalf("unreadable settings of the address's target: %q %v", line, err)
	}
}

// No row: a person's scan of the box's own IP runs every disruptive group but the denial-of-service checks, and the check step says so.
func TestDeepSettings_TheDefaultsLeaveOutTheDenialOfServiceChecks(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t)
	m.exec(`DELETE FROM exp_deep_setting WHERE target_id = ?`, m.id)
	mode, err := m.env.svc.ModeNow(m.ctx(), "admin@acme.example", m.id)
	if err != nil || mode.DoS || !mode.Logins || !mode.Change || !mode.Disruptive || mode.Off != GroupDoS {
		t.Fatalf("the defaults: %+v %v", mode, err)
	}
	got := m.scan("admin@acme.example")
	if !strings.Contains(got.steps[stepNameCheck], "This target's settings: turned off: denial-of-service checks.") {
		t.Fatalf("the check step: %q", got.steps[stepNameCheck])
	}
}

// ---- the API ----

// PUT /exposure/tree/{id}/deep-settings: an administrator's, checked, with two-step sign-in to turn the denial-of-service checks on,
// and audited with the settings before and after. The node shows them.
func TestDeepSettings_PutChecksAndAudits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	admin := Actor{ID: "u-admin", Email: "admin@acme.example", Admin: true}
	ok := DeepSettingsEdit{Logins: true, WebActive: true, DataChange: true, OpenVAS: true, Speed: SpeedNormal}
	if err := e.svc.PutDeepSettings(e.ctx(), Actor{ID: "u-op", Email: "op@acme.example"}, id, ok); !isCode(err, "forbidden") {
		t.Fatalf("an operator: %v", err)
	}
	bad := map[string]DeepSettingsEdit{}
	add := func(name string, f func(*DeepSettingsEdit)) {
		x := ok
		f(&x)
		bad[name] = x
	}
	add("speed", func(x *DeepSettingsEdit) { x.Speed = "fast" })
	add("port 0", func(x *DeepSettingsEdit) { x.SkipPorts = []int{0} })
	add("port 65536", func(x *DeepSettingsEdit) { x.SkipPorts = []int{65536} })
	add("65 ports", func(x *DeepSettingsEdit) {
		for p := 1; p <= 65; p++ {
			x.SkipPorts = append(x.SkipPorts, p)
		}
	})
	add("a path without /", func(x *DeepSettingsEdit) { x.SkipPaths = []string{"admin"} })
	add("a pattern", func(x *DeepSettingsEdit) { x.SkipPaths = []string{"/admin/.*"} })
	add("a query", func(x *DeepSettingsEdit) { x.SkipPaths = []string{"/a?b=1"} })
	add("a control character", func(x *DeepSettingsEdit) { x.SkipPaths = []string{"/a\nb"} })
	add("a space", func(x *DeepSettingsEdit) { x.SkipPaths = []string{"/a b"} })
	add("21 paths", func(x *DeepSettingsEdit) {
		for i := range 21 {
			x.SkipPaths = append(x.SkipPaths, fmt.Sprintf("/p%d", i))
		}
	})
	add("a long path", func(x *DeepSettingsEdit) { x.SkipPaths = []string{"/" + strings.Repeat("a", 200)} })
	for name, x := range bad {
		if err := e.svc.PutDeepSettings(e.ctx(), admin, id, x); !isCode(err, "invalid_settings") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := e.count(`SELECT count(*) FROM exp_deep_setting`); n != 0 {
		t.Fatalf("a refused change stored %d rows", n)
	}
	on := ok
	on.DoS = true
	if err := e.svc.PutDeepSettings(e.ctx(), admin, id, on); !isCode(err, "twofa_required") {
		t.Fatalf("denial of service on without two-step: %v", err)
	}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "", nil }
	if err := e.svc.PutDeepSettings(e.ctx(), admin, id, on); !isCode(err, "twofa_required") {
		t.Fatalf("denial of service on by an admin without two-step: %v", err)
	}
	narrower := ok
	narrower.Logins, narrower.Speed, narrower.SkipPorts, narrower.SkipPaths = false, SpeedGentle, []int{8443, 22, 22}, []string{"/admin", "/api/v1/reset"}
	if err := e.svc.PutDeepSettings(e.ctx(), admin, id, narrower); err != nil {
		t.Fatalf("a narrower change needs no two-step: %v", err)
	}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	if err := e.svc.PutDeepSettings(e.ctx(), admin, id, on); err != nil {
		t.Fatalf("denial of service on with two-step: %v", err)
	}
	details := e.auditDetails("exposure.deep_settings")
	if len(details) != 2 || !strings.Contains(details[0], "before: denial of service off, logins on") || !strings.Contains(details[0], "after: denial of service off, logins off") ||
		!strings.Contains(details[0], "ports skipped [22 8443]") || !strings.Contains(details[1], "after: denial of service on") || !strings.Contains(details[1], "two-step sign-in: app") {
		t.Fatalf("audit: %q", details)
	}
	n := e.node(id)
	if !n.DeepSettings.DoS || !n.DeepSettings.Logins || n.DeepSettings.UpdatedBy == nil || len(n.DeepSettings.SkipPorts) != 0 {
		t.Fatalf("the node's settings: %+v", n.DeepSettings)
	}
	if err := e.svc.PutDeepSettings(e.ctx(), admin, "nobody", ok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no such target: %v", err)
	}
}

func isCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// The settings are a pure narrowing: narrow never sets a bit its input does not have, for every combination.
func TestDeepSettings_NarrowOnlyClears(t *testing.T) {
	t.Parallel()
	for in := range 1 << 7 {
		m := ScanMode{Full: in&1 != 0, Disruptive: in&2 != 0, DoS: in&4 != 0, Logins: in&8 != 0, Change: in&16 != 0, WebActive: in&32 != 0, OpenVAS: in&64 != 0}
		for s := range 1 << 5 {
			d := DeepSettings{DoS: s&1 != 0, Logins: s&2 != 0, DataChange: s&4 != 0, WebActive: s&8 != 0, OpenVAS: s&16 != 0}
			n := narrow(m, d)
			if n.Full && !m.Full || n.Disruptive && !m.Disruptive || n.DoS && (!m.DoS || !d.DoS) || n.Logins && (!m.Logins || !d.Logins) ||
				n.Change && (!m.Change || !d.DataChange) || n.WebActive && (!m.WebActive || !d.WebActive) || n.OpenVAS && (!m.OpenVAS || !d.OpenVAS) {
				t.Fatalf("narrow(%+v, %+v) = %+v", m, d, n)
			}
			if n.Disruptive != (n.DoS || n.Logins || n.Change) {
				t.Fatalf("narrow(%+v, %+v) = %+v: Disruptive is not the groups'", m, d, n)
			}
		}
	}
}

// A domain's deep scan of the box's own IP that is an IP target too: the ports that target's settings skip are not observed there,
// so the re-check of the ports open before never connects to them either.
func TestDeepSettings_TheReCheckLeavesOutTheAddressTargetsSkippedPorts(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.acceptTerms(d.dom.ID, true)
	pr := &probeRecorder{}
	d.svc.cfg.Liveness = pr
	d.scan() // 443 of the box's address is stored open for the domain
	d.deepRow(d.idOfIP(ipA), false, true, true, true, true, SpeedNormal, "[443]", "[]")
	pr.mu.Lock()
	pr.asked = nil
	pr.mu.Unlock()
	d.advance(ScanEvery + time.Minute)
	d.scan()
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if slices.Contains(pr.asked[ipA], 443) {
		t.Fatalf("the re-check connected to a port the address's IP target skips: %v", pr.asked)
	}
}

// A domain's page on an address that is an IP target with web paths to skip: the active web scan of that page runs only through a
// web scanner that leaves the paths out, like the IP target's own scan; without one the page is not attacked and the scan says why.
func TestDeepSettings_ADomainPageOnAnIPTargetWithPathsToSkipGetsNoActiveScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(emptyReport)
	box := e.committedIP(ipA)
	e.deepRow(box.ID, false, true, true, true, true, SpeedNormal, "[]", `["/admin"]`)
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, true)
	e.svc.SetRunner(&fakeRunner{content: Content{
		Hosts: []HostRow{{Name: "acme.example", IP: ipA}, {Name: "www.acme.example", IP: ipA}},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}},
	}})
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != 0 {
		t.Fatalf("ZAP attacked %q although the address's IP target has paths to skip it cannot keep out", w.urls)
	}
	if !lineWith(notChecked(s), notWebPaths) {
		t.Fatalf("not checked: %q", notChecked(s))
	}
}

// A group turned on while a scan runs never widens it: the run started with the defaults (denial of service off), the settings
// are saved with every group on during its active web scan, and the later pages, OpenVAS and nmap's disruptive step keep the run's
// narrower mode.
func TestDeepSettings_AGroupTurnedOnMidRunNeverWidensIt(t *testing.T) {
	t.Parallel()
	m := newMatrixEnv(t)
	m.deepRow(m.id, false, true, true, true, true, SpeedNormal, "[]", "[]")
	m.web.hook = func() { m.deepRow(m.id, true, true, true, true, true, SpeedNormal, "[]", "[]") }
	got := m.scan("admin@acme.example")
	if len(got.zapActive) < 2 || !m.loadTarget(m.id).Deep.DoS {
		t.Fatalf("ZAP active pages: %d; settings now %+v", len(got.zapActive), m.loadTarget(m.id).Deep)
	}
	for _, c := range got.zapActive {
		if c.Mode.DoS {
			t.Errorf("a ZAP page got the denial-of-service group turned on mid-run: %+v", c.Mode)
		}
	}
	if want := levelFor(false, true, true).name; got.gbConfig != want {
		t.Errorf("OpenVAS used %q, want %q", got.gbConfig, want)
	}
	for _, nm := range got.nmapModes {
		if nm.DoS {
			t.Errorf("nmap's disruptive scripts got the denial-of-service group turned on mid-run: %+v", nm)
		}
	}
}

// A domain's passive web scan of a page on an address that is an IP target with web paths to skip: the scanner is asked with the paths
// of both targets, as the active scan is, and a scanner that cannot leave paths out is not asked at all.
func TestDeepSettings_ADomainPassivePageOnAnIPTargetSkipsThatTargetsPathsToo(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(emptyReport)
	e.svc.cfg.Web = pathWeb{w}
	box := e.committedIP(ipA)
	e.deepRow(box.ID, false, true, true, true, true, SpeedNormal, "[]", `["/admin"]`)
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, true) // the terms write the target's settings row
	e.deepRow(dom.ID, false, true, true, true, true, SpeedNormal, "[]", `["/private"]`)
	e.svc.SetRunner(&fakeRunner{content: Content{
		Hosts: []HostRow{{Name: "acme.example", IP: ipA}},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", HTTP: true}},
	}})
	w.targets = nil // the calls of the setup are not the scan's
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID); err != nil {
		t.Fatal(err)
	}
	if len(w.targets) == 0 {
		t.Fatal("the passive scan did not run")
	}
	for i, st := range w.targets {
		if !slices.Contains(st.SkipPaths, "/admin") || !slices.Contains(st.SkipPaths, "/private") {
			t.Errorf("passive call %d (%s %s) got the paths %v, want both targets' paths", i, st.Kind, st.Value, st.SkipPaths)
		}
	}
}
