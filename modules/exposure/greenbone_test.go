package exposure

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const gbReportID = "5f2c5a6e-1b7d-4c1e-9a55-0c0f1f2e3d4a"

func gbFixture(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile("testdata/greenbone-report.xml")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func readReport(raw string) ([]GreenboneRow, int, error) {
	r := &gmpReport{}
	if _, err := decodeGMP(&capReader{r: strings.NewReader(raw), n: gmpMaxReport}, "get_reports", r); err != nil {
		return nil, 0, err
	}
	return parseGMPReport(r, gbReportID, ipA)
}

// ---- a fake gvmd: answers GMP commands over a net.Pipe ----

type fakeGVM struct {
	mu         sync.Mutex
	cmds       []string // command names in the order they came
	authFail   bool
	syncing    bool     // get_feeds reports a feed that is still loading
	noFAF      bool     // "Full and fast" is not there yet (404)
	states     []string // get_tasks answers in turn; the last repeats
	report     string   // the get_reports answer
	hasConfig  bool     // Vedette's config exists already
	families   []string // families sent in the last family_selection
	logAtStart int      // probe rows in the log when start_task came
	log        *gbLog
}

// with changes the fake under its lock (the session goroutines read it).
func (f *fakeGVM) with(fn func(*fakeGVM)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }

func (f *fakeGVM) seen(cmd string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.cmds, cmd)
}

func (f *fakeGVM) answer(cmd string, body string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	ok := func(inner string) string {
		return "<" + cmd + `_response status="200" status_text="OK">` + inner + "</" + cmd + "_response>"
	}
	switch cmd {
	case "authenticate":
		if f.authFail {
			return `<authenticate_response status="400" status_text="Authentication failed"/>`
		}
		return ok("<role>Admin</role>")
	case "get_feeds":
		sync := ""
		if f.syncing {
			sync = "<currently_syncing><timestamp>x</timestamp></currently_syncing>"
		}
		return ok("<feed><type>NVT</type><name>Greenbone Community Feed</name>" + sync + "</feed><feed><type>SCAP</type></feed>")
	case "get_configs":
		switch {
		case strings.Contains(body, "filter="):
			if f.hasConfig {
				return ok(`<config id="11111111-2222-4333-8444-555555555555"><name>` + GreenboneConfigName + `</name></config>`)
			}
			return ok("")
		case f.noFAF:
			return `<get_configs_response status="404" status_text="Failed to find config"/>`
		}
		return ok(`<config id="` + gmpFullAndFast + `"><name>Full and fast</name><families><family><name>General</name></family><family><name>Brute force attacks</name></family>` +
			`<family><name>Default Accounts</name></family><family><name>Denial of Service</name></family><family><name>Web application abuses</name></family></families></config>`)
	case "create_config":
		f.hasConfig = true
		return `<create_config_response status="201" status_text="OK, resource created" id="11111111-2222-4333-8444-555555555555"/>`
	case "modify_config":
		if strings.Contains(body, "family_selection") {
			f.families = nil
			for _, part := range strings.Split(body, "<family><name>")[1:] {
				f.families = append(f.families, part[:strings.Index(part, "<")])
			}
		}
		return ok("")
	case "get_port_lists":
		return ok(`<port_list id="` + gmpIANATCP + `"><name>All IANA assigned TCP</name></port_list>`)
	case "create_target":
		return `<create_target_response status="201" status_text="OK, resource created" id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"/>`
	case "create_task":
		return `<create_task_response status="201" status_text="OK, resource created" id="bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"/>`
	case "start_task":
		if f.log != nil {
			f.logAtStart = len(f.log.rows)
		}
		return `<start_task_response status="202" status_text="OK, request submitted"><report_id>` + gbReportID + `</report_id></start_task_response>`
	case "get_tasks":
		st := "Done"
		if len(f.states) > 0 {
			st = f.states[0]
			if len(f.states) > 1 {
				f.states = f.states[1:]
			}
		}
		return ok(`<task id="bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"><name>x</name><status>` + st + `</status><progress>50</progress></task>`)
	case "get_reports":
		return f.report
	}
	return ok("")
}

// serve reads commands from conn and answers each one; it ends when the client closes the connection.
func (f *fakeGVM) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	dec := xml.NewDecoder(conn)
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var raw struct {
			Inner string `xml:",innerxml"`
		}
		if err := dec.DecodeElement(&raw, &se); err != nil {
			return
		}
		attrs := ""
		for _, a := range se.Attr {
			attrs += " " + a.Name.Local + "=" + a.Value
		}
		if _, err := io.WriteString(conn, f.answer(se.Name.Local, attrs+raw.Inner)); err != nil {
			return
		}
	}
}

// fakeGB is the host side: Up and Down are counted, Dial hands out a pipe to the fake gvmd.
type fakeGB struct {
	mu      sync.Mutex
	gvm     *fakeGVM
	ups     int
	downs   int
	dials   int
	upErr   error
	downErr error
	dialErr error
	upGate  chan struct{} // when set, Up waits for it
}

func (h *fakeGB) Up(ctx context.Context) error {
	h.mu.Lock()
	h.ups++
	gate, err := h.upGate, h.upErr
	h.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (h *fakeGB) Down(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.downs++
	return h.downErr
}

func (h *fakeGB) Dial(context.Context) (net.Conn, GMPLogin, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dials++
	if h.dialErr != nil {
		return nil, GMPLogin{}, h.dialErr
	}
	client, server := net.Pipe()
	go h.gvm.serve(server)
	return client, GMPLogin{User: "vedette", Password: "s3cret<&>"}, nil
}

func (h *fakeGB) with(fn func(*fakeGB)) { h.mu.Lock(); defer h.mu.Unlock(); fn(h) }

func (h *fakeGB) dialCount() int { h.mu.Lock(); defer h.mu.Unlock(); return h.dials }

// gbLog is the probe log of Config.Probes with the Greenbone face.
type gbLog struct {
	rows []GreenboneProbe
	err  error
}

func (l *gbLog) RecordTemplateProbes(context.Context, []TemplateProbe) error { return l.err }
func (l *gbLog) RecordGreenboneProbe(_ context.Context, p GreenboneProbe) error {
	if l.err != nil {
		return l.err
	}
	l.rows = append(l.rows, p)
	return nil
}

const gib = 1 << 30

// gbEnv is an env with Greenbone wired: 16 GiB of memory, 200 GB free, a ready gvmd with the fixture report, a probe log, and no
// waiting between polls.
func gbEnv(t *testing.T) (*env, *fakeGB) {
	t.Helper()
	e := newEnv(t)
	gvm := &fakeGVM{report: gbFixture(t)}
	h := &fakeGB{gvm: gvm}
	l := &gbLog{}
	gvm.log = l
	e.svc.cfg.Greenbone, e.svc.cfg.Probes, e.svc.cfg.DataDir = h, l, "/data"
	g := e.svc.gb()
	g.memTotal = func() (int64, error) { return 16 * gib, nil }
	g.diskFree = func(string) (int64, error) { return 200e9, nil }
	g.poll = 0
	return e, h
}

// enable turns Greenbone on as an administrator and waits for its start.
func (e *env) enable() GreenboneView {
	e.t.Helper()
	v, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", true)
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc.gb().upWG.Wait()
	return v
}

func (e *env) gbState() GreenboneView {
	e.t.Helper()
	e.advance(gbProbeEvery) // past the cache
	v, err := e.svc.GreenboneSetting(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

// ---- the report parser ----

// INV-25: a report of the real shape gives one row per result of the scanned address with QoD >= 70: another host and a low QoD are
// dropped, text is plain (markup removed), CVE ids are checked and without repeats, and "general/tcp" is a port of no number.
func TestContract_INV25_ParsesTheReport(t *testing.T) {
	t.Parallel()
	rows, total, err := readReport(gbFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 || len(rows) != 4 {
		t.Fatalf("total %d, rows = %+v", total, rows)
	}
	terrapin := rows[1]
	if terrapin.Name != "SSH Transport Protocol Prefix Truncation Attack (Terrapin Attack)" || terrapin.Port != "22/tcp" || terrapin.QoD != 70 || terrapin.Severity != 5.9 ||
		!slices.Equal(terrapin.CVEs, []string{"CVE-2023-48795"}) || strings.ContainsAny(terrapin.Solution, "<>") || terrapin.OID != "1.3.6.1.4.1.25623.1.0.151396" {
		t.Fatalf("terrapin = %+v", terrapin)
	}
	if !slices.Equal(rows[2].CVEs, []string{"CVE-2021-41773", "CVE-2021-42013"}) || greenbonePort(rows[2].Port) != 443 {
		t.Fatalf("apache = %+v", rows[2])
	}
	if rows[3].Port != "general/tcp" || greenbonePort(rows[3].Port) != 0 || len(rows[3].CVEs) != 0 {
		t.Fatalf("timestamps = %+v", rows[3])
	}
}

// INV-25: an answer that cannot be trusted is refused, never read as "nothing found".
func TestContract_INV25_HostileAnswersAreRefused(t *testing.T) {
	t.Parallel()
	wrap := func(results string) string {
		return `<get_reports_response status="200"><report id="` + gbReportID + `"><report id="` + gbReportID + `"><results>` + results + `</results></report></report></get_reports_response>`
	}
	res := func(sev, qod string) string {
		return `<result><name>x</name><host>8.8.8.8</host><port>80/tcp</port><nvt oid="1.2.3"><name>x</name></nvt><severity>` + sev + `</severity><qod><value>` + qod + `</value></qod></result>`
	}
	tests := []struct{ name, raw string }{
		{"empty", ``},
		{"not xml", `HTTP/1.1 502 Bad Gateway`},
		{"another command's answer", `<get_tasks_response status="200"/>`},
		{"an error status", `<get_reports_response status="400" status_text="Bogus"/>`},
		{"no status", `<get_reports_response/>`},
		{"no report", `<get_reports_response status="200"></get_reports_response>`},
		{"two reports", `<get_reports_response status="200"><report id="` + gbReportID + `"><report id="x"><results/></report></report><report id="` + gbReportID + `"/></get_reports_response>`},
		{"another report", strings.ReplaceAll(wrap(""), gbReportID, "00000000-0000-4000-8000-000000000000")},
		{"no results list", `<get_reports_response status="200"><report id="` + gbReportID + `"><report id="x"/></report></get_reports_response>`},
		{"severity is a word", wrap(res("High", "80"))},
		{"severity out of range", wrap(res("11", "80"))},
		{"severity missing", wrap(`<result><name>x</name><host>8.8.8.8</host><qod><value>80</value></qod></result>`)},
		{"qod is a word", wrap(res("5.0", "good"))},
		{"qod out of range", wrap(res("5.0", "101"))},
		{"no name", wrap(`<result><host>8.8.8.8</host><nvt oid="1.2"/><severity>5.0</severity><qod><value>80</value></qod></result>`)},
		{"too many results", wrap(strings.Repeat(res("5.0", "80"), gmpMaxResults+1))},
		{"unclosed", wrap(res("5.0", "80"))[:200]},
		{"entity bomb", `<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]><get_reports_response status="200">&b;</get_reports_response>`},
		{"over the size cap", `<get_reports_response status="200"><x>` + strings.Repeat("a", gmpMaxReport) + `</x></get_reports_response>`},
		{"latin-1", `<?xml version="1.0" encoding="ISO-8859-1"?><get_reports_response status="200"/>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rows, _, err := readReport(tc.raw)
			if err == nil {
				t.Fatalf("read as %+v", rows)
			}
			if !errors.Is(err, ErrGMPBad) && !strings.Contains(tc.name, "error status") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// a clean scan is a report of zero rows, not an error
	if rows, _, err := readReport(wrap("")); err != nil || len(rows) != 0 {
		t.Fatalf("clean = %+v, %v", rows, err)
	}
	// an id that is not a UUID never goes into the next command
	if _, err := gmpID(`x"/><delete_task`, "task"); !errors.Is(err, ErrGMPBad) {
		t.Fatal("a hostile id was accepted")
	}
}

func FuzzDecodeGMPReport(f *testing.F) {
	f.Add(gbFixture(f))
	f.Add(`<get_reports_response status="200"><report id="` + gbReportID + `"><report><results><result><severity>1</severity><qod><value>70</value></qod></result></results></report></report></get_reports_response>`)
	f.Fuzz(func(t *testing.T, raw string) {
		rows, _, err := readReport(raw)
		if err != nil {
			return
		}
		for _, r := range rows {
			if r.Name == "" || r.QoD < GreenboneMinQoD || r.Severity <= 0 || r.Severity > 10 || strings.ContainsAny(r.Name+r.Solution, "<>\x00") || len(r.CVEs) > gmpMaxCVEs {
				t.Fatalf("row kept: %+v", r)
			}
			for _, id := range r.CVEs {
				if !cveID.MatchString(id) {
					t.Fatalf("cve %q", id)
				}
			}
		}
	})
}

// ---- the setting ----

// INV-25: the preflight refuses below 8 GB (decimal) of memory or 60 GB free, with the measured number in plain English, and accepts
// a real 8 GiB machine (about 7.7 GiB reported).
func TestContract_INV25_Preflight(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		mem, disk int64
		code      string
		text      string
	}{
		{"7.1 GB of memory", 7_100_000_000, 200e9, "low_memory", "This box has 7.1 GB of memory; Greenbone needs at least 8.0 GB."},
		{"low disk", 16 * gib, 41_300_000_000, "low_disk", "This box has 41.3 GB of free disk space; Greenbone needs at least 60.0 GB free."},
		{"8.3 GB of memory", 8_300_000_000, 60e9, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			g := e.svc.gb()
			g.memTotal = func() (int64, error) { return tc.mem, nil }
			g.diskFree = func(string) (int64, error) { return tc.disk, nil }
			before, err := e.svc.GreenboneSetting(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			if before.State != GBOff || *before.Preflight.MemoryBytes != tc.mem || before.Preflight.OK != (tc.code == "") {
				t.Fatalf("before = %+v", before)
			}
			_, err = e.svc.SetGreenbone(e.ctx(), "admin@acme.example", true)
			if tc.code != "" {
				wantAPI(t, err, 409, tc.code)
				var ae *APIError
				if errors.As(err, &ae); ae.Message != tc.text || str(before.Preflight.Reason) != tc.text || h.ups != 0 || slices.Contains(e.auditActions(), "exposure.greenbone") {
					t.Fatalf("refusal = %q, reason %q, ups %d", ae.Message, str(before.Preflight.Reason), h.ups)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e.svc.gb().upWG.Wait()
			if h.ups != 1 {
				t.Fatalf("ups = %d", h.ups)
			}
		})
	}
	if v := parseOrZero("MemTotal:        7965424 kB\nMemFree: 1 kB\n"); v != 7965424*1024 {
		t.Fatalf("meminfo = %d", v)
	}
	if v := parseOrZero("MemTotal: lots kB\n"); v != 0 {
		t.Fatalf("bad meminfo = %d", v)
	}
}

func parseOrZero(s string) int64 { v, _ := parseMemTotal(s); return v }

// INV-25: the states: off, starting while Up runs, loading while a feed syncs or "Full and fast" is missing (a phase, not a hang),
// ready, error with the reason; disable stops the project, keeps the data and is audited like enable.
func TestContract_INV25_StateMachine(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	if v := e.gbState(); v.State != GBOff || h.dialCount() != 0 {
		t.Fatalf("default = %+v", v)
	}
	gate := make(chan struct{})
	h.with(func(h *fakeGB) { h.upGate = gate })
	v, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", true)
	if err != nil || v.State != GBStarting || str(v.ChangedBy) != "admin@acme.example" {
		t.Fatalf("enable = %+v, %v", v, err)
	}
	if v := e.gbState(); v.State != GBStarting {
		t.Fatalf("while Up runs = %+v", v)
	}
	close(gate)
	e.svc.gb().upWG.Wait()
	h.gvm.with(func(g *fakeGVM) { g.syncing = true })
	if v := e.gbState(); v.State != GBLoading || str(v.Reason) != "Greenbone is loading its feed (first time takes about 2 hours)" {
		t.Fatalf("syncing = %+v", v)
	}
	h.gvm.with(func(g *fakeGVM) { g.syncing, g.noFAF = false, true })
	if v := e.gbState(); v.State != GBLoading {
		t.Fatalf("no Full and fast yet = %+v", v)
	}
	h.gvm.with(func(g *fakeGVM) { g.noFAF = false })
	if v := e.gbState(); v.State != GBReady || v.Reason != nil {
		t.Fatalf("ready = %+v", v)
	}
	h.gvm.with(func(g *fakeGVM) { g.authFail = true })
	if v := e.gbState(); v.State != GBError || str(v.Reason) != gbAuthFailed {
		t.Fatalf("login refused = %+v", v)
	}
	h.with(func(h *fakeGB) { h.dialErr = errors.New("no socket") })
	if v := e.gbState(); v.State != GBStarting { // right after Up the socket may be missing a while
		t.Fatalf("socket missing early = %+v", v)
	}
	e.advance(GreenboneStartGrace)
	if v := e.gbState(); v.State != GBError || str(v.Reason) != gbNotAnswering {
		t.Fatalf("socket missing late = %+v", v)
	}
	v, err = e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false)
	if err != nil || v.State != GBOff || h.downs != 1 {
		t.Fatalf("disable = %+v, %v, downs %d", v, err, h.downs)
	}
	var details []string
	for _, a := range e.audits() {
		if a.Action == "exposure.greenbone" {
			details = append(details, a.Detail)
		}
	}
	if len(details) != 2 || details[0] != "enabled (memory 17.2 GB, free disk 200.0 GB)" || details[1] != "disabled (data kept)" {
		t.Fatalf("audit = %q", details)
	}
	// Up fails: error with the reason, until it is turned off and on again
	h.with(func(h *fakeGB) { h.dialErr, h.upErr = nil, &Unavailable{Reason: "the images could not be pulled"} })
	e.enable()
	if v := e.gbState(); v.State != GBError || str(v.Reason) != "Greenbone could not be started: the images could not be pulled" {
		t.Fatalf("up failed = %+v", v)
	}
	// Down fails: 502 host_error, and scans no longer use it
	h.with(func(h *fakeGB) { h.downErr = &Unavailable{Reason: "podman is not answering"} })
	_, err = e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false)
	wantAPI(t, err, 502, "host_error")
	if on, _, _, _ := loadGreenbone(e.ctx(), e.db.Reader()); on {
		t.Fatal("still on after a failed stop")
	}
}

// INV-25: without a GreenboneHost the page says Greenbone is not available, enabling is 501, and every scan of an IP says so.
func TestContract_INV25_SeamNilWording(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v, err := e.svc.GreenboneSetting(e.ctx())
	if err != nil || v.State != GBUnavailable || str(v.Reason) != "Greenbone is not available on this box." {
		t.Fatalf("view = %+v, %v", v, err)
	}
	_, err = e.svc.SetGreenbone(e.ctx(), "admin@acme.example", true)
	wantAPI(t, err, 501, "not_implemented")
	s := e.scanIP(Content{})
	if !slices.Contains(notChecked(s), NotAvailableGreenbone) || len(s.Greenbone) != 0 {
		t.Fatalf("not checked = %q", notChecked(s))
	}
}

// ---- when it runs ----

// INV-25: an enabled, ready Greenbone scans the verified, committed IP after the other steps: the safe config (brute force, default
// accounts and DoS off), the probe log row before the task starts, results stored, the task and target cleaned up.
func TestContract_INV25_ScansTheVerifiedIP(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Requested", "Running", "Done"} })
	s := e.scanIP(Content{})
	if len(s.Greenbone) != 4 || s.Greenbone[0].Severity != 9.8 {
		t.Fatalf("greenbone = %+v", s.Greenbone)
	}
	gvm := h.gvm
	if !slices.Equal(gvm.families, []string{"General", "Web application abuses"}) {
		t.Fatalf("families = %q", gvm.families)
	}
	l := gvm.log
	if len(l.rows) != 1 || l.rows[0].IP != ipA || l.rows[0].PortList != GreenbonePortList || !strings.Contains(l.rows[0].Note, "many probes") || gvm.logAtStart != 1 {
		t.Fatalf("probe log = %+v, rows at start %d", l.rows, gvm.logAtStart)
	}
	if !gvm.seen("delete_task") || !gvm.seen("delete_target") || gvm.seen("stop_task") {
		t.Fatalf("cmds = %q", gvm.cmds)
	}
	if !slices.Contains(checkKinds(s), "greenbone") {
		t.Fatalf("checks = %+v", s.Checks)
	}
}

// INV-25: no GMP call for a domain, an unverified or paused IP, a disabled Greenbone; no target is made while it loads its feed.
func TestContract_INV25_WhenItDoesNotRun(t *testing.T) {
	t.Parallel()
	t.Run("domain", func(t *testing.T) {
		t.Parallel()
		e, h := gbEnv(t)
		e.enable()
		dials := h.dialCount()
		dom := e.committedDomain()
		e.svc.SetRunner(&fakeRunner{content: Content{}})
		snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
		if err != nil {
			t.Fatal(err)
		}
		if h.dialCount() != dials || !slices.ContainsFunc(snap.NotChecked, func(n NotCheckedRow) bool { return n.Text == notGBDomain }) {
			t.Fatalf("dials %d -> %d, not checked %+v", dials, h.dialCount(), snap.NotChecked)
		}
	})
	t.Run("off", func(t *testing.T) {
		t.Parallel()
		e, h := gbEnv(t)
		s := e.scanIP(Content{})
		if h.dialCount() != 0 || h.ups != 0 || !slices.Contains(notChecked(s), notGBOff) {
			t.Fatalf("dials %d, not checked %q", h.dialCount(), notChecked(s))
		}
	})
	t.Run("loading", func(t *testing.T) {
		t.Parallel()
		e, h := gbEnv(t)
		e.enable()
		h.gvm.with(func(g *fakeGVM) { g.syncing = true })
		s := e.scanIP(Content{})
		if h.gvm.seen("create_target") || !slices.Contains(notChecked(s), notGBLoading) {
			t.Fatalf("cmds %q, not checked %q", h.gvm.cmds, notChecked(s))
		}
	})
	t.Run("unverified and paused", func(t *testing.T) {
		t.Parallel()
		e, h := gbEnv(t)
		e.enable()
		e.svc.SetRunner(&fakeRunner{content: Content{}})
		ips := e.detect(ipA)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err == nil { // no commitment
			t.Fatal("scanned without a commitment")
		}
		if _, err := e.commit(ips[0].ID); err != nil {
			t.Fatal(err)
		}
		e.advance(ScanEvery)
		e.fullAs(ipB) // paused (INV-13)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err == nil {
			t.Fatal("scanned a paused IP")
		}
		if h.gvm.seen("create_target") {
			t.Fatalf("cmds = %q", h.gvm.cmds)
		}
	})
	t.Run("probe log fails", func(t *testing.T) {
		t.Parallel()
		e, h := gbEnv(t)
		e.enable()
		h.gvm.log.err = errors.New("disk full")
		s := e.scanIP(Content{})
		if h.gvm.seen("start_task") || !slices.Contains(notChecked(s), notGBNoLog) {
			t.Fatalf("cmds %q, not checked %q", h.gvm.cmds, notChecked(s))
		}
	})
}

// INV-25: a scan that does not finish within the cap says so, and the task is stopped and deleted.
func TestContract_INV25_Timeout(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Running"} })
	e.svc.gb().poll, e.svc.gb().cap = time.Millisecond, 50*time.Millisecond
	s := e.scanIP(Content{})
	if !slices.Contains(notChecked(s), notGBSlow) || len(s.Greenbone) != 0 || !h.gvm.seen("stop_task") || !h.gvm.seen("delete_task") {
		t.Fatalf("not checked %q, cmds %q", notChecked(s), h.gvm.cmds)
	}
}

// kevLookup is a Matcher that also says which CVE ids are on the list.
type kevLookup struct {
	fakeMatcher
	kev map[string]KEVEntry
}

func (k *kevLookup) Exploited(_ context.Context, ids []string) (map[string]KEVEntry, error) {
	out := map[string]KEVEntry{}
	for _, id := range ids {
		if e, ok := k.kev[id]; ok {
			out[id] = e
		}
	}
	return out, nil
}

// INV-25: a CVE Greenbone names that is on the list becomes a row of basis greenbone with its QoD, next to the version row of the
// same CVE, which keeps its basis and text; a CVE not on the list is not a row; Greenbone's rows do not enter the day comparison.
func TestContract_INV25_GreenboneNeverReplacesAVersionRow(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	e.enable()
	version := VulnRow{IP: ipA, Port: 443, CVE: "CVE-2021-41773", Name: "Apache path traversal", Basis: "version", Summary: "In range."}
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: []ServiceRow{{IP: ipA, Port: 443, Name: "https", Product: "Apache httpd", Version: "2.4.49"}}}}
	e.svc.cfg.Matcher = &kevLookup{fakeMatcher: fakeMatcher{m: Matches{Compared: 1, Vulns: []VulnRow{version}}},
		kev: map[string]KEVEntry{"CVE-2021-41773": {Name: "Apache path traversal"}, "CVE-2023-48795": {Name: "Terrapin"}}}
	s := e.scanIP(Content{})
	var basis []string
	for _, v := range s.Vulns {
		basis = append(basis, v.CVE+" "+v.Basis)
	}
	want := []string{"CVE-2021-41773 version", "CVE-2021-41773 greenbone", "CVE-2023-48795 greenbone"}
	if !slices.Equal(basis, want) {
		t.Fatalf("vulns = %q", basis)
	}
	if s.Vulns[0] != version {
		t.Fatalf("version row changed: %+v", s.Vulns[0])
	}
	if s.Vulns[1].QoD != 99 || s.Vulns[1].Port != 443 || !strings.HasPrefix(s.Vulns[1].Summary, "Scanner: Greenbone, QoD 99.") {
		t.Fatalf("greenbone row = %+v", s.Vulns[1])
	}
	// without the lookup, Greenbone's CVEs stay in its own section and the page says they were not compared
	e.svc.cfg.Matcher = &fakeMatcher{m: Matches{Compared: 1, Vulns: []VulnRow{version}}}
	got, err := e.svc.SnapshotOf(e.ctx(), e.ipTarget(ipA), s.Date)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vulns) != 1 || !slices.Contains(notChecked(got), notGBNotCompared) {
		t.Fatalf("vulns = %+v, not checked %q", got.Vulns, notChecked(got))
	}
	for _, d := range entriesOf(s) {
		if strings.Contains(d, "CVE-2023-48795") {
			t.Fatalf("a Greenbone row entered the comparison: %q", d)
		}
	}
}

func (e *env) ipTarget(ip string) string {
	e.t.Helper()
	all, err := e.svc.Targets(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, v := range all {
		if v.Value == ip {
			return v.ID
		}
	}
	e.t.Fatalf("no target %s", ip)
	return ""
}

func entriesOf(s Snapshot) []string {
	m, _ := entries(s)
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
