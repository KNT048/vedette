package exposure

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/store"
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
	syncing    bool       // get_feeds reports a feed that is still loading
	noFAF      bool       // "Full and fast" is not there yet (404)
	states     []string   // get_tasks answers in turn; the last repeats
	report     string     // the get_reports answer
	configs    []*fakeCfg // Vedette's configs, made by create_config
	foreign    string     // a config of this name belongs to another GMP user
	taskConfig string     // the config of the last create_task
	logAtStart int        // probe rows in the log when start_task came
	log        *gbLog
	noPref     bool            // the feed has no "Disable default account checks"
	keepNo     bool            // gvmd ignores the change of the checkboxes
	noWebPref  bool            // the feed has no "Enable generic web application scanning"
	keepWeb    bool            // gvmd ignores the change of that checkbox only
	keepSafe   bool            // gvmd ignores the change of safe_checks
	keepFamily bool            // gvmd ignores the family selection
	inUse      bool            // modify_config refused: a task uses the config
	leftover   string          // the state of a task an earlier scan left behind; "" none
	fail       map[string]bool // commands answered with 400
	hang       map[string]bool // commands never answered
	onPoll     func()          // runs (without the lock) at each poll of the task
	bodies     []string        // every command's attributes and body
}

const leftoverTask = "cccccccc-dddd-4eee-8fff-000000000000"

// fakeCfg is one scan config of Vedette's in the fake gvmd: its families and preferences (the checkboxes and safe_checks).
type fakeCfg struct {
	id, name string
	families []string
	prefs    map[string]string
}

var cfgIDRe = regexp.MustCompile(`config_id=([0-9a-f-]{36})`)

// cfgIn is the config a command names (config_id=…), nil when none of Vedette's.
func (f *fakeGVM) cfgIn(body string) *fakeCfg {
	m := cfgIDRe.FindStringSubmatch(body)
	for _, c := range f.configs {
		if m != nil && c.id == m[1] {
			return c
		}
	}
	return nil
}

// cfg is a copy of Vedette's config of that name, and the name of the config the last task used.
func (f *fakeGVM) cfg(name string) (fakeCfg, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	used := ""
	for _, c := range f.configs {
		if c.id == f.taskConfig {
			used = c.name
		}
		if c.name == name {
			return fakeCfg{id: c.id, name: c.name, families: slices.Clone(c.families), prefs: maps.Clone(c.prefs)}, used
		}
	}
	return fakeCfg{}, used
}

// with changes the fake under its lock (the session goroutines read it).
func (f *fakeGVM) with(fn func(*fakeGVM)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }

func (f *fakeGVM) seen(cmd string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.cmds, cmd)
}

func (f *fakeGVM) answer(cmd string, body string) string {
	if cmd == "get_tasks" && strings.Contains(body, "task_id=") {
		f.mu.Lock()
		hook := f.onPoll
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds, f.bodies = append(f.cmds, cmd), append(f.bodies, body)
	if f.hang[cmd] {
		return ""
	}
	if f.fail[cmd] {
		return "<" + cmd + `_response status="400" status_text="Bogus"/>`
	}
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
			name := body[strings.Index(body, "filter=name=")+len("filter=name=") : strings.Index(body, " rows=")]
			out := ""
			if f.foreign == name {
				out += `<config id="99999999-2222-4333-8444-555555555555"><name>` + name + `</name><owner><name>someone</name></owner></config>`
			}
			for _, c := range f.configs {
				if c.name == name {
					out += `<config id="` + c.id + `"><name>` + c.name + `</name><owner><name>vedette</name></owner></config>`
				}
			}
			return ok(out)
		case f.cfgIn(body) != nil:
			c := f.cfgIn(body)
			fams := ""
			for _, n := range c.families {
				fams += "<family><name>" + n + "</name><nvt_count>10</nvt_count></family>"
			}
			return ok(`<config id="` + c.id + `"><name>` + c.name + `</name><families>` + fams + `</families></config>`)
		case f.noFAF:
			return `<get_configs_response status="404" status_text="Failed to find config"/>`
		}
		return ok(`<config id="` + gmpFullAndFast + `"><name>Full and fast</name><families><family><name>General</name></family><family><name>Brute force attacks</name></family>` +
			`<family><name>Default Accounts</name></family><family><name>Denial of Service</name></family><family><name>Web application abuses</name></family></families></config>`)
	case "create_config":
		name := body[strings.Index(body, "<name>")+len("<name>") : strings.Index(body, "</name>")]
		c := &fakeCfg{id: fmt.Sprintf("11111111-2222-4333-8444-5555555555%02d", len(f.configs)), name: name,
			families: []string{"General", "Brute force attacks", "Default Accounts", "Denial of Service", "Web application abuses"},
			prefs:    map[string]string{"safe_checks": "yes", "Enable generic web application scanning": "no", "Disable brute force checks": "no", "Disable default account checks": "no"}}
		f.configs = append(f.configs, c)
		return `<create_config_response status="201" status_text="OK, resource created" id="` + c.id + `"/>`
	case "modify_config":
		if f.inUse {
			return `<modify_config_response status="400" status_text="Config is in use"/>`
		}
		c := f.cfgIn(body)
		if c == nil {
			return `<modify_config_response status="404" status_text="Failed to find config"/>`
		}
		value := func() string {
			v := body[strings.Index(body, "<value>")+len("<value>") : strings.Index(body, "</value>")]
			b, _ := base64.StdEncoding.DecodeString(v)
			return string(b)
		}
		for _, p := range gbDisruptive.prefs {
			if !strings.Contains(body, p.oid+":") || !strings.Contains(body, ":checkbox:"+p.name+"<") || f.keepNo || (f.keepWeb && p.oid == gmpGlobalOID) {
				continue
			}
			c.prefs[p.name] = value()
		}
		if strings.Contains(body, "<name>safe_checks</name>") && !f.keepSafe {
			c.prefs["safe_checks"] = value()
		}
		if strings.Contains(body, "family_selection") && !f.keepFamily {
			c.families = nil
			for _, part := range strings.Split(body, "<family><name>")[1:] {
				c.families = append(c.families, part[:strings.Index(part, "<")])
			}
		}
		return ok("")
	case "get_port_lists":
		return ok(`<port_list id="` + gmpIANATCP + `"><name>All IANA assigned TCP</name></port_list>`)
	case "create_target":
		return `<create_target_response status="201" status_text="OK, resource created" id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"/>`
	case "create_task":
		f.taskConfig = body[strings.Index(body, `config id="`)+len(`config id="`):]
		f.taskConfig = f.taskConfig[:strings.Index(f.taskConfig, `"`)]
		return `<create_task_response status="201" status_text="OK, resource created" id="bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"/>`
	case "start_task":
		if f.log != nil {
			f.logAtStart = len(f.log.rows)
		}
		return `<start_task_response status="202" status_text="OK, request submitted"><report_id>` + gbReportID + `</report_id></start_task_response>`
	case "get_preferences":
		c := f.cfgIn(body)
		if c == nil {
			return `<get_preferences_response status="404" status_text="Failed to find config"/>`
		}
		if strings.Contains(body, "preference=safe_checks") {
			return ok(`<preference><name>safe_checks</name><value>` + c.prefs["safe_checks"] + `</value></preference>`)
		}
		v := func(n string) string { return c.prefs[n] }
		if strings.Contains(body, gmpGlobalOID) {
			if f.noWebPref {
				return ok(`<preference><nvt oid="` + gmpGlobalOID + `"/><id>1</id><name>HTTP User-Agent</name><type>entry</type><value>x</value></preference>`)
			}
			return ok(`<preference><nvt oid="` + gmpGlobalOID + `"><name>Global variable settings</name></nvt><id>12</id><hr_name>Enable generic web application scanning</hr_name><name>Enable generic web application scanning</name><type>checkbox</type><value>` + v("Enable generic web application scanning") + `</value></preference>`)
		}
		out := `<preference><nvt oid="` + gmpBruteOID + `"><name>Options for Brute Force NVTs</name></nvt><id>3</id><hr_name>Disable brute force checks</hr_name><name>Disable brute force checks</name><type>checkbox</type><value>` + v("Disable brute force checks") + `</value></preference>`
		if !f.noPref {
			out += `<preference><nvt oid="` + gmpBruteOID + `"/><id>4</id><hr_name>Disable default account checks</hr_name><name>Disable default account checks</name><type>checkbox</type><value>` + v("Disable default account checks") + `</value></preference>`
		}
		return ok(out)
	case "get_targets":
		if f.leftover != "" {
			return ok(`<target id="dddddddd-eeee-4fff-8000-111111111111"><name>vedette-scan-old</name><owner><name>vedette</name></owner></target>`)
		}
		return ok("")
	case "stop_task", "delete_task":
		if strings.Contains(body, leftoverTask) && cmd == "delete_task" {
			f.leftover = ""
		}
		return ok("")
	case "get_tasks":
		if strings.Contains(body, "filter=") {
			out := `<task id="eeeeeeee-ffff-4000-8111-222222222222"><name>vedette-scan-theirs</name><owner><name>someone</name></owner><status>Running</status></task>`
			if f.leftover != "" {
				out += `<task id="` + leftoverTask + `"><name>vedette-scan-old</name><owner><name>vedette</name></owner><status>` + f.leftover + `</status></task>`
			}
			return ok(out)
		}
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
		a := f.answer(se.Name.Local, attrs+raw.Inner)
		if a == "" { // a command gvmd never answers
			continue
		}
		if _, err := io.WriteString(conn, a); err != nil {
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
	syncs   int
	syncErr error
	onSync  func() // runs (without the lock) inside SyncFeed
	// syncStarted, when set, makes SyncFeed say it started and then run until its context is cancelled (review r1 L2)
	syncStarted   chan struct{}
	syncEnded     bool
	downAfterSync bool // Down came after the feed update had returned
}

func (h *fakeGB) SyncFeed(ctx context.Context) error {
	h.mu.Lock()
	h.syncs++
	hook, err, started := h.onSync, h.syncErr, h.syncStarted
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	if started != nil {
		close(started)
		<-ctx.Done()
		h.mu.Lock()
		h.syncEnded = true
		h.mu.Unlock()
		return ctx.Err()
	}
	return err
}

func (h *fakeGB) syncCount() int { h.mu.Lock(); defer h.mu.Unlock(); return h.syncs }

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
	h.downAfterSync = h.syncEnded
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

func (f *fakeGVM) leftoverState() string { f.mu.Lock(); defer f.mu.Unlock(); return f.leftover }

// touched says a command named the id.
func (f *fakeGVM) touched(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.bodies, func(b string) bool { return strings.Contains(b, id) })
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

// gbEnv is an env with Greenbone wired, two-step sign-in on, and the IP of scanIP with its testing terms accepted (D-566), without the
// disruptive tick: 16 GiB of memory, 200 GB free, a ready gvmd with the fixture report, a probe log, and no waiting between polls.
func gbEnv(t *testing.T) (*env, *fakeGB) {
	t.Helper()
	e := newEnv(t)
	gvm := &fakeGVM{report: gbFixture(t)}
	h := &fakeGB{gvm: gvm}
	l := &gbLog{}
	gvm.log = l
	e.svc.cfg.Greenbone, e.svc.cfg.Probes, e.svc.cfg.DataDir = h, l, "/data"
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	e.terms = new(bool)
	g := e.svc.gb()
	g.memInfo = func() (int64, int64, error) { return 16 * gib, 0, nil }
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
	if terrapin.IP != ipA || terrapin.Name != "SSH Transport Protocol Prefix Truncation Attack (Terrapin Attack)" || terrapin.Port != "22/tcp" || terrapin.QoD != 70 || terrapin.Severity != 5.9 ||
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

// INV-25: the preflight refuses below 6 GB (decimal) of memory or 60 GB free, with the measured number in plain English, and accepts
// the 7 GB box of the trial (D-569).
func TestContract_INV25_Preflight(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		mem, swap, disk int64
		code            string
		text            string
	}{
		{"5.9 GB of memory", 5_900_000_000, 4e9, 200e9, "low_memory", "This box has 5.9 GB of memory; OpenVAS needs at least 6.0 GB."},
		{"just under 6 GB reads 5.9", 5_999_999_999, 4e9, 200e9, "low_memory", "This box has 5.9 GB of memory; OpenVAS needs at least 6.0 GB."},
		{"low disk", 16 * gib, 0, 41_300_000_000, "low_disk", "This box has 41.3 GB of free disk space; OpenVAS needs at least 60.0 GB free."},
		{"7.1 GB of memory, no swap", 7_100_000_000, 0, 60e9, "low_memory", "This box has 7.1 GB of memory and 0.0 GB of swap; with less than 8.0 GB of memory OpenVAS needs at least 2.0 GB of swap for its first feed load."},
		{"7.1 GB of memory, 1.9 GB of swap", 7_100_000_000, 1_999_999_999, 60e9, "low_memory", "This box has 7.1 GB of memory and 1.9 GB of swap; with less than 8.0 GB of memory OpenVAS needs at least 2.0 GB of swap for its first feed load."},
		{"exactly 6 GB with 2 GB of swap", 6_000_000_000, 2e9, 60e9, "", ""},
		{"7.1 GB of memory with swap", 7_100_000_000, 4e9, 60e9, "", ""},
		{"exactly 8 GB needs no swap", 8_000_000_000, 0, 60e9, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			g := e.svc.gb()
			g.memInfo = func() (int64, int64, error) { return tc.mem, tc.swap, nil }
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
	if m, sw, err := parseMemInfo("MemTotal:        7965424 kB\nMemFree: 1 kB\nSwapTotal: 4194300 kB\n"); err != nil || m != 7965424*1024 || sw != 4194300*1024 {
		t.Fatalf("meminfo = %d %d %v", m, sw, err)
	}
	if m, sw, err := parseMemInfo("MemTotal: 7965424 kB\nSwapTotal: -5 kB\n"); err != nil || m != 7965424*1024 || sw != 0 {
		t.Fatalf("bad swap = %d %d %v", m, sw, err)
	}
	if v := parseOrZero("MemTotal: lots kB\n"); v != 0 {
		t.Fatalf("bad meminfo = %d", v)
	}
}

func parseOrZero(s string) int64 { v, _, _ := parseMemInfo(s); return v }

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
	if v := e.gbState(); v.State != GBLoading || str(v.Reason) != "OpenVAS is loading its feed (first time takes about 2 hours)" {
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
	if v := e.gbState(); v.State != GBLoading || str(v.Reason) != gbLoginPending { // N42-4: an old volume's password, until the host sets it
		t.Fatalf("login refused soon after Up = %+v", v)
	}
	h.with(func(h *fakeGB) { h.dialErr = errors.New("no socket") })
	if v := e.gbState(); v.State != GBStarting { // right after Up the socket may be missing a while
		t.Fatalf("socket missing early = %+v", v)
	}
	e.advance(GreenboneStartGrace)
	if v := e.gbState(); v.State != GBError || str(v.Reason) != gbNotAnswering {
		t.Fatalf("socket missing late = %+v", v)
	}
	h.with(func(h *fakeGB) { h.dialErr = nil })
	e.advance(GreenboneLoadGrace)
	if v := e.gbState(); v.State != GBError || str(v.Reason) != gbAuthFailed { // still refused hours after Up: say what to do
		t.Fatalf("login refused late = %+v", v)
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
	if len(details) != 2 || details[0] != "enabled (memory 17.1 GB, free disk 200.0 GB)" || details[1] != "disabled (data kept)" {
		t.Fatalf("audit = %q", details)
	}
	// Up fails: error with the reason, until it is turned off and on again
	h.with(func(h *fakeGB) { h.dialErr, h.upErr = nil, &Unavailable{Reason: "the images could not be pulled"} })
	e.enable()
	if v := e.gbState(); v.State != GBError || str(v.Reason) != "OpenVAS could not be started: the images could not be pulled" {
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
	if err != nil || v.State != GBUnavailable || str(v.Reason) != "OpenVAS is not available on this box." {
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

// INV-25, D-566: an enabled, ready Greenbone scans the verified, committed IP with accepted testing terms after the other steps: the
// deep config (every family but brute force, default accounts and DoS; generic web scanning on; brute-force options off; safe checks
// on), the probe log row before the task starts, results stored, the task and target cleaned up.
func TestContract_INV25_ScansTheVerifiedIP(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Requested", "Running", "Done"} })
	s := e.scanIP(Content{})
	if len(s.Greenbone) != 4 || s.Greenbone[0].Severity != 9.8 || s.Greenbone[0].IP != ipA || s.Greenbone[3].IP != ipA {
		t.Fatalf("greenbone = %+v", s.Greenbone)
	}
	gvm := h.gvm
	c, used := gvm.cfg(gbDeep.name)
	if v := c.prefs; used != gbDeep.name || v["Disable brute force checks"] != "yes" || v["Disable default account checks"] != "yes" || v["Enable generic web application scanning"] != "yes" || v["safe_checks"] != "yes" {
		t.Fatalf("config %q used, prefs %v", used, v)
	}
	if !slices.Equal(c.families, []string{"General", "Web application abuses"}) {
		t.Fatalf("families = %q", c.families)
	}
	l := gvm.log
	if len(l.rows) != 1 || l.rows[0].IP != ipA || l.rows[0].PortList != GreenbonePortList || !strings.Contains(l.rows[0].Note, "many probes") || gvm.logAtStart != 1 {
		t.Fatalf("probe log = %+v, rows at start %d", l.rows, gvm.logAtStart)
	}
	if !gvm.seen("delete_task") || !gvm.seen("delete_target") || gvm.seen("stop_task") || !slices.Contains(e.auditActions(), "exposure.greenbone_scan") {
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
	if s.Vulns[1].QoD != 99 || s.Vulns[1].Port != 443 || s.Vulns[1].IP != ipA || !strings.HasPrefix(s.Vulns[1].Summary, "Scanner: OpenVAS, QoD 99.") {
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

// ---- review r1 ----

// M2, L2, M4: the brute-force and default-account checkboxes must be read back "yes", a config of another GMP user is not taken, and a
// config a foreign task uses is said as such; in each case no task is started.
func TestContract_INV25_SafeConfigFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		set  func(*fakeGVM)
		want string
	}{
		{"option missing from the feed", func(g *fakeGVM) { g.noPref = true }, `OpenVAS did not scan: the OpenVAS feed has no "Disable default account checks" option`},
		{"option not kept", func(g *fakeGVM) { g.keepNo = true }, `OpenVAS did not scan: OpenVAS did not keep "Disable brute force checks" on`},
		{"config of another user", func(g *fakeGVM) { g.foreign = gbDeep.name }, "belongs to another OpenVAS user"},
		{"config in use", func(g *fakeGVM) { g.inUse = true }, "is used by a task Vedette did not start"},
		// D-564 G2, D-566: generic web application scanning, safe_checks and the families are read back too
		{"web scanning option missing", func(g *fakeGVM) { g.noWebPref = true }, `the OpenVAS feed has no "Enable generic web application scanning" option`},
		{"web scanning not kept on", func(g *fakeGVM) { g.keepWeb = true }, `OpenVAS did not keep "Enable generic web application scanning" on`},
		{"families not kept", func(g *fakeGVM) { g.keepFamily = true }, `OpenVAS did not keep the family "Brute force attacks" off`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			e.enable()
			h.gvm.with(tc.set)
			s := e.scanIP(Content{})
			if h.gvm.seen("create_task") || h.gvm.seen("start_task") || !slices.ContainsFunc(notChecked(s), func(l string) bool { return strings.Contains(l, tc.want) }) {
				t.Fatalf("cmds %q, not checked %q", h.gvm.cmds, notChecked(s))
			}
		})
	}
}

// M4: a task an earlier scan left running is stopped and deleted before a new one starts; a task of another GMP user is not touched;
// one that cannot be deleted while it stops blocks the new task; a failed cleanup is logged, audited and said on the page.
func TestContract_INV25_LeftoversAndCleanup(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.leftover = "Running" })
	s := e.scanIP(Content{})
	if len(s.Greenbone) != 4 || h.gvm.leftoverState() != "" || h.gvm.touched("eeeeeeee-ffff-4000-8111-222222222222") {
		t.Fatalf("rows %d, leftover %q, cmds %q", len(s.Greenbone), h.gvm.leftoverState(), h.gvm.cmds)
	}
	e2, h2 := gbEnv(t)
	e2.enable()
	h2.gvm.with(func(g *fakeGVM) { g.leftover, g.fail = "Stop Requested", map[string]bool{"delete_task": true} })
	s2 := e2.scanIP(Content{})
	if h2.gvm.seen("create_task") || !slices.ContainsFunc(notChecked(s2), func(l string) bool { return strings.Contains(l, "still stopping") }) {
		t.Fatalf("cmds %q, not checked %q", h2.gvm.cmds, notChecked(s2))
	}
	e3, h3 := gbEnv(t)
	e3.enable()
	h3.gvm.with(func(g *fakeGVM) { g.fail = map[string]bool{"delete_target": true} })
	s3 := e3.scanIP(Content{})
	if len(s3.Greenbone) != 4 || !slices.ContainsFunc(notChecked(s3), func(l string) bool {
		return strings.Contains(l, "delete_target") && strings.Contains(l, "The next scan stops")
	}) {
		t.Fatalf("not checked %q", notChecked(s3))
	}
	var detail string
	for _, a := range e3.audits() {
		if a.Action == "exposure.greenbone_scan" {
			detail = a.Detail
		}
	}
	if !strings.HasPrefix(detail, "done: 4 results") || !strings.Contains(detail, "delete_target") {
		t.Fatalf("audit = %q", detail)
	}
}

// M5: the snapshot of the other steps is stored before Greenbone starts and the run shows its own phase; Greenbone's rows are added
// to that snapshot when it ends.
func TestContract_INV25_SnapshotFirstThenGreenbone(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	var stored int
	var phase string
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running", "Done"}
		g.onPoll = func() {
			if stored == 0 {
				_ = e.db.Reader().QueryRowContext(context.Background(), `SELECT count(*) FROM exp_snapshot WHERE not_checked LIKE '%runs for up to 90 minutes%'`).Scan(&stored)
				if r := e.svc.CurrentScan(); r != nil {
					phase = r.Phase
				}
			}
		}
	})
	s := e.scanIP(Content{})
	if stored != 1 || phase != PhaseGreenbone {
		t.Fatalf("stored before Greenbone = %d, phase %q", stored, phase)
	}
	if len(s.Greenbone) != 4 || slices.ContainsFunc(notChecked(s), func(l string) bool { return strings.Contains(l, "runs for up to 90 minutes") }) {
		t.Fatalf("greenbone %d, not checked %q", len(s.Greenbone), notChecked(s))
	}
}

// M5: a stop during the Greenbone step keeps the snapshot of the other steps, says Greenbone was stopped, stops gvmd's task, and
// writes one exposure.scan row (the snapshot) and one exposure.greenbone_scan row (stopped).
func TestContract_INV25_StopKeepsTheEarlierResults(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.svc.gb().poll = time.Millisecond
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running"}
		g.onPoll = func() { e.svc.cancelRun("admin@acme.example") }
	})
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(ips[0].ID, false)
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{ipA, 443, "https", "", "", 0, false}}}})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err == nil {
		t.Fatal("a stopped run reads as done")
	}
	run := e.svc.CurrentScan()
	if run == nil || run.Status != RunStopped || run.SnapshotID == nil {
		t.Fatalf("run = %+v", run)
	}
	snap, err := e.svc.SnapshotOf(e.ctx(), ips[0].ID, run.StartedAt[:10])
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Ports) != 1 || !slices.Contains(notChecked(snap), notGBStopped) || !h.gvm.seen("stop_task") {
		t.Fatalf("ports %d, not checked %q, cmds %q", len(snap.Ports), notChecked(snap), h.gvm.cmds)
	}
	var rows []string
	for _, a := range e.audits() {
		if a.Action == "exposure.scan" || a.Action == "exposure.greenbone_scan" {
			rows = append(rows, a.Action+" "+a.Detail)
		}
	}
	if len(rows) != 2 || !strings.HasPrefix(rows[1], "exposure.greenbone_scan stopped") {
		t.Fatalf("audit = %q", rows)
	}
}

// M3: a deadline is slow, not unreadable; a slow gvmd soon after Up reads as loading, later as an error that says it was slow.
func TestContract_INV25_SlowIsNotUnreadable(t *testing.T) {
	t.Parallel()
	if _, err := decodeGMP(deadlineReader{}, "get_feeds", nil); !errors.Is(err, errGMPSlow) || errors.Is(err, ErrGMPBad) {
		t.Fatalf("err = %v", err)
	}
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.hang = map[string]bool{"get_feeds": true} })
	g := e.svc.gb()
	g.mu.Lock()
	upAt := g.upAt
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx(), 50*time.Millisecond)
	defer cancel()
	if st, why := e.svc.gbProbe(ctx, upAt); st != GBLoading || why != gbBusyReason {
		t.Fatalf("soon after Up = %s %q", st, why)
	}
	ctx2, cancel2 := context.WithTimeout(e.ctx(), 50*time.Millisecond)
	defer cancel2()
	if st, why := e.svc.gbProbe(ctx2, upAt.Add(-GreenboneLoadGrace)); st != GBError || why != gbSlowReason {
		t.Fatalf("long after Up = %s %q", st, why)
	}
}

type deadlineReader struct{}

func (deadlineReader) Read([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

// L3: a read or a scan that saw "on" just before an administrator turned Greenbone off never starts it again.
func TestContract_INV25_OffIsNotUndoneByAPoll(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	e.svc.gbStatus(e.ctx(), true) // what a GET that read "on" before the switch does next
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 1 {
			t.Errorf("ups = %d", h.ups)
		}
	})
}

// L1: the note about results that are not kept appears only when more than 200 are kept.
func TestContract_INV25_TruncationNote(t *testing.T) {
	t.Parallel()
	rows := make([]GreenboneRow, maxGreenboneRows+5)
	for i := range rows {
		rows[i] = GreenboneRow{IP: ipA, Port: "80/tcp", Severity: 5, Name: "x", QoD: 80}
	}
	if got := sanitizeGreenbone(rows); len(got) != maxGreenboneRows {
		t.Fatalf("kept %d", len(got))
	}
}

// L5: flow 16 follows the setting.
func TestContract_INV25_GreenboneEnabled(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	if e.svc.GreenboneEnabled(e.ctx()) {
		t.Fatal("on by default")
	}
	e.enable()
	if !e.svc.GreenboneEnabled(e.ctx()) {
		t.Fatal("off after enable")
	}
}

// ---- D-564 ----

// D-566 (FULL-2): Greenbone can be enabled (no review gate any more) but scans only a target whose testing terms are accepted: without
// them "Not checked" says so and gvmd is never asked; with the disruptive tick its own config turns on brute force, default accounts
// and DoS, the brute-force options and safe_checks off, all read back; withdrawn terms are seen right before the step.
func TestContract_INV25_TermsDecideGreenbone(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.terms = nil
	e.enable()
	before := h.dialCount() // reading the setting may ask gvmd whether it is ready; the scan must not
	s := e.scanIP(Content{})
	if !slices.Contains(notChecked(s), notGBTerms) || len(s.Greenbone) != 0 || h.dialCount() != before {
		t.Fatalf("not checked %q, dials %d -> %d", notChecked(s), before, h.dialCount())
	}
	id := e.ipTarget(ipA)
	e.acceptTerms(id, true)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	c, used := h.gvm.cfg(gbDisruptive.name)
	if v := c.prefs; used != gbDisruptive.name || v["Disable brute force checks"] != "no" || v["Disable default account checks"] != "no" || v["Enable generic web application scanning"] != "yes" || v["safe_checks"] != "no" {
		t.Fatalf("config %q used, prefs %v", used, v)
	}
	if !slices.Equal(c.families, []string{"General", "Brute force attacks", "Default Accounts", "Denial of Service", "Web application abuses"}) {
		t.Fatalf("families = %q", c.families)
	}
	if d, _ := h.gvm.cfg(gbDeep.name); d.id != "" {
		t.Fatal("the deep config was made for a disruptive scan")
	}
	// safe_checks not kept: nothing starts
	h.gvm.with(func(g *fakeGVM) { g.keepSafe = true })
	h.gvm.with(func(g *fakeGVM) { g.configs[0].prefs["safe_checks"] = "yes" })
	e.advance(ScanEvery)
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := e.svc.SnapshotOf(e.ctx(), id, snap.Date)
	if !slices.ContainsFunc(notChecked(got), func(l string) bool { return strings.Contains(l, "did not keep safe checks off") }) {
		t.Fatalf("not checked %q", notChecked(got))
	}
	// withdrawn: the step checks the terms again and sends nothing
	if _, err := e.svc.RevokeTerms(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	dials := h.dialCount()
	o, err := e.svc.greenboneStep(e.ctx(), ScanTarget{ID: id, Kind: KindIP, Value: ipA, User: "admin@acme.example", Mode: ScanMode{Full: true, Disruptive: true}})
	if err != nil || len(o.not) != 1 || o.not[0].Text != notGBTerms || h.dialCount() != dials {
		t.Fatalf("step = %+v, %v, dials %d -> %d", o, err, dials, h.dialCount())
	}
}

// G3: the check line tells high and medium results from the Low ones, which are hardening notes.
func TestContract_INV25_LowIsAHardeningNote(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	e.enable()
	s := e.scanIP(Content{})
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.Contains(c.Text, "4 results with QoD 70 or more (2 high or medium, 2 hardening notes)")
	}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
}

// G6: the feed is updated a week after Greenbone was enabled, then weekly; never while a scan holds the slot, and no scan starts
// while it runs; the state is "loading" meanwhile; below 60 GB free it is refused and says why, and tried again a day later; each
// update tried is one audit row, and the setting shows the last and the next.
func TestContract_INV25_WeeklyFeedUpdate(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	run := func() {
		t.Helper()
		if err := e.svc.RunGreenboneSync(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	e.advance(2 * GreenboneSyncEvery)
	run()
	if h.syncCount() != 0 {
		t.Fatal("updated while off")
	}
	e.enable()
	run()
	if h.syncCount() != 0 {
		t.Fatal("updated right after enable")
	}
	e.advance(GreenboneSyncEvery)
	e.svc.runMu.Lock()
	e.svc.run = &scanRun{view: ScanRun{Status: RunRunning}}
	e.svc.runMu.Unlock()
	run()
	if h.syncCount() != 0 {
		t.Fatal("updated during a scan")
	}
	e.svc.runMu.Lock()
	e.svc.run = nil
	e.svc.runMu.Unlock()
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	e.svc.SetRunner(&fakeRunner{content: Content{}})
	var during GreenboneView
	var scanErr error
	h.with(func(h *fakeGB) {
		h.onSync = func() {
			during, _ = e.svc.GreenboneSetting(e.ctx())
			_, scanErr = e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
		}
	})
	run()
	if h.syncCount() != 1 || during.State != GBLoading || str(during.Reason) != "OpenVAS is loading its weekly feed update" {
		t.Fatalf("syncs %d, during = %+v", h.syncCount(), during)
	}
	wantAPI(t, scanErr, 409, "busy")
	if ae := (*APIError)(nil); !errors.As(scanErr, &ae) || !strings.Contains(ae.Message, "at most 60 minutes") || !strings.Contains(ae.Message, "(started ") { // review r1 L4
		t.Fatalf("busy = %v", scanErr)
	}
	v := e.gbState()
	if v.FeedSync.OK == nil || !*v.FeedSync.OK || v.FeedSync.LastAt == nil || v.FeedSync.NextAt == nil {
		t.Fatalf("feed sync = %+v", v.FeedSync)
	}
	last, _ := parseTS(*v.FeedSync.LastAt)
	if next, _ := parseTS(*v.FeedSync.NextAt); !next.Equal(last.Add(GreenboneSyncEvery)) {
		t.Fatalf("next = %s, last %s", *v.FeedSync.NextAt, *v.FeedSync.LastAt)
	}
	h.with(func(h *fakeGB) { h.onSync = nil })
	e.svc.gb().diskFree = func(string) (int64, error) { return 41_300_000_000, nil }
	e.advance(GreenboneSyncEvery)
	run()
	v = e.gbState()
	if h.syncCount() != 1 || v.FeedSync.OK == nil || *v.FeedSync.OK || str(v.FeedSync.Note) != "Not updated: this box has 41.3 GB of free disk space; OpenVAS needs at least 60.0 GB free." {
		t.Fatalf("syncs %d, feed sync = %+v", h.syncCount(), v.FeedSync)
	}
	e.svc.gb().diskFree = func(string) (int64, error) { return 200e9, nil }
	e.advance(gbSyncRetry)
	run()
	var notes []string
	for _, a := range e.audits() {
		if a.Action == "exposure.greenbone_sync" {
			notes = append(notes, a.Detail)
		}
	}
	if h.syncCount() != 2 || len(notes) != 3 || !strings.HasPrefix(notes[0], "Updated") || !strings.HasPrefix(notes[1], "Not updated: this box has 41.3 GB") {
		t.Fatalf("syncs %d, audit %q", h.syncCount(), notes)
	}
}

// D-564: the setting with its feed update fits the API schema, before the first update and after one.
func TestContract_INV25_SettingFitsTheSchema(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	e.enable()
	v := e.gbState()
	if _, err := into[oas.ExposureGetExposureGreenboneOK](v); err != nil || v.FeedSync.NextAt == nil {
		t.Fatalf("before the first update: %v, %+v", err, v.FeedSync)
	}
	e.advance(GreenboneSyncEvery)
	if err := e.svc.RunGreenboneSync(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := into[oas.ExposurePutExposureGreenboneOK](e.gbState()); err != nil {
		t.Fatal(err)
	}
}

// review r1 L1: the next update counts from the later of the last update and the last time Greenbone was turned on, and the page
// never shows a past date.
func TestContract_INV25_NextFeedUpdate(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	ts := func(s string) *string { return &s }
	cases := []struct {
		name string
		f    GreenboneFeedSync
		want string
	}{
		{"none yet", GreenboneFeedSync{}, "2026-03-08T00:00:00.000Z"},
		{"last worked after enabling", GreenboneFeedSync{LastAt: ts("2026-03-03T00:00:00.000Z"), OK: &yes}, "2026-03-10T00:00:00.000Z"},
		{"last failed after enabling", GreenboneFeedSync{LastAt: ts("2026-03-03T00:00:00.000Z"), OK: &no}, "2026-03-04T00:00:00.000Z"},
		{"last before turned on again", GreenboneFeedSync{LastAt: ts("2025-12-01T00:00:00.000Z"), OK: &yes}, "2026-03-08T00:00:00.000Z"},
	}
	for _, tc := range cases {
		got, ok := nextSync("2026-03-01T00:00:00.000Z", tc.f)
		if !ok || store.FormatTS(got) != tc.want {
			t.Errorf("%s: next = %s, want %s", tc.name, store.FormatTS(got), tc.want)
		}
	}
	e, _ := gbEnv(t)
	e.enable()
	e.advance(3 * GreenboneSyncEvery) // due long ago: Greenbone was not ready, or scans held the slot
	v := e.gbState()
	if next, _ := parseTS(str(v.FeedSync.NextAt)); next.Before(e.clock.Now()) {
		t.Fatalf("next = %s, now %s", str(v.FeedSync.NextAt), e.clock.Now())
	}
}

// review r1 L2: Turn off cancels a running feed update and waits for it to end before it stops Greenbone.
func TestContract_INV25_TurnOffWaitsForTheFeedUpdate(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.advance(GreenboneSyncEvery)
	started := make(chan struct{})
	h.with(func(h *fakeGB) { h.syncStarted = started })
	errc := make(chan error, 1)
	go func() { errc <- e.svc.RunGreenboneSync(e.ctx()) }()
	<-started
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	h.with(func(h *fakeGB) {
		if h.downs != 1 || !h.downAfterSync {
			t.Errorf("downs %d, after the update ended %v", h.downs, h.downAfterSync)
		}
	})
	var last string
	for _, a := range e.audits() {
		if a.Action == "exposure.greenbone_sync" {
			last = a.Detail
		}
	}
	if !strings.HasPrefix(last, "Not updated: it was stopped") {
		t.Fatalf("audit = %q", last)
	}
}
