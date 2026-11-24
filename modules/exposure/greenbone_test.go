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
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
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
	mu          sync.Mutex
	cmds        []string // command names in the order they came
	authFail    bool
	syncing     bool       // get_feeds reports a feed that is still loading
	nvtVersion  string     // the NVT feed's <version> in get_feeds; "" is the default 202611140611
	dataSync    bool       // gvmd's own feed lock is taken: its GVMD_DATA feed is syncing (the lock is one for every feed of gvmd)
	noFAF       bool       // "Full and fast" is not there yet (404)
	states      []string   // get_tasks answers in turn; the last repeats
	report      string     // the get_reports answer
	configs     []*fakeCfg // Vedette's configs, made by create_config
	foreign     string     // a config of this name belongs to another GMP user
	taskConfig  string     // the config of the last create_task
	logAtStart  int        // probe rows in the log when start_task came
	log         *gbLog
	noPref      bool            // the feed has no "Disable default account checks"
	keepNo      bool            // gvmd ignores the change of the checkboxes
	noWebPref   bool            // the feed has no "Enable generic web application scanning"
	keepWeb     bool            // gvmd ignores the change of that checkbox only
	keepSafe    bool            // gvmd ignores the change of safe_checks
	keepFamily  bool            // gvmd ignores the family selection
	keepNVTs    bool            // gvmd ignores the NVT selection of a family
	partNVTs    bool            // gvmd keeps only the first NVT of a selection
	webExtra    []string        // NVTs a feed update added to Web application abuses
	inUse       bool            // modify_config refused: a task uses the config
	leftover    string          // the state of a task an earlier scan left behind; "" none
	fail        map[string]bool // commands answered with 400
	hang        map[string]bool // commands never answered
	onPoll      func()          // runs (without the lock) at each poll of the task
	bodies      []string        // every command's attributes and body
	stopTo      string          // after a stop_task of the scan's task, get_tasks says this state ("" keeps the states)
	portRange   string          // the port_range of the last create_port_list
	hadLeftover bool            // an earlier scan's task was listed: its port list is there too
	ranges      []string        // the port_range of every create_port_list
	lastHost    string          // the hosts of the last create_target: the report's rows of ipA are this address's
	ran         bool            // the task was served "Running" once: its progress is 50 from then on, -1 before
	hangOnce    map[string]bool // commands not answered the first time they come
}

const leftoverTask = "cccccccc-dddd-4eee-8fff-000000000000"

// fakeCfg is one scan config of Vedette's in the fake gvmd: its families and preferences (the checkboxes and safe_checks).
type fakeCfg struct {
	id, name string
	families []string
	prefs    map[string]string
	web      []string // the NVTs of Web application abuses; nil is the whole family (growing)
}

// fakeWebNVTs is the feed's family Web application abuses in the fake gvmd.
var fakeWebNVTs = []string{"1.3.6.1.4.1.25623.1.0.113002", gmpWebRootTravOID, "1.3.6.1.4.1.25623.1.0.117574"}

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
			return fakeCfg{id: c.id, name: c.name, families: slices.Clone(c.families), prefs: maps.Clone(c.prefs), web: slices.Clone(c.web)}, used
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
	if f.hangOnce[cmd] {
		delete(f.hangOnce, cmd)
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
		lock := ""
		if f.dataSync {
			lock = "<currently_syncing><timestamp>x</timestamp></currently_syncing>"
		}
		ver := f.nvtVersion
		if ver == "" {
			ver = "202611140611"
		}
		// as gvmd answers without the SCAP and CERT data: a feed whose feed.xml is missing is left out
		return ok("<feed><type>NVT</type><name>Greenbone Community Feed</name><version>" + ver + "</version>" + sync +
			"</feed><feed><type>GVMD_DATA</type><name>Greenbone Community gvmd Data Feed</name><version>202611130507</version>" + lock + "</feed>")
	case "get_info", "get_resource_names": // gvmd 26.43.0 without SCAP/CERT (gmp.c)
		return "<" + cmd + `_response status="400" status_text="The SCAP database is required"/>`
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
			if !strings.Contains(body, p.oid+":") || !strings.Contains(body, ":checkbox:"+p.name+"<") || f.keepNo {
				continue
			}
			c.prefs[p.name] = value()
			if f.keepWeb && p.oid == gmpGlobalOID { // gvmd stores the opposite of what was asked
				c.prefs[p.name] = map[string]string{"yes": "no", "no": "yes"}[value()]
			}
		}
		if strings.Contains(body, "<name>safe_checks</name>") && !f.keepSafe {
			c.prefs["safe_checks"] = value()
		}
		if strings.Contains(body, "nvt_selection") && !f.keepNVTs {
			c.web = []string{}
			for _, part := range strings.Split(body, `<nvt oid="`)[1:] {
				c.web = append(c.web, part[:strings.Index(part, `"`)])
			}
			if f.partNVTs {
				c.web = c.web[:1]
			}
		}
		if strings.Contains(body, "family_selection") && !f.keepFamily {
			c.web = nil // all and growing: the whole family again
			c.families = nil
			for _, part := range strings.Split(body, "<family><name>")[1:] {
				c.families = append(c.families, part[:strings.Index(part, "<")])
			}
		}
		return ok("")
	case "get_nvts":
		web := append(slices.Clone(fakeWebNVTs), f.webExtra...)
		if c := f.cfgIn(body); c != nil && c.web != nil {
			web = c.web
		}
		out := ""
		for _, oid := range web {
			out += `<nvt oid="` + oid + `"><name>x</name></nvt>`
		}
		return ok(out)
	case "get_port_lists":
		if f.hadLeftover { // the earlier scan left its port list too
			return ok(`<port_list id="99999999-eeee-4fff-8000-111111111111"><name>vedette-scan-old</name><owner><name>vedette</name></owner></port_list>` +
				`<port_list id="88888888-eeee-4fff-8000-111111111111"><name>vedette-scan-theirs</name><owner><name>someone</name></owner></port_list>`)
		}
		return ok("")
	case "create_port_list":
		f.portRange = body[strings.Index(body, "<port_range>")+len("<port_range>") : strings.Index(body, "</port_range>")]
		f.ranges = append(f.ranges, f.portRange)
		return `<create_port_list_response status="201" status_text="OK, resource created" id="ffffffff-aaaa-4bbb-8ccc-dddddddddddd"/>`
	case "create_target":
		f.lastHost = body[strings.Index(body, "<hosts>")+len("<hosts>") : strings.Index(body, "</hosts>")]
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
		if strings.Contains(body, "preference=") && !strings.Contains(body, "nvt_oid=") {
			return ok("") // as a real gvmd answers: preference= without nvt_oid matches NVT preferences only
		}
		if !strings.Contains(body, "nvt_oid=") { // the whole list: scanner preferences (empty nvt oid) and NVT ones, as a real gvmd prints them
			return ok(`<preference><nvt oid="1.3.6.1.4.1.25623.1.0.100315"><name>Ping Host</name></nvt><id>5</id><hr_name>safe_checks</hr_name><name>safe_checks</name><type>checkbox</type><value>no</value></preference>` +
				`<preference><nvt oid=""><name></name></nvt><id></id><hr_name>safe_checks</hr_name><name>safe_checks</name><type></type><value>` + c.prefs["safe_checks"] + `</value><default>1</default></preference>`)
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
		if cmd == "stop_task" && f.stopTo != "" && strings.Contains(body, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff") {
			f.states = []string{f.stopTo}
		}
		return ok("")
	case "get_tasks":
		if strings.Contains(body, "filter=") {
			out := `<task id="eeeeeeee-ffff-4000-8111-222222222222"><name>vedette-scan-theirs</name><owner><name>someone</name></owner><status>Running</status></task>`
			if f.leftover != "" {
				f.hadLeftover = true
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
		f.ran = f.ran || st == "Running"
		progress := "-1"
		if f.ran {
			progress = "50"
		}
		return ok(`<task id="bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"><name>x</name><status>` + st + `</status><progress>` + progress + `</progress></task>`)
	case "get_reports":
		if f.lastHost != "" {
			return strings.ReplaceAll(f.report, ipA, f.lastHost)
		}
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
	upErrs  []error // answered first, one per Up, before upErr
	downErr error
	dialErr error
	upGate  chan struct{} // when set, Up waits for it
	syncs   int
	syncErr error
	onSync  func() // runs (without the lock) inside SyncFeed
	// syncStarted, when set, makes SyncFeed say it started and then run until its context is cancelled
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
	if len(h.upErrs) > 0 {
		err, h.upErrs = h.upErrs[0], h.upErrs[1:]
	}
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

// gbOpen is the content of a scan that found ports 22 and 443 open on ipA: OpenVAS checks those.
func gbOpen() Content {
	return Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}, {IP: ipA, Port: 22, Service: "ssh"}}}
}

// gbEnv is an env with Greenbone wired, two-step sign-in on, and the IP of scanIP with its testing terms accepted, without the
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
// the 7 GB box of the trial.
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
	if v := e.gbState(); v.State != GBLoading || str(v.Reason) != gbLoginPending { // An old volume's password, until the host sets it
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
	s := e.scanIP(gbOpen())
	if !slices.Contains(notChecked(s), NotAvailableGreenbone) || len(s.Greenbone) != 0 {
		t.Fatalf("not checked = %q", notChecked(s))
	}
}

// ---- when it runs ----

// INV-25: an enabled, ready Greenbone scans the verified, committed IP with accepted testing terms after the other steps: the
// deep config (every family but brute force, default accounts and DoS; generic web scanning and the web-root traversal NVT off; brute-force options off; safe checks
// on), the probe log row before the task starts, results stored, the task and target cleaned up.
func TestContract_INV25_ScansTheVerifiedIP(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Requested", "Running", "Done"} })
	s := e.scanIP(gbOpen())
	if len(s.Greenbone) != 4 || s.Greenbone[0].Severity != 9.8 || s.Greenbone[0].IP != ipA || s.Greenbone[3].IP != ipA {
		t.Fatalf("greenbone = %+v", s.Greenbone)
	}
	gvm := h.gvm
	c, used := gvm.cfg(gbDeep.name)
	if v := c.prefs; used != gbDeep.name || v["Disable brute force checks"] != "yes" || v["Disable default account checks"] != "yes" || v["Enable generic web application scanning"] != "no" || v["safe_checks"] != "yes" {
		t.Fatalf("config %q used, prefs %v", used, v)
	}
	if !slices.Equal(c.families, []string{"General", "Web application abuses"}) {
		t.Fatalf("families = %q", c.families)
	}
	// #915: the web-root traversal test, which the checkbox does not gate, is left out; the rest of its family stays
	if want := []string{"1.3.6.1.4.1.25623.1.0.113002", "1.3.6.1.4.1.25623.1.0.117574"}; !slices.Equal(c.web, want) {
		t.Fatalf("web application tests = %q", c.web)
	}
	l := gvm.log
	if len(l.rows) != 1 || l.rows[0].IP != ipA || l.rows[0].PortList != "T:22,443" || !strings.Contains(l.rows[0].Note, "many probes") || gvm.logAtStart != 1 {
		t.Fatalf("probe log = %+v, rows at start %d", l.rows, gvm.logAtStart)
	}
	if !gvm.seen("delete_task") || !gvm.seen("delete_target") || !gvm.seen("delete_port_list") || gvm.seen("stop_task") || !slices.Contains(e.auditActions(), "exposure.greenbone_scan") {
		t.Fatalf("cmds = %q", gvm.cmds)
	}
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.HasPrefix(c.Text, "OpenVAS scanned "+ipA)
	}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
	if s.GreenboneRun.State != GBRunDone || s.GreenboneRun.StartedAt == nil {
		t.Fatalf("greenbone_run = %+v", s.GreenboneRun)
	}
}

// OpenVAS checks only the ports the run found open: a port list "T:<those ports>" of its own made before the target,
// the target on that list with alive test "Consider Alive" (no ping, no IANA list), and the list deleted after the target.
func TestContract_INV25_PortListOfTheOpenPorts(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	c := gbOpen()
	c.Ports = append(c.Ports, PortRow{IP: ipA, Port: 443, Service: "https"}, PortRow{IP: ipB, Port: 8080, Service: "http"}) // a repeat, another address
	s := e.scanIP(c)
	gvm := h.gvm
	gvm.mu.Lock()
	defer gvm.mu.Unlock()
	order := func(cmd string) int { return slices.Index(gvm.cmds, cmd) }
	if gvm.portRange != "T:22,443" || order("create_port_list") < 0 || order("create_port_list") > order("create_target") ||
		order("delete_target") > slices.Index(gvm.cmds, "delete_port_list") {
		t.Fatalf("port range %q, cmds %q", gvm.portRange, gvm.cmds)
	}
	target := gvm.bodies[order("create_target")]
	if !strings.Contains(target, `<port_list id="ffffffff-aaaa-4bbb-8ccc-dddddddddddd"/>`) || !strings.Contains(target, "<alive_tests>Consider Alive</alive_tests>") ||
		!strings.Contains(target, "<hosts>"+ipA+"</hosts>") {
		t.Fatalf("create_target = %q", target)
	}
	if !strings.Contains(gvm.bodies[slices.Index(gvm.cmds, "delete_port_list")], "port_list_id=ffffffff-aaaa-4bbb-8ccc-dddddddddddd") {
		t.Fatalf("cmds %q", gvm.cmds)
	}
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.Contains(c.Text, "; TCP ports 22, 443)")
	}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
}

// A scan that found no open port does not start OpenVAS (no pending line, nothing sent) and says why; more
// than the believable number of open ports (a box that answers on every port) is not sent either.
func TestContract_INV25_NoOpenPortNoOpenVAS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		content Content
		want    string
	}{
		{"none", Content{}, notGBNoPorts},
		{"another address only", Content{Ports: []PortRow{{IP: ipB, Port: 443, Service: "https"}}}, notGBNoPorts},
		{"answers everywhere", func() Content {
			var c Content
			for p := range commonports.MaxBelievableOpen + 1 {
				c.Ports = append(c.Ports, PortRow{IP: ipA, Port: 1000 + p, Service: "x"})
			}
			return c
		}(), notGBTooManyPorts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			e.enable()
			s := e.scanIP(tc.content)
			if h.gvm.seen("create_port_list") || h.gvm.seen("create_target") || h.gvm.seen("start_task") || !slices.Contains(notChecked(s), tc.want) ||
				slices.ContainsFunc(notChecked(s), func(l string) bool { return l == gbPending }) || s.GreenboneRun.State != GBRunNotRun || s.GreenboneRun.StartedAt != nil {
				t.Fatalf("cmds %q, not checked %q, run %+v", h.gvm.cmds, notChecked(s), s.GreenboneRun)
			}
		})
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
		s := e.scanIP(gbOpen())
		if h.dialCount() != 0 || h.ups != 0 || !slices.Contains(notChecked(s), notGBOff) {
			t.Fatalf("dials %d, not checked %q", h.dialCount(), notChecked(s))
		}
	})
	t.Run("loading", func(t *testing.T) {
		t.Parallel()
		e, h := gbEnv(t)
		e.enable()
		h.gvm.with(func(g *fakeGVM) { g.syncing = true })
		s := e.scanIP(gbOpen())
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
		s := e.scanIP(gbOpen())
		if h.gvm.seen("start_task") || !slices.Contains(notChecked(s), notGBNoLog) {
			t.Fatalf("cmds %q, not checked %q", h.gvm.cmds, notChecked(s))
		}
	})
}

// gbEmptyReport is a report of the scan's task with no result.
const gbEmptyReport = `<get_reports_response status="200" status_text="OK"><report id="` + gbReportID + `"><report id="` + gbReportID + `"><results></results></report></report></get_reports_response>`

// gbAudit is the detail of the last exposure.greenbone_scan audit row.
func (e *env) gbAudit() string {
	var detail string
	for _, a := range e.audits() {
		if a.Action == "exposure.greenbone_scan" {
			detail = a.Detail
		}
	}
	return detail
}

// INV-25: what the 90-minute cap leaves, on the bubble's clock (testing/synctest: the cap and the polls are the real 90 minutes and
// 15 seconds, and no test waits for them). A task that scanned is stopped and what it had found is shown with the line that says so;
// one that never left Requested did not run; one that reached Done after the stop is done; a report the cap cut while gvmd
// had finished, or a task still stopping when the 5-minute budget ends, is read again over a new session; only a report
// that cannot be read at all says "not shown".
func TestContract_INV25_Timeout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		set           func(*fakeGVM)
		poll          time.Duration
		state, line   string
		rows          int
		check, prefix string // the check line's start ("" none), the audit's start
	}{
		{"partial rows", func(g *fakeGVM) { g.states, g.stopTo = []string{"Running"}, "Stopped" }, gbPollDefault, GBRunPartial, notGBPartial, 4,
			"OpenVAS partly scanned " + ipA, "stopped after 90 minutes: 4 results, "},
		{"partial without rows", func(g *fakeGVM) { g.states, g.stopTo, g.report = []string{"Running"}, "Stopped", gbEmptyReport }, gbPollDefault, GBRunPartial, notGBPartialNone, 0,
			"OpenVAS partly scanned " + ipA, "stopped after 90 minutes: 0 results"},
		{"never left Requested", func(g *fakeGVM) { g.states, g.stopTo, g.report = []string{"Requested"}, "Stopped", gbEmptyReport }, gbPollDefault, GBRunNotRun, notGBQueued, 0,
			"", "not done: did not start scanning within 90 minutes"},
		{"Done right after the stop", func(g *fakeGVM) { g.states, g.stopTo = []string{"Running"}, "Done" }, gbPollDefault, GBRunDone, "", 4,
			"OpenVAS scanned " + ipA, "done: 4 results"},
		// Done comes at the third poll (89 minutes), and its report read hangs into the cap: read again over a new session
		{"the cap cut the report of a finished task", func(g *fakeGVM) {
			g.states, g.hangOnce = []string{"Running", "Running", "Done"}, map[string]bool{"get_reports": true}
		}, 89 * time.Minute / 2, GBRunDone, "", 4, "OpenVAS scanned " + ipA, "done: 4 results"},
		{"still stopping when the budget ends", func(g *fakeGVM) { g.states, g.stopTo = []string{"Running"}, "Stop Requested" }, gbPollDefault, GBRunPartial, notGBPartial, 4,
			"OpenVAS partly scanned " + ipA, "stopped after 90 minutes: 4 results"},
		{"report unreadable", func(g *fakeGVM) {
			g.states, g.stopTo, g.fail = []string{"Running"}, "Stopped", map[string]bool{"get_reports": true}
		}, gbPollDefault, GBRunFailed, notGBSlow, 0, "", "not done: did not finish within 90 minutes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				e, h := gbEnv(t)
				e.enable()
				h.gvm.with(tc.set)
				e.svc.gb().poll = tc.poll
				s := e.scanIP(gbOpen())
				if s.GreenboneRun.State != tc.state || len(s.Greenbone) != tc.rows || (tc.line != "" && !slices.Contains(notChecked(s), tc.line)) {
					t.Fatalf("run %+v, rows %d, not checked %q, cmds %q", s.GreenboneRun, len(s.Greenbone), notChecked(s), h.gvm.cmds)
				}
				gb := slices.IndexFunc(s.Checks, func(c CheckRow) bool { return c.Kind == "greenbone" })
				if (tc.check == "") != (gb < 0) || (gb >= 0 && !strings.HasPrefix(s.Checks[gb].Text, tc.check)) {
					t.Fatalf("checks %+v", s.Checks)
				}
				if tc.state != GBRunPartial && slices.ContainsFunc(notChecked(s), func(l string) bool { return strings.Contains(l, "these are the results") }) {
					t.Fatalf("not checked %q", notChecked(s))
				}
				if d := e.gbAudit(); !strings.HasPrefix(d, tc.prefix) {
					t.Fatalf("audit %q", d)
				}
				if !h.gvm.seen("delete_task") || !h.gvm.seen("delete_port_list") {
					t.Fatalf("cmds %q", h.gvm.cmds)
				}
				h.gvm.mu.Lock()
				reads, stops := 0, 0
				for _, c := range h.gvm.cmds {
					reads += map[bool]int{true: 1}[c == "get_reports"]
					stops += map[bool]int{true: 1}[c == "stop_task"]
				}
				h.gvm.mu.Unlock()
				if tc.name == "the cap cut the report of a finished task" && (reads != 2 || stops != 0) {
					t.Fatalf("get_reports %d, stop_task %d: the report was not read again", reads, stops)
				}
			})
		})
	}
}

// A Stop while the task is being stopped at the cap reads nothing more: the step is stopped, the task stopped and deleted.
func TestContract_INV25_StopDuringTheCap(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e, h := gbEnv(t)
		e.enable()
		e.svc.gb().poll = gbPollDefault
		h.gvm.with(func(g *fakeGVM) {
			g.states, g.stopTo = []string{"Running"}, "Stop Requested"
			g.onPoll = func() {
				if h.gvm.seen("stop_task") { // a poll of gbPartial: the customer presses Stop
					e.svc.StopScan(context.Background(), "admin@acme.example")
				}
			}
		})
		ips := e.detect(ipA)
		if _, err := e.commit(ips[0].ID); err != nil {
			t.Fatal(err)
		}
		e.acceptTerms(ips[0].ID, false)
		e.svc.SetRunner(&fakeRunner{content: gbOpen()})
		snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
		if err == nil {
			t.Fatal("a stopped run reads as done")
		}
		if snap.GreenboneRun.State != GBRunStopped || len(snap.Greenbone) != 0 || !slices.Contains(notChecked(snap), gbStoppedLine(personStop("admin@acme.example"), false)) || !h.gvm.seen("delete_task") {
			t.Fatalf("run %+v, not checked %q, cmds %q, %v", snap.GreenboneRun, notChecked(snap), h.gvm.cmds, err)
		}
	})
}

// A scan OpenVAS ended without Vedette's stop (Stopped or Interrupted: a crash, a gvmd restart, a person in
// OpenVAS's own interface) is "ended", never "did not scan": the line says so, and the rows its report holds are shown; a report that
// cannot be read claims no count. A task it ended before it was ever seen scanning (Requested -> Interrupted at
// 0 %, its scanner not connected) did not run: no "partly scanned" check line, and no line says it ended "by itself".
func TestContract_INV25_EndedByOpenVAS(t *testing.T) {
	t.Parallel()
	reason := "OpenVAS reports it as interrupted; Vedette did not stop it."
	for _, tc := range []struct {
		name   string
		states []string
		fail   bool
		rows   int
		state  string
		line   string
		check  bool
	}{
		{"report read", []string{"Running", "Interrupted"}, false, 4, GBRunEnded, notGBEnded + reason, true},
		{"report unreadable", []string{"Running", "Interrupted"}, true, 0, GBRunEnded, notGBEnded + reason + notGBEndedUnread, false},
		{"never seen scanning", []string{"Requested", "Interrupted"}, false, 0, GBRunNotRun, notGBEndedEarly + reason, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			e.enable()
			h.gvm.with(func(g *fakeGVM) {
				g.states = tc.states
				if tc.fail {
					g.fail = map[string]bool{"get_reports": true}
				}
				if tc.rows == 0 {
					g.report = gbEmptyReport
				}
			})
			s := e.scanIP(gbOpen())
			if s.GreenboneRun.State != tc.state || len(s.Greenbone) != tc.rows || !slices.Contains(notChecked(s), tc.line) || h.gvm.seen("stop_task") ||
				slices.ContainsFunc(notChecked(s), func(l string) bool { return strings.Contains(l, "by itself") }) {
				t.Fatalf("run %+v, rows %d, not checked %q, cmds %q", s.GreenboneRun, len(s.Greenbone), notChecked(s), h.gvm.cmds)
			}
			if has := slices.ContainsFunc(s.Checks, func(c CheckRow) bool { return c.Kind == "greenbone" }); has != tc.check {
				t.Fatalf("checks %+v", s.Checks)
			}
		})
	}
}

// The probe row's port list is clipped with its count, so a row of 40 five-digit ports keeps what follows it.
func TestGreenboneProbePortsAreClipped(t *testing.T) {
	t.Parallel()
	var ports []int
	for p := range 40 {
		ports = append(ports, 10000+p)
	}
	got := gbProbePorts(ports)
	if len(got) > 70 || !strings.HasPrefix(got, "T:10000,10001,") || !strings.HasSuffix(got, ",… (40 ports)") {
		t.Fatalf("%q", got)
	}
	if got := gbProbePorts([]int{22, 443}); got != "T:22,443" {
		t.Fatalf("%q", got)
	}
}

// ipTarget is the id of the target of ipA (scanIP's).
func (e *env) ipTarget() string {
	e.t.Helper()
	ip := ipA
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

// ---- more Greenbone cases ----

// The brute-force and default-account checkboxes must be read back "yes", a config of another GMP user is not taken, and a
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
		// Generic web application scanning, safe_checks and the families are read back too
		{"web scanning option missing", func(g *fakeGVM) { g.noWebPref = true }, `the OpenVAS feed has no "Enable generic web application scanning" option`},
		{"web scanning not kept off", func(g *fakeGVM) { g.keepWeb = true }, `OpenVAS did not keep "Enable generic web application scanning" off`},
		{"families not kept", func(g *fakeGVM) { g.keepFamily = true }, `OpenVAS did not keep the family "Brute force attacks" off`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			e.enable()
			h.gvm.with(tc.set)
			s := e.scanIP(gbOpen())
			if h.gvm.seen("create_task") || h.gvm.seen("start_task") || !slices.ContainsFunc(notChecked(s), func(l string) bool { return strings.Contains(l, tc.want) }) {
				t.Fatalf("cmds %q, not checked %q", h.gvm.cmds, notChecked(s))
			}
		})
	}
}

// A task an earlier scan left running is stopped and deleted before a new one starts (its target and port list too); a task or
// port list of another GMP user is not touched;
// one that cannot be deleted while it stops blocks the new task; a failed cleanup is logged, audited and said on the page.
func TestContract_INV25_LeftoversAndCleanup(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.leftover = "Running" })
	s := e.scanIP(gbOpen())
	if len(s.Greenbone) != 4 || h.gvm.leftoverState() != "" || h.gvm.touched("eeeeeeee-ffff-4000-8111-222222222222") {
		t.Fatalf("rows %d, leftover %q, cmds %q", len(s.Greenbone), h.gvm.leftoverState(), h.gvm.cmds)
	}
	// Its leftover port list too (after the targets), never another user's
	if !h.gvm.touched("99999999-eeee-4fff-8000-111111111111") || h.gvm.touched("88888888-eeee-4fff-8000-111111111111") {
		t.Fatalf("cmds %q, bodies %q", h.gvm.cmds, h.gvm.bodies)
	}
	e2, h2 := gbEnv(t)
	e2.enable()
	h2.gvm.with(func(g *fakeGVM) { g.leftover, g.fail = "Stop Requested", map[string]bool{"delete_task": true} })
	s2 := e2.scanIP(gbOpen())
	if h2.gvm.seen("create_task") || !slices.ContainsFunc(notChecked(s2), func(l string) bool { return strings.Contains(l, "still stopping") }) {
		t.Fatalf("cmds %q, not checked %q", h2.gvm.cmds, notChecked(s2))
	}
	e3, h3 := gbEnv(t)
	e3.enable()
	h3.gvm.with(func(g *fakeGVM) { g.fail = map[string]bool{"delete_target": true} })
	s3 := e3.scanIP(gbOpen())
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

// A stop during the Greenbone step keeps the snapshot of the other steps, says Greenbone was stopped, stops gvmd's task, and
// writes one exposure.scan row (the snapshot) and one exposure.greenbone_scan row (stopped).
func TestContract_INV25_StopKeepsTheEarlierResults(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.svc.gb().poll = time.Millisecond
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running"}
		g.onPoll = func() { e.svc.StopScan(context.Background(), "admin@acme.example") }
	})
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(ips[0].ID, false)
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}}}})
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	if err == nil {
		t.Fatal("a stopped run reads as done")
	}
	if run := e.svc.CurrentScan(e.ctx()); run == nil || run.Status != RunStopped {
		t.Fatalf("run = %+v", run)
	}
	// why and by whom it was stopped, and when (the page shows the time in the viewer's zone)
	st := snap.GreenboneRun.Stop
	if len(snap.Ports) != 1 || !slices.Contains(notChecked(snap), "OpenVAS was stopped before it finished (admin@acme.example pressed Stop), so its results are not shown. The results of the other checks above are kept.") ||
		!h.gvm.seen("stop_task") || snap.GreenboneRun.State != GBRunStopped || st == nil || st.Reason != StopPerson || st.By == nil || *st.By != "admin@acme.example" ||
		snap.GreenboneRun.EndedAt == nil {
		t.Fatalf("ports %d, not checked %q, cmds %q, run %+v", len(snap.Ports), notChecked(snap), h.gvm.cmds, snap.GreenboneRun)
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

// A deadline is slow, not unreadable; a slow gvmd soon after Up reads as loading, later as an error that says it was slow.
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

// A read or a scan that saw "on" just before an administrator turned Greenbone off never starts it again.
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

// The note about results that are not kept appears only when more than 200 are kept.
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

// Flow 16 follows the setting.
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

// ---- Greenbone setting and feed ----

// Greenbone can be enabled (no review gate any more) but scans only a target whose testing terms are accepted: without
// them "Not checked" says so and gvmd is never asked; with the disruptive tick its own config turns on brute force, default accounts
// and DoS, the brute-force options and safe_checks off, all read back; withdrawn terms are seen right before the step.
func TestContract_INV25_TermsDecideGreenbone(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.terms = nil
	e.enable()
	before := h.dialCount() // reading the setting may ask gvmd whether it is ready; the scan must not
	s := e.scanIP(gbOpen())
	if !slices.Contains(notChecked(s), notGBTerms) || len(s.Greenbone) != 0 || h.dialCount() != before {
		t.Fatalf("not checked %q, dials %d -> %d", notChecked(s), before, h.dialCount())
	}
	id := e.ipTarget()
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
	if c.web != nil || h.gvm.seen("get_nvts") { // #915: the disruptive level keeps the whole family, growing
		t.Fatalf("web application tests = %q", c.web)
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
	got := snap
	if !slices.ContainsFunc(notChecked(got), func(l string) bool { return strings.Contains(l, "did not keep safe checks off") }) {
		t.Fatalf("not checked %q", notChecked(got))
	}
	// withdrawn: the step checks the terms again and sends nothing
	if _, err := e.svc.RevokeTerms(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	dials := h.dialCount()
	o, err := e.svc.greenboneStep(e.ctx(), ScanTarget{ID: id, Kind: KindIP, Value: ipA, User: "admin@acme.example", Mode: ScanMode{Full: true, Disruptive: true}}, []int{443})
	if err != nil || len(o.not) != 1 || o.not[0].Text != notGBTerms || h.dialCount() != dials {
		t.Fatalf("step = %+v, %v, dials %d -> %d", o, err, dials, h.dialCount())
	}
}

// #915: a gvmd that does not keep the web-root traversal test out of the deep config starts nothing, and says why; a feed answer
// with an NVT id that is not Greenbone's is refused.
func TestContract_INV25_WebRootTraversalOffFailsClosed(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.keepNVTs = true })
	s := e.scanIP(gbOpen())
	if h.gvm.seen("create_task") || len(s.Greenbone) != 0 ||
		!slices.ContainsFunc(notChecked(s), func(l string) bool { return strings.Contains(l, "did not keep the web-root traversal test off") }) {
		t.Fatalf("not checked %q, cmds %q", notChecked(s), h.gvm.cmds)
	}
	for name, set := range map[string]func(*fakeGVM){
		"part": func(g *fakeGVM) { g.keepNVTs, g.partNVTs = false, true }, // r1 M1: most of the family missing
		"not an OID": func(g *fakeGVM) { // a feed answer with an id that is not an OID
			g.partNVTs, g.webExtra = false, []string{"1.3.6.1.4.1.25623.1.0.1;rm"}
		},
	} {
		h.gvm.with(func(g *fakeGVM) { g.cmds = nil; set(g) })
		e.advance(ScanEvery)
		s := e.scanIP(gbOpen())
		if h.gvm.seen("create_task") || len(s.Greenbone) != 0 {
			t.Fatalf("%s: started, cmds %q", name, h.gvm.cmds)
		}
	}
}

// #915: an NVT a feed update adds to Web application abuses is in the deep config from the next scan on, and the check line says
// the web-root traversal test is off.
func TestContract_INV25_WebFamilyFollowsTheFeed(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	s := e.scanIP(gbOpen())
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.Contains(c.Text, "web-root traversal test off")
	}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
	h.gvm.with(func(g *fakeGVM) { g.webExtra = []string{"1.3.6.1.4.1.25623.1.0.200000"} })
	e.advance(ScanEvery)
	e.scanIP(gbOpen())
	if c, _ := h.gvm.cfg(gbDeep.name); !slices.Contains(c.web, "1.3.6.1.4.1.25623.1.0.200000") || slices.Contains(c.web, gmpWebRootTravOID) {
		t.Fatalf("web application tests = %q", c.web)
	}
}

// The check line tells high and medium results from the Low ones, which are hardening notes.
func TestContract_INV25_LowIsAHardeningNote(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	e.enable()
	s := e.scanIP(gbOpen())
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.Contains(c.Text, "4 results with QoD 70 or more (2 high or medium, 2 hardening notes)")
	}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
}

// The feed is updated a week after Greenbone was enabled, then weekly; never while a scan holds the slot, and no scan starts
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
	e.svc.execs["run-1"] = &scanExec{targetID: "xt-1", started: true, done: make(chan struct{})}
	e.svc.runMu.Unlock()
	run()
	if h.syncCount() != 0 {
		t.Fatal("updated during a scan")
	}
	e.svc.runMu.Lock()
	delete(e.svc.execs, "run-1")
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
	if ae := (*APIError)(nil); !errors.As(scanErr, &ae) || !strings.Contains(ae.Message, "at most 60 minutes") || !strings.Contains(ae.Message, "(started ") {
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

// The setting with its feed update fits the API schema, before the first update and after one.
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

// The next update counts from the later of the last update and the last time Greenbone was turned on, and the page
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

// Turn off cancels a running feed update and waits for it to end before it stops Greenbone.
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

// The two answers of a real gvmd, as measured. The filtered one (preference="safe_checks", no nvt_oid) is empty, so it
// can never say "not kept"; the read-back now reads the whole list, where safe_checks is the preference with an empty nvt oid.
func TestSafeChecksIsTheScannerPreference(t *testing.T) {
	t.Parallel()
	read := func(answer string) gmpPrefs {
		var p gmpPrefs
		if _, err := decodeGMP(strings.NewReader(answer), "get_preferences", &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, ok := read(`<get_preferences_response status="200" status_text="OK"></get_preferences_response>`).scanner("safe_checks"); ok {
		t.Fatal("the empty filtered answer holds safe_checks")
	}
	all := read(`<get_preferences_response status="200" status_text="OK">` +
		`<preference><nvt oid="1.3.6.1.4.1.25623.1.0.100315"><name>Ping Host</name></nvt><id>5</id><hr_name>safe_checks</hr_name><name>safe_checks</name><type>checkbox</type><value>no</value></preference>` +
		`<preference><nvt oid=""><name></name></nvt><id></id><hr_name>safe_checks</hr_name><name>safe_checks</name><type></type><value>yes</value><default>1</default></preference>` +
		`</get_preferences_response>`)
	if x, ok := all.scanner("safe_checks"); !ok || x.Value != "yes" {
		t.Fatalf("scanner safe_checks = %+v %v", x, ok)
	}
}

// LEAN-1 stage A: Greenbone runs without its SCAP and CERT data. gvmd's get_feeds then lists only the NVT and gvmd data feeds;
// readiness waits for nothing else (gvmd's own feed lock shows on the gvmd data feed), a whole scan works, and the client never sends
// a command that needs the SCAP or CERT database (get_info, get_resource_names) or asks for a report format (format_id: the
// report-formats data are a stage B candidate).
func TestContract_INV25_NeedsNoSCAPOrCERTData(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.dataSync = true })
	if v := e.gbState(); v.State != GBLoading {
		t.Fatalf("gvmd's feed lock taken = %+v", v)
	}
	h.gvm.with(func(g *fakeGVM) { g.dataSync = false })
	if v := e.gbState(); v.State != GBReady {
		t.Fatalf("NVT and gvmd data loaded, no SCAP or CERT feed = %+v", v)
	}
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Running", "Done"} })
	if s := e.scanIP(gbOpen()); len(s.Greenbone) != 4 {
		t.Fatalf("greenbone = %+v", s.Greenbone)
	}
	h.gvm.with(func(g *fakeGVM) {
		for i, c := range g.cmds {
			if c == "get_info" || c == "get_resource_names" || strings.Contains(g.bodies[i], "format_id") {
				t.Errorf("sent %s %q, which needs the SCAP/CERT data or a report format", c, g.bodies[i])
			}
		}
	})
}

// The setting shows the date of the vulnerability tests OpenVAS has loaded, read from gvmd's get_feeds, from the first feed
// load at Enable on (also while it loads), so a working OpenVAS before its first weekly update never reads as "never updated". The
// weekly update stays due a week after Enable.
func TestContract_INV25_FeedDateFromGvmd(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	if v := e.gbState(); v.State != GBOff || v.Feed != nil {
		t.Fatalf("off before the first enable: %s %+v", v.State, v.Feed)
	}
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.syncing = true })
	v := e.gbState()
	if v.State != GBLoading || v.Feed == nil || str(v.Feed.NVTVersion) != "202611140611" {
		t.Fatalf("while loading: %s %+v", v.State, v.Feed)
	}
	h.gvm.with(func(g *fakeGVM) { g.syncing = false })
	v = e.gbState()
	if v.State != GBReady || v.Feed == nil || str(v.Feed.NVTVersion) != "202611140611" || str(v.Feed.NVTDate) != "2026-11-14T06:11:00.000Z" ||
		v.Feed.CheckedAt != store.FormatTS(e.clock.Now()) {
		t.Fatalf("ready: %s %+v", v.State, v.Feed)
	}
	if v.FeedSync.LastAt != nil || v.FeedSync.NextAt == nil || *v.FeedSync.NextAt != store.FormatTS(parseTSMust(t, *v.ChangedAt).Add(GreenboneSyncEvery)) {
		t.Fatalf("weekly update = %+v (changed %s)", v.FeedSync, str(v.ChangedAt))
	}
	if _, err := into[oas.ExposureGetExposureGreenboneOK](v); err != nil {
		t.Fatal(err)
	}
	// a version gvmd sends in another shape is shown without a date; one Vedette would not print is not shown at all
	h.gvm.with(func(g *fakeGVM) { g.nvtVersion = "20261114" })
	if v = e.gbState(); v.Feed == nil || str(v.Feed.NVTVersion) != "20261114" || v.Feed.NVTDate != nil {
		t.Fatalf("8 digits: %+v", v.Feed)
	}
	h.gvm.with(func(g *fakeGVM) { g.nvtVersion = "&lt;b&gt;x" })
	if v = e.gbState(); v.State != GBReady || v.Feed == nil || v.Feed.NVTVersion != nil || v.Feed.NVTDate != nil {
		t.Fatalf("markup: %s %+v", v.State, v.Feed)
	}
	// get_feeds refused: the state says so; the last feed read is kept, never replaced by a guess
	h.gvm.with(func(g *fakeGVM) { g.nvtVersion = ""; g.fail = map[string]bool{"get_feeds": true} })
	if v = e.gbState(); v.State != GBError || v.Feed == nil || v.Feed.NVTVersion != nil {
		t.Fatalf("refused: %s %+v", v.State, v.Feed)
	}
	// off: no feed line
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	if v = e.gbState(); v.State != GBOff || v.Feed != nil {
		t.Fatalf("off: %s %+v", v.State, v.Feed)
	}
}

func parseTSMust(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := parseTS(s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// T10: gvmd's get_feeds answer is untrusted. The NVT version is read only in the shape Vedette prints and its date only from
// "YYYYMMDDhhmm" (UTC); a feed list without an NVT feed gives nothing; an answer that is not GMP is refused (fail closed).
func TestGMPFeedsNVTVersion(t *testing.T) {
	t.Parallel()
	const head = `<get_feeds_response status="200" status_text="OK"><feed_owner_set>0</feed_owner_set><feed_roles_set>0</feed_roles_set><feed_resources_access>1</feed_resources_access>`
	feed := func(typ, ver string) string {
		return `<feed><type>` + typ + `</type><name>Greenbone Community Feed</name><version>` + ver + `</version><description>x</description></feed>`
	}
	cases := []struct {
		name, raw, version, date string
	}{
		{"gvmd 26 without SCAP/CERT", head + feed("NVT", "202611140611") + feed("GVMD_DATA", "202611130507") + `</get_feeds_response>`, "202611140611", "2026-11-14T06:11:00.000Z"},
		{"spaces around", head + feed("NVT", " 202611140611\n") + `</get_feeds_response>`, "202611140611", "2026-11-14T06:11:00.000Z"},
		{"only gvmd data", head + feed("GVMD_DATA", "202611130507") + `</get_feeds_response>`, "<nil>", ""},
		{"no feed", head + `</get_feeds_response>`, "<nil>", ""},
		{"8 digits", head + feed("NVT", "20261114") + `</get_feeds_response>`, "20261114", ""},
		{"not a month", head + feed("NVT", "202613140611") + `</get_feeds_response>`, "202613140611", ""},
		{"last century", head + feed("NVT", "199911140611") + `</get_feeds_response>`, "199911140611", ""},
		{"too long", head + feed("NVT", strings.Repeat("1", 41)) + `</get_feeds_response>`, "<nil>", ""},
		{"markup", head + feed("NVT", "&lt;script&gt;") + `</get_feeds_response>`, "<nil>", ""},
		{"empty", head + feed("NVT", "") + `</get_feeds_response>`, "<nil>", ""},
	}
	for _, tc := range cases {
		var f gmpFeeds
		if _, err := decodeGMP(&capReader{r: strings.NewReader(tc.raw), n: gmpMaxAnswer}, "get_feeds", &f); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		v, at := f.nvtFeed()
		gotDate := ""
		if at != nil {
			gotDate = store.FormatTS(*at)
		}
		if str(v) != tc.version || gotDate != tc.date {
			t.Errorf("%s: version %q date %q, want %q %q", tc.name, str(v), gotDate, tc.version, tc.date)
		}
	}
	for _, raw := range []string{``, `HTTP/1.1 502 Bad Gateway`, `<get_feeds_response status="200"><feed><type>NVT</type>`, `<get_configs_response status="200"/>`,
		`<get_feeds_response status="503" status_text="Service unavailable"/>`, `<get_feeds_response status="200"><feed><version>` + strings.Repeat("9", gmpMaxAnswer) + `</version></feed></get_feeds_response>`} {
		var f gmpFeeds
		if _, err := decodeGMP(&capReader{r: strings.NewReader(raw), n: gmpMaxAnswer}, "get_feeds", &f); err == nil {
			t.Errorf("accepted %.60q", raw)
		}
	}
}

// personStop is the stop of a person who pressed Stop.
func personStop(by string) *GreenboneStop { return &GreenboneStop{Reason: StopPerson, By: &by} }
