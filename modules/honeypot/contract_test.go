package honeypot_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/honeypot"
)

func sources(t *testing.T) map[string]*ast.File {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = af
	}
	if len(out) < 10 {
		t.Fatalf("only %d source files", len(out))
	}
	return out
}

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "honeypot", honeypot.Migrations, "hp_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// INV-1 (code side): the module cannot connect anywhere. It imports no dialer (net, net/http, os/exec) and never
// calls Dial; the host is a port. syscall is imported by tail.go alone, for the open flags O_NOFOLLOW and O_NONBLOCK of
// the log (the log folder belongs to the container), and nothing else of it is used. The packet-level proof (no packet leaves the container towards a source) is WP-08's.
// INV-14 / D-82: no signal is sent either: that would need a connection.
func TestContract_INV1_NoDialer(t *testing.T) {
	t.Parallel()
	banned := map[string]bool{"net": true, "net/http": true, "os/exec": true, "crypto/tls": true, "net/smtp": true}
	for name, f := range sources(t) {
		for _, im := range f.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if banned[p] || p == "syscall" && name != "tail.go" {
				t.Errorf("%s imports %s", name, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if se, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := se.X.(*ast.Ident); ok && id.Name == "syscall" && se.Sel.Name != "O_NOFOLLOW" && se.Sel.Name != "O_NONBLOCK" {
					t.Errorf("%s uses syscall.%s", name, se.Sel.Name)
				}
			}
			if c, ok := n.(*ast.CallExpr); ok {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(s.Sel.Name, "Dial") {
					t.Errorf("%s calls %s", name, s.Sel.Name)
				}
			}
			return true
		})
	}
}

// INV-2: five services, fixed ports; the generated configuration enables nothing else and opens no other port.
func TestContract_INV2_FivePorts(t *testing.T) {
	t.Parallel()
	want := map[honeypot.ServiceName]int{honeypot.SMB: 445, honeypot.RDP: 3389, honeypot.SSH: 22, honeypot.MSSQL: 1433, honeypot.HTTP: 80}
	if len(honeypot.Services) != 5 {
		t.Fatalf("%d services", len(honeypot.Services))
	}
	for s, p := range want {
		if s.Port() != p {
			t.Errorf("%s port %d", s, s.Port())
		}
	}
	raw, err := honeypot.RenderConfig(honeypot.ConfigInput{Enabled: honeypot.Services, LogPath: "/v/x.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	var on []string
	for k, v := range c {
		if b, ok := v.(bool); ok && b && strings.HasSuffix(k, ".enabled") {
			on = append(on, strings.TrimSuffix(k, ".enabled"))
		}
		if strings.HasSuffix(k, ".port") {
			svc := honeypot.ServiceName(strings.TrimSuffix(k, ".port"))
			if int(v.(float64)) != svc.Port() {
				t.Errorf("%s = %v", k, v)
			}
		}
	}
	slices.Sort(on)
	if !slices.Equal(on, []string{"http", "mssql", "rdp", "smb", "ssh"}) {
		t.Fatalf("enabled = %v", on)
	}
	none, _ := honeypot.RenderConfig(honeypot.ConfigInput{LogPath: "/v/x.jsonl"})
	if strings.Contains(string(none), `": true`) {
		t.Fatalf("nothing is on but the config enables something: %s", none)
	}
}

func TestRenderConfigGolden(t *testing.T) {
	t.Parallel()
	got, err := honeypot.RenderConfig(honeypot.ConfigInput{Enabled: []honeypot.ServiceName{honeypot.SSH, honeypot.SMB, honeypot.HTTP}, LogPath: "/vol/opencanary.jsonl", NASDecoy: true})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "opencanary.golden.json", got)
	tok, err := honeypot.RenderTokens([]string{"b.xlsx", "a.docx", "b.xlsx"}, "FILESRV-OLD")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "honeytokens.golden.json", tok)
	again, _ := honeypot.RenderConfig(honeypot.ConfigInput{Enabled: []honeypot.ServiceName{honeypot.HTTP, honeypot.SMB, honeypot.SSH}, LogPath: "/vol/opencanary.jsonl", NASDecoy: true})
	if string(again) != string(got) {
		t.Fatal("same state, different bytes")
	}
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(p, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p) //nolint:gosec // a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs:\n%s", name, got)
	}
}

// The trap log is bounded: the container rotates it (10 MiB, 3 copies), so a flood of connections cannot fill the file
// system of the database; the tailer follows the name and notices the rotation.
func TestRenderConfigBoundsTheTrapLog(t *testing.T) {
	t.Parallel()
	b, err := honeypot.RenderConfig(honeypot.ConfigInput{Enabled: []honeypot.ServiceName{honeypot.HTTP}, LogPath: "/x/opencanary.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Logger struct {
			Kwargs struct {
				Handlers map[string]map[string]any `json:"handlers"`
			} `json:"kwargs"`
		} `json:"logger"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	h := c.Logger.Kwargs.Handlers["file"]
	if h["class"] != "logging.handlers.RotatingFileHandler" || h["maxBytes"] != float64(10<<20) || h["backupCount"] != float64(3) || h["filename"] != "/x/opencanary.jsonl" {
		t.Fatalf("trap log handler %v: not a bounded rotating file", h)
	}
}

// FORBID-2: the configuration holds no banner of the box itself (host name, box IP, OS) and no secret.
func TestContract_FORBID2_NoBoxBannerNoSecret(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if _, err := e.svc.AddToken(e.ctx(), "a@x", honeypot.TokenInput{Type: honeypot.TokenCredential, Name: "svc-backup-old", PlantAt: "wiki"}); err != nil {
		t.Fatal(err)
	}
	pw := e.tokenPassword("svc-backup-old")
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{honeypot.ConfFile, honeypot.TokensFile} {
		b, err := os.ReadFile(filepath.Join(e.dir, "config", f)) //nolint:gosec // a file of the test directory
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"vedette-hq", "192.168.10.2\"", pw, "svc-backup-old"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
}

func (e *env) tokenPassword(name string) string {
	e.t.Helper()
	l, err := e.svc.Tokens(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, tk := range l {
		if tk.Name == name && tk.Password != nil {
			return *tk.Password
		}
	}
	e.t.Fatalf("no credential token %s", name)
	return ""
}

// FORBID-5: nothing in the module's API edits or deletes a hit.
func TestContract_FORBID5_NoHitEditing(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`(?i)(delete|patch|put|update|edit|remove|clear).*hit`)
	for _, typ := range []reflect.Type{reflect.TypeFor[*honeypot.HoneypotHandlers](), reflect.TypeFor[*honeypot.Service]()} {
		for i := range typ.NumMethod() {
			if n := typ.Method(i).Name; re.MatchString(n) {
				t.Errorf("%s has %s", typ, n)
			}
		}
	}
	for name, f := range sources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.BasicLit); ok && s.Kind == token.STRING && !strings.HasPrefix(name, "prune") && !strings.HasPrefix(name, "ingest") {
				if v := strings.ToUpper(s.Value); strings.Contains(v, "DELETE FROM HP_HITS") || strings.Contains(v, "UPDATE HP_HITS") {
					t.Errorf("%s writes hits: %s", name, s.Value)
				}
			}
			return true
		})
	}
}

// INV-3: the scanner of the box itself and broadcasts make no hit; the scanner is counted in ignored_7d.
func TestContract_INV3_ScannerAndBroadcastExcluded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.appendLog(
		sshNew("192.168.10.2", 40000, t0).json(), // the box itself
		ln{LogType: 4000, Src: "255.255.255.255", SrcPort: 1, DstPort: 22, At: t0}.json(),
		ln{LogType: 4000, Src: "192.168.10.107", SrcPort: 1, Dst: "192.168.10.255", DstPort: 22, At: t0}.json(), // to the LAN broadcast
		ln{LogType: 4000, Src: "224.0.0.251", SrcPort: 1, DstPort: 22, At: t0}.json(),
	)
	e.poll()
	if n := e.count(`SELECT count(*) FROM hp_hits`); n != 0 {
		t.Fatalf("%d hits", n)
	}
	o, _ := e.svc.Overview(e.ctx())
	if o.Ignored7d != 1 {
		t.Fatalf("ignored_7d = %d", o.Ignored7d)
	}
	if len(e.pub.all()) != 0 {
		t.Fatal("an excluded line was announced")
	}
}

// INV-4: test hits are listed but never counted, never published, never come from a device.
func TestContract_INV4_TestHitsNotCounted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	tok, _ := e.svc.AddToken(e.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenFile, Name: "Payroll", PlantAt: "x", Ext: "xlsx"})
	h1, err := e.svc.TestHit(e.ctx(), "op", honeypot.SSH)
	if err != nil || !h1.IsTest || h1.SrcName != nil || h1.SrcAssetID != nil || h1.SrcIP != "192.168.10.2" {
		t.Fatalf("%+v %v", h1, err)
	}
	h2, err := e.svc.TestScan(e.ctx(), "op")
	if err != nil || !h2.IsTest || h2.Kind != honeypot.KindScan || h2.Label != "Port scan across 2 decoy IPs" {
		t.Fatalf("%+v %v", h2, err)
	}
	h3, err := e.svc.TestToken(e.ctx(), "op", tok.ID)
	if err != nil || !h3.IsTest || h3.Kind != honeypot.KindToken || h3.Label != "File token Payroll" {
		t.Fatalf("%+v %v", h3, err)
	}
	o, _ := e.svc.Overview(e.ctx())
	if o.Summary.Today != 0 || o.Summary.Week != 0 || o.Summary.LastHitAt != nil || o.Summary.LastSrc != nil {
		t.Fatalf("summary counts tests: %+v", o.Summary)
	}
	for _, tr := range o.Traps {
		if tr.Hits7d != 0 || tr.LastHitAt != nil {
			t.Fatalf("trap counts tests: %+v", tr)
		}
	}
	if len(e.pub.all()) != 0 {
		t.Fatal("a test hit was announced")
	}
	l, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if len(l) != 3 {
		t.Fatalf("%d listed", len(l))
	}
	l, _ = e.svc.Hits(e.ctx(), honeypot.HitFilter{Asset: "a-box"})
	if len(l) != 0 {
		t.Fatal("a test hit belongs to the box device")
	}
	if tk, _ := e.svc.Tokens(e.ctx()); tk[0].Triggers != 0 || tk[0].LastTriggeredAt == nil {
		t.Fatalf("token counts: %+v", tk[0])
	}
	// PRE-1
	if _, err := e.svc.TestHit(e.ctx(), "op", honeypot.RDP); apiCode(t, err) != "trap_off" {
		t.Fatalf("%v", err)
	}
	e.inv.add(dev("a-new", "192.168.10.240", "NEWBOX", "pc"))
	if _, err := e.svc.TestHit(e.ctx(), "op", honeypot.SSH); apiCode(t, err) != "ip_in_use" {
		t.Fatalf("%v", err)
	}
}

// INV-5: the matrix of addresses and names of a Trap IP; the checks of a Trap IP in the order the form shows its fields.
func TestContract_INV5_IPValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	cases := []struct{ ip, code string }{
		{"", "bad_ip"}, {"nonsense", "bad_ip"}, {"192.168.010.240", "bad_ip"}, {"192.168.10.256", "bad_ip"}, {"::1", "bad_ip"}, {"::ffff:192.168.10.240", "bad_ip"},
		{"0.0.0.0", "bad_ip"},
		{"10.0.0.5", "ip_outside_lan"}, {"192.168.10.0", "ip_outside_lan"}, {"192.168.10.255", "ip_outside_lan"}, {"192.168.11.5", "ip_outside_lan"},
		{"192.168.10.2", "ip_is_box"},
		{"192.168.10.107", "ip_in_use"}, {"192.168.10.10", "ip_in_use"},
	}
	for _, c := range cases {
		if _, err := e.tryAddTrapIP("BUILD-01", c.ip, honeypot.Linux, honeypot.SSH); apiCode(t, err) != c.code {
			t.Errorf("trap IP %q: %v, want %s", c.ip, err, c.code)
		}
	}
	d := e.addTrapIP("BUILD-01", "192.168.10.241", honeypot.Linux, honeypot.SSH)
	if d.ID == "" || len(d.Services) != 1 || !d.Enabled {
		t.Fatalf("%+v", d)
	}
	if _, err := e.tryAddTrapIP("BUILD-02", "192.168.10.241", honeypot.Linux, honeypot.SSH); apiCode(t, err) != "ip_in_use" {
		t.Fatalf("second Trap IP on the same IP: %v", err)
	}
	if _, err := e.tryAddTrapIP("build-01", "192.168.10.242", honeypot.Linux, honeypot.SSH); apiCode(t, err) != "name_in_use" {
		t.Fatalf("a name another Trap IP has (any case): %v", err)
	}
	// names
	for _, n := range []string{"", "x_y", "-AB", "AB-", "123456", "ABCDEFGHIJKLMNOP", "SRV-FILE"} {
		_, err := e.tryAddTrapIP(n, "192.168.10.242", honeypot.Custom, honeypot.SSH)
		want := "bad_name"
		if n == "SRV-FILE" {
			want = "name_in_use"
		}
		if apiCode(t, err) != want {
			t.Errorf("name %q: %v", n, err)
		}
	}
	if _, err := e.tryAddTrapIP("X1", "192.168.10.243", "toaster", honeypot.SSH); apiCode(t, err) != "bad_preset" {
		t.Fatal(err)
	}
	if _, err := e.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "X1", IP: "192.168.10.243", Preset: honeypot.Custom, Vendor: ptr("acme"), Services: []honeypot.ServiceName{honeypot.SSH}}); apiCode(t, err) != "bad_vendor" {
		t.Fatal(err)
	}
	for _, svcs := range [][]honeypot.ServiceName{nil, {"telnet"}, {honeypot.SSH, honeypot.SSH}} {
		if _, err := e.tryAddTrapIP("X1", "192.168.10.243", honeypot.Custom, svcs...); apiCode(t, err) != "bad_services" {
			t.Errorf("services %v: %v", svcs, err)
		}
	}
	// a change runs the same checks; the Trap IP may keep its own name and address
	if _, err := e.svc.EditTrapIP(e.ctx(), "a", d.ID, honeypot.TrapIPInput{Name: "BUILD-01", IP: "192.168.10.241", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.SSH, honeypot.HTTP}}); err != nil {
		t.Fatalf("an edit that keeps the name and address: %v", err)
	}
	if _, err := e.svc.EditTrapIP(e.ctx(), "a", d.ID, honeypot.TrapIPInput{Name: "BUILD-01", IP: "192.168.10.107", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.SSH}}); apiCode(t, err) != "ip_in_use" {
		t.Fatalf("edit onto a device: %v", err)
	}
	if _, err := e.svc.EditTrapIP(e.ctx(), "a", "tip-nope", honeypot.TrapIPInput{Name: "X2", IP: "192.168.10.244", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.SSH}}); apiCode(t, err) != "not_found" {
		t.Fatalf("edit of a missing Trap IP: %v", err)
	}
	// no LAN declared (fresh install)
	e.inv.mu.Lock()
	e.inv.ranges = nil
	e.inv.mu.Unlock()
	if _, err := e.tryAddTrapIP("X3", "192.168.10.242", honeypot.Linux, honeypot.SSH); apiCode(t, err) != "no_lan" {
		t.Fatal(err)
	}
	if o, _ := e.svc.Overview(e.ctx()); o.LAN != nil {
		t.Fatal("lan should be null")
	}
}

// INV-6, INV-7, FORBID-1: a device that later takes a Trap IP's address makes it conflict and stop.
func TestContract_INV6_INV7_ConflictStopsListening(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	o, _ := e.svc.Overview(e.ctx())
	states := map[honeypot.ServiceName]string{}
	for _, tr := range o.Traps {
		states[tr.Service] = tr.State
	}
	if states[honeypot.SSH] != "listening" || states[honeypot.SMB] != "listening" || states[honeypot.RDP] != "off" {
		t.Fatalf("states %v", states)
	}
	if !e.host.running || !e.host.ips[addr("192.168.10.240")] {
		t.Fatalf("host %v %v", e.host.running, e.host.ips)
	}
	conf, _ := os.ReadFile(filepath.Join(e.dir, "config", honeypot.ConfFile))
	if !strings.Contains(string(conf), `"ssh.enabled": true`) || !strings.Contains(string(conf), `"rdp.enabled": false`) {
		t.Fatalf("conf: %s", conf)
	}
	// a device appears on the Trap IP's address
	e.inv.add(dev("a-late", "192.168.10.240", "LATE-PC", "pc"))
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	o, _ = e.svc.Overview(e.ctx())
	if d := e.trapIP(e.main); d.State != honeypot.StateConflict || d.DeviceID == nil || *d.DeviceID != "a-late" || d.DeviceName == nil || *d.DeviceName != "LATE-PC" {
		t.Fatalf("trap IP on a device: %+v", d)
	}
	for _, tr := range o.Traps {
		if tr.Enabled && tr.State != "conflict" {
			t.Fatalf("%s is %s", tr.Service, tr.State)
		}
	}
	if e.host.running || e.host.ips[addr("192.168.10.240")] {
		t.Fatalf("still listening on a device's IP: %v %v", e.host.running, e.host.ips)
	}
	conf, _ = os.ReadFile(filepath.Join(e.dir, "config", honeypot.ConfFile))
	if strings.Contains(string(conf), `": true`) {
		t.Fatalf("config enables a service on a device IP: %s", conf)
	}
	if err := e.enable(e.main, false); err != nil {
		t.Fatal(err)
	}
	if err := e.enable(e.main, true); apiCode(t, err) != "ip_in_use" {
		t.Fatalf("turning on a Trap IP a device sits on: %v", err)
	}
}

// INV-7 on a machine that cannot run the container: nothing listens and the reason is reported.
func TestContract_INV7_NotAnApplianceNeverListens(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.host = newHost(false); e.cfg.Host = e.host })
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	o, _ := e.svc.Overview(e.ctx())
	for _, tr := range o.Traps {
		if tr.State == "listening" {
			t.Fatalf("%s listens on a machine that is not an appliance", tr.Service)
		}
	}
	if !o.Traps[2].Enabled || o.Traps[2].State != honeypot.StateFailed || o.Problem == nil || !strings.Contains(*o.Problem, "not an appliance") {
		t.Fatalf("ssh trap: %+v, problem %v", o.Traps[2], o.Problem)
	}
	ok, why := e.svc.HostStatus()
	if ok || !strings.Contains(why, "appliance") {
		t.Fatalf("status %v %q", ok, why)
	}
	if calls := e.host.log(); len(calls) != 0 {
		t.Fatalf("host was asked to act: %v", calls)
	}
	// the files are still made from the database
	if _, err := os.Stat(filepath.Join(e.dir, "config", honeypot.ConfFile)); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRemovesStaleIPsAndStopsWhenNothingIsOn(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	d := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if !e.host.ips[addr("192.168.10.241")] || !e.host.ips[addr("192.168.10.240")] {
		t.Fatalf("%v", e.host.ips)
	}
	// POST-5: delete a Trap IP, its address goes
	if err := e.svc.DeleteTrapIP(e.ctx(), "a", d.ID); err != nil {
		t.Fatal(err)
	}
	// a new process only knows what the database says
	svc2, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.host.ips[addr("192.168.10.241")] {
		t.Fatal("deleted Trap IP still has its IP")
	}
	if err := e.enable(e.main, false); err != nil {
		t.Fatal(err)
	}
	if err := svc2.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.host.running || len(e.host.ips) != 0 {
		t.Fatalf("running=%v ips=%v", e.host.running, e.host.ips)
	}
	// The service that was told, but whose Apply has not run, says so: the host has not confirmed (S-HP-1, "stopping").
	if o, _ := e.svc.Overview(e.ctx()); o.Traps[0].State != honeypot.StateStopping {
		t.Fatalf("a trap turned off, not yet applied: %s", o.Traps[0].State)
	}
	if o, _ := svc2.Overview(e.ctx()); o.Traps[0].State != honeypot.StateOff {
		t.Fatalf("trap after being turned off and applied: %s", o.Traps[0].State)
	}
}

// INV-8, POST-1, INV-9: one real connection is one hit with the right fields; the source device is looked up at read
// time; newest first; the detail has the honeypot lines marked, and the lines of the logs module when there is one.
func TestContract_POST1_INV8_INV9_RealConnection(t *testing.T) {
	t.Parallel()
	logs := fakeLogs{lines: []honeypot.LogEvent{{TS: t0.Add(-4 * time.Minute), Source: "firewall", Text: "Firewall: allowed"}, {TS: t0, Source: "honeypot", Text: "ours, skipped"}}}
	e := newEnv(t, func(e *env) { e.cfg.Logs = logs })
	e.setup()
	src := "192.168.10.107"
	e.now = t0.Add(2 * time.Hour) // lines from the future are clamped to now
	e.appendLog(
		sshNew(src, 51000, t0).json(),
		sshLogin(src, 51000, t0.Add(time.Second), "root").json(),
		sshLogin(src, 51000, t0.Add(time.Second), "root").json(), // the same line again: nothing changes
		sshNew("192.168.10.157", 52000, t0.Add(time.Hour)).json(),
	)
	e.poll()
	if n := e.count(`SELECT count(*) FROM hp_hits`); n != 2 {
		t.Fatalf("%d hits, want one per connection", n)
	}
	pubs := e.pub.all()
	if len(pubs) != 2 || pubs[0].Name != "honeypot.hit.created" {
		t.Fatalf("published %+v", pubs)
	}
	data := pubs[0].Data.(honeypot.HitEventData)
	if data.SrcIP != src || data.Service != "ssh" || data.Label != "SSH" || data.ID == "" || data.Port != 22 {
		t.Fatalf("%+v", data)
	}
	// The response trigger (S-RESP-3) reads what was touched and the source device the inventory knew when the hit was stored.
	if data.Decoy == "" || data.SrcAssetID != "a-pc07" {
		t.Fatalf("decoy %q, source device %q", data.Decoy, data.SrcAssetID)
	}
	if d := pubs[1].Data.(honeypot.HitEventData); d.SrcAssetID != "" || d.Decoy == "" {
		t.Fatalf("unknown source: %+v", d)
	}
	l, err := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if err != nil || len(l) != 2 || l[0].SrcIP != "192.168.10.157" {
		t.Fatalf("%+v %v", l, err)
	}
	if l[0].SrcName != nil || l[0].SrcAssetID != nil {
		t.Fatalf("unknown source has a name: %+v", l[0])
	}
	if l[1].SrcName == nil || *l[1].SrcName != "PC-HR-01" || *l[1].SrcAssetID != "a-pc07" || l[1].Kind != honeypot.KindService || *l[1].Service != honeypot.SSH || *l[1].Port != 22 || l[1].IsTest {
		t.Fatalf("%+v", l[1])
	}
	if l[1].SourceIP() != src {
		t.Fatal("source_ip")
	}
	if !strings.Contains(l[1].Excerpt, `account "root"`) || strings.Contains(l[1].Excerpt, "hunter2") {
		t.Fatalf("excerpt %q", l[1].Excerpt)
	}
	// the device changes its IP: the name follows the inventory (INV-8: looked up when read)
	e.inv.mu.Lock()
	e.inv.devices[1].IP = addr("192.168.10.108")
	e.inv.mu.Unlock()
	if l, _ = e.svc.Hits(e.ctx(), honeypot.HitFilter{}); l[1].SrcName != nil {
		t.Fatal("stale name")
	}
	e.inv.mu.Lock()
	e.inv.devices[1].IP = addr(src)
	e.inv.mu.Unlock()
	by, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{Asset: "a-pc07"})
	if len(by) != 1 || by[0].ID != l[1].ID {
		t.Fatalf("?asset= %+v", by)
	}
	if by, _ = e.svc.Hits(e.ctx(), honeypot.HitFilter{Asset: "nope"}); len(by) != 0 {
		t.Fatal("unknown asset lists hits")
	}
	d, err := e.svc.HitDetail(e.ctx(), l[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.WindowMinutes != 60 || d.TrapIP != "192.168.10.240" || d.TrapHostname != "FILESRV-OLD" || d.Asset == nil || d.Asset.Kind != "pc" || !d.Asset.Approved {
		t.Fatalf("%+v", d)
	}
	var marks, fw int
	for i, ev := range d.Events {
		if ev.Mark {
			marks++
		}
		if ev.Source == "firewall" {
			fw++
		}
		if i > 0 && ev.TS < d.Events[i-1].TS {
			t.Fatal("events not in time order")
		}
		if ev.Source == "honeypot" && ev.Text == "ours, skipped" {
			t.Fatal("honeypot line of the logs module duplicated")
		}
	}
	if marks < 1 || fw != 1 {
		t.Fatalf("marks=%d firewall=%d: %+v", marks, fw, d.Events)
	}
	if _, err := e.svc.HitDetail(e.ctx(), "hit-nope"); apiCode(t, err) != "not_found" {
		t.Fatal(err)
	}
	// without a logs module the field is there, empty of other sources
	e2 := newEnv(t)
	e2.setup()
	e2.appendLog(sshNew(src, 1, t0).json())
	e2.poll()
	h, _ := e2.svc.Hits(e2.ctx(), honeypot.HitFilter{})
	d2, _ := e2.svc.HitDetail(e2.ctx(), h[0].ID)
	if d2.Events == nil {
		t.Fatal("events must be an empty list, not null")
	}
	raw, _ := json.Marshal(d2)
	if !strings.Contains(string(raw), `"events":[`) {
		t.Fatalf("%s", raw)
	}
}

// POST-2, INV-10: a bait account or file produces a token hit; a deleted token no longer does; only credential tokens
// carry a password; file tokens carry a docx/xlsx name (POST-4).
func TestContract_INV10_POST2_POST4_Tokens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	cred, err := e.svc.AddToken(e.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenCredential, Name: "svc-backup-old", PlantAt: "Password manager"})
	if err != nil || cred.Password == nil || *cred.Password == "" || !regexp.MustCompile(`^svc_[a-z]{6}$`).MatchString(cred.Value) {
		t.Fatalf("%+v %v: the bait account is generated (svc_ and six letters), not the display name of the token", cred, err)
	}
	file, err := e.svc.AddToken(e.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenFile, Name: "Payroll 2026", PlantAt: `\\SRV\HR`, Ext: "xlsx"})
	if err != nil || file.Password != nil || file.Value != "Payroll-2026.xlsx" {
		t.Fatalf("%+v %v", file, err)
	}
	u, _ := e.svc.AddToken(e.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenURL, Name: "Wiki link", PlantAt: "wiki"})
	// D-465: without a Box address the URL token carries the box's IP, never its host name (vedette-hq here, "vedette" on many boxes)
	if u.Password != nil || !strings.HasPrefix(u.Value, "https://192.168.10.2:8443/t/") {
		t.Fatalf("%+v", u)
	}
	// D-468: the box runs no DNS server (D-81/D-82: no project servers), so a DNS token could never alert; none is made.
	if _, err := e.svc.AddToken(e.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenDNS, Name: "Backup host", PlantAt: "script"}); err == nil || !strings.Contains(err.Error(), "409 dns_unavailable") {
		t.Fatalf("DNS token: %v, want 409 dns_unavailable", err)
	}
	if n := e.count(`SELECT count(*) FROM hp_tokens WHERE type = 'dns'`); n != 0 {
		t.Fatalf("%d DNS tokens written", n)
	}
	withBox := newEnv(t, func(e *env) { e.cfg.BoxURL = func() string { return "https://vedette.office.lan:8443/" } })
	withBox.setup()
	if u, err := withBox.svc.AddToken(withBox.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenURL, Name: "Wiki link", PlantAt: "wiki"}); err != nil || !strings.HasPrefix(u.Value, "https://vedette.office.lan:8443/t/") {
		t.Fatalf("with a Box address: %+v %v", u, err)
	}
	noAddr := newEnv(t, func(e *env) { e.inv.box = honeypot.Box{Name: "vedette"} })
	if _, err := noAddr.svc.AddToken(noAddr.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenURL, Name: "Wiki link", PlantAt: "wiki"}); err == nil || !strings.Contains(err.Error(), "409 no_box_address") {
		t.Fatalf("no address known: %v, want 409 no_box_address", err)
	}
	list, _ := e.svc.Tokens(e.ctx())
	for _, tk := range list {
		if (tk.Type == honeypot.TokenCredential) != (tk.Password != nil) {
			t.Fatalf("password on %s token", tk.Type)
		}
	}
	if e.count(`SELECT count(*) FROM core_secret WHERE purpose = 'hp_token.password'`) != 1 {
		t.Fatal("bait password not in core_secret")
	}
	if e.count(`SELECT count(*) FROM hp_tokens WHERE value LIKE '%' || ? || '%'`, *cred.Password) != 0 {
		t.Fatal("password stored in the clear")
	}
	src := "192.168.10.157"
	e.appendLog(
		sshNew(src, 5000, t0).json(),
		sshLogin(src, 5000, t0.Add(time.Second), strings.ToUpper(cred.Value)).json(),
		ln{LogType: 5000, Src: src, Dst: "192.168.10.240", DstPort: 445, At: t0.Add(time.Minute), Data: map[string]any{"FILENAME": `HR\Payroll-2026.xlsx`, "USER": "x"}}.json(),
	)
	e.poll()
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	byKind := map[honeypot.HitKind][]honeypot.Hit{}
	for _, h := range hits {
		byKind[h.Kind] = append(byKind[h.Kind], h)
	}
	if len(byKind[honeypot.KindToken]) != 2 || len(byKind[honeypot.KindService]) != 2 {
		t.Fatalf("%+v", hits)
	}
	labels := []string{byKind[honeypot.KindToken][0].Label, byKind[honeypot.KindToken][1].Label}
	slices.Sort(labels)
	if labels[0] != "Credential token svc-backup-old" || labels[1] != "File token Payroll 2026" {
		t.Fatalf("labels %v", labels)
	}
	for _, h := range byKind[honeypot.KindToken] {
		if h.Service != nil || h.Port != nil {
			t.Fatalf("token hit has a service: %+v", h)
		}
	}
	tk, _ := e.svc.Tokens(e.ctx())
	for _, x := range tk {
		if x.ID == cred.ID && (x.Triggers != 1 || x.LastTriggeredAt == nil) {
			t.Fatalf("%+v", x)
		}
	}
	// deleting a token stops the hits (INV-10) and frees the secret, old hits stay
	if err := e.svc.DeleteToken(e.ctx(), "a", cred.ID); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM core_secret WHERE purpose = 'hp_token.password'`) != 0 {
		t.Fatal("secret kept")
	}
	e.now = t0.Add(time.Hour)
	e.appendLog(sshLogin(src, 6000, e.now, cred.Value).json())
	e.poll()
	if n := e.count(`SELECT count(*) FROM hp_hits WHERE kind = 'token'`); n != 2 {
		t.Fatalf("%d token hits after delete, want the 2 old ones", n)
	}
	if n := e.count(`SELECT count(*) FROM hp_hits WHERE kind = 'service'`); n != 3 {
		t.Fatalf("service hit of the later connection missing: %d", n)
	}
	// validation (same messages as the mock)
	for _, c := range []struct {
		in   honeypot.TokenInput
		code string
	}{
		{honeypot.TokenInput{Type: "x", Name: "n", PlantAt: "p"}, "bad_type"},
		{honeypot.TokenInput{Type: honeypot.TokenFile, Name: "Ünï", PlantAt: "p", Ext: "docx"}, "bad_name"},
		{honeypot.TokenInput{Type: honeypot.TokenFile, Name: "ok", PlantAt: " ", Ext: "docx"}, "bad_plant_at"},
		{honeypot.TokenInput{Type: honeypot.TokenFile, Name: "ok", PlantAt: "p", Ext: "exe"}, "bad_ext"},
		{honeypot.TokenInput{Type: honeypot.TokenFile, Name: "payroll 2026", PlantAt: "p", Ext: "docx"}, "duplicate"},
	} {
		if _, err := e.svc.AddToken(e.ctx(), "a", c.in); apiCode(t, err) != c.code {
			t.Errorf("%+v: %v want %s", c.in, err, c.code)
		}
	}
	if err := e.svc.DeleteToken(e.ctx(), "a", "tok-nope"); apiCode(t, err) != "not_found" {
		t.Fatal(err)
	}
}

// INV-11: suggestions come only from device types that exist in the inventory.
func TestContract_INV11_Suggestions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r, err := e.svc.TrapIPs(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"items":[]`) {
		t.Fatalf("%s", raw)
	}
	e.setup()
	if r, err = e.svc.TrapIPs(e.ctx()); err != nil {
		t.Fatal(err)
	}
	got := map[honeypot.Preset]honeypot.TrapSuggestion{}
	for _, s := range r.Suggestions {
		got[s.Preset] = s
	}
	if _, ok := got[honeypot.Camera]; ok {
		t.Fatal("camera suggested but the inventory has none")
	}
	if _, ok := got[honeypot.Linux]; ok {
		t.Fatal("linux suggested but no linux server")
	}
	if _, ok := got[honeypot.Custom]; ok {
		t.Fatal("custom is no device type")
	}
	if got[honeypot.FileServer].Count != 1 || got[honeypot.FileServer].Examples[0] != "SRV-FILE" || got[honeypot.NAS].Count != 1 || got[honeypot.Printer].Examples[0] != "PRN-LOBBY" {
		t.Fatalf("%+v", got)
	}
	if len(r.Items) != 1 || len(r.SpareIPs) != 5 || r.SpareIPs[0] != "192.168.10.230" || !r.SpareChecked {
		t.Fatalf("%+v", r)
	}
	for _, ip := range r.SpareIPs {
		if ip == "192.168.10.240" {
			t.Fatal("a Trap IP offered as spare")
		}
	}
}

// INV-12: everything from the network is cut and cleaned, stored as text; a hostile line cannot do more.
func TestContract_INV12_HostileText(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	long := strings.Repeat("A", 5000)
	e.appendLog(
		ln{LogType: 4002, Src: "192.168.10.157", SrcPort: 1, DstPort: 22, At: t0, Data: map[string]any{"USERNAME": "ro\x00ot\u202e'; DROP TABLE hp_hits;--" + long, "REMOTEVERSION": "$(rm -rf /)\n\r"}}.json(),
		`{"logtype": 4000, "src_host": "not an ip", "dst_port": 22}`,
		`{"logtype": 4000, "src_host": "300.1.1.1"}`,
		`{"logtype": 4000, "src_host": "10.0.0.5"} trailing`,
		`not json at all`,
		`[1,2,3]`,
		`{"logtype": "4000", "src_host": "10.0.0.5"}`,
		`{"logtype": 4000, "src_host": "192.168.10.158", "src_port": 99999999999999999999, "logdata": {"USERNAME": {"a": [1]}}}`,
	)
	e.poll()
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	// two usable lines: the hostile SSH login, and the last one, whose absurd port is read as 0 and whose object user name is ignored (INV-12b:
	// a port that is not 1-65535 no longer makes the whole line unusable)
	if len(hits) != 2 {
		t.Fatalf("%d hits from hostile lines", len(hits))
	}
	for _, h := range hits {
		if len(h.Excerpt) > 600 || strings.ContainsAny(h.Excerpt, "\x00\n\r\u202e") {
			t.Fatalf("excerpt %q", h.Excerpt)
		}
	}
	// the two hits by content, not by position: the hostile SSH login (.157) and the line whose port and user name were unusable (.158)
	var h, other honeypot.Hit
	for _, x := range hits {
		switch x.SrcIP {
		case "192.168.10.157":
			h = x
		case "192.168.10.158":
			other = x
		}
	}
	if h.ID == "" || other.ID == "" {
		t.Fatalf("expected one hit from .157 and one from .158, got %+v", hits)
	}
	// the object user name is ignored (no text from it), the absurd source port became 0 (Hit has no source port; the trap port is the service's)
	if strings.Contains(other.Excerpt, "[1]") || strings.Contains(other.Excerpt, "map[") || other.Excerpt != "new connection" {
		t.Fatalf("the .158 hit kept something from its object user name: excerpt %q", other.Excerpt)
	}
	if e.count(`SELECT count(*) FROM sqlite_master WHERE name = 'hp_hits'`) != 1 {
		t.Fatal("table gone")
	}
	st := e.svc.Stats()
	if st.Unusable < 5 || st.Lines != 2 {
		t.Fatalf("%+v", st)
	}
	for _, id := range []string{h.ID, other.ID} {
		d, _ := e.svc.HitDetail(e.ctx(), id)
		for _, ev := range d.Events {
			if len(ev.Text) > 400 {
				t.Fatalf("event text %d long", len(ev.Text))
			}
		}
	}
}

// INV-13: every mutation writes core_audit.
func TestContract_INV13_EveryMutationAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	var first, second honeypot.TrapIP
	steps := []struct {
		action string
		do     func() error
	}{
		{"honeypot.trap_ip_add", func() (err error) {
			first, err = e.svc.AddTrapIP(ctx, "a@x", honeypot.TrapIPInput{Name: "FILESRV-OLD", IP: "192.168.10.240", Preset: honeypot.FileServer, Vendor: ptr("dell"), Services: []honeypot.ServiceName{honeypot.SMB, honeypot.SSH}})
			return err
		}},
		{"honeypot.test_hit", func() error { _, err := e.svc.TestHit(ctx, "o@x", honeypot.SSH); return err }},
		{"honeypot.trap_ip_add", func() (err error) {
			second, err = e.svc.AddTrapIP(ctx, "a@x", honeypot.TrapIPInput{Name: "PRN-2", IP: "192.168.10.241", Preset: honeypot.Printer, Services: []honeypot.ServiceName{honeypot.HTTP}})
			return err
		}},
		{"honeypot.test_scan", func() error { _, err := e.svc.TestScan(ctx, "o@x"); return err }},
		{"honeypot.token_add", func() error {
			_, err := e.svc.AddToken(ctx, "a@x", honeypot.TokenInput{Type: honeypot.TokenURL, Name: "urlbait", PlantAt: "x"})
			return err
		}},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.action, err)
		}
		if a := e.auditActions(); a[len(a)-1] != s.action {
			t.Fatalf("after %s the log ends with %v", s.action, a)
		}
	}
	tok, _ := e.svc.Tokens(ctx)
	more := []struct {
		action string
		do     func() error
	}{
		{"honeypot.trap_ip_edit", func() error {
			_, err := e.svc.EditTrapIP(ctx, "a@x", second.ID, honeypot.TrapIPInput{Name: "PRN-3", IP: "192.168.10.241", Preset: honeypot.Printer, Services: []honeypot.ServiceName{honeypot.HTTP}})
			return err
		}},
		{"honeypot.trap_ip_disable", func() error { _, err := e.svc.SetTrapIPEnabled(ctx, "a@x", second.ID, false); return err }},
		{"honeypot.trap_ip_enable", func() error { _, err := e.svc.SetTrapIPEnabled(ctx, "a@x", second.ID, true); return err }},
		{"honeypot.test_token", func() error { _, err := e.svc.TestToken(ctx, "o@x", tok[0].ID); return err }},
		{"honeypot.trap_ip_delete", func() error { return e.svc.DeleteTrapIP(ctx, "a@x", second.ID) }},
		{"honeypot.token_delete", func() error { return e.svc.DeleteToken(ctx, "a@x", tok[0].ID) }},
	}
	for _, s := range more {
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.action, err)
		}
		if a := e.auditActions(); a[len(a)-1] != s.action {
			t.Fatalf("after %s the log ends with %v", s.action, a)
		}
	}
	var user, target, detail string
	_ = e.db.Reader().QueryRowContext(ctx, `SELECT user, target, detail FROM core_audit WHERE action = 'honeypot.trap_ip_add' ORDER BY seq LIMIT 1`).Scan(&user, &target, &detail)
	if user != "a@x" || target != first.IP || !strings.Contains(detail, "FILESRV-OLD") || !strings.Contains(detail, "smb") {
		t.Fatalf("audit of the add: %q %q %q", user, target, detail)
	}
	// a refused mutation leaves no trace
	n := len(e.auditActions())
	if _, err := e.tryAddTrapIP("X1", "10.9.9.9", honeypot.Linux, honeypot.SSH); err == nil {
		t.Fatal("accepted")
	}
	if err := e.svc.DeleteTrapIP(ctx, "a@x", "tip-nope"); apiCode(t, err) != "not_found" {
		t.Fatal(err)
	}
	if len(e.auditActions()) != n {
		t.Fatal("refused change audited as done")
	}
}

// Event names: the 3-segment name notify already listens to; the module off sends nothing and subscribes to the two
// inventory events as hints only.
func TestEventNames(t *testing.T) {
	t.Parallel()
	if honeypot.EventHitCreated != "honeypot.hit.created" {
		t.Fatal(honeypot.EventHitCreated)
	}
}

func TestHostFailureDoesNotLoseState(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.host.failStart = errStart
	if err := e.svc.Apply(e.ctx()); err == nil {
		t.Fatal("start failure swallowed")
	}
	o, _ := e.svc.Overview(e.ctx())
	if o.Traps[2].State != honeypot.StateFailed || !o.Traps[2].Enabled || o.Problem == nil || !strings.Contains(*o.Problem, "did not start") {
		t.Fatalf("%+v %v", o.Traps[2], o.Problem)
	}
	e.host.failStart = nil
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if o, _ = e.svc.Overview(e.ctx()); o.Traps[2].State != "listening" {
		t.Fatalf("%+v", o.Traps[2])
	}
}

func TestOverviewFields(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	o, err := e.svc.Overview(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if o.TrapIPs.Total != 0 || o.SMBName != nil || o.HTTPPage != nil || o.LAN == nil || *o.LAN != "192.168.10.0/24" || o.Box.Name != "vedette-hq" || *o.Box.IP != "192.168.10.2" || len(o.Traps) != 5 || o.UpdatedAt == "" {
		t.Fatalf("%+v", o)
	}
	if o.Traps[0].Service != "smb" || o.Traps[0].Port != 445 || o.Traps[4].Service != "http" {
		t.Fatalf("%+v", o.Traps)
	}
	raw, _ := json.Marshal(o)
	for _, want := range []string{`"smb_name":null`, `"http_page":null`, `"problem":null`, `"last_hit_at":null`, `"last_src":null`, `"trap_ips":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s in %s", want, raw)
		}
	}
	// D-466 (4): the first Trap IP handed to the host with SMB names the share, the first with HTTP picks the page.
	e.setup()
	e.addTrapIP("NAS-ARCHIVE", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	e.addTrapIP("PRN-FLOOR2", "192.168.10.242", honeypot.Printer, honeypot.HTTP)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	o, _ = e.svc.Overview(e.ctx())
	if o.TrapIPs != (honeypot.TrapIPCounts{Total: 3, Enabled: 3, Listening: 3}) || o.SMBName == nil || *o.SMBName != "FILESRV-OLD" || o.HTTPPage == nil || *o.HTTPPage != "nas" {
		t.Fatalf("counts %+v, smb %v, http %v", o.TrapIPs, deref(o.SMBName), deref(o.HTTPPage))
	}
	if !slices.Equal(o.Traps[0].TrapIPs, []string{"FILESRV-OLD", "NAS-ARCHIVE"}) || !slices.Equal(o.Traps[4].TrapIPs, []string{"NAS-ARCHIVE", "PRN-FLOOR2"}) || o.Traps[1].Enabled {
		t.Fatalf("traps %+v", o.Traps)
	}
	if b, _ := os.ReadFile(filepath.Join(e.dir, "config", honeypot.TokensFile)); !strings.Contains(string(b), `"netbios_name": "FILESRV-OLD"`) {
		t.Fatalf("honeytokens.json: %s", b)
	}
}
