package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-6 (D-94, D-95, response INV-22, FORBID-1) in the real wiring: the real store, the real writer and the conntest fakes
// (loopback only, through conntest; never a real host). An approved item reaches its device over its connection: the check before, the
// run, the read-back; and the undo with its own read-back.

type devClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *devClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *devClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type devUsers map[string]response.User

func (u devUsers) Lookup(_ context.Context, id string) (response.User, bool, error) {
	x, ok := u[id]
	return x, ok, nil
}

// devConns wraps the connection port of response: once armed, it counts the reads. The first is the approval's, the second is runItem's
// (after the approval is committed), the third is the claim's. before and after run around the read of that number.
type devConns struct {
	inner  response.Connections
	mu     sync.Mutex
	armed  bool
	n      int
	before map[int]func()
	after  map[int]func()
}

func (c *devConns) List(ctx context.Context) ([]response.ConnectionInfo, error) {
	c.mu.Lock()
	var n int
	if c.armed {
		c.n++
		n = c.n
	}
	before, after := c.before[n], c.after[n]
	c.mu.Unlock()
	if before != nil {
		before()
	}
	l, err := c.inner.List(ctx)
	if after != nil {
		after()
	}
	return l, err
}

// devExec wraps the executor: before and after run around a step of the phase.
type devExec struct {
	inner  response.Executor
	mu     sync.Mutex
	before map[string]func()
	after  map[string]func()
}

func (x *devExec) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	x.mu.Lock()
	before, after := x.before[s.Phase], x.after[s.Phase]
	x.mu.Unlock()
	if before != nil {
		before()
	}
	r, err := x.inner.Execute(ctx, s)
	if after != nil {
		after()
	}
	return r, err
}

type devEnv struct {
	t     *testing.T
	s     *stack
	svc   *response.Service
	clock *devClock
	conns *devConns
	exec  *devExec
}

var (
	devAdmin = response.Actor{ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Via: response.ViaApp}
	devOper  = response.Actor{ID: "u-op", Name: "IT Operator", Email: "it@acme.example", Via: response.ViaApp}
)

// newDevEnv is the binary's wiring with a response service built from responseConfig (the real executor: the real writer on the real
// connection store), with the two seams that put a hook between the steps.
func newDevEnv(t *testing.T) *devEnv {
	t.Helper()
	clock := &devClock{t: time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)}
	s := newStackWith(t, func(d *deps) { d.Clock = clock.Now })
	for _, m := range []string{"notify", "inventory", "response"} {
		s.setModule(m, true)
	}
	cfg, err := responseConfig(s.d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Executor == nil || cfg.Connections == nil {
		t.Fatal("the wiring has no executor or no connections")
	}
	cfg.Users = devUsers{"u-admin": {ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Role: "admin", TwoStep: true}}
	e := &devEnv{t: t, s: s, clock: clock, conns: &devConns{inner: cfg.Connections}, exec: &devExec{inner: cfg.Executor}}
	cfg.Connections, cfg.Executor = e.conns, e.exec
	if e.svc, err = response.New(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *devEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *devEnv) ctx() context.Context { return e.t.Context() }

// connect saves a connection and runs its first Test, which pins the certificate or host key and makes it ready.
func (e *devEnv) connect(in conn.Input) conn.Connection {
	e.t.Helper()
	c := e.s.connCreate(in)
	if _, err := e.s.d.Conn.Test(e.ctx(), "admin@acme.example", c.ID, func(context.Context, *sql.Tx) error { return nil }); err != nil {
		e.t.Fatalf("test %s: %v", in.Name, err)
	}
	got, err := e.s.d.Conn.Get(e.ctx(), c.ID)
	e.must(err)
	return got
}

func (e *devEnv) bind(actionID, connID string) {
	e.t.Helper()
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), devAdmin, actionID, response.CatalogUpdate{ConnectionID: &connID, Enabled: &on, Present: map[string]bool{"connection_id": true, "enabled": true}})
	e.must(err)
}

func (e *devEnv) turnOn() {
	e.t.Helper()
	_, err := e.svc.SetExecution(e.ctx(), devAdmin, true, response.RiskPhrase)
	e.must(err)
}

func (e *devEnv) rule(trigger string, actions []response.RuleAction) {
	e.t.Helper()
	in := response.RuleInput{Name: "Device test", Enabled: true, Live: true, Trigger: trigger, Match: "all", Conditions: []response.Condition{}, Actions: actions, MaxPerHour: 10}
	r, err := e.svc.AddRule(e.ctx(), devAdmin, in)
	e.must(err)
	_, err = e.svc.ChangeRule(e.ctx(), devAdmin, r.ID, in)
	e.must(err)
}

func (e *devEnv) fire(d response.Det) {
	e.t.Helper()
	d.TS = store.FormatTS(e.clock.Now())
	e.must(e.svc.StoreEvent(e.ctx(), d))
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
}

func (e *devEnv) ioc() response.Det {
	const dest = "198.51.100.7"
	return response.Det{ID: "e1", Trigger: "ioc_connection", Summary: "PC-SALES-02 connected to " + dest,
		Fields: map[string]string{"src_ip": "192.168.10.105", "device": "PC-SALES-02", "dest": dest, "dest_kind": "ip", "dest_ip": dest, "dest_domain": "", "feeds": "IPsum", "confidence": "0.92", "switch_port": ""}}
}

func (e *devEnv) trap(id, src, port string) response.Det {
	return response.Det{ID: id, Trigger: "honeypot", Summary: "PC-HR-01 touched a trap from " + src,
		Fields: map[string]string{"source_ip": src, "source_device": "PC-HR-01", "decoy": "FILESRV-OLD", "kind": "scan", "switch_port": port}}
}

func (e *devEnv) only() response.ActionRequest {
	e.t.Helper()
	l, err := e.svc.Actions(e.ctx())
	e.must(err)
	if len(l) != 1 {
		e.t.Fatalf("%d requests, want 1", len(l))
	}
	return l[0]
}

func (e *devEnv) approve() response.ActionRequest {
	e.t.Helper()
	got, err := e.svc.Approve(e.ctx(), devOper, e.only().ID, nil, "")
	e.must(err)
	return got
}

func (e *devEnv) logCount(like string) int {
	e.t.Helper()
	return e.s.count(`SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%' || ? || '%'`, like)
}

func (e *devEnv) arm() {
	e.conns.mu.Lock()
	e.conns.armed, e.conns.n = true, 0
	e.conns.mu.Unlock()
}

// editSecret gives the connection another token: another version of it, whatever else stays the same.
func (e *devEnv) editSecret(c conn.Connection, tools ...conn.ToolInput) {
	e.t.Helper()
	in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: c.Auth.Type, Username: c.Username, Allow: c.Allow, Enabled: true, Secret: secrets.NewValue("tok-9876543210-zyxwvu"), Tools: tools}
	e.must(e.s.d.DB.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := e.s.d.Conn.Update(e.ctx(), tx, "admin@acme.example", c.ID, in)
		return err
	}))
}

func httpsInput(f *conntest.HTTPS, name string) conn.Input {
	return conn.Input{Name: name, Kind: "http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue("tok-0123456789-abcdef"), Allow: []string{f.URL + "/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}}
}

func sshInput(f *conntest.SSH, name string) conn.Input {
	user := "vedette"
	return conn.Input{Name: name, Kind: "ssh", Target: f.Addr, AuthType: "basic", Username: &user, Secret: secrets.NewValue("pw-0123456789"), Allow: []string{"show version"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "run_approved_command", Enabled: true}}}
}

// bans is a firewall that keeps a banned list: the read-back shows the address while it is banned.
func bans() http.Handler {
	var banned atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/monitor/user/banned/add_users":
			banned.Store(true)
		case "/api/v2/monitor/user/banned/clear_users":
			banned.Store(false)
		case "/api/v2/monitor/user/banned/select":
			if banned.Load() {
				_, _ = io.WriteString(w, `{"results":[{"ip_address":"198.51.100.7"}],"canary":"DEVICE-OUTPUT-CANARY"}`)
				return
			}
			_, _ = io.WriteString(w, `{"results":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"success"}`)
	})
}

func banRule() []response.RuleAction {
	return []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: ttl(60)}}
}

func ttl(n int) *int { return &n }

// The exact HTTP request of every step, the read-back, and the undo by the sweep when the undo time ends, with its own read-back.
func TestDeviceHTTPExactRequestsAndTheTTLSweep(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	base := len(f.Requests())

	got := e.approve()
	it := got.Items[0]
	if got.Status != response.StatusExecuted || it.Status != response.ItemExecuted || it.Verified == nil || !it.Verified.OK || it.Result == nil || *it.Result != "HTTP 200" {
		t.Fatalf("request %+v item %+v", got, it)
	}
	sent := f.Requests()[base:]
	if len(sent) != 2 {
		t.Fatalf("%d requests, want the run and the read-back: %+v", len(sent), sent)
	}
	run, back := sent[0], sent[1]
	if run.Method != "POST" || run.Path != "/api/v2/monitor/user/banned/add_users" || string(run.Body) != `{"ip_addresses":["198.51.100.7"],"expiry":3600}` ||
		run.Header.Get("Authorization") != "Bearer tok-0123456789-abcdef" || run.Header.Get("Content-Type") != "application/json" || run.Header.Get("Accept") != "application/json" {
		t.Fatalf("the run request: %+v", run)
	}
	if back.Method != "GET" || back.Path != "/api/v2/monitor/user/banned/select" || len(back.Body) != 0 || back.Header.Get("Authorization") != "Bearer tok-0123456789-abcdef" {
		t.Fatalf("the read-back request: %+v", back)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%CANARY%'`, `SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%CANARY%'`, `SELECT COUNT(*) FROM core_audit WHERE detail LIKE '%CANARY%'`} {
		if e.s.count(q) != 0 {
			t.Fatalf("what the device printed was kept: %s", q)
		}
	}

	// The undo time ends: the sweep sends the rollback and reads back, and the read-back no longer holds the address.
	e.clock.Advance(61 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	sent = f.Requests()[base+2:]
	if len(sent) != 2 || sent[0].Method != "POST" || sent[0].Path != "/api/v2/monitor/user/banned/clear_users" || string(sent[0].Body) != `{"ip_addresses":["198.51.100.7"]}` || sent[1].Method != "GET" {
		t.Fatalf("the undo requests: %+v", sent)
	}
	after := e.only()
	if after.Status != response.StatusRolledBack || after.Items[0].Status != response.ItemRolledBack || !strings.Contains(*after.Items[0].Result, "Read back from the device: the change is gone.") {
		t.Fatalf("after the sweep: %+v", after.Items[0])
	}
	if e.logCount("Undo: ") == 0 {
		t.Fatal("the undo is not in the log")
	}
}

// An action with headers: exactly the headers of the template, filled with checked values; the sign-in is the connection's.
func TestDeviceHTTPHeadersOfATemplate(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, nil)
	c := e.connect(httpsInput(f, "Pi-hole"))
	act, err := e.svc.AddAction(e.ctx(), devAdmin, response.CatalogInput{Name: "Block a domain (custom)", Description: "d", ConnectionID: c.ID, Risk: response.RiskLow, Enabled: true,
		Run:      response.Tpl{Method: "POST", Path: "/api/domains/deny/{domain}", Headers: "X-Vedette-Domain: {domain}\nX-Vedette-Source: rule", Body: `{"domain":"{domain}"}`},
		Rollback: response.Tpl{Method: "DELETE", Path: "/api/domains/deny/{domain}"}})
	e.must(err)
	e.turnOn()
	e.rule("ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: ttl(60)}})
	ev := e.ioc()
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	base := len(f.Requests())
	got := e.approve()
	if got.Items[0].Status != response.ItemExecuted {
		t.Fatalf("item %+v", got.Items[0])
	}
	sent := f.Requests()[base:]
	if len(sent) != 1 {
		t.Fatalf("%d requests", len(sent))
	}
	q := sent[0]
	if q.Method != "POST" || q.Path != "/api/domains/deny/bad.example.com" || string(q.Body) != `{"domain":"bad.example.com"}` || q.Header.Get("X-Vedette-Domain") != "bad.example.com" ||
		q.Header.Get("X-Vedette-Source") != "rule" || q.Header.Get("Authorization") != "Bearer tok-0123456789-abcdef" {
		t.Fatalf("the request: %+v", q)
	}
}

// A certificate that is not the pinned one gets no request, so no Authorization header: the item fails and nothing was changed.
func TestDeviceChangedCertificateGetsNothing(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	f.Rotate(t)
	base := len(f.Requests())
	got := e.approve()
	it := got.Items[0]
	if it.Status != response.ItemFailed || it.Result == nil || !strings.Contains(*it.Result, "Nothing was changed") || len(f.Requests()) != base {
		t.Fatalf("item %+v, %d new requests", it, len(f.Requests())-base)
	}
	if in, err := e.svc.ChangesInForce(e.ctx(), c.ID); err != nil || in {
		t.Fatalf("a step that was not sent counts as in force: %v %v", in, err)
	}
}

// The switch: the exact lines of the check before, the run and the read-back, one line each; a check that refuses sends nothing to write;
// a line that errors stops the rest; the sweep sends the rollback and its read-back.
func TestDeviceSSHExactLinesRefusalAndStop(t *testing.T) {
	t.Parallel()
	const port = "Gi1/0/12"
	respond := func(shut *atomic.Bool, mode *atomic.Value, bad string) func(string) string {
		return func(line string) string {
			switch line {
			case "show interfaces " + port + " switchport":
				return "Name: " + port + "\nAdministrative Mode: " + mode.Load().(string) + "\nSwitchport: Enabled"
			case "show interfaces " + port:
				return port + " is up, line protocol is up"
			case "show interfaces " + port + " status":
				if shut.Load() {
					return port + "   disabled  1  auto auto 10/100/1000BaseTX"
				}
				return port + "   connected  1  a-full a-1000 10/100/1000BaseTX"
			case "shutdown":
				shut.Store(true)
			case "no shutdown":
				shut.Store(false)
			case bad:
				return "% Invalid input detected at '^' marker."
			}
			return ""
		}
	}
	setup := func(t *testing.T, bad string) (*devEnv, *conntest.SSH, *atomic.Value) {
		e := newDevEnv(t)
		var shut atomic.Bool
		mode := &atomic.Value{}
		mode.Store("static access")
		f := conntest.NewSSH(t, conntest.SSHOpts{Respond: respond(&shut, mode, bad)})
		c := e.connect(sshInput(f, "Core switch"))
		e.bind("cisco_port_shut", c.ID)
		e.turnOn()
		e.rule("honeypot", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: ttl(30)}})
		e.fire(e.trap("h1", "192.168.10.157", port))
		return e, f, mode
	}
	join := func(l []string) string { return strings.Join(l, "|") }

	t.Run("exact lines and the undo", func(t *testing.T) {
		e, f, _ := setup(t, "")
		got := e.approve()
		it := got.Items[0]
		if it.Status != response.ItemExecuted || it.Verified == nil || !it.Verified.OK {
			t.Fatalf("item %+v", it)
		}
		want := "terminal length 0|show interfaces " + port + " switchport|show interfaces " + port +
			"|terminal length 0|configure terminal|interface " + port + "|shutdown|end" +
			"|terminal length 0|show interfaces " + port + " status"
		if join(f.Lines()) != want {
			t.Fatalf("lines\n got %s\nwant %s", join(f.Lines()), want)
		}
		e.clock.Advance(31 * time.Minute)
		e.must(e.svc.Sweep(e.ctx()))
		undo := "terminal length 0|configure terminal|interface " + port + "|no shutdown|end|terminal length 0|show interfaces " + port + " status"
		if got := join(f.Lines()[len(strings.Split(want, "|")):]); got != undo {
			t.Fatalf("undo lines\n got %s\nwant %s", got, undo)
		}
		if a := e.only(); a.Status != response.StatusRolledBack || !strings.Contains(*a.Items[0].Result, "the change is gone") {
			t.Fatalf("after the sweep: %+v", a.Items[0])
		}
	})

	t.Run("a refusing check sends nothing to write", func(t *testing.T) {
		e, f, mode := setup(t, "")
		mode.Store("trunk")
		got := e.approve()
		it := got.Items[0]
		if it.Status != response.ItemFailed || !strings.Contains(*it.Result, "Refused by the check before: Mode: trunk") {
			t.Fatalf("item %+v", it)
		}
		if join(f.Lines()) != "terminal length 0|show interfaces "+port+" switchport|show interfaces "+port {
			t.Fatalf("lines %v: only the check before may be sent", f.Lines())
		}
		l, err := e.s.d.Conn.List(e.ctx())
		e.must(err)
		if in, _ := e.svc.ChangesInForce(e.ctx(), l[0].ID); in {
			t.Fatal("a refused item counts as in force")
		}
	})

	t.Run("a line that errors stops the rest", func(t *testing.T) {
		e, f, _ := setup(t, "interface "+port)
		got := e.approve()
		it := got.Items[0]
		if it.Status != response.ItemFailed || !strings.Contains(*it.Result, "State unknown") {
			t.Fatalf("item %+v", it)
		}
		want := "terminal length 0|show interfaces " + port + " switchport|show interfaces " + port + "|terminal length 0|configure terminal|interface " + port
		if join(f.Lines()) != want {
			t.Fatalf("lines\n got %s\nwant %s", join(f.Lines()), want)
		}
		l, err := e.s.d.Conn.List(e.ctx())
		e.must(err)
		if in, err := e.svc.ChangesInForce(e.ctx(), l[0].ID); err != nil || !in {
			t.Fatalf("a half-applied step is not in force: %v %v", in, err)
		}
	})
}

// The MCP arguments are the typed values of the template, sent as they are.
func TestDeviceMCPArgumentsAreTheTypedValues(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{{Name: "block_ip"}, {Name: "unblock_ip"}}})
	in := conn.Input{Name: "MCP firewall", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "token", Secret: secrets.NewValue("tok-0123456789-abcdef"), Allow: []string{f.URL + "/mcp"}, Enabled: true}
	c := e.connect(in) // finds the tools: write tools that start off
	in.Secret = secrets.Value{}
	in.Tools = []conn.ToolInput{{Name: "block_ip", Enabled: true}, {Name: "unblock_ip", Enabled: true}}
	e.must(e.s.d.DB.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := e.s.d.Conn.Update(e.ctx(), tx, "admin@acme.example", c.ID, in)
		return err
	}))
	bt, ut := "block_ip", "unblock_ip"
	act, err := e.svc.AddAction(e.ctx(), devAdmin, response.CatalogInput{Name: "Block an IP (MCP)", Description: "d", ConnectionID: c.ID, Tool: &bt, RollbackTool: &ut, Risk: response.RiskLow, Enabled: true,
		Run: response.Tpl{Body: `{"address":"{ip}","ttl":3600,"on":true,"tags":["vedette","auto"]}`}, Rollback: response.Tpl{Body: `{"address":"{ip}"}`}})
	e.must(err)
	e.turnOn()
	e.rule("ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: ttl(60)}})
	e.fire(e.ioc())
	base := len(f.Calls())
	got := e.approve()
	if got.Items[0].Status != response.ItemExecuted || got.Items[0].Verified != nil {
		t.Fatalf("item %+v", got.Items[0])
	}
	var calls []conntest.MCPCall
	for _, c := range f.Calls()[base:] {
		if c.RPCMethod == "tools/call" {
			calls = append(calls, c)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("%d tool calls", len(calls))
	}
	a := calls[0].Args
	tags, _ := a["tags"].([]any)
	if a["address"] != "198.51.100.7" || a["ttl"] != float64(3600) || a["on"] != true || len(tags) != 2 || tags[0] != "vedette" || len(a) != 4 || calls[0].Authorization != "Bearer tok-0123456789-abcdef" {
		t.Fatalf("the server got %+v", calls[0])
	}
	e.clock.Advance(61 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	var undo []conntest.MCPCall
	for _, c := range f.Calls()[base:] {
		if c.RPCMethod == "tools/call" {
			undo = append(undo, c)
		}
	}
	if len(undo) != 2 || undo[1].Args["address"] != "198.51.100.7" || len(undo[1].Args) != 1 || e.only().Status != response.StatusRolledBack {
		t.Fatalf("the undo: %+v", undo)
	}
}

// An emergency stop that commits after the approval and before the claim means no request reaches the device.
func TestDeviceEmergencyStopBetweenApproveAndClaimSendsNothing(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	base := len(f.Requests())
	e.conns.after = map[int]func(){2: func() { _, err := e.svc.EmergencyStop(e.ctx(), devAdmin); e.must(err) }}
	e.arm()
	got := e.approve()
	if len(f.Requests()) != base || got.Items[0].Status != response.ItemFailed || !strings.Contains(*got.Items[0].Result, "Execution is off") {
		t.Fatalf("%d new requests, item %+v", len(f.Requests())-base, got.Items[0])
	}
	if n := e.logCount("Running: "); n != 0 {
		t.Fatalf("%d Running lines: the step was claimed", n)
	}
}

// A connection edited after the approval: refused connection_changed, with zero requests, whether the edit lands before the run reads the
// connection or after (between that read and the claim).
func TestDeviceConnectionEditedAfterApproveIsConnectionChanged(t *testing.T) {
	t.Parallel()
	for name, when := range map[string]string{"before the run reads it": "before", "between the read and the claim": "after"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newDevEnv(t)
			f := conntest.NewHTTPS(t, bans())
			c := e.connect(httpsInput(f, "Office firewall"))
			e.bind("fgt_ban_ip", c.ID)
			e.turnOn()
			e.rule("ioc_connection", banRule())
			e.fire(e.ioc())
			base := len(f.Requests())
			edit := func() { e.editSecret(c, conn.ToolInput{Name: "send_request", Enabled: true}) }
			if when == "before" {
				e.conns.before = map[int]func(){2: edit}
			} else {
				e.conns.after = map[int]func(){2: edit}
			}
			e.arm()
			got := e.approve()
			it := got.Items[0]
			if it.Status != response.ItemFailed || !strings.Contains(*it.Result, "was changed after the request was made") || len(f.Requests()) != base {
				t.Fatalf("item %+v, %d new requests", it, len(f.Requests())-base)
			}
			if e.logCount("connection_changed") == 0 {
				t.Fatal("the refusal is not in the log")
			}
			if n := e.logCount("Running: "); n != 0 { // the claim refused: the item was never marked running, so no step was "being sent"
				t.Fatalf("%d Running lines: the step was claimed", n)
			}
		})
	}
}

// A fingerprint race inside the executor: the connection is edited after the claim and before the writer reloads it. The writer compares
// the fingerprint of the request with the connection as it is then, so nothing is sent.
func TestDeviceFingerprintRaceInsideTheExecutorSendsNothing(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	base := len(f.Requests())
	var edited atomic.Bool
	e.exec.before = map[string]func(){"run": func() {
		if edited.CompareAndSwap(false, true) {
			e.editSecret(c, conn.ToolInput{Name: "send_request", Enabled: true})
		}
	}}
	got := e.approve()
	it := got.Items[0]
	if !edited.Load() || it.Status != response.ItemFailed || !strings.Contains(*it.Result, "was changed after the request was made") || len(f.Requests()) != base {
		t.Fatalf("edited %v, item %+v, %d new requests", edited.Load(), it, len(f.Requests())-base)
	}
}

// A connection deleted after the approval is refused at the claim, which reads the connections again: nothing is sent.
func TestDeviceConnectionDeletedAfterApproveIsRefusedAtTheClaim(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	base := len(f.Requests())
	// After runItem read the connections (the second read) and before the claim reads them again (the third).
	e.conns.after = map[int]func(){2: func() { e.s.exec(`DELETE FROM core_connection WHERE id = ?`, c.ID) }}
	e.arm()
	got := e.approve()
	it := got.Items[0]
	if it.Status != response.ItemFailed || !strings.Contains(*it.Result, "no longer exists") || len(f.Requests()) != base {
		t.Fatalf("item %+v, %d new requests", it, len(f.Requests())-base)
	}
	if e.logCount("connection_changed") == 0 {
		t.Fatal("the refusal is not in the log")
	}
}

// A late result for a connection that vanished while the step ran (core/conn refuses a delete while a step is in flight, but a restore or a
// manual edit of the database does not): the result is recorded, the item leaves the sweep, one clear line, no crash, and no undo is retried.
func TestDeviceLateResultForAConnectionThatIsGone(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	// core/conn itself refuses to delete it while the step runs.
	e.exec.before = map[string]func(){"run": func() {
		err := e.s.d.DB.Write(e.ctx(), func(tx *sql.Tx) error { return e.s.d.Conn.Delete(e.ctx(), tx, "admin@acme.example", c.ID) })
		if err == nil {
			t.Error("a connection with a step in flight was deleted through core/conn")
		}
	}}
	e.exec.after = map[string]func(){"run": func() { e.s.exec(`DELETE FROM core_connection WHERE id = ?`, c.ID) }}
	got := e.approve()
	it := got.Items[0]
	if it.Status != response.ItemExecuted || it.RemoveAt != nil {
		t.Fatalf("item %+v", it)
	}
	if n := e.logCount("no longer exists"); n != 1 {
		t.Fatalf("%d lines about the gone connection, want 1", n)
	}
	e.clock.Advance(2 * time.Hour)
	base := len(f.Requests())
	for range 3 {
		e.must(e.svc.Sweep(e.ctx()))
	}
	if n := e.logCount("no longer exists"); n != 1 || len(f.Requests()) != base {
		t.Fatalf("the sweep tried again: %d lines, %d new requests", n, len(f.Requests())-base)
	}
	var raw string
	e.must(e.s.d.DB.Reader().QueryRowContext(e.ctx(), `SELECT items FROM resp_actions`).Scan(&raw))
	var items []map[string]any
	e.must(json.Unmarshal([]byte(raw), &items))
	if items[0]["status"] != "executed" {
		t.Fatalf("item: %v", items[0])
	}
}
