package response_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/response"
)

func tokenOf(url string) string {
	return url[strings.LastIndex(url, "/")+1 : len(url)-len(".txt")]
}

// INV-17: the block list is plain text, one address per line, behind a token; a regenerated token kills the old address at once;
// it never holds a never-touch entry; a reason built from attacker data cannot start a line.
func TestContract_INV17_Blocklist(t *testing.T) {
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Summary = "PC connected\n203.0.113.99\nevil | x"
	e.fire(ev)
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	tok := tokenOf(v.URL)
	if !strings.HasPrefix(v.URL, "https://box.example:8443/api/v1/response/blocklist/") || len(tok) != 32 || v.TokenLast4 != tok[28:] || len(v.Entries) != 1 || v.LastFetch != nil {
		t.Fatalf("view: %+v", v)
	}
	b, err := e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.1")
	e.must(err)
	var lines []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 || lines[0] != "198.51.100.7" || !strings.HasPrefix(string(b), "# vedette blocklist") || strings.Contains(string(b), "203.0.113.99") || strings.Contains(string(b), "PC connected") {
		t.Fatalf("list:\n%s", b)
	}
	if strings.Count(string(b), "\n") != 4 { // three comment lines and the address
		t.Fatalf("a reason added lines:\n%s", b)
	}
	v, _ = e.svc.Blocklist(e.ctx())
	if v.LastFetch == nil || v.LastFetch.From != "192.168.10.1" {
		t.Fatalf("last fetch: %+v", v.LastFetch)
	}
	// A never-touch address that got into the table is not served.
	e.exec1(`INSERT INTO resp_block_entries (value, request_id, item_id, source, reason, added_at) VALUES ('10.9.9.9', 'x', 'y', 's', 'r', '2026-11-09T10:00:00.000Z')`)
	if _, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "10.9.9.0/24", Label: "Management"}}); err != nil {
		t.Fatal(err)
	}
	b, _ = e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.1")
	if strings.Contains(string(b), "10.9.9.9") {
		t.Fatal("the list holds a never-touch address")
	}
	// An entry past its time to live is not served, even before the sweep.
	e.clock.Advance(2 * time.Hour)
	b, _ = e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.1")
	if strings.Contains(string(b), "198.51.100.7") {
		t.Fatal("an expired entry is served")
	}
	// Regenerating the token: the old address stops working at once.
	v2, err := e.svc.RegenerateToken(e.ctx(), admin)
	e.must(err)
	if tokenOf(v2.URL) == tok || v2.LastFetch != nil {
		t.Fatal("the token did not change")
	}
	_, err = e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.1")
	wantCode(t, err, 404, "not_found")
	if _, err = e.svc.FetchBlocklist(e.ctx(), tokenOf(v2.URL), "192.168.10.1"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "x", strings.Repeat("a", 32), strings.ToUpper(tokenOf(v2.URL))} {
		_, err = e.svc.FetchBlocklist(e.ctx(), bad, "192.168.10.2")
		wantCode(t, err, 404, "not_found")
	}
	// The token is sealed, not stored: the table holds only its hash.
	if e.count(`SELECT COUNT(*) FROM resp_blocklist WHERE token_hash = ?`, tokenOf(v2.URL)) != 0 {
		t.Fatal("the token is stored in clear")
	}
}

func TestBlocklistRateLimit(t *testing.T) {
	e := newEnv(t)
	v, _ := e.svc.Blocklist(e.ctx())
	tok := tokenOf(v.URL)
	for i := 0; i < 20; i++ {
		_, err := e.svc.FetchBlocklist(e.ctx(), strings.Repeat("0", 32), "192.168.10.5")
		wantCode(t, err, 404, "not_found")
	}
	_, err := e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.5") // guessing tokens costs the source its turn
	wantCode(t, err, 429, "rate_limited")
	if _, err := e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.6"); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * time.Minute)
	if _, err := e.svc.FetchBlocklist(e.ctx(), tok, "192.168.10.5"); err != nil {
		t.Fatal(err)
	}
}

// webhook_call: the guard refuses loopback in production code paths; the test seam is the only way in and is off by default.
func TestWebhookGuard(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	e := newEnv(t)
	if e.svc.LoopbackAllowedForTest() {
		t.Fatal("loopback is allowed without the test seam")
	}
	tr := e.svc.GuardedClientForTest().Transport.(*http.Transport)
	if tr.Proxy != nil || e.svc.GuardedClientForTest().CheckRedirect == nil || e.svc.GuardedClientForTest().Timeout == 0 {
		t.Fatal("the client has a proxy, follows redirects or has no timeout")
	}
	e.hooks.t, e.hooks.ok = response.WebhookTarget{URL: srv.URL + "/hook", SigningKey: "0123456789abcdef0123"}, true
	e.webhookRule()
	e.fire(e.trap("h1", "192.168.10.157"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || hits.Load() != 0 || contains(*got.Items[0].Result, srv.URL) {
		t.Fatalf("a loopback webhook was reached or leaked: %+v hits=%d", got.Items[0], hits.Load())
	}
	// Address spellings and schemes that are refused before any connection.
	for _, u := range []string{"http://example.com/h", "https://localhost/h", "https://x.localhost/h", "https://2130706433/h", "https://0x7f.1/h", "https://u:p@example.com/h", "https://[::1]/h", "https://169.254.169.254/h", "ftp://example.com"} {
		e2 := newEnv(t)
		e2.hooks.t, e2.hooks.ok = response.WebhookTarget{URL: u, SigningKey: "0123456789abcdef0123"}, true
		e2.webhookRule()
		e2.fire(e2.trap("h1", "192.168.10.157"))
		got, err := e2.svc.Approve(e2.ctx(), oper, e2.only().ID, nil, "")
		e2.must(err)
		if got.Items[0].Status != response.ItemFailed {
			t.Errorf("%s was accepted", u)
		}
	}
}

func TestWebhookSignedPostAndNoRedirect(t *testing.T) {
	var got atomic.Value
	var redirected atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hook":
			b, _ := io.ReadAll(r.Body)
			got.Store(r.Header.Get("X-Vedette-Signature") + "|" + r.Header.Get("X-Vedette-Timestamp") + "|" + string(b))
			w.WriteHeader(204)
		case "/redir":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/elsewhere":
			redirected.Add(1)
		}
	}))
	defer srv.Close()
	e := newEnv(t)
	e.svc.SetWebhookClientForTest(srv.Client()) // trusts the test certificate; the guard itself is covered above
	e.svc.AllowLoopbackForTest()
	e.hooks.t, e.hooks.ok = response.WebhookTarget{URL: srv.URL + "/hook", SigningKey: "0123456789abcdef0123"}, true
	e.webhookRule()
	e.fire(e.trap("h1", "192.168.10.157"))
	a, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	s, _ := got.Load().(string)
	if a.Items[0].Status != response.ItemExecuted || !strings.HasPrefix(s, "sha256=") || !strings.Contains(s, `"text":"PC-HR-01"`) || strings.Contains(*a.Items[0].Result, "/hook") {
		t.Fatalf("item %+v, request seen: %s", a.Items[0], s)
	}
	// The guarded client does not follow a redirect.
	plain := httptest.NewServer(srv.Config.Handler)
	defer plain.Close()
	e.svc.AllowLoopbackForTest()
	e2 := newEnv(t)
	e2.svc.AllowLoopbackForTest()
	req, _ := http.NewRequestWithContext(e2.ctx(), http.MethodGet, plain.URL+"/redir", nil)
	resp, err := e2.svc.GuardedClientForTest().Do(req)
	e2.must(err)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || redirected.Load() != 0 {
		t.Fatalf("status %d, redirect followed: %d", resp.StatusCode, redirected.Load())
	}
}

func (e *env) webhookRule() {
	e.rule("Call the hook", "honeypot", []response.RuleAction{{ActionID: "webhook_call", Params: map[string]string{"text": "{{trigger.source_device}}"}}}, nil)
}

// Events from the bus become triggers: a finding, a device that is not approved. Handlers only record; the evaluate step runs the rules.
func TestEventIntakeFromTheBus(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-nas"] = response.DeviceInfo{ID: "a-nas", Name: "NAS-PHOTOS", IP: "192.168.10.21", Kind: "nas", Approved: true}
	e.dir.devices["a-unk"] = response.DeviceInfo{ID: "a-unk", Name: "192.168.10.157", IP: "192.168.10.157", MAC: "3c:22:fb:10:aa:01", Kind: "iot", Approved: false, Seen: e.clock.Now()}
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a-nas", CVE: "CVE-2024-3400", Severity: "critical", Status: "suspected", KEV: true}
	e.dir.findings["f2"] = response.FindingInfo{ID: "f2", AssetID: "a-nas", CVE: "CVE-2024-1", Severity: "high", Status: "patched"}
	unsub := e.svc.Subscribe(e.bus)
	e.rule("Tell me", "finding", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.device}}: {{trigger.cve}}"}}}, func(in *response.RuleInput) {
		in.Conditions = []response.Condition{{Field: "severity", Op: "eq", Value: "critical"}}
	})
	e.rule("Unknown", "unknown_device", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "Unknown device {{trigger.mac}}"}}}, nil)
	pub := func(name string, data any) {
		e.must(e.bus.Publish(context.Background(), events.Event{Name: name, Data: data}))
	}
	pub("findings.finding.created", map[string]any{"finding_id": "f1", "asset_id": "a-nas", "cve": "CVE-2024-3400", "severity": "critical"})
	pub("findings.finding.created", map[string]any{"finding_id": "f1"}) // twice: one event
	pub("findings.finding.created", map[string]any{"finding_id": "f2"}) // not open
	pub("findings.finding.status_changed", map[string]any{"finding_id": "f1", "to": "patched"})
	pub("inventory.asset.discovered", map[string]any{"asset_id": "a-nas"}) // approved: not unknown
	pub("inventory.asset.discovered", map[string]any{"asset_id": "a-unk"})
	pub("inventory.asset.discovered", map[string]any{"asset_id": "nope"})
	if n := e.count(`SELECT COUNT(*) FROM resp_events`); n != 2 || len(e.actions()) != 0 {
		t.Fatalf("%d events stored, %d requests before evaluation", n, len(e.actions()))
	}
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	if sum.Requests != 2 || len(e.actions()) != 2 {
		t.Fatalf("summary %+v", sum)
	}
	if again, _ := e.svc.Evaluate(e.ctx()); again.Matched != 0 {
		t.Fatalf("an event ran twice: %+v", again)
	}
	var fa response.ActionRequest
	for _, a := range e.actions() {
		if a.Trigger != nil && *a.Trigger == "finding" {
			fa = a
		}
	}
	if fa.FindingID == nil || *fa.FindingID != "f1" || fa.Items[0].Change.CLI != "notify NAS-PHOTOS: CVE-2024-3400" {
		t.Fatalf("finding request: %+v", fa)
	}
	if _, err := e.svc.Approve(e.ctx(), oper, fa.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if len(e.note.msgs) != 1 || !strings.Contains(e.note.msgs[0], "NAS-PHOTOS: CVE-2024-3400") {
		t.Fatalf("messages: %v", e.note.msgs)
	}
	evs, err := e.svc.Events(e.ctx())
	e.must(err)
	if len(evs) != 2 || len(evs[0].HandledBy) == 0 {
		t.Fatalf("events: %+v", evs)
	}
	// While the module is off the handlers record nothing (SYS-5).
	unsub()
	off := &gate{on: false}
	e2 := newEnv(t, func(c *response.Config) { c.Modules = off })
	e2.dir.devices["a-unk"] = e.dir.devices["a-unk"]
	e2.svc.Subscribe(e2.bus)
	e2.must(e2.bus.Publish(context.Background(), events.Event{Name: "inventory.asset.discovered", Data: map[string]any{"asset_id": "a-unk"}}))
	if e2.count(`SELECT COUNT(*) FROM resp_events`) != 0 {
		t.Fatal("an event was recorded while the module is off")
	}
}

// S-RESP-3, #304: a real honeypot hit (honeypot.hit.created) is an event of the honeypot trigger with the trigger fields filled; the
// data came from the network, so an event without a valid source address or with an unknown kind is dropped.
func TestHoneypotHitEvent(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC-HR-01", IP: "192.168.10.107", Kind: "pc", Approved: true}
	e.svc.Subscribe(e.bus)
	e.rule("Trap", "honeypot", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.source_device}} {{trigger.source_ip}} touched {{trigger.decoy}} by {{trigger.kind}}"}}}, func(in *response.RuleInput) {
		in.Conditions = []response.Condition{{Field: "kind", Op: "eq", Value: "service"}}
	})
	pub := func(data map[string]any) {
		e.must(e.bus.Publish(context.Background(), events.Event{Name: "honeypot.hit.created", Data: data}))
	}
	pub(map[string]any{"id": "hit-1", "ts": "2026-11-11T10:00:00.250Z", "kind": "service", "service": "ssh", "port": 22, "src_ip": "192.168.10.107", "label": "SSH", "decoy": "FILESRV-OLD", "src_asset_id": "a-pc"})
	pub(map[string]any{"id": "hit-1", "kind": "service", "src_ip": "192.168.10.107"})                              // the same hit again: one event
	pub(map[string]any{"id": "hit-2", "kind": "token", "src_ip": "::ffff:192.168.10.9", "decoy": "Bait\naccount"}) // no rule matches a token
	for _, bad := range []map[string]any{
		{"id": "hit-3", "kind": "service", "src_ip": "192.168.10.107; reboot"},
		{"id": "hit-4", "kind": "service", "src_ip": "fe80::1%eth0"},
		{"id": "hit-5", "kind": "ssh", "src_ip": "192.168.10.107"},
		{"id": "", "kind": "service", "src_ip": "192.168.10.107"},
	} {
		pub(bad)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'honeypot'`); n != 2 {
		t.Fatalf("%d honeypot events stored, want 2", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'honeypot:hit-2' AND fields LIKE '%"source_ip":"192.168.10.9"%' AND fields NOT LIKE '%\\n%'`); n != 1 {
		t.Fatal("the mapped IPv6 source is not kept as its IPv4 address, or the decoy name kept a line break")
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'honeypot:hit-1' AND ts = '2026-11-11T10:00:00.250Z' AND asset_id = 'a-pc' AND device_kind = 'pc'`); n != 1 {
		t.Fatal("the hit's time or source device was not kept")
	}
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	l := e.actions()
	if sum.Requests != 1 || len(l) != 1 || l[0].Items[0].Change.CLI != "notify PC-HR-01 192.168.10.107 touched FILESRV-OLD by service" {
		lg, _ := e.svc.Log(e.ctx())
		t.Fatalf("summary %+v, requests %+v, log %+v", sum, l, lg)
	}
}

// Review of #304 (D-286 (4)): the source of a port-scan hit can be forged, so a pre-approved rule asks a person for it; a service hit is
// carried out. At most maxHoneypotPerHour hits an hour reach the rules, and the first one over writes one line to the log.
func TestHoneypotScanNeverPreApprovedAndHourlyCap(t *testing.T) {
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	e.rule("Trap", "honeypot", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}},
		func(in *response.RuleInput) { in.PreApproved = true })
	pub := func(id, kind, ip string) {
		e.must(e.bus.Publish(context.Background(), events.Event{Name: "honeypot.hit.created", Data: map[string]any{"id": id, "kind": kind, "src_ip": ip}}))
	}
	pub("hit-scan", "scan", "185.220.101.47")
	pub("hit-svc", "service", "185.220.101.48")
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	got := map[string]response.ActionRequest{}
	for _, a := range e.actions() {
		got[a.Items[0].Title] = a
	}
	if len(got) != 2 {
		t.Fatalf("requests: %+v", got)
	}
	for title, a := range got {
		scan := strings.Contains(title, "185.220.101.47")
		if scan && (a.Status != "pending" || a.PreApproved) || !scan && (a.Status == "pending" || !a.PreApproved) {
			t.Errorf("%s: status %s, pre-approved %v", title, a.Status, a.PreApproved)
		}
	}
	for i := 0; i < 70; i++ {
		pub("flood-"+strconv.Itoa(i), "scan", "185.220.102."+strconv.Itoa(i))
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'honeypot'`); n != 60 {
		t.Errorf("%d honeypot events stored this hour, want the cap of 60", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE detail LIKE 'honeypot_cap:%'`); n != 1 {
		t.Errorf("%d cap lines in the log, want 1", n)
	}
}

type gate struct{ on bool }

func (g *gate) Enabled(string) bool { return g.on }

func TestManualAndScheduledRules(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC-HR-01", IP: "192.168.10.107", MAC: "3c:22:fb:10:aa:01", Kind: "pc", Approved: true}
	r := e.rule("Tell", "manual", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "Manual run on {{trigger.device}}"}}}, nil)
	_, err := e.svc.RunManual(e.ctx(), oper, r.ID, "nope")
	wantCode(t, err, 404, "not_found")
	sum, err := e.svc.RunManual(e.ctx(), oper, r.ID, "a-pc")
	e.must(err)
	if sum.Requests != 1 || len(e.actions()) != 1 {
		t.Fatalf("%+v", sum)
	}
	other := e.rule("Other", "honeypot", blockAction(60), func(in *response.RuleInput) {
		in.Actions = []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "x"}}}
	})
	_, err = e.svc.RunManual(e.ctx(), oper, other.ID, "a-pc")
	wantCode(t, err, 409, "not_manual")
	// A schedule rule runs when due, once per interval.
	e.rule("Digest", "schedule", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "Weekly digest"}}}, func(in *response.RuleInput) { in.ScheduleMin = intp(15) })
	e.must(e.svc.RunSchedules(e.ctx()))
	n := len(e.actions())
	e.must(e.svc.RunSchedules(e.ctx()))
	if n != 2 || len(e.actions()) != n {
		t.Fatalf("%d requests after the first run, %d after the second", n, len(e.actions()))
	}
	e.clock.Advance(16 * time.Minute)
	e.must(e.svc.Sweep(e.ctx())) // the first digest expired unanswered
	e.must(e.svc.RunSchedules(e.ctx()))
	if len(e.actions()) != 3 {
		t.Fatalf("%d requests after the interval", len(e.actions()))
	}
}

// INV-14c: custom actions follow the connection kind and need a write tool; built-ins take only enabled, ai_may_propose and connection_id.
func TestContract_INV14c_Catalog(t *testing.T) {
	e := newEnv(t)
	e.conns.list = []response.ConnectionInfo{
		{Connection: response.Connection{ID: "cn-ro", Name: "Read only", Enabled: true, Kind: "http", WriteTools: []string{}}, Target: "https://a.lan"},
		{Connection: response.Connection{ID: "cn-ssh", Name: "Switch", Enabled: true, Kind: "ssh", WriteTools: []string{"cli"}}, Target: "ssh://sw"},
		{Connection: response.Connection{ID: "cn-http", Name: "API", Enabled: true, Kind: "http", WriteTools: []string{"w"}}, Target: "https://api.lan"},
		{Connection: response.Connection{ID: "cn-mcp", Name: "MCP", Enabled: true, Kind: "mcp-http", WriteTools: []string{"block", "unblock"}}, Target: "https://mcp.lan"},
	}
	in := response.CatalogInput{Name: "Shut a port", Description: "d", ConnectionID: "cn-ssh", Risk: response.RiskMedium, Enabled: true,
		Run: response.Tpl{CLI: "interface {interface}\nshutdown"}, Rollback: response.Tpl{CLI: "interface {interface}\nno shutdown"},
		Precheck: response.Tpl{CLI: "show interfaces {interface} switchport"}, PrecheckRefuse: []string{"Administrative Mode: trunk"}}
	_, err := e.svc.AddAction(e.ctx(), admin, func() response.CatalogInput { x := in; x.ConnectionID = "cn-ro"; return x }())
	wantCode(t, err, 409, "read_only")
	for name, mod := range map[string]func(x *response.CatalogInput){
		"shell":          func(x *response.CatalogInput) { x.Run.CLI = "interface {interface}; reboot" },
		"pipe":           func(x *response.CatalogInput) { x.Run.CLI = "show x | include {name}" },
		"text":           func(x *response.CatalogInput) { x.Run.CLI = "echo {text}" },
		"no placeholder": func(x *response.CatalogInput) { x.Run.CLI = "shutdown"; x.Rollback.CLI = "no shutdown" },
		"other kind":     func(x *response.CatalogInput) { x.Run = response.Tpl{Method: "POST", Path: "/a/{name}"} },
		"extra in rb":    func(x *response.CatalogInput) { x.Rollback.CLI = "vlan {vlan}" },
		"no rollback":    func(x *response.CatalogInput) { x.Rollback = response.Tpl{} },
		"unknown conn":   func(x *response.CatalogInput) { x.ConnectionID = "nope" },
		"risk":           func(x *response.CatalogInput) { x.Risk = "extreme" },
		"mcp no tool": func(x *response.CatalogInput) {
			x.ConnectionID = "cn-mcp"
			x.Run = response.Tpl{Body: `{"ip":"{ip}"}`}
			x.Rollback = x.Run
		},
		"tool on ssh": func(x *response.CatalogInput) { x.Tool = strp("cli") },
	} {
		x := in
		mod(&x)
		_, err := e.svc.AddAction(e.ctx(), admin, x)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	a, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	if a.Builtin || !a.Available || a.Device != true || len(a.Params) != 1 || a.Params[0] != "interface" {
		t.Fatalf("action: %+v", a)
	}
	mcp := in
	mcp.ConnectionID, mcp.Tool, mcp.RollbackTool = "cn-mcp", strp("block"), strp("unblock")
	mcp.Run, mcp.Rollback = response.Tpl{Body: `{"ip":"{ip}"}`}, response.Tpl{Body: `{"ip":"{ip}"}`}
	mcp.Precheck, mcp.PrecheckRefuse = response.Tpl{}, nil // an MCP server has no check before
	if _, err := e.svc.AddAction(e.ctx(), admin, mcp); err != nil {
		t.Fatal(err)
	}
	// Built-in: only enabled, ai_may_propose, connection_id; not deletable; a custom action in use cannot be deleted.
	name := "Hacked"
	up, err := e.svc.ChangeAction(e.ctx(), admin, "blocklist_add", response.CatalogUpdate{Name: &name, Present: map[string]bool{"name": true}})
	e.must(err)
	if up.Name == name {
		t.Fatal("a built-in action was renamed")
	}
	wantCode(t, e.svc.DeleteAction(e.ctx(), admin, "blocklist_add"), 409, "builtin")
	e.rule("Shut", "manual", []response.RuleAction{{ActionID: a.ID, Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(60)}}, nil)
	wantCode(t, e.svc.DeleteAction(e.ctx(), admin, a.ID), 409, "in_use")
	wantCode(t, e.svc.DeleteAction(e.ctx(), admin, "nope"), 404, "not_found")
	// A built-in device action cannot be bound to a read-only connection.
	cid := "cn-ro"
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{ConnectionID: &cid, Present: map[string]bool{"connection_id": true}})
	wantCode(t, err, 409, "read_only")
	// The catalog lists packs from the data files and connections.
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	if len(c.Items) < 20 || len(c.Connections) != 4 {
		t.Fatalf("catalog: %d items, %d connections", len(c.Items), len(c.Connections))
	}
}

func TestTemplatesAndClone(t *testing.T) {
	e := newEnv(t)
	l, err := e.svc.Templates(e.ctx())
	e.must(err)
	if len(l) != 15 {
		t.Fatalf("%d templates", len(l))
	}
	r, err := e.svc.Clone(e.ctx(), admin, l[0].ID)
	e.must(err)
	if r.Enabled || r.Live || r.PreApproved || r.TemplateID == nil || *r.TemplateID != l[0].ID {
		t.Fatalf("clone: %+v", r)
	}
	_, err = e.svc.Clone(e.ctx(), admin, "nope")
	wantCode(t, err, 404, "not_found")
}

// Plans written by the AI job (part 13b) are read here, and one proposal becomes a request.
func TestPlansAndProposalRequest(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a-nas", CVE: "CVE-2024-3400", Severity: "critical", Status: "confirmed"}
	e.dir.devices["a-nas"] = response.DeviceInfo{ID: "a-nas", Name: "NAS", IP: "192.168.10.21", Approved: true}
	steps := `[{"kind":"contain","title":"Switch off the virtual IP","detail":"d","proposal":{"id":"pr-1","action_id":"fgt_ban_ip","params":{"ip":"192.168.10.21"},"ttl_min":1440,"asset_id":"a-nas","asset_name":"NAS"}},{"kind":"check","title":"Check","detail":"d","proposal":null}]`
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES ('plan-f1','f1','CVE-2024-3400','a-nas','NAS','2026-11-09T09:00:00.000Z','m','p','path','[]',?)`, steps)
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	if len(pl.Items) != 1 || pl.Execution || pl.Items[0].Steps[0].Proposal == nil || pl.Items[0].Steps[0].Proposal.State != "execution_off" {
		t.Fatalf("plans: %+v", pl)
	}
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "execution_off")
	e.turnOn()
	pl, _ = e.svc.Plans(e.ctx(), "f1")
	if pl.Items[0].Steps[0].Proposal.State != "ready" {
		t.Fatalf("state %s", pl.Items[0].Steps[0].Proposal.State)
	}
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	e.must(err)
	if a.Source != "ai" || a.Status != response.StatusPending || a.Items[0].ConnectorID == nil {
		t.Fatalf("request: %+v", a)
	}
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "already_requested")
	_, err = e.svc.RequestProposal(e.ctx(), oper, "nope")
	wantCode(t, err, 404, "not_found")
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a-nas", Severity: "critical", Status: "patched"}
	pl, _ = e.svc.Plans(e.ctx(), "")
	if len(pl.Items) != 0 {
		t.Fatal("a plan of a closed finding is listed")
	}
}

func TestJobsBelongToTheModule(t *testing.T) {
	e := newEnv(t)
	js := e.svc.Jobs()
	if len(js) != 3 { // evaluate, sweep, plan
		t.Fatalf("%d jobs", len(js))
	}
	for _, j := range js {
		if j.Module != "response" || j.Every <= 0 {
			t.Fatalf("job %+v", j)
		}
	}
}
