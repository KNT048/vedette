package response_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/response"
)

// WP-31 review, slice R1: header values never reach a reader (D-174), an approver reads the whole change (D-175).

// keyedRequest makes one open request whose API call carries the header "X-Trace: abc123secret".
func keyedRequest(t *testing.T) *env {
	t.Helper()
	e := precheckEnv(t)
	in := apiAction()
	in.Run.Headers = "X-Trace: abc123secret"
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	return e
}

func actionsJSON(t *testing.T, e *env, role routes.Role) string {
	t.Helper()
	h := response.NewResponseHandlers(e.svc)
	ctx := server.WithPrincipal(e.ctx(), server.Principal{ID: "u-x", Email: "x@acme.example", Role: role})
	res, err := h.ResponseGetResponseActions(ctx)
	e.must(err)
	b, err := res.MarshalJSON()
	e.must(err)
	return string(b)
}

// M1: GET /response/actions is a viewer's call. A viewer reads header names only; the people who approve (operators, administrators) read
// every value of what they approve, except a credential's (D-174, D-175).
func TestWP31_M1_ViewerReadsActionsWithoutHeaderValues(t *testing.T) {
	e := keyedRequest(t)
	if got := e.only().Items[0].Change.Rest.Headers["X-Trace"]; got != "abc123secret" {
		t.Fatalf("the service holds %q", got)
	}
	got := actionsJSON(t, e, routes.Viewer)
	if strings.Contains(got, "abc123") || !strings.Contains(got, "X-Trace") || !strings.Contains(got, "(hidden)") {
		t.Errorf("a viewer sees %s", got)
	}
	for _, role := range []routes.Role{routes.Operator, routes.Admin} {
		if got := actionsJSON(t, e, role); !strings.Contains(got, "abc123secret") {
			t.Errorf("%v does not see the header: %s", role, got)
		}
	}
}

// GET /response/plans is a viewer's call too: a proposal holds the exact change.
func TestWP31_M1_ViewerReadsPlansWithoutHeaderValues(t *testing.T) {
	e := planEnv(t)
	e.exec1(`UPDATE resp_catalog SET run = json_set(run, '$.headers', 'X-Trace: abc123secret') WHERE id = 'fgt_vip_disable'`)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_vip_disable","params":{"name":"NAS"},"asset_id":"a-nas","asset_name":"NAS"}`)
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	if b, _ := json.Marshal(pl); !strings.Contains(string(b), "abc123secret") {
		t.Fatalf("the test plan carries no header: %s", b)
	}
	h := response.NewResponseHandlers(e.svc)
	for role, want := range map[routes.Role]bool{routes.Viewer: false, routes.Operator: true, routes.Admin: true} {
		res, err := h.ResponseGetResponsePlans(server.WithPrincipal(e.ctx(), server.Principal{ID: "u-x", Email: "x@acme.example", Role: role}), oas.ResponseGetResponsePlansParams{})
		e.must(err)
		b, err := res.MarshalJSON()
		e.must(err)
		if got := strings.Contains(string(b), "abc123secret"); got != want || !strings.Contains(string(b), "X-Trace") {
			t.Errorf("%v: value shown %v, want %v: %s", role, got, want, b)
		}
	}
}

// D-174 (5): a request stored before credential headers were refused keeps its header, but no read shows its value, an admin's included.
func TestWP31_M1_AStoredCredentialHeaderIsHiddenFromEveryone(t *testing.T) {
	e := keyedRequest(t)
	e.exec1(`UPDATE resp_actions SET items = replace(items, 'X-Trace', 'X-Api-Key')`)
	for _, role := range []routes.Role{routes.Viewer, routes.Admin} {
		if got := actionsJSON(t, e, role); strings.Contains(got, "abc123") || !strings.Contains(got, "X-Api-Key") {
			t.Errorf("%v sees %s", role, got)
		}
	}
}

// The simulation of a rule shows the exact call: an operator or an administrator reads every value except a credential's.
func TestWP31_M1_SimulateHidesCredentialHeaderValues(t *testing.T) {
	e := precheckEnv(t)
	in := apiAction()
	in.Run.Headers = "X-Trace: abc123secret\nX-Api-Key: {domain}"
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	rule := response.RuleInput{Name: "S", Enabled: true, Live: false, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, MaxPerHour: 10,
		Actions: []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}}
	raw, err := json.Marshal(map[string]any{"rule": rule})
	e.must(err)
	var req oas.ResponsePostResponseRulesSimulateReq
	e.must(req.UnmarshalJSON(raw))
	h := response.NewResponseHandlers(e.svc)
	for _, role := range []routes.Role{routes.Operator, routes.Admin} {
		res, err := h.ResponsePostResponseRulesSimulate(server.WithPrincipal(e.ctx(), server.Principal{ID: "u-x", Email: "x@acme.example", Role: role}), &req)
		e.must(err)
		b, err := res.MarshalJSON()
		e.must(err)
		if !strings.Contains(string(b), "abc123secret") || !strings.Contains(string(b), `"X-Api-Key":"(hidden)"`) {
			t.Errorf("%v: %s", role, b)
		}
	}
}

// D-174 (2): a template cannot hold a credential header with a literal value, in any step; its value is exactly one placeholder.
func TestWP31_M1_TemplateWithACredentialHeaderIsRefused(t *testing.T) {
	e := precheckEnv(t)
	for _, h := range []string{"X-API-Key: abc", "x-api-key: abc", "X-ApiKey: abc", "Apikey: abc", "Token: abc", "X-Auth: abc", "X-Password: abc", "X-Session: abc", "X-Auth-Token: abc", "Api-Key: abc",
		"X-PAN-KEY: abc", "X-Vendor-Token: abc", "X-App-Secret: abc", "Cookie: a=b", "Proxy-Authorization: x", "Accept: json\nX-Api-Key: abc",
		"X-API-Key: realkey{", "X-API-Key: {domain}x", "X-API-Key: a{domain}", "X-API-Key: {domain}{domain}", "X-API-Key: {Domain}"} {
		in := apiAction()
		in.Run.Headers = h
		_, err := e.svc.AddAction(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%q: %v", h, err)
		}
	}
	in := apiAction()
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Headers: "X-Api-Key: abc"}
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
		t.Error("a credential header in the read-back was accepted")
	}
	for i, h := range []string{"X-Trace: abc", "Accept: application/json", "X-Api-Key: {domain}", "X-Keep-Going: yes"} {
		in := apiAction()
		in.Name += fmt.Sprint(" ", i)
		in.Run.Headers = h
		if _, err := e.svc.AddAction(e.ctx(), admin, in); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
}

// ---- M2 ----

func telegramEnv(t *testing.T) *env {
	t.Helper()
	e := precheckEnv(t)
	e.note.chs = []response.NotifyChannel{{Type: "telegram", Label: "Telegram", Configured: true, Enabled: true, Approvals: true, Approvers: 1}}
	e.note.approvers = map[string][]response.Approver{"telegram": {{UserID: "u-op", Address: "1001"}}}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"telegram"} })
	return e
}

func lines(n int) string {
	var l []string
	for i := 1; i <= n; i++ {
		l = append(l, fmt.Sprintf("show clock %d", i))
	}
	return strings.Join(l, "\n")
}

// sshRequest makes one request of a custom SSH action whose command is the given text, with the given risk.
func sshRequest(t *testing.T, e *env, run string, risk response.Risk, undo ...string) response.ActionRequest {
	t.Helper()
	run = "show ip route {ip}\n" + run
	in := response.CatalogInput{Name: "Many lines", Description: "d", ConnectionID: "cn-ssh", Risk: risk, Enabled: true,
		Run: response.Tpl{CLI: run}, Rollback: response.Tpl{CLI: "show clock undo\nshow version"}}
	if len(undo) > 0 {
		in.Rollback.CLI = undo[0]
	}
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Many", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.svc.WaitSendsForTest()
	return e.only()
}

// M2: a high-risk, ten-line change reaches the approver in full and with no button.
func TestWP31_M2_HighRiskMultiLineChangeIsInFullWithoutButtons(t *testing.T) {
	e := telegramEnv(t)
	sshRequest(t, e, lines(10), response.RiskHigh)
	m := e.note.requests()
	if len(m) != 1 {
		t.Fatalf("%d messages", len(m))
	}
	for i := 1; i <= 10; i++ {
		if !strings.Contains(m[0].What, fmt.Sprintf("show clock %d", i)) {
			t.Errorf("line %d is not in the message:\n%s", i, m[0].What)
		}
	}
	if !m[0].NoChatButtons || !strings.Contains(m[0].What, "Undo:") || !strings.Contains(m[0].What, "show clock undo") || !strings.Contains(m[0].What, "Vedette") {
		t.Errorf("buttons %v, text:\n%s", !m[0].NoChatButtons, m[0].What)
	}
}

func TestWP31_M2_LowRiskShortChangeKeepsTheButtons(t *testing.T) {
	e := telegramEnv(t)
	sshRequest(t, e, lines(3), response.RiskLow)
	m := e.note.requests()
	if len(m) != 1 || m[0].NoChatButtons || !strings.Contains(m[0].What, "show clock 3") {
		t.Fatalf("%+v", m)
	}
}

// A change that does not fit one message gets no button, and the message says to open Vedette.
func TestWP31_M2_LowRiskChangeOverTheLimitHasNoButtons(t *testing.T) {
	e := telegramEnv(t)
	long := func(tag string) string {
		var l []string
		for i := range 60 {
			l = append(l, fmt.Sprintf("show interfaces %s %03d description", tag, i))
		}
		return strings.Join(l, "\n")[:1960]
	}
	sshRequest(t, e, long("run"), response.RiskLow, long("undo")) // the call and the undo together are about 4000 characters
	m := e.note.requests()
	if len(m) != 1 || !m[0].NoChatButtons || !strings.Contains(m[0].What, "open Vedette") || len([]rune(m[0].What)) > 3000 {
		t.Fatalf("%d messages; %+v", len(m), m)
	}
}

// L6: an AI request carries the label in the message and on the page of the link.
func TestWP31_L6_AIRequestCarriesTheLabel(t *testing.T) {
	e, _, _ := propEnv(t, true)
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 1}}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	r := e.mustPropose(lowBody())
	e.svc.WaitSendsForTest()
	m := e.note.requests()
	if r.Request == nil || len(m) != 1 || !strings.Contains(m[0].What, "AI-generated, needs human review") {
		t.Fatalf("%+v %+v", r, m)
	}
}

// D-175 (3): the rows of the chain hold the whole call; a cap that cuts keeps the SHA-256 of the whole text.
func TestWP31_M2_ChainRowsHoldTheFullCall(t *testing.T) {
	e := precheckEnv(t)
	req := sshRequest(t, e, lines(10), response.RiskLow)
	want := "show ip route 198.51.100.7" + `\n` + strings.ReplaceAll(lines(10), "\n", `\n`)
	if !e.logHas("request", want) {
		t.Fatalf("the request row does not hold the whole call:\n%s", e.dump(`SELECT detail FROM resp_log WHERE kind = 'request'`))
	}
	_, err := e.svc.Approve(e.ctx(), oper, req.ID, nil, "")
	e.must(err)
	if !e.logHas("executed", want) {
		t.Fatalf("the execute row does not hold the whole call:\n%s", e.dump(`SELECT detail FROM resp_log WHERE kind = 'executed'`))
	}
}

func TestWP31_M2_ACutCallKeepsItsHash(t *testing.T) {
	e := precheckEnv(t)
	var l []string
	for i := range 40 {
		l = append(l, fmt.Sprintf("show interfaces description number %04d of the long list", i))
	}
	long := strings.Join(l, "\n")[:1960]
	sshRequest(t, e, long, response.RiskLow)
	call := "command: show ip route 198.51.100.7" + `\n` + strings.ReplaceAll(long, "\n", `\n`)
	if len([]rune(call)) < 1500 {
		t.Fatalf("test needs a call over the cap, got %d", len(call))
	}
	row := e.dump(`SELECT detail FROM resp_log WHERE kind = 'request' AND detail LIKE '%command:%'`)
	if !strings.Contains(row, "[cut; SHA-256 of the full text ") || len([]rune(strings.TrimSpace(row))) > 1500 {
		t.Fatalf("row of %d runes: %s", len([]rune(row)), row)
	}
	h := row[strings.Index(row, "text ")+5:]
	h = h[:64]
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("not a hash: %q", h)
	}
}

func TestWP31_L6_LinkPageOfAnAIRequestCarriesTheLabel(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	if v := e.view(tok); v.State != "ready" || v.AIGenerated {
		t.Fatalf("a rule request is labelled AI: %+v", v)
	}
	e.asAI(a.ID, plainAI)
	if v := e.view(tok); v.State != "ready" || !v.AIGenerated {
		t.Fatalf("an AI request has no label on its page: %+v", v)
	}
}

// The link page is an approver's: it shows the values of the call, never a credential's.
func TestWP31_M1_LinkPageShowsValuesButNoCredential(t *testing.T) {
	e := newLinkEnv(t)
	e.conns.list = []response.ConnectionInfo{{Connection: response.Connection{ID: "cn-http", Name: "API", Enabled: true, Kind: "http", WriteTools: []string{"w"}}, Target: "https://api.lan"}}
	in := apiAction()
	in.Run.Headers = "X-Trace: abc123secret\nX-Api-Key: {domain}"
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	e.svc.WaitSendsForTest()
	a := e.only()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	b, _ := json.Marshal(e.view(tok))
	if !strings.Contains(string(b), "abc123secret") || strings.Contains(string(b), `"X-Api-Key":"bad.example.com"`) || !strings.Contains(string(b), `"X-Api-Key":"(hidden)"`) {
		t.Fatalf("the link page shows %s", b)
	}
	if m := e.note.requests(); len(m) == 1 && (!strings.Contains(m[0].What, "X-Trace: abc123secret") || !strings.Contains(m[0].What, "X-Api-Key: (hidden)")) {
		t.Errorf("the approval message:\n%s", m[0].What)
	}
}
