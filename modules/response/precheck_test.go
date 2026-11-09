package response_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/modules/response"
)

// precheckEnv has an SSH switch, an API and an MCP server that can all write.
func precheckEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.conns.list = []response.ConnectionInfo{
		{Connection: response.Connection{ID: "cn-ssh", Name: "Switch", Enabled: true, Kind: "ssh", WriteTools: []string{"cli"}}, Target: "ssh://sw"},
		{Connection: response.Connection{ID: "cn-http", Name: "API", Enabled: true, Kind: "http", WriteTools: []string{"w"}}, Target: "https://api.lan"},
		{Connection: response.Connection{ID: "cn-mcp", Name: "MCP", Enabled: true, Kind: "mcp-http", WriteTools: []string{"block", "unblock"}}, Target: "https://mcp.lan"},
	}
	return e
}

func portAction() response.CatalogInput {
	return response.CatalogInput{Name: "Shut a port", Description: "d", ConnectionID: "cn-ssh", Risk: response.RiskMedium, Enabled: true,
		Run: response.Tpl{CLI: "interface {interface}\nshutdown"}, Rollback: response.Tpl{CLI: "interface {interface}\nno shutdown"},
		Precheck: response.Tpl{CLI: "show interfaces {interface} switchport"}, PrecheckRefuse: []string{"Administrative Mode: trunk"}}
}

func apiAction() response.CatalogInput {
	return response.CatalogInput{Name: "Block a domain", Description: "d", ConnectionID: "cn-http", Risk: response.RiskLow, Enabled: true,
		Run: response.Tpl{Method: "POST", Path: "/d", Body: `{"domain":"{domain}"}`}, Rollback: response.Tpl{Method: "DELETE", Path: "/d/{domain}"}}
}

// INV-14c (D-95): the check before and the read-back text are typed and validated when an action is saved.
func TestContract_INV14c_PrecheckAndExpectAreTypedAndChecked(t *testing.T) {
	e := precheckEnv(t)
	get := response.Tpl{Method: "GET", Path: "/d/{domain}"}
	api := func(f func(x *response.CatalogInput)) response.CatalogInput { x := apiAction(); f(&x); return x }
	long := func(n int) string { return strings.Repeat("x", n) }
	for name, in := range map[string]response.CatalogInput{
		"expect on the run step":      api(func(x *response.CatalogInput) { x.Run.Expect = "x" }),
		"expect on the rollback step": api(func(x *response.CatalogInput) { x.Rollback.Expect = "x" }),
		"expect on the check": api(func(x *response.CatalogInput) {
			x.Precheck = get
			x.Precheck.Expect = "x"
			x.PrecheckRefuse = []string{"x"}
		}),
		"expect without a read-back":   api(func(x *response.CatalogInput) { x.Verify = response.Tpl{Expect: "x"} }),
		"expect too long":              api(func(x *response.CatalogInput) { x.Verify = get; x.Verify.Expect = long(201) }),
		"expect with a shell char":     api(func(x *response.CatalogInput) { x.Verify = get; x.Verify.Expect = "a; b" }),
		"expect with a newline":        api(func(x *response.CatalogInput) { x.Verify = get; x.Verify.Expect = "a\nb" }),
		"expect with an unknown token": api(func(x *response.CatalogInput) { x.Verify = get; x.Verify.Expect = "{nope}" }),
		"expect with {text}":           api(func(x *response.CatalogInput) { x.Verify = get; x.Verify.Expect = "{text}" }),
		"expect uses a param the action lacks": api(func(x *response.CatalogInput) {
			x.Verify = get
			x.Verify.Expect = "{ip}"
		}),
		"check without refusal texts": api(func(x *response.CatalogInput) { x.Precheck = get }),
		"refusal texts without check": api(func(x *response.CatalogInput) { x.PrecheckRefuse = []string{"x"} }),
		"six refusal texts": api(func(x *response.CatalogInput) {
			x.Precheck = get
			x.PrecheckRefuse = []string{"1", "2", "3", "4", "5", "6"}
		}),
		"refusal text 81 characters":  api(func(x *response.CatalogInput) { x.Precheck = get; x.PrecheckRefuse = []string{long(81)} }),
		"empty refusal text":          api(func(x *response.CatalogInput) { x.Precheck = get; x.PrecheckRefuse = []string{""} }),
		"blank refusal text":          api(func(x *response.CatalogInput) { x.Precheck = get; x.PrecheckRefuse = []string{"   "} }),
		"refusal text with a newline": api(func(x *response.CatalogInput) { x.Precheck = get; x.PrecheckRefuse = []string{"a\nb"} }),
		"refusal text with a control": api(func(x *response.CatalogInput) { x.Precheck = get; x.PrecheckRefuse = []string{"a\x00b"} }),
		"check that writes": api(func(x *response.CatalogInput) {
			x.Precheck = response.Tpl{Method: "POST", Path: "/d/{domain}"}
			x.PrecheckRefuse = []string{"x"}
		}),
		"check with a body": api(func(x *response.CatalogInput) {
			x.Precheck = response.Tpl{Method: "GET", Path: "/d/{domain}", Body: `{"a":1}`}
			x.PrecheckRefuse = []string{"x"}
		}),
		"check with a shell char": api(func(x *response.CatalogInput) {
			x.Precheck = response.Tpl{Method: "GET", Path: "/d/{domain}; x"}
			x.PrecheckRefuse = []string{"x"}
		}),
		"check with a command on API": api(func(x *response.CatalogInput) {
			x.Precheck = response.Tpl{CLI: "show x {domain}"}
			x.PrecheckRefuse = []string{"x"}
		}),
		"check uses a missing param": api(func(x *response.CatalogInput) {
			x.Precheck = response.Tpl{Method: "GET", Path: "/x/{ip}"}
			x.PrecheckRefuse = []string{"x"}
		}),
		"check on an MCP server": {Name: "M", Description: "d", ConnectionID: "cn-mcp", Tool: strp("block"), RollbackTool: strp("unblock"), Risk: response.RiskLow, Enabled: true,
			Run: response.Tpl{Body: `{"ip":"{ip}"}`}, Rollback: response.Tpl{Body: `{"ip":"{ip}"}`}, Precheck: response.Tpl{Body: `{}`}, PrecheckRefuse: []string{"x"}},
	} {
		_, err := e.svc.AddAction(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// What is allowed is stored and shown as typed; nothing else is changed by it.
	ok := apiAction()
	ok.Verify, ok.Verify.Expect = get, `"{domain}"`
	ok.Precheck, ok.PrecheckRefuse = get, []string{"already listed", "x"}
	a, err := e.svc.AddAction(e.ctx(), admin, ok)
	e.must(err)
	if a.Verify.Expect != `"{domain}"` || a.Precheck != get || !slices.Equal(a.PrecheckRefuse, []string{"already listed", "x"}) {
		t.Fatalf("stored: %+v", a)
	}
	// Without them the lists are empty, never nil (the wire form is [] not null).
	plain, err := e.svc.AddAction(e.ctx(), admin, func() response.CatalogInput { x := apiAction(); x.Name = "Plain"; return x }())
	e.must(err)
	if plain.PrecheckRefuse == nil || len(plain.PrecheckRefuse) != 0 || !plain.Precheck.Empty() || plain.Verify.Expect != "" {
		t.Fatalf("plain: %+v", plain)
	}
	// An update is validated like a create.
	bad := []string{}
	_, err = e.svc.ChangeAction(e.ctx(), admin, a.ID, response.CatalogUpdate{PrecheckRefuse: &bad})
	wantCode(t, err, 400, "invalid")
	more := []string{"one", "two"}
	up, err := e.svc.ChangeAction(e.ctx(), admin, a.ID, response.CatalogUpdate{PrecheckRefuse: &more})
	e.must(err)
	if !slices.Equal(up.PrecheckRefuse, more) {
		t.Fatalf("update: %+v", up)
	}
	// An MCP action without them is fine.
	m := response.CatalogInput{Name: "M", Description: "d", ConnectionID: "cn-mcp", Tool: strp("block"), RollbackTool: strp("unblock"), Risk: response.RiskLow, Enabled: true,
		Run: response.Tpl{Body: `{"ip":"{ip}"}`}, Rollback: response.Tpl{Body: `{"ip":"{ip}"}`}}
	if _, err := e.svc.AddAction(e.ctx(), admin, m); err != nil {
		t.Fatal(err)
	}
}

// INV-14c (D-95 (3), M4 of the WP-13a review): a device action that names a port needs a check before it with at least one refusal
// text, so a trunk or uplink port is never touched. Refused when saved; an older row without one is "not available".
func TestContract_INV14c_PortActionNeedsACheckBefore(t *testing.T) {
	e := precheckEnv(t)
	for name, mod := range map[string]func(x *response.CatalogInput){
		"no check":           func(x *response.CatalogInput) { x.Precheck, x.PrecheckRefuse = response.Tpl{}, nil },
		"no refusal text":    func(x *response.CatalogInput) { x.PrecheckRefuse = nil },
		"empty refusal list": func(x *response.CatalogInput) { x.PrecheckRefuse = []string{} },
	} {
		in := portAction()
		mod(&in)
		_, err := e.svc.AddAction(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" || !strings.Contains(strings.ToLower(err.Error()), "check before") {
			t.Errorf("%s: %v", name, err)
		}
	}
	a, err := e.svc.AddAction(e.ctx(), admin, portAction())
	e.must(err)
	if !a.Available || len(a.PrecheckRefuse) != 1 {
		t.Fatalf("a port action with a check: %+v", a)
	}
	// An MCP server cannot run a check, so it cannot carry an action that names a port.
	mcp := response.CatalogInput{Name: "M", Description: "d", ConnectionID: "cn-mcp", Tool: strp("block"), RollbackTool: strp("unblock"), Risk: response.RiskLow, Enabled: true,
		Run: response.Tpl{Body: `{"port":"{interface}"}`}, Rollback: response.Tpl{Body: `{"port":"{interface}"}`}}
	_, err = e.svc.AddAction(e.ctx(), admin, mcp)
	wantCode(t, err, 400, "invalid")
	// A row saved before the check existed (no check, no refusal) is shown as not available and cannot be approved.
	e.exec1(`UPDATE resp_catalog SET precheck = '{}', precheck_refuse = '[]' WHERE id = ?`, a.ID)
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, x := range c.Items {
		if x.ID == a.ID && (x.Available || x.UnavailableReason == nil || !strings.Contains(*x.UnavailableReason, "check before")) {
			t.Fatalf("the old row is %+v", x)
		}
	}
}

// INV-14c (13b-2, action-templates 12.1): the shipped data carries the fixes.
func TestContract_INV14c_LibraryDataFixes(t *testing.T) {
	e := newEnv(t)
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	by := map[string]response.CatalogAction{}
	for _, a := range c.Items {
		by[a.ID] = a
	}
	// 1. tool is for MCP connections only
	for _, id := range []string{"fgt_addrgrp_add", "fgt_vip_disable", "fgt_policy_disable"} {
		if by[id].Tool != nil {
			t.Errorf("%s has a tool: %q", id, *by[id].Tool)
		}
	}
	// 2. SSH: every step starts with the platform's paging-off line; a change sits between configure and end
	for id, first := range map[string]string{"cisco_port_shut": "terminal length 0", "aoscx_port_shut": "no page", "arubasw_port_shut": "no page"} {
		a := by[id]
		if !strings.HasPrefix(a.Run.CLI, first+"\n") || !strings.HasSuffix(a.Run.CLI, "\nend") || !strings.HasPrefix(a.Precheck.CLI, first+"\n") {
			t.Errorf("%s: run %q precheck %q", id, a.Run.CLI, a.Precheck.CLI)
		}
	}
	if by["cisco_port_shut"].Run.CLI != "terminal length 0\nconfigure terminal\ninterface {interface}\nshutdown\nend" {
		t.Errorf("cisco_port_shut run: %q", by["cisco_port_shut"].Run.CLI)
	}
	// 3. every action that names a port has a check before with refusal texts
	want := map[string][]string{
		"cisco_port_shut":            {"Administrative Mode: trunk", "Operational Mode: trunk", "Administrative Mode: dynamic"},
		"cisco_port_vlan_quarantine": {"Administrative Mode: trunk", "Operational Mode: trunk", "Administrative Mode: dynamic"},
		"aoscx_port_shut":            {"VLAN Mode: trunk", "VLAN Mode: native-untagged", "VLAN Mode: native-tagged"},
		"aoscx_vlan_quarantine":      {"VLAN Mode: trunk", "VLAN Mode: native-untagged", "VLAN Mode: native-tagged"},
		"arubasw_port_shut":          {"Tagged"}, "arubasw_vlan_quarantine": {"Tagged"},
	}
	for id, refuse := range want {
		if !slices.Equal(by[id].PrecheckRefuse, refuse) || by[id].Precheck.Empty() {
			t.Errorf("%s: %+v / %v", id, by[id].Precheck, by[id].PrecheckRefuse)
		}
	}
	for _, a := range c.Items {
		if a.Device && slices.Contains(a.Params, response.PInterface) && (a.Precheck.Empty() || len(a.PrecheckRefuse) == 0) {
			t.Errorf("%s names a port and has no check before", a.ID)
		}
		if a.PrecheckRefuse == nil {
			t.Errorf("%s: precheck_refuse is nil", a.ID)
		}
	}
	// 4. read-back text
	for id, exp := range map[string]string{"fgt_addrgrp_add": `"vedette-{ip}"`, "fgt_ban_ip": "{ip}", "fgt_vip_disable": `"status":"disable"`, "fgt_policy_disable": `"status":"disable"`,
		"opn_alias_add": `"{ip}"`, "pihole_block": `"domain":"{domain}"`, "cisco_port_shut": "disabled", "aoscx_port_shut": "Admin state is down", "cisco_acl_deny": "deny ip host {ip} any",
		"cisco_port_vlan_quarantine": "Access Mode VLAN: {vlan} "} {
		if by[id].Verify.Expect != exp {
			t.Errorf("%s expect = %q", id, by[id].Verify.Expect)
		}
	}
	for _, id := range []string{"cisco_save_config", "pf_alias_add", "arubasw_port_shut"} {
		if by[id].Verify.Expect != "" {
			t.Errorf("%s has an expect", id)
		}
	}
	// 6. the unverified FortiGate built-ins start switched off on a new install
	for _, id := range []string{"fgt_addrgrp_add", "fgt_ban_ip", "fgt_vip_disable"} {
		if by[id].Enabled {
			t.Errorf("%s is enabled", id)
		}
	}
	if !by["blocklist_add"].Enabled {
		t.Error("blocklist_add is not enabled")
	}
}

// An existing install keeps what its database says: seeding again refreshes the templates and the check, never the switch.
func TestLibrarySeedKeepsTheUsersSwitchAndRefreshesTheCheck(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	on := true
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{Enabled: &on})
	e.must(err)
	e.exec1(`UPDATE resp_catalog SET precheck = '{}', precheck_refuse = '[]' WHERE id = 'cisco_port_shut'`) // as an older build left it
	svc, err := response.New(e.cfg)                                                                         // a new process over the same database seeds again
	e.must(err)
	c, err := svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, a := range c.Items {
		if a.ID == "fgt_ban_ip" && !a.Enabled {
			t.Error("the seed switched an action the user had enabled back off")
		}
		if a.ID == "cisco_port_shut" && len(a.PrecheckRefuse) != 3 {
			t.Errorf("the seed did not refresh the check: %v", a.PrecheckRefuse)
		}
	}
}

// INV-9 (D-95 (4)): the fingerprint of an action covers its check, its refusal texts and its read-back text. Editing any of them cancels
// the open requests; a change that did not go through ChangeAction refuses the run.
func TestContract_INV9_PrecheckAndExpectAreInTheFingerprint(t *testing.T) {
	setup := func(t *testing.T) (*env, response.CatalogAction, string) {
		e := precheckEnv(t)
		in := apiAction()
		in.Name = "Quarantine an IP (API)"
		in.Run, in.Rollback = response.Tpl{Method: "POST", Path: "/q/{ip}"}, response.Tpl{Method: "DELETE", Path: "/q/{ip}"}
		in.Verify, in.Verify.Expect = response.Tpl{Method: "GET", Path: "/q/{ip}"}, "{ip}"
		in.Precheck, in.PrecheckRefuse = response.Tpl{Method: "GET", Path: "/q/{ip}"}, []string{"already"}
		in.ConnectionID = "cn-http"
		act, err := e.svc.AddAction(e.ctx(), admin, in)
		e.must(err)
		e.turnOn()
		e.rule("Quarantine", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
		e.fire(e.iocEvent("e1", "198.51.100.7"))
		return e, act, e.only().ID
	}
	// editing through the API cancels the open request
	for name, up := range map[string]response.CatalogUpdate{
		"refusal texts":  {PrecheckRefuse: &[]string{"already", "other"}},
		"check":          {Precheck: &response.Tpl{Method: "GET", Path: "/q2/{ip}"}},
		"read-back text": {Verify: &response.Tpl{Method: "GET", Path: "/q/{ip}", Expect: "ip {ip}"}},
	} {
		e, act, _ := setup(t)
		_, err := e.svc.ChangeAction(e.ctx(), admin, act.ID, up)
		e.must(err)
		if got := e.only(); got.Status != response.StatusRejected || !e.logHas("rejected", "was edited by") {
			t.Errorf("%s: the open request is %s", name, got.Status)
		}
	}
	// an edit behind the API's back refuses the approval
	for name, q := range map[string]string{
		"refusal texts":  `UPDATE resp_catalog SET precheck_refuse = '["x"]' WHERE id = ?`,
		"check":          `UPDATE resp_catalog SET precheck = json_set(precheck, '$.path', '/other/{ip}') WHERE id = ?`,
		"read-back text": `UPDATE resp_catalog SET verify = json_set(verify, '$.expect', 'zzz') WHERE id = ?`,
	} {
		e, act, id := setup(t)
		e.exec1(q, act.ID)
		_, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
		if s, c := apiCode(err); s != 409 || c != "tool_unavailable" {
			t.Errorf("%s: %v", name, err)
		}
		if e.exec.count() != 0 {
			t.Errorf("%s: a step reached the device", name)
		}
	}
}

// FORBID-5 (D-97): the AI proposals route exists only in the preview build; the real build answers 404 like an unknown route.
func TestContract_FORBID5_AiProposalsRouteIsPreviewOnly(t *testing.T) {
	e := newEnv(t)
	h := response.NewResponseHandlers(e.svc)
	res, err := h.ResponsePostResponseAiProposals(e.ctx(), &oas.ResponsePostResponseAiProposalsReq{})
	wantCode(t, err, 404, "not_found")
	if res != nil {
		t.Fatalf("a result came back: %+v", res)
	}
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || e.count(`SELECT COUNT(*) FROM resp_log`) != 0 {
		t.Fatal("the preview route wrote something")
	}
}

// INV-14b (D-94): no template sets a credential, address or hop-by-hop header, on the custom path, in any step.
func TestContract_INV14b_NoCredentialOrHopHeadersInCustomActions(t *testing.T) {
	e := precheckEnv(t)
	bad := []string{"Authorization: Bearer {name}", "authorization: x", "AUTHORIZATION: x", "Cookie: a=b", "Host: evil.lan", "Proxy-Authorization: x", "Proxy-Foo: x", "proxy-connection: x",
		"Connection: close", "Keep-Alive: 5", "TE: trailers", "Transfer-Encoding: chunked", "Upgrade: websocket", "Trailer: x", "Forwarded: for=1.2.3.4", "X-Forwarded-For: 1.2.3.4",
		"x-forwarded-host: x", "X-Forwarded-Proto: https", "X-Test: a\nAuthorization: b"}
	get := response.Tpl{Method: "GET", Path: "/d/{domain}"}
	for _, h := range bad {
		for step, mod := range map[string]func(x *response.CatalogInput){
			"run":      func(x *response.CatalogInput) { x.Run.Headers = h },
			"rollback": func(x *response.CatalogInput) { x.Rollback.Headers = h },
			"verify":   func(x *response.CatalogInput) { x.Verify = get; x.Verify.Headers = h },
			"check": func(x *response.CatalogInput) {
				x.Precheck = get
				x.Precheck.Headers = h
				x.PrecheckRefuse = []string{"x"}
			},
		} {
			in := apiAction()
			mod(&in)
			_, err := e.svc.AddAction(e.ctx(), admin, in)
			if s, c := apiCode(err); s != 400 || c != "invalid" || !strings.Contains(err.Error(), "set by the connection") {
				t.Errorf("%s header %q: %v", step, h, err)
			}
		}
	}
	// an update goes through the same check
	a, err := e.svc.AddAction(e.ctx(), admin, apiAction())
	e.must(err)
	run := response.Tpl{Method: "POST", Path: "/d", Headers: "Authorization: Bearer {name}"}
	_, err = e.svc.ChangeAction(e.ctx(), admin, a.ID, response.CatalogUpdate{Run: &run})
	wantCode(t, err, 400, "invalid")
	// other headers stay allowed
	in := apiAction()
	in.Name = "With headers"
	in.Run.Headers = "Content-Type: application/json\nX-Request-Id: {name}"
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err != nil {
		t.Fatalf("plain headers refused: %v", err)
	}
	// and the shipped library has none of them
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, x := range c.Items {
		for _, tpl := range []response.Tpl{x.Run, x.Rollback, x.Verify, x.Precheck} {
			if tpl.Headers != "" && response.ValidateTpl(tpl, x.ID) != "" {
				t.Errorf("%s has headers a template may not set: %q", x.ID, tpl.Headers)
			}
		}
	}
}

// 12.1 (5): a value only the device can give is not available until a later version reads it (the time to live is worked out without the device).
func TestBuiltinActionsNeedingADeviceReadAreNotAvailableYet(t *testing.T) {
	e := precheckEnv(t)
	for _, id := range []string{"cisco_acl_deny", "cisco_port_vlan_quarantine", "aoscx_acl_deny", "aoscx_vlan_quarantine", "arubasw_acl_deny", "arubasw_vlan_quarantine"} {
		cid, on := "cn-ssh", true
		_, err := e.svc.ChangeAction(e.ctx(), admin, id, response.CatalogUpdate{ConnectionID: &cid, Enabled: &on, Present: map[string]bool{"connection_id": true}})
		e.must(err)
	}
	for _, id := range []string{"mt_addrlist_add", "adguard_block", "fgt_ban_ip"} {
		cid, on := "cn-http", true
		_, err := e.svc.ChangeAction(e.ctx(), admin, id, response.CatalogUpdate{ConnectionID: &cid, Enabled: &on, Present: map[string]bool{"connection_id": true}})
		e.must(err)
	}
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, a := range c.Items {
		switch a.ID {
		case "cisco_acl_deny", "cisco_port_vlan_quarantine", "aoscx_acl_deny", "aoscx_vlan_quarantine", "arubasw_acl_deny", "arubasw_vlan_quarantine", "mt_addrlist_add", "adguard_block":
			if a.Available || a.UnavailableReason == nil || !strings.Contains(*a.UnavailableReason, "Not available yet") {
				t.Errorf("%s: %+v", a.ID, a.UnavailableReason)
			}
		case "fgt_ban_ip":
			if !a.Available {
				t.Errorf("fgt_ban_ip should be available: %v", a.UnavailableReason)
			}
		}
	}
}
