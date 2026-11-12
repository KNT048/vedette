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
	t.Parallel()
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
		"nine refusal texts": api(func(x *response.CatalogInput) {
			x.Precheck = get
			x.PrecheckRefuse = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}
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
	t.Parallel()
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
	t.Parallel()
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
	for id, first := range map[string]string{"cisco_port_shut": "terminal length 0", "aoscx_port_shut": "no page"} {
		a := by[id]
		if !strings.HasPrefix(a.Run.CLI, first+"\n") || !strings.HasSuffix(a.Run.CLI, "\nend") || !strings.HasPrefix(a.Precheck.CLI, first+"\n") {
			t.Errorf("%s: run %q precheck %q", id, a.Run.CLI, a.Precheck.CLI)
		}
	}
	if by["cisco_port_shut"].Run.CLI != "terminal length 0\nconfigure terminal\ninterface {interface}\nshutdown\nend" {
		t.Errorf("cisco_port_shut run: %q", by["cisco_port_shut"].Run.CLI)
	}
	// 3. every action that names a port has a check before with refusal texts
	ciscoRefuse := []string{"Mode: trunk", "Mode: dynamic", "Mode: private-vlan trunk", "Mode: tunnel", "Switchport: Disabled"}
	want := map[string][]string{
		"cisco_port_shut":            append(slices.Clone(ciscoRefuse), "administratively down"),
		"cisco_port_vlan_quarantine": ciscoRefuse,
		"aoscx_port_shut":            {"VLAN Mode: trunk", "VLAN Mode: native-untagged", "VLAN Mode: native-tagged", "Admin state is down"},
		"aoscx_vlan_quarantine":      {"VLAN Mode: trunk", "VLAN Mode: native-untagged", "VLAN Mode: native-tagged"},
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
	for _, id := range []string{"cisco_save_config", "pf_alias_add"} {
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
	t.Parallel()
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
		if a.ID == "cisco_port_shut" && len(a.PrecheckRefuse) != 6 {
			t.Errorf("the seed did not refresh the check: %v", a.PrecheckRefuse)
		}
	}
}

// INV-9 (D-95 (4)): the fingerprint of an action covers its check, its refusal texts and its read-back text. Editing any of them cancels
// the open requests; a change that did not go through ChangeAction refuses the run.
func TestContract_INV9_PrecheckAndExpectAreInTheFingerprint(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	e := precheckEnv(t)
	for _, id := range []string{"cisco_acl_deny", "cisco_port_vlan_quarantine", "aoscx_acl_deny", "aoscx_vlan_quarantine"} {
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
		case "cisco_acl_deny", "cisco_port_vlan_quarantine", "aoscx_acl_deny", "aoscx_vlan_quarantine", "mt_addrlist_add", "adguard_block":
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

// D-88 (26): GET /response/catalog hides the header values of every template, the check before included, from everyone but an admin.
func TestContract_D88_PrecheckHeaderValuesAreHiddenFromNonAdmins(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	in := apiAction()
	in.Run.Headers, in.Rollback.Headers = "X-Trace: s3cretrun", "X-Trace: s3cretrollback"
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Headers: "X-Trace: s3cretverify"}
	in.Precheck, in.PrecheckRefuse = response.Tpl{Method: "GET", Path: "/d/{domain}", Headers: "X-Trace: s3cretvalue"}, []string{"already"}
	_, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	seen := func(full bool) string {
		c, err := e.svc.Catalog(e.ctx(), full)
		e.must(err)
		var all strings.Builder
		for _, a := range c.Items {
			for _, tpl := range []response.Tpl{a.Run, a.Rollback, a.Verify, a.Precheck} {
				all.WriteString(tpl.Headers + "\n")
			}
		}
		return all.String()
	}
	if got := seen(false); strings.Contains(got, "s3cret") || !strings.Contains(got, "X-Trace: (hidden)") {
		t.Errorf("a viewer sees header values, or loses the header names: %q", got)
	}
	if got := seen(true); !strings.Contains(got, "s3cretvalue") {
		t.Errorf("an admin does not see the check header: %q", got)
	}
}

// INV-14 / D-95 (3) amended: the port guard cannot be dodged by naming the port through another placeholder. The type system has no
// "port name" type ({port} is a TCP or UDP number, {id} a whole number, {name} a free name), so in a customer's command or API
// path all of {interface}, {port}, {id} and {name} need the check before with a refusal text.
func TestContract_INV14_PortNamedThroughAnotherPlaceholderStillNeedsACheck(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	for name, cli := range map[string]string{
		"{port} in the interface name": "interface GigabitEthernet1/0/{port}\nshutdown",
		"{id} as a port-channel":       "interface Port-channel{id}\nshutdown",
		"{name} as the interface":      "interface {name}\nshutdown",
	} {
		in := response.CatalogInput{Name: "Shut " + strings.Trim(strings.Fields(name)[0], "{}"), Description: "d", ConnectionID: "cn-ssh", Risk: response.RiskMedium, Enabled: true,
			Run: response.Tpl{CLI: cli}, Rollback: response.Tpl{CLI: strings.Replace(cli, "\nshutdown", "\nno shutdown", 1)}}
		_, err := e.svc.AddAction(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" || !strings.Contains(err.Error(), "check before") || !strings.Contains(err.Error(), "{interface}") {
			t.Errorf("%s: %v", name, err)
		}
		// with the check before and a refusal text it is accepted
		in.PrecheckRefuse = []string{"Mode: trunk"}
		in.Precheck = response.Tpl{CLI: "show running-config interface " + strings.Fields(strings.Split(cli, "\n")[0])[1]}
		a, err := e.svc.AddAction(e.ctx(), admin, in)
		if err != nil || !a.Available {
			t.Errorf("%s with a check before: %v", name, err)
		}
	}
	// an API path counts too; an address or a domain does not
	for name, path := range map[string]string{"{name} in a path": "/api/interface/{name}/disable", "{id} in a path": "/api/ports/{id}/disable", "{port} in a path": "/api/ports/{port}"} {
		in := apiAction()
		in.Name = "Disable " + strings.Trim(strings.Fields(name)[0], "{}")
		in.Run, in.Rollback = response.Tpl{Method: "POST", Path: path}, response.Tpl{Method: "DELETE", Path: path}
		if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
			t.Errorf("%s: saved without a check before", name)
		}
	}
	if _, err := e.svc.AddAction(e.ctx(), admin, apiAction()); err != nil { // {domain} in a path and in the body
		t.Errorf("a domain action was refused: %v", err)
	}
	// a name in the body only (a field of the JSON, not a command or a path) is not a port
	in := apiAction()
	in.Name = "Name in a body"
	in.Run.Body = `{"domain":"{domain}","name":"{name}"}`
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err != nil {
		t.Errorf("a name in the body was refused: %v", err)
	}
}

// D-95 (1): the check before and the read-back only read. Over SSH nothing says which lines write, so a generic rule: no line of
// either may be a line of the action or of its undo (a first line that is the same in both, a pager or terminal setup line, is fine),
// and the commands listed in data/cli-ban.json are refused in them.
func TestContract_INV14_SSHCheckBeforeAndReadBackCannotWrite(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	for name, mod := range map[string]func(x *response.CatalogInput){
		"the check shuts the port": func(x *response.CatalogInput) {
			x.Precheck.CLI = "configure terminal\ninterface {interface}\nshutdown\nend"
		},
		"the check repeats a run line":        func(x *response.CatalogInput) { x.Precheck.CLI = "show interfaces {interface}\nshutdown" },
		"the check repeats a rollback line":   func(x *response.CatalogInput) { x.Precheck.CLI = "show interfaces {interface}\n  No  Shutdown " },
		"the check enters configuration":      func(x *response.CatalogInput) { x.Precheck.CLI = "configure terminal\nshow interfaces {interface}" },
		"the check reloads":                   func(x *response.CatalogInput) { x.Precheck.CLI = "show interfaces {interface}\nreload" },
		"the check writes memory":             func(x *response.CatalogInput) { x.Precheck.CLI = "write memory\nshow interfaces {interface}" },
		"the read-back repeats a run line":    func(x *response.CatalogInput) { x.Verify = response.Tpl{CLI: "show interfaces {interface}\nshutdown"} },
		"the read-back configures":            func(x *response.CatalogInput) { x.Verify = response.Tpl{CLI: "conf t\nshow interfaces {interface}"} },
		"the read-back copies to startup":     func(x *response.CatalogInput) { x.Verify = response.Tpl{CLI: "copy running-config startup-config"} },
		"the read-back deletes":               func(x *response.CatalogInput) { x.Verify = response.Tpl{CLI: "delete flash:config"} },
		"the check shares a later first line": func(x *response.CatalogInput) { x.Precheck.CLI = "show interfaces {interface}\nterminal length 0" },
	} {
		in := portAction()
		if name == "the check shares a later first line" {
			in.Run.CLI = "terminal length 0\n" + in.Run.CLI // the pager line is a line of the action
		}
		mod(&in)
		_, err := e.svc.AddAction(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a pager line that is the first line of both the check and the action is fine, and so is a plain check and read-back
	in := portAction()
	in.Run.CLI = "terminal length 0\n" + in.Run.CLI
	in.Rollback.CLI = "terminal length 0\n" + in.Rollback.CLI
	in.Precheck.CLI = "terminal length 0\nshow interfaces {interface} switchport"
	in.Verify = response.Tpl{CLI: "terminal length 0\nshow interfaces {interface} status", Expect: "disabled"}
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err != nil {
		t.Errorf("a plain check before and read-back were refused: %v", err)
	}
}

// Spec 9.3 (general ban, as data): a customer's command lines may not contain the refused commands, in any step. Built-in actions are
// reviewed data and are not held to the run-line list (FortiOS "delete" of its own object), but their reads are.
func TestContract_INV14_CustomCommandsObeyTheRefusedCommandList(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	for _, cmd := range []string{"reload", "Reboot now", "erase startup-config", "write erase", "format flash:", "delete flash:x", "factory-reset", "no username admin", "username evil secret x",
		"enable secret 5 x", "crypto key generate rsa", "copy running-config tftp://10.0.0.9/x", "copy flash: scp://10.0.0.9/x"} {
		in := portAction()
		in.Run.CLI = "interface {interface}\nshutdown\n" + cmd
		if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
			t.Errorf("run line %q was accepted", cmd)
		}
	}
	in := portAction()
	in.Run.CLI = "interface {interface}\nshutdown\nshow clock" // a word that merely starts like a refused one is fine ("format" is not "shutdown")
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err != nil {
		t.Errorf("a plain run was refused: %v", err)
	}
}

// Spec 1.6 and 9.1 (3): the read-back runs after the action and after the undo, so it only reads: an API call is a GET without a body.
func TestContract_INV14_ReadBackMustBeReadOnly(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	for _, m := range []string{"DELETE", "POST", "PUT", "PATCH"} {
		in := apiAction()
		in.Name = "Block " + m
		in.Verify = response.Tpl{Method: m, Path: "/d/{domain}", Expect: `"{domain}"`}
		if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
			t.Errorf("a read-back with method %s was accepted", m)
		}
	}
	in := apiAction()
	in.Name = "Block body"
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Body: `{"delete":true}`, Expect: "x"}
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
		t.Error("a read-back with a body was accepted")
	}
	in = apiAction()
	in.Name = "Read GET"
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Expect: "x"}
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err != nil {
		t.Errorf("a GET read-back was refused: %v", err)
	}
}

// An MCP action has no named read tool for its check before or read-back, so one that carries either is not available.
func TestContract_INV14_MCPActionWithACheckOrReadBackIsNotAvailable(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	a, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "M", Description: "d", ConnectionID: "cn-mcp", Tool: strp("block"), RollbackTool: strp("unblock"), Risk: response.RiskLow, Enabled: true,
		Run: response.Tpl{Body: `{"ip":"{ip}"}`}, Rollback: response.Tpl{Body: `{"ip":"{ip}"}`}})
	e.must(err)
	if !a.Available {
		t.Fatalf("the plain MCP action is not available: %v", a.UnavailableReason)
	}
	e.exec1(`UPDATE resp_catalog SET verify = '{"cli":"","method":"GET","path":"/x","body":"","headers":"","expect":"ok"}' WHERE id = ?`, a.ID)
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, x := range c.Items {
		if x.ID == a.ID && (x.Available || x.UnavailableReason == nil || !strings.Contains(*x.UnavailableReason, "read tool")) {
			t.Fatalf("%+v", x.UnavailableReason)
		}
	}
}

// L8: a read-back or check before that holds only headers is not empty: it is validated, so it cannot carry a credential header or raw
// control characters past the checks.
func TestContract_INV14b_HeaderOnlyStepsAreRefused(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	for name, mod := range map[string]func(x *response.CatalogInput){
		"verify with only a credential header":   func(x *response.CatalogInput) { x.Verify = response.Tpl{Headers: "Authorization: Bearer abc"} },
		"precheck with only a credential header": func(x *response.CatalogInput) { x.Precheck = response.Tpl{Headers: "Authorization: Bearer abc"} },
		"verify with only a raw CR LF header":    func(x *response.CatalogInput) { x.Verify = response.Tpl{Headers: "X-A: 1\r\nHost: evil"} },
		"verify with only a plain header":        func(x *response.CatalogInput) { x.Verify = response.Tpl{Headers: "X-A: 1"} },
		"rollback with only a header":            func(x *response.CatalogInput) { x.Rollback = response.Tpl{Headers: "X-A: 1"} },
	} {
		in := apiAction()
		in.Name = "Headers only"
		mod(&in)
		a, err := e.svc.AddAction(e.ctx(), admin, in)
		if err == nil {
			t.Errorf("%s: saved (verify headers %q, precheck headers %q)", name, a.Verify.Headers, a.Precheck.Headers)
			e.must(e.svc.DeleteAction(e.ctx(), admin, a.ID))
		}
	}
	if (response.Tpl{Headers: "X-A: 1"}).Empty() {
		t.Error("a step with only headers counts as empty")
	}
	if err := func() error { _, err := e.svc.AddAction(e.ctx(), admin, apiAction()); return err }(); err != nil {
		t.Errorf("a plain action was refused: %v", err)
	}
}

// L9: headers that make a server act as another method, client or path are refused like the credential headers (D-94), in every
// step, the check before included.
func TestContract_INV14b_MethodOverrideAndForwardingHeadersAreRefused(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	for _, h := range []string{"X-HTTP-Method-Override: DELETE", "X-HTTP-Method: PUT", "X-Method-Override: POST", "X-Real-IP: 10.0.0.1", "X-Original-URL: /admin", "X-Rewrite-URL: /admin",
		"Via: 1.1 proxy", "X-Forwarded: for=1.2.3.4", "x-http-method-override: delete"} {
		for step, mod := range map[string]func(x *response.CatalogInput){
			"run": func(x *response.CatalogInput) { x.Run.Headers = h },
			"check": func(x *response.CatalogInput) {
				x.Precheck = response.Tpl{Method: "GET", Path: "/d/{domain}", Headers: h}
				x.PrecheckRefuse = []string{"x"}
			},
		} {
			in := apiAction()
			in.Name = "Override"
			mod(&in)
			if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
				t.Errorf("%s header %q accepted", step, h)
			}
		}
	}
}

// D-95 (1), amended 2026-11-10: a check before may also name a text its output must contain; it is validated, stored, shown and
// fingerprinted like the refusal texts.
func TestContract_INV14c_PrecheckExpectIsTypedStoredAndFingerprinted(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	long := strings.Repeat("x", 81)
	for name, mod := range map[string]func(x *response.CatalogInput){
		"too long":            func(x *response.CatalogInput) { x.PrecheckExpect = long },
		"a newline":           func(x *response.CatalogInput) { x.PrecheckExpect = "a\nb" },
		"a control character": func(x *response.CatalogInput) { x.PrecheckExpect = "a\x00" },
		"blank":               func(x *response.CatalogInput) { x.PrecheckExpect = "   " },
		"non ASCII":           func(x *response.CatalogInput) { x.PrecheckExpect = "café" },
		"without a check": func(x *response.CatalogInput) {
			x.Precheck, x.PrecheckRefuse, x.PrecheckExpect = response.Tpl{}, nil, "x"
		},
	} {
		in := portAction()
		mod(&in)
		_, err := e.svc.AddAction(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	in := portAction()
	in.PrecheckExpect = "Administrative Mode: static access"
	a, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	if a.PrecheckExpect != in.PrecheckExpect {
		t.Fatalf("stored: %q", a.PrecheckExpect)
	}
	// a check with only a required text (no refusal text) is a check; for a port action the refusal text is still needed (D-95 (3))
	only := apiAction()
	only.Name = "Expect only"
	only.Precheck, only.PrecheckExpect = response.Tpl{Method: "GET", Path: "/d/{domain}"}, "ok"
	if _, err := e.svc.AddAction(e.ctx(), admin, only); err != nil {
		t.Errorf("a check with only a required text was refused: %v", err)
	}
	port := portAction()
	port.Name = "Port expect only"
	port.PrecheckRefuse, port.PrecheckExpect = nil, "x"
	if _, err := e.svc.AddAction(e.ctx(), admin, port); err == nil {
		t.Error("a port action with only a required text was accepted")
	}
	// editing it is a template edit
	other := "Administrative Mode: access"
	up, err := e.svc.ChangeAction(e.ctx(), admin, a.ID, response.CatalogUpdate{PrecheckExpect: &other})
	e.must(err)
	if up.PrecheckExpect != other {
		t.Fatalf("update: %q", up.PrecheckExpect)
	}
	// and the wire form always carries it
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, x := range c.Items {
		if x.ID == "cisco_port_shut" && x.PrecheckExpect != "Administrative Mode: static access" {
			t.Errorf("cisco_port_shut expects %q", x.PrecheckExpect)
		}
	}
}

// The approver sees what runs around the change: the check before (exact call or lines, and when it refuses) and the read-back (exact
// call and what it must contain).
func TestContract_INV14c_ApprovalShowsTheCheckBeforeAndTheReadBack(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	in := apiAction()
	in.Name = "Quarantine an IP (API)"
	in.Run, in.Rollback = response.Tpl{Method: "POST", Path: "/q/{ip}"}, response.Tpl{Method: "DELETE", Path: "/q/{ip}"}
	in.Verify = response.Tpl{Method: "GET", Path: "/q/{ip}/state", Expect: "{ip}"}
	in.Precheck, in.PrecheckRefuse, in.PrecheckExpect = response.Tpl{Method: "GET", Path: "/q/{ip}/pre"}, []string{"already listed"}, "ready"
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Quarantine", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	ch := e.only().Items[0].Change
	if ch.Precheck != "GET https://api.lan/q/198.51.100.7/pre" || ch.Verify != "GET https://api.lan/q/198.51.100.7/state" {
		t.Errorf("exact calls: %q / %q", ch.Precheck, ch.Verify)
	}
	for _, want := range []string{`"already listed"`, `"ready"`, "prints nothing"} {
		if !strings.Contains(ch.PrecheckRules, want) {
			t.Errorf("precheck rules %q lack %q", ch.PrecheckRules, want)
		}
	}
	if !strings.Contains(ch.VerifyRule, `"198.51.100.7"`) || !strings.Contains(ch.VerifyRule, "after the undo it must not") {
		t.Errorf("read-back rule: %q", ch.VerifyRule)
	}
}

// L10: an action whose check before has no form the bound connection can run is not available on that connection.
func TestContract_INV14c_PrecheckMustFitTheConnectionKind(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	// a library-style action with both forms of run and rollback but a command-only check, bound to an API connection
	e.exec1(`INSERT INTO resp_catalog (id, builtin, pack, kind, name, description, connection_id, run, rollback, verify, precheck, precheck_refuse, risk, enabled, ai_may_propose, position)
VALUES ('x_port', 0, 'generic', 'device', 'Port', 'd', 'cn-http', ?, ?, '{}', ?, '["Mode: trunk"]', 'medium', 1, 0, 9000)`,
		`{"cli":"interface {interface}\nshutdown","method":"POST","path":"/ports/{interface}/disable","body":"","headers":"","expect":""}`,
		`{"cli":"interface {interface}\nno shutdown","method":"POST","path":"/ports/{interface}/enable","body":"","headers":"","expect":""}`,
		`{"cli":"show interfaces {interface} switchport","method":"","path":"","body":"","headers":"","expect":""}`)
	reason := func(id string) string {
		c, err := e.svc.Catalog(e.ctx(), true)
		e.must(err)
		for _, x := range c.Items {
			if x.ID == id {
				if x.UnavailableReason == nil {
					return ""
				}
				return *x.UnavailableReason
			}
		}
		t.Fatalf("no action %s", id)
		return ""
	}
	if r := reason("x_port"); !strings.Contains(r, "check before") || !strings.Contains(r, "command") {
		t.Errorf("on an API connection: %q", r)
	}
	// the same action on an SSH connection (the check is a command) is available
	e.exec1(`UPDATE resp_catalog SET connection_id = 'cn-ssh' WHERE id = 'x_port'`)
	if r := reason("x_port"); r != "" {
		t.Errorf("on an SSH connection: %q", r)
	}
	// an API-only check on an SSH connection is not
	e.exec1(`UPDATE resp_catalog SET precheck = '{"cli":"","method":"GET","path":"/ports/{interface}","body":"","headers":"","expect":""}' WHERE id = 'x_port'`)
	if r := reason("x_port"); !strings.Contains(r, "API call") {
		t.Errorf("an API check on SSH: %q", r)
	}
}

// INV-9 (L12): the undo tool is checked before the run as well as at the undo: an action whose undo tool changed after the request was
// made does not start, because it could not be undone as it was approved.
func TestContract_INV9_UndoToolIsCheckedBeforeTheRun(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	act, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "M", Description: "d", ConnectionID: "cn-mcp", Tool: strp("block"), RollbackTool: strp("unblock"), Risk: response.RiskLow, Enabled: true,
		Run: response.Tpl{Body: `{"ip":"{ip}"}`}, Rollback: response.Tpl{Body: `{"ip":"{ip}"}`}})
	e.must(err)
	e.turnOn()
	e.rule("M", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	id := e.only().ID
	e.exec1(`UPDATE resp_catalog SET rollback_tool = 'block' WHERE id = ?`, act.ID) // another tool undoes it now
	_, err = e.svc.Approve(e.ctx(), oper, id, nil, "")
	wantCode(t, err, 409, "tool_unavailable")
	if e.exec.count() != 0 {
		t.Fatal("a step reached the device")
	}
	e.exec1(`UPDATE resp_catalog SET rollback_tool = 'unblock' WHERE id = ?`, act.ID)
	if _, err := e.svc.Approve(e.ctx(), oper, id, nil, ""); err != nil {
		t.Fatalf("the unchanged action did not run: %v", err)
	}
}

// Spec 6.2: ArubaOS-Switch is not a built-in action until a lab confirms it; a customer can still add one as a custom action.
func TestLibraryHasNoArubaOSSwitchBuiltIn(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, a := range c.Items {
		if strings.HasPrefix(a.ID, "arubasw_") || strings.Contains(a.Pack, "ArubaOS-Switch") {
			t.Errorf("%s is in the library", a.ID)
		}
	}
}
