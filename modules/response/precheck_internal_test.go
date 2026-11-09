package response

import (
	"strings"
	"testing"
)

func TestActionFPCoversPrecheckRefuseAndExpect(t *testing.T) {
	base := catRow{Run: Tpl{Method: "POST", Path: "/q/{ip}"}, Rollback: Tpl{Method: "DELETE", Path: "/q/{ip}"}, Verify: Tpl{Method: "GET", Path: "/q/{ip}", Expect: "{ip}"},
		Precheck: Tpl{Method: "GET", Path: "/q/{ip}"}, PrecheckRefuse: []string{"already"}, Risk: RiskLow}
	fp := actionFP(base)
	if fp != actionFP(base) {
		t.Fatal("the fingerprint is not stable")
	}
	for name, mod := range map[string]func(c *catRow){
		"precheck path":  func(c *catRow) { c.Precheck.Path = "/x/{ip}" },
		"precheck cli":   func(c *catRow) { c.Precheck = Tpl{CLI: "show x {ip}"} },
		"refuse text":    func(c *catRow) { c.PrecheckRefuse = []string{"other"} },
		"refuse added":   func(c *catRow) { c.PrecheckRefuse = []string{"already", "more"} },
		"refuse removed": func(c *catRow) { c.PrecheckRefuse = nil },
		"expect":         func(c *catRow) { c.Verify.Expect = "x" },
		"expect cleared": func(c *catRow) { c.Verify.Expect = "" },
	} {
		c := base
		mod(&c)
		if actionFP(c) == fp {
			t.Errorf("%s did not change the fingerprint", name)
		}
	}
}

// INV-14b (D-94): the shipped library goes through the same check as a customer's template, so a forbidden header, a check that
// writes, or a port action without a refusal in the data files stops the service from starting.
func TestBuiltinLibraryIsCheckedLikeACustomerAction(t *testing.T) {
	ok := builtinDef{ID: "x_port", Kind: "device", Risk: RiskLow,
		Run: Tpl{CLI: "interface {interface}\nshutdown"}, Rollback: Tpl{CLI: "interface {interface}\nno shutdown"}, Verify: Tpl{CLI: "show {interface}", Expect: "down"},
		Precheck: Tpl{CLI: "show interfaces {interface} switchport"}, PrecheckRefuse: []string{"trunk"}}
	if err := checkBuiltinTpls(ok); err != nil {
		t.Fatalf("a good action was refused: %v", err)
	}
	api := builtinDef{ID: "x_api", Kind: "device", Risk: RiskLow, Run: Tpl{Method: "POST", Path: "/a/{ip}"}, Rollback: Tpl{Method: "DELETE", Path: "/a/{ip}"}}
	if err := checkBuiltinTpls(api); err != nil {
		t.Fatalf("a good API action was refused: %v", err)
	}
	for name, mod := range map[string]func(a *builtinDef){
		"credential header on run": func(a *builtinDef) { a.Run.Headers = "Authorization: Bearer x" },
		"cookie on rollback":       func(a *builtinDef) { a.Rollback.Headers = "Cookie: a=b" },
		"forwarded on verify": func(a *builtinDef) {
			a.Verify = Tpl{Method: "GET", Path: "/a/{ip}", Headers: "X-Forwarded-For: 1.2.3.4"}
		},
		"host on the check": func(a *builtinDef) {
			a.Precheck = Tpl{Method: "GET", Path: "/a/{ip}", Headers: "Host: x"}
			a.PrecheckRefuse = []string{"x"}
		},
		"expect on run": func(a *builtinDef) { a.Run.Expect = "x" },
		"expect on the check": func(a *builtinDef) {
			a.Precheck = Tpl{Method: "GET", Path: "/a/{ip}", Expect: "x"}
			a.PrecheckRefuse = []string{"x"}
		},
		"check that writes": func(a *builtinDef) {
			a.Precheck = Tpl{Method: "POST", Path: "/a/{ip}"}
			a.PrecheckRefuse = []string{"x"}
		},
		"check without refusal": func(a *builtinDef) { a.Precheck = Tpl{Method: "GET", Path: "/a/{ip}"}; a.PrecheckRefuse = nil },
		"expect too long":       func(a *builtinDef) { a.Verify = Tpl{Method: "GET", Path: "/a/{ip}", Expect: strings.Repeat("x", 201)} },
		"seven refusals": func(a *builtinDef) {
			a.Precheck = Tpl{Method: "GET", Path: "/a/{ip}"}
			a.PrecheckRefuse = []string{"1", "2", "3", "4", "5", "6", "7"}
		},
		"port action without a refusal": func(a *builtinDef) {
			a.Run, a.Rollback = Tpl{CLI: "interface {interface}\nshutdown"}, Tpl{CLI: "interface {interface}\nno shutdown"}
			a.Precheck, a.PrecheckRefuse = Tpl{}, nil
		},
	} {
		a := api
		mod(&a)
		if err := checkBuiltinTpls(a); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	box := builtinDef{ID: "x_box", Kind: "box", Risk: RiskLow, Run: Tpl{CLI: "blocklist add {ip}"}, Precheck: Tpl{CLI: "blocklist show {ip}"}, PrecheckRefuse: []string{"x"}}
	if err := checkBuiltinTpls(box); err == nil {
		t.Error("a box action with a check before was accepted")
	}
}

func TestForbiddenHeaderNames(t *testing.T) {
	for _, h := range []string{"Authorization", "authorization", "COOKIE", "Host", "Proxy-Authorization", "proxy-x", "Connection", "Keep-Alive", "TE", "Transfer-Encoding", "Upgrade", "Proxy-Connection", "Trailer", "Forwarded", "X-Forwarded-For", "x-forwarded-anything"} {
		if !forbiddenHeader(h) {
			t.Errorf("%s is allowed", h)
		}
	}
	for _, h := range []string{"Content-Type", "Accept", "X-Api-Key", "X-Request-Id", "Hosted", "Authorization-Info-X", "Teapot", "X-Forward"} {
		if forbiddenHeader(h) {
			t.Errorf("%s is forbidden", h)
		}
	}
}
