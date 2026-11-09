package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
)

func (s *stack) pull(path string) int {
	s.t.Helper()
	return s.pullRaw(path).Code
}

func (s *stack) pullRaw(path string) *httptest.ResponseRecorder {
	s.t.Helper()
	r := httptest.NewRequestWithContext(s.t.Context(), http.MethodGet, server.Prefix+path, nil)
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	return w
}

// The response module in the real wiring: off by default (no route at all, the public ones included), the preview-only
// endpoints do not exist in the real build (FORBID-5), part 13b answers 501, and the block list is a public route behind a token
// that disappears with the module (SYS-5).
func TestWiringResponseModule(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, p := range []string{"/response/settings", "/response/rules", "/response/log"} {
		if c, _ := s.do("GET", p, "admin", ""); c != 404 {
			t.Errorf("GET %s with the module off: %d", p, c)
		}
	}
	if c := s.pull("/response/blocklist/" + strings.Repeat("a", 32) + ".txt"); c != 404 {
		t.Errorf("the public block list with the module off: %d", c)
	}
	s.setModule("notify", true)
	s.setModule("inventory", true)
	s.setModule("response", true)

	c, v := s.do("GET", "/response/settings", "admin", "")
	if c != 200 || v["execution"] != false {
		t.Fatalf("settings: %d %v", c, v)
	}
	if c, _ := s.do("GET", "/response/settings", "operator", ""); c != 403 {
		t.Errorf("settings as operator: %d", c)
	}
	// Preview-only: 404 like an unknown route, for every role.
	for _, role := range []string{"admin", "operator"} {
		if c, v := s.do("POST", "/response/rules/run", role, ""); c != 404 || at(v, "error", "code") != "not_found" {
			t.Errorf("POST /response/rules/run as %s: %d %v", role, c, v)
		}
	}
	if c, v := s.do("POST", "/response/actions/act-1/chat-decision", "admin", `{"channel":"slack","external_id":"U1","decision":"approve"}`); c != 404 || at(v, "error", "code") != "not_found" {
		t.Errorf("chat-decision: %d %v", c, v)
	}
	// Part 13b: 501 not_implemented.
	for _, r := range [][3]string{{"GET", "/response/ai", ""}, {"POST", "/response/ai/resume", ""}, {"POST", "/response/ai/proposals", `{"trigger":"finding","action_id":"blocklist_add","params":{},"confidence":0.9,"evidence":[],"why":"x"}`},
		{"GET", "/response/approve/" + strings.Repeat("a", 32), ""}, {"POST", "/response/approve/" + strings.Repeat("a", 32), `{"decision":"approve"}`}} {
		if c, v := s.do(r[0], r[1], "admin", r[2]); c != 501 || at(v, "error", "code") != "not_implemented" {
			t.Errorf("%s %s: %d %v", r[0], r[1], c, v)
		}
	}
	// Execution cannot be turned on from a session whose account does not exist or has no two-step sign-in.
	if c, _ := s.do("POST", "/response/execution", "admin", `{"enabled":true,"phrase":"I ACCEPT THE RISK"}`); c != 403 && c != 409 {
		t.Errorf("enabling execution: %d", c)
	}
	// Rules start in dry run; the catalog is the data library.
	c, v = s.do("GET", "/response/catalog", "viewer", "")
	if c != 200 || len(v["items"].([]any)) < 20 {
		t.Fatalf("catalog: %d", c)
	}
	c, v = s.do("POST", "/response/rules", "admin", `{"name":"Block","enabled":true,"live":true,"trigger":"ioc_connection","match":"all","conditions":[],"actions":[{"action_id":"blocklist_add","params":{"ip":"{{trigger.dest_ip}}"},"ttl_min":60}],"pre_approved":false,"max_per_hour":5,"schedule_min":null}`)
	if c != 201 || v["live"] != false {
		t.Fatalf("add rule: %d %v", c, v)
	}
	if c, _ := s.do("POST", "/response/rules", "operator", `{}`); c != 403 {
		t.Errorf("add rule as operator: %d", c)
	}
	// The block list: admin sees the address, anyone with the token pulls plain text, a wrong token is 404, the module off is 404.
	c, v = s.do("GET", "/response/blocklist", "admin", "")
	url, _ := v["url"].(string)
	if c != 200 || !strings.HasSuffix(url, ".txt") {
		t.Fatalf("blocklist: %d %v", c, v)
	}
	path := url[strings.Index(url, "/response/"):]
	pulled := s.pullRaw(path)
	if pulled.Code != 200 || !strings.HasPrefix(pulled.Body.String(), "# vedette blocklist") {
		t.Errorf("pull: %d %q", pulled.Code, pulled.Body.String())
	}
	// The token is in the address: never cached, never sniffed (blocklist-format 6).
	if pulled.Header().Get("Cache-Control") != "no-store" || pulled.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("block list headers: %v", pulled.Header())
	}
	if c := s.pull("/response/blocklist/" + strings.Repeat("0", 32) + ".txt"); c != http.StatusNotFound {
		t.Errorf("wrong token: %d", c)
	}
	s.setModule("response", false)
	if c := s.pull(path); c != 404 {
		t.Errorf("pull with the module off: %d", c)
	}
	if c, _ := s.do("GET", "/response/rules", "admin", ""); c != 404 {
		t.Errorf("rules with the module off: %d", c)
	}
	// Data stays; the jobs are gated by the scheduler (SYS-5): the module has exactly its two.
	if s.count(`SELECT COUNT(*) FROM resp_rules`) != 1 {
		t.Error("the data did not stay")
	}
}
