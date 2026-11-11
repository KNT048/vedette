package main

import (
	"strings"
	"testing"
)

// The weekly report reads the real inventory, findings and the CISA list through its ports: a device on the list, a finding
// from it, and the report counts both (INV-1). Reports is off by default (404); sending needs the email channel of notify.
func TestWiringReportsWeeklyFromRealModules(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if code, _ := s.do("GET", "/reports/weekly/preview", "admin", ""); code != 404 {
		t.Fatalf("reports is off by default: %d", code)
	}
	s.setModule("reports", true)
	s.kev("CVE-2026-4001", "Fortinet", "FortiOS")
	s.addFortiGate()
	code, b := s.do("GET", "/reports/weekly/preview", "viewer", "")
	rep, _ := b["report"].(map[string]any)
	if code != 200 || rep == nil {
		t.Fatalf("preview: %d %v", code, b)
	}
	c := rep["counts"].(map[string]any)
	if c["devices"] != float64(1) || c["new_findings"] != float64(1) || c["open_suspected"] != float64(1) || c["kev_new"] != float64(1) || c["kev_matched"] != float64(1) {
		t.Fatalf("counts = %v", c)
	}
	if code, b = s.do("POST", "/reports/weekly/send", "operator", ""); code != 400 || !strings.Contains(b["error"].(map[string]any)["code"].(string), "no_recipients") {
		t.Fatalf("send without recipients: %d %v", code, b)
	}
	if code, b = s.do("PUT", "/reports/schedule", "admin", `{"enabled":false,"day":1,"hour":8,"recipients":["boss@acme.example"]}`); code != 200 {
		t.Fatalf("save schedule: %d %v", code, b)
	}
	if code, b = s.do("POST", "/reports/weekly/send", "operator", ""); code != 409 || b["error"].(map[string]any)["code"] != "email_not_ready" {
		t.Fatalf("send with no email channel: %d %v", code, b)
	}
	if code, b = s.do("GET", "/reports/pdpl", "viewer", ""); code != 200 || b["ai_available"] != false {
		t.Fatalf("pdpl: %d %v", code, b)
	}
	if code, b = s.do("POST", "/reports/weekly/ai-summary", "operator", ""); code != 409 || b["error"].(map[string]any)["code"] != "ai_unavailable" {
		t.Fatalf("ai with no profile: %d %v", code, b)
	}
}

func TestParseParagraphs(t *testing.T) {
	t.Parallel()
	got, err := parseParagraphs(`{"paragraphs":["  One   two\n three ","", "Four"]}`)
	if err != nil || len(got) != 2 || got[0] != "One two three" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{``, `[]`, `{"paragraphs":[]}`, `{"paragraphs":["a"],"x":1}`, `{"paragraphs":["a"]} {"x":1}`, `{"paragraphs":["a","b","c","d","e"]}`, `{"paragraphs":[""]}`} {
		if _, err := parseParagraphs(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	long := strings.Repeat("é", 3000)
	if got, err := parseParagraphs(`{"paragraphs":["` + long + `"]}`); err != nil || len([]rune(got[0])) != 1200 {
		t.Fatalf("long paragraph: %d, %v", len([]rune(got[0])), err)
	}
}
