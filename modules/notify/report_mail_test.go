package notify_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/notify"
)

// reports INV-4: the weekly report goes out through the email channel of notify, to the addresses it names (and only those),
// never to the alert list, and is not recorded as an alert.
func TestSendReport(t *testing.T) {
	e := newEnv(t)
	mail := notify.ReportMail{Title: "Weekly report: 1 new, 0 resolved, 2 open", What: "3 devices.", Action: "Fix CVE-2026-1 on fw-01", Items: []string{"Fix CVE-2026-1 on fw-01", "pc\r\nBcc: x@evil.example"}, Path: "/reports"}
	if err := e.svc.SendReport(e.ctx(), []string{"boss@acme.example"}, mail); err == nil {
		t.Fatal("no email channel, yet SendReport succeeded")
	}
	s := newFakeSMTP(t)
	e.email(s)
	if err := e.svc.SendReport(e.ctx(), []string{"boss@acme.example", "cfo@acme.example"}, mail); err != nil {
		t.Fatal(err)
	}
	rc := s.recipients()
	if len(rc) != 2 || !strings.Contains(rc[0], "boss@acme.example") || !strings.Contains(rc[1], "cfo@acme.example") || strings.Contains(strings.Join(rc, " "), "it@acme.example") {
		t.Fatalf("recipients = %v", rc)
	}
	body := emailBody(t, s.messages()[0])
	if !strings.Contains(body, "Fix CVE-2026-1 on fw-01") || !strings.Contains(body, "3 devices.") {
		t.Fatalf("body = %q", body)
	}
	if strings.Contains(body, "\nBcc:") {
		t.Fatalf("a line break in an item became a header-like line: %q", body)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send`) != 0 {
		t.Fatal("a report was recorded as an alert")
	}
	for _, bad := range [][]string{nil, {"not-an-address"}, {"a@acme.example\r\nBcc: b@y.example"}} {
		if err := e.svc.SendReport(e.ctx(), bad, mail); err == nil {
			t.Fatalf("recipients %q were accepted", bad)
		}
	}
}
