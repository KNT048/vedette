package main

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/reports"
)

// The periodic report reads the real modules through its ports: a device on the CISA list is open in Still open, a package an agent
// updated past the distribution's fix is in Handled as patched by Vedette with both versions, and the schedule is a core/schedule
// owner. Reports is off by default (404); sending needs the email channel of notify.
func TestWiringReportsDocumentFromRealModules(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	if code, _ := s.do("GET", "/reports/document", "admin", ""); code != 404 {
		t.Fatalf("reports is off by default: %d", code)
	}
	s.setModule("reports", true)
	s.kev("CVE-2026-4001", "Fortinet", "FortiOS")
	fw := s.addFortiGate()

	// the WinRAR case on real modules: an agent reports the update, the match pass credits it
	const cve = "CVE-2026-7101"
	s.kevAdded(cve, "OpenBSD", "OpenSSH", time.Now().AddDate(0, -1, 0))
	now := store.FormatTS(time.Now().UTC())
	s.exec(`UPDATE feeds_cve SET nvd_at = ?2, nvd_status = 'Analyzed' WHERE cve = ?1`, cve, now)
	s.exec(`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'nvd', 'a', 'openbsd', 'openssh', 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', '', '', '', '10.6p2')`, cve)
	s.exec(`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '24.04', 'openssh', ?, 'fixed', '1:9.6p1-3ubuntu13.5')`, cve)
	box, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "web-01", OS: "Ubuntu 24.04"})
	if err != nil {
		t.Fatal(err)
	}
	for _, full := range []string{"1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.14"} {
		it := inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95,
			Packaged: true, PkgVersion: full, PkgSource: "openssh"}
		if err := s.d.Inventory.UpsertSoftware(ctx, box, []inventory.SoftwareItem{it}, "osquery"); err != nil {
			t.Fatal(err)
		}
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
	}

	code, def := s.do("GET", "/reports/definition", "viewer", "")
	if code != 200 || def["schedule_key"] != "reports.def:security" {
		t.Fatalf("definition: %d %v", code, def)
	}
	if code, b := s.do("GET", "/schedules/reports.def:security", "viewer", ""); code != 200 || b["enabled"] != false {
		t.Fatalf("the report's schedule is a core/schedule owner: %d %v", code, b)
	}
	code, doc := s.do("GET", "/reports/document", "viewer", "")
	if code != 200 {
		t.Fatalf("document: %d %v", code, doc)
	}
	sum, _ := doc["summary"].(map[string]any)
	if sum["open_now"] != float64(1) || sum["handled"] != float64(1) {
		t.Fatalf("summary = %v", sum)
	}
	open, _ := doc["open"].(map[string]any)
	g, _ := open["groups"].([]any)
	if len(g) != 1 || g[0].(map[string]any)["key"] != fw {
		t.Fatalf("still open = %v", open)
	}
	hd, _ := doc["handled"].(map[string]any)
	devs, _ := hd["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("handled = %v", hd)
	}
	item := devs[0].(map[string]any)["items"].([]any)[0].(map[string]any)
	h := item["handled"].(map[string]any)
	if item["cve"] != cve || h["resolution"] != "patched" || h["via"] != "version_moved" || h["by"] != "system" ||
		h["from_version"] != "1:9.6p1-3ubuntu13.4" || h["to_version"] != "1:9.6p1-3ubuntu13.14" {
		t.Fatalf("handled item = %v", item)
	}
	cov, _ := doc["coverage"].(map[string]any)
	if cov["devices"] != float64(2) || cov["with_agent"] != float64(1) {
		t.Fatalf("coverage = %v", cov)
	}

	if code, b := s.do("POST", "/reports/send", "operator", ""); code != 400 || b["error"].(map[string]any)["code"] != "no_recipients" {
		t.Fatalf("send without recipients: %d %v", code, b)
	}
	opts, _ := json.Marshal(def["options"])
	if code, b := s.do("PUT", "/reports/definition", "admin", `{"name":"Security report","options":`+string(opts)+`,"recipients":["boss@acme.example"]}`); code != 200 {
		t.Fatalf("save definition: %d %v", code, b)
	}
	if code, b := s.do("POST", "/reports/send", "operator", ""); code != 409 || b["error"].(map[string]any)["code"] != "email_not_ready" {
		t.Fatalf("send with no email channel: %d %v", code, b)
	}
	if code, b := s.do("GET", "/reports/history", "viewer", ""); code != 200 || len(b["items"].([]any)) != 0 {
		t.Fatalf("history: %d %v", code, b)
	}
	if code, b := s.do("GET", "/reports/pdpl", "viewer", ""); code != 200 || b["ai_available"] != false {
		t.Fatalf("pdpl: %d %v", code, b)
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

// The report mail carries the report itself: HTML with a plain-text alternative, its sections in the page's words, a still-open finding
// with its badge, reasons line and verification line, and the link to the sent report. Before, it was a plain-text digest of figures.
func TestWiringReportMailCarriesTheReport(t *testing.T) {
	t.Parallel()
	s, sink := linkStack(t, false, []string{"vedette.office.example"}, "0.0.0.0:8443") // the box has an address: the mail links to the sent report
	s.setModule("reports", true)
	s.kev("CVE-2026-4001", "Fortinet", "FortiOS")
	s.addFortiGate()
	code, def := s.do("GET", "/reports/definition", "viewer", "")
	if code != 200 {
		t.Fatalf("definition: %d %v", code, def)
	}
	opts, _ := json.Marshal(def["options"])
	if code, b := s.do("PUT", "/reports/definition", "admin", `{"name":"Security report","options":`+string(opts)+`,"recipients":["boss@acme.example"]}`); code != 200 {
		t.Fatalf("save definition: %d %v", code, b)
	}
	before := len(sink.messages())
	code, sent := s.do("POST", "/reports/send", "operator", "")
	if code != 200 || sent["status"] != "sent" {
		t.Fatalf("send: %d %v", code, sent)
	}
	msgs := sink.messages()[before:]
	if len(msgs) != 1 {
		t.Fatalf("%d mails, want the report", len(msgs))
	}
	m, err := mail.ReadMessage(strings.NewReader(msgs[0]))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("the report mail is %q, want HTML with a text alternative", m.Header.Get("Content-Type"))
	}
	parts := map[string]string{}
	r := multipart.NewReader(m.Body, params["boundary"])
	for {
		p, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		pt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		parts[pt] = string(b)
	}
	link := "/reports/sent/" + sent["id"].(string)
	for _, typ := range []string{"text/plain", "text/html"} {
		body := parts[typ]
		for _, want := range []string{"Summary", "Handled this period", "Still open", "New this period", "External exposure", "Detections", "Coverage",
			"CVE-2026-4001", "Exploited in the wild: CISA KEV (", "Not confirmed yet: based on a version someone entered", link} {
			if !strings.Contains(body, want) {
				t.Errorf("%s part: %q missing", typ, want)
			}
		}
	}
	if t.Failed() {
		t.Logf("text part:\n%s", parts["text/plain"])
	}
}

// An open finding's fix in the report is the block release the Findings lists name, with the finding's own product and advisory.
func TestReportListedFixIsTheBlockRelease(t *testing.T) {
	t.Parallel()
	url, v := "https://www.vmware.example/advisory", "9.0.2.0100"
	own := reports.Fix{Key: "vmware|vcenter|update|9.0.2.0100", Kind: "update", Product: "VMware vCenter Server", Version: &v, URL: &url}
	got := listedFix(own, findings.ListedFix{Key: "vmware|vcenter|update|9.0.2.0200", Fix: findings.Fix{Kind: findings.FixUpdate, Version: "9.0.2.0200"}})
	if got.Key != "vmware|vcenter|update|9.0.2.0200" || got.Version == nil || *got.Version != "9.0.2.0200" || got.Product != own.Product || got.URL != &url || got.Kind != "update" {
		t.Fatalf("listed fix %+v", got)
	}
}
