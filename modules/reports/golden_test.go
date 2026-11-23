package reports

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func golden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name)
	if *update {
		mustNoErr(t, os.MkdirAll("testdata", 0o750))
		mustNoErr(t, os.WriteFile(path, got, 0o600))
	}
	want, err := os.ReadFile(path) //nolint:gosec // a fixed file of the package testdata
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update to write it)", err, t.Name())
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file; if the change is meant, run go test -run %s -update and review the diff\n%s", path, t.Name(), got)
	}
}

// The golden report: the document of the fixture network over the last 7 days, and the email it sends. Every section reads the
// fixture through the ports; the file is the whole contract shape, so any change to a figure, an order or a field shows in review.
func TestDocumentGolden(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	doc, err := e.svc.Document(e.ctx())
	mustNoErr(t, err)
	golden(t, "document_week.golden.json", struct {
		Document Document `json:"document"`
		Mail     Mail     `json:"mail"`
	}{doc, digest(doc, "rep-1")})
}

// The case that started it: WinRAR updated on a PC without telling Vedette. Its CVEs are in Handled with who and how, from stored
// fields, and the email says so in the words of the pages.
func TestDocumentWinRARIsPatchedByVedette(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	doc, err := e.svc.Document(e.ctx())
	mustNoErr(t, err)
	var winrar []HandledItem
	for _, d := range doc.Handled.Devices {
		for _, it := range d.Items {
			if it.Product == "WinRAR" {
				if d.Device.Name != "ws-accounting-07" {
					t.Fatalf("WinRAR is under %s", d.Device.Name)
				}
				winrar = append(winrar, it)
			}
		}
	}
	if len(winrar) != 2 {
		t.Fatalf("WinRAR handled items = %+v", winrar)
	}
	for _, it := range winrar {
		h := it.Handled
		if h.Resolution != "patched" || h.Via != "version_moved" || h.By != "system" || *h.FromVersion != "6.24" || *h.ToVersion != "7.23" {
			t.Fatalf("%s handled = %+v", it.CVE, h)
		}
		if line := HandledLine(h, it.Product, time.UTC); !strings.HasPrefix(line, "Patched by Vedette: version moved 6.24 → 7.23 (9 Nov 2026)") {
			t.Fatalf("handled line = %q", line)
		}
	}
	m := digest(doc, "rep-1")
	if !slices.Contains(m.Items, "Handled: CVE-2023-38831, WinRAR on ws-accounting-07: Patched by Vedette: version moved 6.24 → 7.23 (9 Nov 2026)") {
		t.Fatalf("mail items = %q", m.Items)
	}
	if !slices.ContainsFunc(m.Items, func(s string) bool { return strings.Contains(s, "6.24 → 7.23 (9 Nov 2026): Checked on the machine.") }) {
		t.Fatalf("the person's note joins Vedette's credit: %q", m.Items)
	}
	if m.Path != "/reports/sent/rep-1" {
		t.Fatalf("mail path = %q", m.Path)
	}
}

// The summary counts what the sections list, and the period's arithmetic holds but for the one reopened acceptance.
func TestDocumentSummaryAgreesWithTheSections(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	doc, err := e.svc.Document(e.ctx())
	mustNoErr(t, err)
	s := doc.Summary
	if s.OpenNow != doc.Open.Total || s.New != doc.New.Total || s.Handled != countHandled(doc.Handled) {
		t.Fatalf("summary %+v vs open %d, new %d, handled %d", s, doc.Open.Total, doc.New.Total, countHandled(doc.Handled))
	}
	if s.OpenBefore != 4 || s.New != 2 || s.Handled != 3 || s.OpenNow != 4 { // 4 + 2 - 3 = 3; the Outlook acceptance ran out: 4
		t.Fatalf("summary = %+v", s)
	}
	if doc.Handled.MedianDays == nil || *doc.Handled.MedianDays != 20 { // WinRAR took 19.96 days twice, Log4j 5
		t.Fatalf("median days = %v", doc.Handled.MedianDays)
	}
	if len(s.First) != 3 || s.First[0].CVE != "CVE-2021-41773" || s.First[0].Status != "under_attack" {
		t.Fatalf("first = %+v", s.First)
	}
	open := doc.Open.Groups
	if open[0].Key != "a-web" || open[0].Status != "under_attack" || len(open[0].Items[0].Reasons) != 2 {
		t.Fatalf("still open = %+v", open)
	}
}

// The options shape the document: not added yet and not relevant in or out, grouping by CVE, sections off, the month period.
func TestDocumentOptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	d, _ := e.svc.Definition(e.ctx())
	o := d.Options
	o.Grouping, o.IncludeNotAdded, o.IncludeNotRelevant = groupCVE, false, true
	o.Sections.Exposure, o.Sections.Coverage = false, false
	_, err := e.svc.SaveDefinition(e.ctx(), "admin@acme.example", DefinitionInput{Name: d.Name, Options: o, Recipients: []string{}})
	mustNoErr(t, err)
	doc, err := e.svc.Document(e.ctx())
	mustNoErr(t, err)
	if doc.Exposure != nil || doc.Coverage != nil {
		t.Fatal("a section switched off is absent")
	}
	for _, g := range doc.Open.Groups {
		if !strings.HasPrefix(g.Key, "CVE-") {
			t.Fatalf("group key %q", g.Key)
		}
		for _, f := range g.Items {
			if !f.Device.Added {
				t.Fatalf("a device not added yet is listed: %+v", f)
			}
		}
	}
	var nr bool
	for _, dv := range doc.Handled.Devices {
		for _, it := range dv.Items {
			nr = nr || it.Handled.Resolution == "not_relevant"
		}
	}
	if !nr || doc.Summary.Handled != 4 || doc.Summary.New != 2 { // the HP correction counts; 7-Zip on the laptop does not
		t.Fatalf("not relevant in: %v, summary %+v", nr, doc.Summary)
	}
	if doc.Detections.Top[1].Device != nil {
		t.Fatalf("the trap touch names a device not added yet: %+v", doc.Detections.Top[1])
	}

	o.Period = PeriodMonth
	_, err = e.svc.SaveDefinition(e.ctx(), "admin@acme.example", DefinitionInput{Name: d.Name, Options: o, Recipients: []string{}})
	mustNoErr(t, err)
	doc, err = e.svc.Document(e.ctx())
	mustNoErr(t, err)
	if doc.Period.From != "2026-10-01T00:00:00.000Z" || doc.Period.To != "2026-11-01T00:00:00.000Z" || doc.Period.TZ != "UTC" {
		t.Fatalf("calendar month = %+v", doc.Period)
	}
	// In October: the Outlook acceptance held (not open at the end), Apache and the WinRAR lines were open, nothing was handled
	// but the October patch and the Outlook acceptance.
	if doc.Summary.OpenNow != 3 || doc.Summary.Handled != 2 {
		t.Fatalf("October summary = %+v", doc.Summary)
	}
}

// A finding reopened and handled again in the period is listed once, with its last handling.
func TestHistoryOfAFindingHandledTwice(t *testing.T) {
	t.Parallel()
	f := FindingView{ID: "f", CVE: "CVE-1", FirstSeen: at("2026-11-01T00:00:00Z"), Events: []FindingEvent{
		created("2026-11-01T00:00:00Z"),
		handledEv("2026-11-05T00:00:00Z", "patched", "person", "a@x.example", nil, nil, nil, nil),
		{At: at("2026-11-06T00:00:00Z"), Kind: "reopened"},
		handledEv("2026-11-08T00:00:00Z", "false_positive", "person", "b@x.example", nil, nil, nil, nil),
	}}
	h := historyOf(f, at("2026-11-04T10:00:00Z"), t0)
	if !h.openAtFrom || h.openAtTo || h.handled == nil || h.handled.Resolution != "false_positive" || h.handledAtTo.By != "b@x.example" {
		t.Fatalf("history = %+v", h)
	}
	// with no state events (an older row): its first sighting and its handling now
	f = FindingView{ID: "g", FirstSeen: at("2026-10-01T00:00:00Z"), Handled: &Handled{Resolution: "patched", Via: "person", At: "2026-11-05T00:00:00.000Z"}}
	h = historyOf(f, at("2026-11-04T10:00:00Z"), t0)
	if !h.openAtFrom || h.openAtTo || h.handled == nil {
		t.Fatalf("history without events = %+v", h)
	}
}

// A match Vedette corrected (not relevant) and then detected again in the period is open at its end: with "include not relevant"
// off it is still listed as open and counted, only its not-relevant handling is left out of Handled.
func TestDocumentReopenedAfterACorrectionStaysOpen(t *testing.T) {
	t.Parallel()
	f := FindingView{ID: "f-flap", CVE: "CVE-2024-0001", Device: devWeb, Product: "OpenSSH", Status: "exploited", Urgency: 2, Severity: sev("high", 8.1),
		Verification: byBanner, Fix: fix("update", "OpenSSH", "9.8"), FirstSeen: at("2026-10-01T09:00:00Z"),
		Events: []FindingEvent{created("2026-10-01T09:00:00Z"),
			handledEv("2026-11-06T09:00:00Z", "not_relevant", "data_corrected", "system", nil, nil, nil, nil),
			{At: at("2026-11-08T09:00:00Z"), Kind: "reopened"}}}
	doc := buildDocument(docInput{def: defaultDefinition(), now: t0, loc: time.UTC, findings: []FindingView{f}})
	if doc.Open.Total != 1 || doc.Summary.OpenNow != 1 || doc.Summary.OpenBefore != 1 {
		t.Fatalf("a finding open at the end of the period is missing: open %+v, summary %+v", doc.Open, doc.Summary)
	}
	if doc.Summary.Handled != 0 || len(doc.Handled.Devices) != 0 {
		t.Fatalf("a not-relevant handling is listed with include not relevant off: %+v", doc.Handled)
	}
}

// The email writes its dates in the organisation's zone, as the pages do: the last calendar month in Ho Chi Minh City is 1 to 31
// October, and a handling at 20:00 UTC on 8 Nov is on 9 Nov there.
func TestDigestWritesDatesInTheOrganisationZone(t *testing.T) {
	t.Parallel()
	loc, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	mustNoErr(t, err)
	def := defaultDefinition()
	def.Options.Period = PeriodMonth
	f := FindingView{ID: "f", CVE: "CVE-2024-0002", Device: devWS, Product: "WinRAR", Status: "patched", Urgency: 2, FirstSeen: at("2026-10-02T09:00:00Z"),
		Events: []FindingEvent{created("2026-10-02T09:00:00Z"),
			handledEv("2026-10-08T20:00:00Z", "patched", "version_moved", "system", nil, sp("6.24"), sp("7.23"), nil)}}
	m := digest(buildDocument(docInput{def: def, now: t0, loc: loc, findings: []FindingView{f}}), "rep-1")
	if !strings.Contains(m.Title, "(1 Oct to 31 Oct 2026)") {
		t.Fatalf("mail title = %q", m.Title)
	}
	if !slices.Contains(m.Items, "Handled: CVE-2024-0002, WinRAR on ws-accounting-07: Patched by Vedette: version moved 6.24 → 7.23 (9 Oct 2026)") {
		t.Fatalf("mail items = %q", m.Items)
	}
}

// The mail's own heading says "What to do first": the first thing follows it without a second "Do first", the others are marked
// "Then", every handled line says it is one and names its CVE, and an accepted risk's last day is written as the pages write it.
func TestDigestHeadsItsLines(t *testing.T) {
	t.Parallel()
	doc := Document{Title: "Security report", Period: DocPeriod{From: "2026-11-01T00:00:00.000Z", To: "2026-11-08T00:00:00.000Z", TZ: "UTC"},
		Summary: &ReportSummary{OpenByStatus: []StatusCount{}, First: []FirstThing{
			{Status: "exploited", CVE: "CVE-2026-1", Product: "vCenter", Devices: []DeviceRef{{Name: "vcenter-01"}}, DeviceCount: 1, Fix: Fix{Kind: "update", Version: sp("9.0.2.0200")}},
			{Status: "exploited", CVE: "CVE-2026-2", Product: "Junos", Devices: []DeviceRef{{Name: "ex4200"}}, DeviceCount: 1, Fix: Fix{Kind: "none_yet"}}}},
		Handled: &ReportHandled{Totals: []HandledTotal{{Resolution: "accepted", Via: "person", N: 1}}, Devices: []HandledDevice{{Device: DeviceRef{Name: "ex4200"},
			Items: []HandledItem{{CVE: "CVE-2020-1631", Product: "Junos", Handled: Handled{Resolution: "accepted", Via: "person", By: "ana@example.com",
				At: "2026-11-05T10:00:00.000Z", AcceptedUntil: sp("2026-12-24")}}}}}}}
	m := digest(doc, "rep-1")
	if strings.Contains(m.Action, "Do first") || !strings.HasPrefix(m.Action, "Exploited in the wild: CVE-2026-1") {
		t.Errorf("action = %q", m.Action)
	}
	want := []string{"Then: Exploited in the wild: CVE-2026-2 in Junos on ex4200: no fix is published yet; follow the vendor advisory",
		"Handled: CVE-2020-1631, Junos on ex4200: Risk accepted until 24 Dec 2026 by ana@example.com (5 Nov 2026)"}
	if !slices.Equal(m.Items, want) {
		t.Errorf("items = %q\nwant  %q", m.Items, want)
	}
}

// "Include not relevant" off leaves Vedette's not-relevant closures out of Handled; the section says how many, so its count is not
// taken for a smaller Findings › Handled. With the option on, nothing is left out.
func TestHandledSaysWhatNotRelevantLeftOut(t *testing.T) {
	t.Parallel()
	f := FindingView{ID: "f", CVE: "CVE-2026-46300", Device: devWS, Product: "Linux kernel", Status: "not_relevant", Urgency: 5, FirstSeen: at("2026-11-02T09:00:00Z"),
		Events: []FindingEvent{created("2026-11-02T09:00:00Z"), handledEv("2026-11-09T09:00:00Z", "not_relevant", "data_corrected", "system", nil, nil, nil, nil)}}
	def := defaultDefinition()
	doc := buildDocument(docInput{def: def, now: t0, loc: time.UTC, findings: []FindingView{f}})
	if doc.Handled == nil || doc.Handled.NotRelevantLeftOut != 1 || countHandled(doc.Handled) != 0 {
		t.Fatalf("option off: %+v", doc.Handled)
	}
	def.Options.IncludeNotRelevant = true
	doc = buildDocument(docInput{def: def, now: t0, loc: time.UTC, findings: []FindingView{f}})
	if doc.Handled.NotRelevantLeftOut != 0 || countHandled(doc.Handled) != 1 {
		t.Fatalf("option on: %+v", doc.Handled)
	}
}
