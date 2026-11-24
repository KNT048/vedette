package reports

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
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
	if s.OpenBefore != 4 || s.New != 2 || s.Handled != 3 || s.Reopened != 1 || s.OpenNow != 4 { // 4 + 2 - 3 + 1 reopened (the Outlook acceptance ran out) = 4
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

// A finding handled in the period and opened again before its end is listed under Handled with the day it opened again, counted as
// reopened in the summary, and the figures add up in the page's chart and in the mail.
func TestDocumentHandledThenReopenedSaysSo(t *testing.T) {
	t.Parallel()
	f := FindingView{ID: "f-back", CVE: "CVE-2026-97205", Device: devWeb, Product: "nginx", Status: "update_recommended", Urgency: 5, Severity: sev("high", 7.5),
		Verification: byBanner, Fix: fix("update", "nginx", "1.30.7"), FirstSeen: at("2026-10-01T09:00:00Z"),
		Events: []FindingEvent{created("2026-10-01T09:00:00Z"),
			handledEv("2026-11-07T09:00:00Z", "patched", "version_moved", "ana@acme.example", nil, sp("1.30.5"), sp("1.30.6"), nil),
			{At: at("2026-11-08T09:00:00Z"), Kind: "reopened"}}}
	done := FindingView{ID: "f-done", CVE: "CVE-2026-97206", Device: devWeb, Product: "nginx", Status: "patched", Urgency: 5, Severity: sev("high", 7.5),
		Verification: byBanner, Fix: fix("update", "nginx", "1.30.7"), FirstSeen: at("2026-11-06T09:00:00Z"),
		Events: []FindingEvent{created("2026-11-06T09:00:00Z"), handledEv("2026-11-07T09:00:00Z", "patched", "person", "ana@acme.example", nil, nil, nil, nil)}}
	doc := buildDocument(docInput{def: defaultDefinition(), now: t0, loc: time.UTC, findings: []FindingView{f, done}})
	s := doc.Summary
	if s.OpenBefore != 1 || s.New != 1 || s.Handled != 2 || s.Reopened != 1 || s.OpenNow != 1 {
		t.Fatalf("summary = %+v, want 1 + 1 new - 2 handled + 1 reopened = 1", s)
	}
	var items []HandledItem
	for _, d := range doc.Handled.Devices {
		items = append(items, d.Items...)
	}
	if len(items) != 2 {
		t.Fatalf("handled items = %+v", items)
	}
	for _, it := range items {
		switch {
		case it.FindingID == "f-back" && (it.ReopenedAt == nil || *it.ReopenedAt != ts(at("2026-11-08T09:00:00Z"))):
			t.Errorf("the reopened finding does not say when it opened again: %+v", it)
		case it.FindingID == "f-done" && it.ReopenedAt != nil:
			t.Errorf("a finding still handled says it opened again: %+v", it)
		}
		if it.FindingID == "f-back" {
			if got := ItemLine(it, time.UTC); !strings.HasSuffix(got, "; open again since 8 Nov 2026") {
				t.Errorf("ItemLine = %q", got)
			}
		}
	}
	if got, want := FlowLine(*s), "Open at the start: 1. New: 1. Handled: 2. Reopened: 1. Open now: 1."; got != want {
		t.Errorf("FlowLine = %q, want %q", got, want)
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

// A document with no section the mail can sum up says where the whole report is in words that hold with and without the link
// (notify leaves the link out when the box has no web address), never "the page linked below".
func TestDigestClaimsNoLink(t *testing.T) {
	t.Parallel()
	m := digest(Document{Title: "Security report", Period: DocPeriod{From: "2026-11-01T00:00:00.000Z", To: "2026-11-08T00:00:00.000Z", TZ: "UTC"}}, "rep-1")
	if m.What != "The whole report is in Vedette, under Reports, History." || strings.Contains(strings.ToLower(m.What), "link") || m.Path != "/reports/sent/rep-1" {
		t.Errorf("what = %q, path = %q", m.What, m.Path)
	}
}

// A version a person changed (the line was their own entry, so findings closes it as version_moved by that person) is theirs in the
// report: the handled line names them, and the totals count it with the people's handlings, never as something Vedette saw by itself.
func TestHandledAPersonsVersionChangeIsTheirs(t *testing.T) {
	t.Parallel()
	from, to := "1.30.5", "1.30.6"
	at := "2026-11-24T03:51:00.000Z"
	person := Handled{Resolution: "patched", Via: "version_moved", By: "qa@example.com", At: at, FromVersion: &from, ToVersion: &to}
	vedette := Handled{Resolution: "patched", Via: "version_moved", By: "system", At: at, FromVersion: &from, ToVersion: &to}
	if line := HandledLine(person, "nginx", time.UTC); line != "Patched by qa@example.com: version changed 1.30.5 → 1.30.6 (24 Nov 2026)" {
		t.Errorf("person's line = %q", line)
	}
	if line := HandledLine(vedette, "nginx", time.UTC); line != "Patched by Vedette: version moved 1.30.5 → 1.30.6 (24 Nov 2026)" {
		t.Errorf("Vedette's line = %q", line)
	}
	out := handledOf([]row{{h: history{handled: &person}}, {h: history{handled: &person}}, {h: history{handled: &vedette}}})
	got := map[string]int{}
	for _, x := range out.Totals {
		got[x.Resolution+"/"+x.Via] = x.N
	}
	if got["patched/person"] != 2 || got["patched/version_moved"] != 1 || len(got) != 2 {
		t.Errorf("totals = %v, want the person's two with the people's handlings and Vedette's one as version_moved", got)
	}
}

// "Not installed" is a person's word that keeps its own count in the totals ("2 software not installed"): only a version a person
// changed joins the people's marks.
func TestHandledNotInstalledKeepsItsOwnCount(t *testing.T) {
	t.Parallel()
	at := "2026-11-24T03:51:00.000Z"
	ni := Handled{Resolution: "not_relevant", Via: "not_installed", By: "qa@example.com", At: at}
	out := handledOf([]row{{h: history{handled: &ni}}})
	if len(out.Totals) != 1 || out.Totals[0].Via != "not_installed" || out.Totals[0].N != 1 {
		t.Errorf("totals = %+v, want one not_installed", out.Totals)
	}
}

// While the schedule sends the report, the schedule decides the period: every week the last 7 days, every month the last calendar
// month, whatever Settings says (a monthly report never covers one week). Off, the period of Settings stands.
func TestDocumentPeriodFollowsTheSchedule(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ every, set, want string }{
		{"", PeriodLast30, PeriodLast30},
		{"weekly", PeriodLast30, PeriodLast7},
		{"monthly", PeriodLast7, PeriodMonth},
	} {
		e := newEnv(t)
		e.seed()
		e.every = c.every
		d, _ := e.svc.Definition(e.ctx())
		o := d.Options
		o.Period = c.set
		_, err := e.svc.SaveDefinition(e.ctx(), "admin@acme.example", DefinitionInput{Name: d.Name, Options: o, Recipients: []string{}})
		mustNoErr(t, err)
		doc, err := e.svc.Document(e.ctx())
		mustNoErr(t, err)
		if doc.Period.Kind != c.want || doc.Options.Period != c.want {
			t.Errorf("schedule %q, settings %s: the document covers %s (options %s), want %s", c.every, c.set, doc.Period.Kind, doc.Options.Period, c.want)
		}
	}
}

// While the schedule decides the period, a report covers whole days in the organisation's zone and ends at midnight of the day it
// is made: a weekly one the 7 days before, a monthly one the last calendar month. So the reports one schedule sends cover time with no
// gap and no overlap, through a daylight-saving change too.
func TestScheduledPeriodsCoverTimeWithoutAGap(t *testing.T) {
	t.Parallel()
	hcm, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	mustNoErr(t, err)
	ny, err := time.LoadLocation("America/New_York")
	mustNoErr(t, err)
	for _, c := range []struct {
		every string
		loc   *time.Location
		first time.Time // the first send, in loc
		next  func(time.Time) time.Time
	}{
		{"weekly", hcm, time.Date(2026, 11, 3, 8, 30, 0, 0, hcm), func(t time.Time) time.Time { return t.AddDate(0, 0, 7) }},
		{"weekly", ny, time.Date(2026, 10, 20, 7, 0, 0, 0, ny), func(t time.Time) time.Time { return t.AddDate(0, 0, 7) }}, // 1 Nov ends DST
		{"monthly", hcm, time.Date(2026, 9, 1, 8, 30, 0, 0, hcm), func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
	} {
		var prevTo time.Time
		for i, send := 0, c.first; i < 4; i, send = i+1, c.next(send) {
			kind, whole := periodFollows(PeriodLast30, c.every)
			from, to := periodOf(kind, whole, send.UTC(), c.loc)
			if day := time.Date(send.Year(), send.Month(), send.Day(), 0, 0, 0, 0, c.loc); !to.Equal(day) {
				t.Errorf("%s %s sent %s: ends %s, want midnight of the send day %s", c.every, c.loc, send, to.In(c.loc), day)
			}
			if c.every == "weekly" && !from.Equal(to.In(c.loc).AddDate(0, 0, -7)) {
				t.Errorf("weekly sent %s: starts %s, want 7 days before %s", send, from.In(c.loc), to.In(c.loc))
			}
			if i > 0 && !from.Equal(prevTo) {
				t.Errorf("%s %s sent %s: starts %s, the report before ended %s", c.every, c.loc, send, from.In(c.loc), prevTo.In(c.loc))
			}
			prevTo = to
		}
	}
}

// A weekly report made by its schedule names the 7 whole days before the day it is sent: sent Wednesday 11 November, 4 – 10 November.
func TestWeeklyDocumentCoversTheSevenDaysBeforeTheSendDay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.every = "weekly"
	doc, err := e.svc.Document(e.ctx())
	mustNoErr(t, err)
	if doc.Period.From != "2026-11-04T00:00:00.000Z" || doc.Period.To != "2026-11-11T00:00:00.000Z" {
		t.Errorf("weekly report made %s covers %s – %s, want 2026-11-04T00:00:00.000Z – 2026-11-11T00:00:00.000Z", t0, doc.Period.From, doc.Period.To)
	}
	if m := digest(doc, "rep-1"); !strings.Contains(m.Title, "to 10 Nov") {
		t.Errorf("the email names the period %q, want it to end on 10 Nov", m.Title)
	}
}

// An incident that names many devices (12 new devices found at once) is listed with their number, not with the first device's name
// as if it were the only one.
func TestDocumentDetectionOfManyDevicesSaysHowMany(t *testing.T) {
	t.Parallel()
	in := docInput{def: defaultDefinition(), now: t0, loc: time.UTC, devices: []Device{{ID: "a-dell", Name: "Dell", Approved: false}},
		detections: detectionsIn{on: true, counts: []DetectionCount{{Kind: "unknown_device", N: 1, LastAt: at("2026-11-10T09:00:00Z")}},
			top: []Detection{
				{Kind: "unknown_device", Title: "12 new devices on the network", Severity: "medium", DeviceID: "a-dell", DeviceName: "Dell", Devices: 12, At: at("2026-11-10T09:00:00Z")},
				{Kind: "trap", Title: "Trap touched", Severity: "high", DeviceID: "a-dell", DeviceName: "Dell", Devices: 1, At: at("2026-11-10T10:00:00Z")},
			}}}
	doc := buildDocument(in)
	top := doc.Detections.Top
	if len(top) != 2 {
		t.Fatalf("top = %+v", top)
	}
	for _, d := range top {
		want := 0
		if d.Kind == "unknown_device" {
			want = 12
		}
		if d.DeviceCount != want {
			t.Errorf("%s: device count %d, want %d", d.Kind, d.DeviceCount, want)
		}
	}
}

// A report lists 100 open rows at most. Each group's header counts the group's open findings, listed or not ("70 of 147 shown"), and
// New counts the findings still open among all the new ones, not among the rows listed. Measured on a box: "Juniper EX4200: 70
// findings" for a device with 147 open, and "342 findings · 100 of them are still open" with 335 open.
func TestDocumentCountsWholeGroupsBeyondTheListedRows(t *testing.T) {
	t.Parallel()
	var fs []FindingView
	add := func(n int, d DeviceRef, urgency int, status string) {
		for range n {
			i := len(fs)
			fs = append(fs, FindingView{ID: fmt.Sprintf("f-%03d", i), CVE: fmt.Sprintf("CVE-2026-9%04d", i), Device: d, Product: "nginx", Status: status, Urgency: urgency,
				Severity: sev("high", 7.5), Verification: byBanner, Fix: fix("update", "nginx", "1.31.9"), FirstSeen: at("2026-11-06T09:00:00Z"),
				Events: []FindingEvent{created("2026-11-06T09:00:00Z")}})
		}
	}
	other := devWeb
	other.ID, other.Name = "a-switch", "switch-01"
	add(70, devWeb, 2, "exploited")
	add(80, other, 5, "update_recommended")
	doc := buildDocument(docInput{def: defaultDefinition(), now: t0, loc: time.UTC, findings: fs})
	totals := map[string][2]int{}
	for _, g := range doc.Open.Groups {
		totals[g.Key] = [2]int{len(g.Items), g.Total}
	}
	if totals[devWeb.ID] != [2]int{70, 70} || totals["a-switch"] != [2]int{30, 80} {
		t.Errorf("group rows/totals = %v, want web 70/70 and switch 30 of 80", totals)
	}
	if doc.New.Total != 150 || doc.New.Open != 150 || len(doc.New.Items) != MaxRows {
		t.Errorf("new = total %d, open %d, listed %d; want 150, 150, %d", doc.New.Total, doc.New.Open, len(doc.New.Items), MaxRows)
	}
}
