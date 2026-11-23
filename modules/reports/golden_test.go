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
		if line := HandledLine(h, it.Product); !strings.HasPrefix(line, "Patched by Vedette: version moved 6.24 → 7.23 (9 Nov)") {
			t.Fatalf("handled line = %q", line)
		}
	}
	m := digest(doc, "rep-1")
	if !slices.Contains(m.Items, "WinRAR on ws-accounting-07: Patched by Vedette: version moved 6.24 → 7.23 (9 Nov)") {
		t.Fatalf("mail items = %q", m.Items)
	}
	if !slices.ContainsFunc(m.Items, func(s string) bool { return strings.Contains(s, "6.24 → 7.23 (9 Nov): Checked on the machine.") }) {
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
