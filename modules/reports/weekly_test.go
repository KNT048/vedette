package reports

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func day0(n int) time.Time { return t0.Add(-time.Duration(n) * 24 * time.Hour) }

func sampleInput() weeklyInput {
	return weeklyInput{
		now: t0,
		devices: []Device{
			{ID: "a1", Name: "fw-01", IP: "10.0.0.1", Kind: "firewall", Approved: true, FirstSeen: day0(60), OS: "FortiOS 7"},
			{ID: "a2", Name: "pc-old", IP: "10.0.0.2", Kind: "pc", Approved: false, FirstSeen: day0(2), OS: "Windows 10 Pro", KevKeys: []string{"microsoft|windows"}},
			{ID: "a3", Name: "srv", IP: "10.0.0.3", Kind: "server", Approved: true, FirstSeen: day0(30), OS: "Windows Server 2016"},
		},
		findings: []Finding{
			{ID: "f1", AssetID: "a2", CVE: "CVE-2026-0001", Status: "confirmed", Severity: "critical", FirstSeen: day0(1)},
			{ID: "f2", AssetID: "a3", CVE: "CVE-2026-0002", Status: "suspected", Severity: "high", FirstSeen: day0(20)},
			{ID: "f3", AssetID: "a1", CVE: "CVE-2026-0003", Status: "patched", Severity: "high", FirstSeen: day0(10), ResolvedAt: day0(3)},
			{ID: "f4", AssetID: "a1", CVE: "CVE-2026-0004", Status: "false_positive", Severity: "low", FirstSeen: day0(40), ResolvedAt: day0(30)},
			{ID: "f5", AssetID: "a2", CVE: "CVE-2026-0005", Status: "confirmed", Severity: "medium", FirstSeen: t0.Add(time.Hour)}, // in the future: ignored
		},
		kev: []KEVEntry{
			{CVE: "CVE-2026-0001", Vendor: "Microsoft", Product: "Windows", Key: "microsoft|windows", DateAdded: day0(1).Truncate(24 * time.Hour)},
			{CVE: "CVE-2026-0002", Vendor: "Acme", Product: "Srv", Key: "acme|srv", DateAdded: day0(2).Truncate(24 * time.Hour)},
			{CVE: "CVE-2025-9999", Vendor: "Old", Product: "Thing", Key: "old|thing", DateAdded: day0(40).Truncate(24 * time.Hour)},
		},
		kevAt: day0(0).Add(-time.Hour),
	}
}

func TestWeeklyCounts(t *testing.T) {
	t.Parallel()
	r := buildWeekly(sampleInput())
	c := r.Counts
	want := Counts{NewFindings: 1, Resolved: 1, OpenConfirmed: 1, OpenSuspected: 1, Devices: 3, DevicesUnapprove: 1, DevicesNew: 1, KevNew: 2, KevMatched: 1}
	if c != want {
		t.Fatalf("counts = %+v, want %+v", c, want)
	}
	if len(r.NewFindings) != 1 || r.NewFindings[0].ID != "f1" || r.NewFindings[0].Device != "pc-old" || r.NewFindings[0].Product != "Microsoft Windows" {
		t.Fatalf("new findings = %+v", r.NewFindings)
	}
	if len(r.Resolved) != 1 || r.Resolved[0].ID != "f3" {
		t.Fatalf("resolved = %+v", r.Resolved)
	}
	if len(r.Open) != 2 || r.Open[0].ID != "f1" || r.Open[1].ID != "f2" { // critical before high
		t.Fatalf("open = %+v", r.Open)
	}
}

func TestWeeklyActionsOrderAndCap(t *testing.T) {
	t.Parallel()
	r := buildWeekly(sampleInput())
	var kinds []string
	for _, a := range r.Actions {
		kinds = append(kinds, a.Kind)
	}
	if got := strings.Join(kinds, ","); got != "fix,verify,review_devices,plan_os" {
		t.Fatalf("actions = %s", got)
	}
	if r.Actions[2].Count != 1 || r.Actions[3].Count != 2 { // one unapproved device; two end-of-life systems
		t.Fatalf("action counts = %+v", r.Actions)
	}
	in := sampleInput()
	for i := 0; i < 20; i++ {
		in.findings = append(in.findings, Finding{ID: fmt.Sprintf("x%d", i), AssetID: "a1", CVE: "CVE-2026-1", Status: "confirmed", Severity: "low", FirstSeen: day0(3)})
	}
	if n := len(buildWeekly(in).Actions); n != 6 {
		t.Fatalf("actions are capped at 6, got %d", n)
	}
}

func TestWeeklySourcesDoNotClaimHoneypotOrLogs(t *testing.T) {
	t.Parallel()
	r := buildWeekly(sampleInput())
	var ids []string
	for _, s := range r.Sources {
		ids = append(ids, s.ID)
	}
	if strings.Join(ids, ",") != "inventory,findings,kev" { // INV-9
		t.Fatalf("sources = %v", ids)
	}
	if r.Sources[2].At != ts(sampleInput().kevAt) {
		t.Fatalf("kev source time = %s", r.Sources[2].At)
	}
	if r.AISummary != nil {
		t.Fatal("the report holds no AI text until one is attached (INV-1)")
	}
}

func TestWeeklyListsAreCappedButCountsAreNot(t *testing.T) {
	t.Parallel()
	in := sampleInput()
	for i := 0; i < MaxRows+50; i++ {
		in.findings = append(in.findings, Finding{ID: fmt.Sprintf("n%03d", i), AssetID: "a1", CVE: "CVE-2026-2", Status: "suspected", Severity: "info", FirstSeen: day0(1)})
	}
	r := buildWeekly(in)
	if len(r.NewFindings) != MaxRows || len(r.Open) != MaxRows {
		t.Fatalf("rows = %d new, %d open, want %d", len(r.NewFindings), len(r.Open), MaxRows)
	}
	if r.Counts.NewFindings != MaxRows+51 || r.Counts.OpenSuspected != MaxRows+51 {
		t.Fatalf("counts must be of everything: %+v", r.Counts)
	}
}

func TestWeeklyCleansNamesFromTheNetwork(t *testing.T) {
	t.Parallel()
	in := sampleInput()
	in.devices[1].Name = "pc\r\nBcc: x@evil.example‮<script>"
	r := buildWeekly(in)
	got := r.NewFindings[0].Device
	if strings.ContainsAny(got, "\r\n‮") || strings.Contains(got, "  ") {
		t.Fatalf("device name was not cleaned: %q", got)
	}
	long := strings.Repeat("é", 500)
	if n := len([]rune(clip(long, 80))); n != 80 {
		t.Fatalf("clip length = %d", n)
	}
}

func TestWeeklyEmptyBoxHasEmptyListsNotNull(t *testing.T) {
	t.Parallel()
	r := buildWeekly(weeklyInput{now: t0})
	if r.NewFindings == nil || r.Resolved == nil || r.Open == nil || r.Actions == nil {
		t.Fatal("lists must be [] in JSON, never null")
	}
}

func TestWeeklyKEVWindowIsTheLastSevenCalendarDays(t *testing.T) {
	t.Parallel()
	today := t0.Truncate(24 * time.Hour)
	in := weeklyInput{now: t0, kev: []KEVEntry{
		{CVE: "a", DateAdded: today},               // today: in
		{CVE: "b", DateAdded: today.Add(-6 * day)}, // six days ago: in
		{CVE: "c", DateAdded: today.Add(-7 * day)}, // a week ago: out
		{CVE: "d", DateAdded: today.Add(day)},      // tomorrow (clock skew in the feed): out
	}}
	if n := buildWeekly(in).Counts.KevNew; n != 2 {
		t.Fatalf("kev_new = %d, want 2", n)
	}
}
