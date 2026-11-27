package main

import (
	"testing"

	"github.com/knt048/vedette/modules/reports"
)

// The fix of a finding in the report mail is the line the report page and the finding page show (findings' fixLine words): every kind
// has one, a fix with no release named says what to do, and a listed finding's own version is the "from" of an update.
func TestReportMailFixIsThePagesFixLine(t *testing.T) {
	v := func(s string) *string { return &s }
	cases := []struct {
		fix  reports.Fix
		from string
		want string
	}{
		{reports.Fix{Kind: "update", Product: "FortiOS", Version: v("7.2.11")}, "7.2.0", "Update FortiOS 7.2.0 → 7.2.11"},
		{reports.Fix{Kind: "update", Product: "FortiOS", Version: v("7.2.11")}, "", "Update FortiOS to 7.2.11"},
		{reports.Fix{Kind: "update", Product: "FortiOS"}, "7.2.0", "Update FortiOS to a fixed release"},
		{reports.Fix{Kind: "distro_update", Product: "openssl", Version: v("3.0.13-0ubuntu3.4")}, "3.0.13", "Install the openssl package 3.0.13-0ubuntu3.4 or later"},
		{reports.Fix{Kind: "distro_update", Product: "openssl"}, "", "Install the distribution's security updates for openssl"},
		{reports.Fix{Kind: "distro_update", Product: "python3-pip", Version: v("25.1.1+dfsg-1ubuntu2+esm3"), Channel: "ubuntu_pro"}, "", "Install the python3-pip package 25.1.1+dfsg-1ubuntu2+esm3 from Ubuntu Pro (ESM): only Ubuntu Pro has this fix"},
		{reports.Fix{Kind: "os_update", Product: "Windows 10 22H2", Ref: v("KB5066791"), Channel: "esu"}, "", "Install KB5066791 on Windows 10 22H2 (needs an Extended Security Updates subscription)"},
		{reports.Fix{Kind: "os_update", Product: "Windows 11 24H2", Version: v("10.0.26100.4061"), Ref: v("KB5058411")}, "", "Install KB5058411 on Windows 11 24H2"},
		{reports.Fix{Kind: "os_update", Product: "Windows 11 24H2", Version: v("10.0.26100.4061")}, "", "Update Windows 11 24H2 to build 10.0.26100.4061"},
		{reports.Fix{Kind: "os_update", Product: "Windows 11 24H2"}, "", "Install the latest cumulative update on Windows 11 24H2"},
		{reports.Fix{Kind: "feature_update", Product: "Windows 10", Version: v("22H2")}, "", "Move Windows 10 to release 22H2"},
		{reports.Fix{Kind: "feature_update", Product: "Windows 10"}, "", "Move Windows 10 to a later release"},
		{reports.Fix{Kind: "restart", Product: "Kernel", Version: v("7.0.0-44.44")}, "7.0.0", "Restart to run the installed Kernel 7.0.0-44.44"},
		{reports.Fix{Kind: "restart", Product: "Kernel"}, "", "Restart to run the installed Kernel"},
		{reports.Fix{Kind: "none_yet", Product: "Example Manager"}, "", "No fix known yet for Example Manager"},
		{reports.Fix{Kind: "unknown", Product: "Example Manager"}, "", "See the vendor advisory for the fixed release of Example Manager"},
	}
	for _, c := range cases {
		if got := reportFix(c.fix, c.from); got != c.want {
			t.Errorf("%s from %q: %q, want %q", c.fix.Kind, c.from, got, c.want)
		}
	}
}

// The mail says what the page says about counts beyond the listed rows: a group's header names its whole open total ("30 of 80
// findings shown"), and New says how many of all the new findings are still open and how many are listed.
func TestReportMailCountsBeyondTheListedRows(t *testing.T) {
	rows := func(n int) []reports.ReportFinding {
		out := make([]reports.ReportFinding, n)
		for i := range out {
			out[i] = reports.ReportFinding{FindingID: "f", CVE: "CVE-2026-1", Product: "nginx", Status: "update_recommended", Device: reports.DeviceRef{ID: "a", Name: "web-01", Added: true}}
		}
		return out
	}
	d := reports.Document{Open: &reports.ReportOpen{Grouping: "device", Total: 150, More: 50, Groups: []reports.OpenGroup{
		{Key: "a", Label: "web-01", Status: "exploited", Items: rows(70), Total: 70}, {Key: "b", Label: "switch-01", Status: "update_recommended", Items: rows(30), Total: 80}}},
		New: &reports.ReportNew{Total: 342, Open: 335, Items: rows(100), More: 242}}
	doc := reportMailDoc(d)
	var caps, paras []string
	for _, s := range doc.Sections {
		for _, tb := range s.Tables {
			caps = append(caps, tb.Caption)
		}
		paras = append(paras, s.Paragraphs...)
	}
	want := map[string]bool{"web-01 · 70 findings": false, "switch-01 · 30 of 80 findings shown": false, "342 findings, 335 still open; 100 listed.": false}
	for _, x := range append(caps, paras...) {
		if _, ok := want[x]; ok {
			want[x] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("mail lacks %q (captions %q, paragraphs %q)", k, caps, paras)
		}
	}
}
