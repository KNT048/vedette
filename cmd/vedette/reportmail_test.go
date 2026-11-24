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
