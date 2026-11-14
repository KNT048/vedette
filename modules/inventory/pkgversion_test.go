package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// D-516: a packaged agent row keeps its full Debian version and source package for findings; another source's claim, a
// malformed value or a row not from a package database keeps neither. A package update that keeps the upstream number
// (13.5 -> 13.14) is the same row with a new full version, and findings is told to read the device again.
func TestPackagedRowKeepsFullVersionAndSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{"openbsd|openssh": {"CVE-2026-10001"}}}))
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.20.50")}
	sync := func(src observe.Source, full string) {
		t.Helper()
		err := e.svc.ReplaceSoftware(e.ctx(), hint, src, []observe.Software{
			{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9, Packaged: true, PkgVersion: full, PkgSource: "openssh"},
			{Display: "curl", Vendor: "curl", Product: "curl", Version: "8.5.0", Confidence: 0.9, Packaged: true, PkgVersion: "8.5.0-2ubuntu10; rm", PkgSource: "curl"},
			{Display: "Chrome", Vendor: "Google", Product: "Chrome", Version: "130.0", Confidence: 0.9, PkgVersion: "130.0-1", PkgSource: "chrome"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string][2]string {
		t.Helper()
		d, ok, err := e.svc.MatchInput(e.ctx(), e.idOf("192.168.20.50"))
		if err != nil || !ok {
			t.Fatalf("MatchInput: %v %v", ok, err)
		}
		got := map[string][2]string{}
		for _, sw := range d.Software {
			got[sw.Product+"/"+sw.Source] = [2]string{sw.PkgVersion, sw.PkgSource}
		}
		return got
	}
	sync(observe.Agent, "1:9.6p1-3ubuntu13.5")
	got := read()
	if got["OpenSSH/agent"] != [2]string{"1:9.6p1-3ubuntu13.5", "openssh"} || got["curl/agent"] != [2]string{} || got["Chrome/agent"] != [2]string{} {
		t.Fatalf("stored %v", got)
	}
	e.ev.reset()
	sync(observe.Agent, "1:9.6p1-3ubuntu13.14")
	if got := read(); got["OpenSSH/agent"][0] != "1:9.6p1-3ubuntu13.14" {
		t.Fatalf("after the update %v", got)
	}
	if n := len(e.ev.named(inventory.EventMatchChanged)); n != 1 {
		t.Fatalf("%d match events after a package update, want 1", n)
	}
	e.ev.reset()
	sync(observe.Agent, "1:9.6p1-3ubuntu13.14") // the same list again: nothing to tell
	if n := len(e.ev.named(inventory.EventMatchChanged)); n != 0 {
		t.Fatalf("%d match events for an unchanged list", n)
	}
	sync(observe.Scan, "1:9.6p1-3ubuntu13.14") // only an agent reads a package database
	if got := read(); got["OpenSSH/scan"] != [2]string{} {
		t.Fatalf("a scan row kept a package version: %v", got)
	}
}
