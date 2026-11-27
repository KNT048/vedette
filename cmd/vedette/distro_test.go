package main

import (
	"database/sql"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// End to end: the feeds' distribution rows and the inventory's full package version reach the matcher. A packaged
// OpenSSH below Ubuntu's fixed version is a version finding that names the fix; after the package update (the upstream
// number stays 9.6p1) the finding closes by itself.
func TestDistroFixReachesFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-7101"
	s.kevAdded(cve, "OpenBSD", "OpenSSH", time.Now().AddDate(0, -1, 0))
	now := store.FormatTS(time.Now().UTC())
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE feeds_cve SET nvd_at = ?2, nvd_status = 'Analyzed' WHERE cve = ?1`, []any{cve, now}},
			{`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'nvd', 'a', 'openbsd', 'openssh', 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', '', '', '', '10.6p2')`, []any{cve}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '24.04', 'openssh', ?, 'fixed', '1:9.6p1-3ubuntu13.5')`, []any{cve}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "web-01", OS: "Ubuntu 24.04"})
	if err != nil {
		t.Fatal(err)
	}
	install := func(full string) {
		t.Helper()
		it := inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95,
			Packaged: true, PkgVersion: full, PkgSource: "openssh"}
		if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{it}, "osquery"); err != nil {
			t.Fatal(err)
		}
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	finding := func() findings.Record {
		t.Helper()
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil || len(recs) != 1 || recs[0].CVE != cve {
			t.Fatalf("findings %+v %v", recs, err)
		}
		return recs[0]
	}
	install("1:9.6p1-3ubuntu13.4")
	if f := finding(); f.Status != findings.StatusConfirmed || f.Basis != findings.BasisVersion || !strings.Contains(f.Evidence.Summary, "Ubuntu fixed "+cve+" in openssh 1:9.6p1-3ubuntu13.5") {
		t.Fatalf("below the fix: %+v", f)
	}
	install("1:9.6p1-3ubuntu13.14")
	// the agent read another release at or above Ubuntu's fix: an update the device got (patched), with Ubuntu's word as the proof
	if f := finding(); f.Status != findings.StatusPatched || f.Row.Via != findings.ViaVersionMoved || f.Row.FromVersion != "1:9.6p1-3ubuntu13.4" || f.Row.ToVersion != "1:9.6p1-3ubuntu13.14" {
		t.Fatalf("after the update: %+v", f)
	}
}

// The dev box's kernel: Ubuntu lists its kernel CVEs under source package linux (the images come from linux-signed,
// same version). With 7.0.0-30 running, the CVE fixed in 7.0.0-31.31 is a finding that names the fix and the one fixed in
// 7.0.0-22.22 is not; once 7.0.0-43 is installed but before the reboot it stays (review H1 of #732); after the reboot to
// 7.0.0-43 it closes. The old kernel stays installed throughout.
func TestDistroKernelFollowsTheRunningKernel(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	fixes := map[string]string{"CVE-2026-46300": "7.0.0-22.22", "CVE-2026-53266": "7.0.0-31.31"}
	for cve, fixed := range fixes {
		s.kevAdded(cve, "Linux", "Kernel", time.Now().AddDate(0, -1, 0))
		err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '26.04', 'linux', ?, 'fixed', ?)`, cve, fixed)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "srv01", OS: "Ubuntu 26.04"})
	if err != nil {
		t.Fatal(err)
	}
	install := func(running string, pkgs ...agentintake.DebPackage) {
		t.Helper()
		for i := range pkgs {
			pkgs[i].Kernel = running
		}
		sw, _ := agentintake.MapDebPackages(pkgs)
		items := make([]inventory.SoftwareItem, len(sw))
		for i, x := range sw {
			items[i] = inventory.SoftwareItem{Display: x.Display, Vendor: x.Vendor, Product: x.Product, Version: x.Version, KevKeys: x.KevKeys, Confidence: x.Confidence,
				Packaged: x.Packaged, PkgVersion: x.PkgVersion, PkgSource: x.PkgSource}
		}
		if err := s.d.Inventory.UpsertSoftware(ctx, id, items, "osquery"); err != nil {
			t.Fatal(err)
		}
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	status := func() map[string]findings.Record {
		t.Helper()
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]findings.Record{}
		for _, r := range recs {
			out[r.CVE] = r
		}
		return out
	}
	old := agentintake.DebPackage{Name: "linux-image-7.0.0-30-generic", Version: "7.0.0-30.30", Source: "linux-signed"}
	updated := agentintake.DebPackage{Name: "linux-image-7.0.0-43-generic", Version: "7.0.0-43.43", Source: "linux-signed"}
	meta := agentintake.DebPackage{Name: "linux-image-generic", Version: "7.0.0-43.43", Source: "linux-meta"}
	install("7.0.0-30-generic", old, meta)
	got := status()
	if f, ok := got["CVE-2026-53266"]; !ok || f.Status != findings.StatusConfirmed || !strings.Contains(f.Evidence.Summary, "Ubuntu fixed CVE-2026-53266 in linux 7.0.0-31.31") {
		t.Fatalf("7.0.0-30 below the fix: %+v", got)
	}
	if _, ok := got["CVE-2026-46300"]; ok {
		t.Fatalf("7.0.0-30 is past the fix of CVE-2026-46300, yet it is a finding: %+v", got["CVE-2026-46300"])
	}
	install("7.0.0-30-generic", old, updated, meta) // installed, not rebooted
	if f := status()["CVE-2026-53266"]; f.Status != findings.StatusConfirmed {
		t.Fatalf("the new kernel is installed but does not run yet, and the finding closed: %+v", f)
	}
	install("7.0.0-43-generic", old, updated, meta) // rebooted
	if f := status()["CVE-2026-53266"]; f.Status != findings.StatusPatched || f.Row.Via != findings.ViaVersionMoved || f.Row.FromVersion != "7.0.0-30.30" || f.Row.ToVersion != "7.0.0-43.43" {
		t.Fatalf("after the reboot to 7.0.0-43: %+v", f)
	}
}

var _ feeds.DistroLister = feedsInventory{} // A drifted signature would silently pull every feed again (review M1)

// The adapter tells feeds which distributions need their files: a device of that OS with a deb package an agent read, with
// its source packages as the security data names them (the tier rows are kept for those only).
func TestFeedsInventoryDistros(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	inv := feedsInventory{s.d.Inventory}
	distros := func() map[string]map[string]bool {
		t.Helper()
		got, err := inv.Distros(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "web-01", OS: "Ubuntu 24.04"})
	if err != nil {
		t.Fatal(err)
	}
	pkg := inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Confidence: 0.95, Packaged: true, PkgVersion: "1:9.6p1-3ubuntu13.4", PkgSource: "openssh"}
	if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{pkg}, "scan"); err != nil {
		t.Fatal(err)
	}
	if got := distros(); len(got) != 0 {
		t.Fatalf("a package a scan reported: %v", got)
	}
	if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{pkg}, "osquery"); err != nil {
		t.Fatal(err)
	}
	if got := distros(); !reflect.DeepEqual(got, map[string]map[string]bool{"ubuntu": {"openssh": true}}) {
		t.Fatalf("an agent's deb package on Ubuntu: %v", got)
	}
	if _, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "web-01", OS: "Debian GNU/Linux 12 (bookworm)"}); err != nil {
		t.Fatal(err)
	}
	if got := distros(); !reflect.DeepEqual(got, map[string]map[string]bool{"debian": {"openssh": true}}) {
		t.Fatalf("the same box on Debian: %v", got)
	}
	// a person says the device runs Alpine Linux (inventory INV-41): alpine-osv is needed, with no package; cleared, it is not
	alpine, none := "Alpine Linux 3.23", ""
	if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{OS: &alpine}); err != nil {
		t.Fatal(err)
	}
	if got := distros(); got["alpine"] == nil || len(got["alpine"]) != 0 {
		t.Fatalf("a person's Alpine Linux: %v", got)
	}
	if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{OS: &none}); err != nil {
		t.Fatal(err)
	}
	if got := distros(); got["alpine"] != nil {
		t.Fatalf("the correction cleared: %v", got)
	}
}

// End to end: alpine-osv's rows reach the matcher through findingsFeeds. gw-alpine (nmap's OpenSSH 10.2 on a device a person says runs
// Alpine Linux 3.23) with the package release 10.2_p1-r1 a person gave is not affected by CVE-2026-123158 by Alpine's fixed release for 3.23;
// 10.2_p1-r0 is a version finding naming that release.
func TestAlpineFixReachesFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-123158"
	s.kevAdded(cve, "OpenBSD", "OpenSSH", time.Now().AddDate(0, 0, -11))
	now := store.FormatTS(time.Now().UTC())
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE feeds_cve SET nvd_at = ?2, nvd_status = 'Analyzed' WHERE cve = ?1`, []any{cve, now}},
			{`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'nvd', 'a', 'openbsd', 'openssh', 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', '', '', '', '10.6')`, []any{cve}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('alpine-osv', 'alpine', '3.23', 'openssh', ?, 'fixed', '10.2_p1-r1')`, []any{cve}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('alpine-osv', 'alpine', '3.24', 'openssh', ?, 'fixed', '10.3_p1-r2')`, []any{cve}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('alpine-osv', 'alpine', '3.22', 'openssh', ?, 'fixed', '10.0_p1-r11')`, []any{cve}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("10.142.0.1")
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.Hostname, Value: "gw-alpine", Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	addrs, err := s.d.Inventory.AddressMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addrs[ip.String()]
	if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{{Display: "OpenSSH 10.2", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2",
		KevKeys: []string{"openbsd|openssh"}, Confidence: 0.8}}, "scan"); err != nil {
		t.Fatal(err)
	}
	alpine := "Alpine Linux 3.23"
	if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{OS: &alpine}); err != nil {
		t.Fatal(err)
	}
	dev, err := s.d.Inventory.Device(ctx, id)
	if err != nil || len(dev.Software) != 1 {
		t.Fatalf("gw-alpine: %+v %v", dev, err)
	}
	give := func(rel string) []findings.Record {
		t.Helper()
		if err := s.d.Inventory.EditSoftware(ctx, "it@acme.example", id, dev.Software[0].ID, inventory.SoftwareEdit{PkgVersion: &rel}); err != nil {
			t.Fatal(err)
		}
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return recs
	}
	// the release the person gave is below Alpine's fix: their word, so the finding is confirmed by them
	if recs := give("10.2_p1-r0"); len(recs) != 1 || recs[0].Status != findings.StatusConfirmed || !strings.Contains(recs[0].Evidence.Summary, "Update openssh-server to 10.2_p1-r1 or later") {
		t.Fatalf("below the 3.23 fix: %+v", recs)
	}
	// the person corrected the release a scan's banner gave no word on: Vedette corrected its match, no patch credit
	if recs := give("10.2_p1-r1"); len(recs) != 1 || recs[0].Status != findings.StatusNotRelevant || recs[0].Row.Via != findings.ViaDataCorrected {
		t.Fatalf("at the 3.23 fix: %+v", recs)
	}
}

// While alpine-osv is on but not loaded, gw-alpine's Alpine-only CVE stays a question (never an NVD finding), and the
// person's "Alpine Linux 3.23" wakes the feeds pull at once; with the feed off NVD decides (a finding).
func TestAlpineNotLoadedKeepsTheQuestionAndWakesThePull(t *testing.T) {
	t.Parallel()
	var woke []string
	s := newStackWith(t, func(d *deps) { d.Wake = func(module, job string) { woke = append(woke, module+"/"+job) } })
	ctx := t.Context()
	const cve = "CVE-2026-123158"
	s.kevAdded(cve, "OpenBSD", "OpenSSH", time.Now().AddDate(0, 0, -11))
	now := store.FormatTS(time.Now().UTC())
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET nvd_at = ?2, nvd_status = 'Analyzed' WHERE cve = ?1`, cve, now); err != nil {
			return err
		}
		return seedRange(ctx, tx, cve, "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6")
	})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("10.142.0.1")
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.Hostname, Value: "gw-alpine", Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	addrs, err := s.d.Inventory.AddressMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addrs[ip.String()]
	if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{{Display: "OpenSSH 10.2", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2",
		KevKeys: []string{"openbsd|openssh"}, Confidence: 0.8}}, "scan"); err != nil {
		t.Fatal(err)
	}
	if len(woke) != 0 {
		t.Fatalf("woke the pull for a device that states no Alpine: %v", woke)
	}
	alpine := "Alpine Linux 3.23"
	if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{OS: &alpine}); err != nil {
		t.Fatal(err)
	}
	if len(woke) != 1 || woke[0] != "feeds/pull" {
		t.Fatalf("a person's Alpine Linux woke %v", woke)
	}
	run := func() []findings.Record {
		t.Helper()
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return recs
	}
	if recs := run(); len(recs) != 0 {
		t.Fatalf("alpine-osv on, not loaded: %+v", recs)
	}
	if c, b := s.do("PUT", "/feeds/sources/alpine-osv", "admin", `{"enabled":false}`); c != 200 {
		t.Fatalf("turning alpine-osv off: %d %v", c, b)
	}
	if recs := run(); len(recs) != 1 || recs[0].Status != findings.StatusSuspected {
		t.Fatalf("alpine-osv off: NVD decides, %+v", recs)
	}
}
