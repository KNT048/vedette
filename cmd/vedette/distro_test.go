package main

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// D-516 end to end: the feeds' distribution rows and the inventory's full package version reach the matcher. A packaged
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
			{`INSERT INTO feeds_affected_cve (cve, updated_at) VALUES (?, ?)`, []any{cve, now}},
			{`INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', '', '', '', '10.6p2')`, []any{cve}},
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
		if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{it}, "agent"); err != nil {
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
	if f := finding(); f.Status != findings.StatusSuspected || f.Basis != findings.BasisVersion || !strings.Contains(f.Evidence.Summary, "Ubuntu fixed "+cve+" in openssh 1:9.6p1-3ubuntu13.5") {
		t.Fatalf("below the fix: %+v", f)
	}
	install("1:9.6p1-3ubuntu13.14")
	if f := finding(); f.Status != findings.StatusNotRelevant || f.ResolutionReason != findings.ReasonNotAffectedVersion || !strings.Contains(f.ResolutionNote, "this device has 1:9.6p1-3ubuntu13.14") {
		t.Fatalf("after the update: %+v", f)
	}
}

// D-516, the dev box's kernel: Ubuntu lists its kernel CVEs under source package linux (the images come from linux-signed,
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
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "byn", OS: "Ubuntu 26.04"})
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
		if err := s.d.Inventory.UpsertSoftware(ctx, id, items, "agent"); err != nil {
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
	if f, ok := got["CVE-2026-53266"]; !ok || f.Status != findings.StatusSuspected || !strings.Contains(f.Evidence.Summary, "Ubuntu fixed CVE-2026-53266 in linux 7.0.0-31.31") {
		t.Fatalf("7.0.0-30 below the fix: %+v", got)
	}
	if _, ok := got["CVE-2026-46300"]; ok {
		t.Fatalf("7.0.0-30 is past the fix of CVE-2026-46300, yet it is a finding: %+v", got["CVE-2026-46300"])
	}
	install("7.0.0-30-generic", old, updated, meta) // installed, not rebooted
	if f := status()["CVE-2026-53266"]; f.Status != findings.StatusSuspected {
		t.Fatalf("the new kernel is installed but does not run yet, and the finding closed: %+v", f)
	}
	install("7.0.0-43-generic", old, updated, meta) // rebooted
	if f := status()["CVE-2026-53266"]; f.Status != findings.StatusNotRelevant || !strings.Contains(f.ResolutionNote, "fixed CVE-2026-53266 in linux 7.0.0-31.31, and this device has 7.0.0-43.43") {
		t.Fatalf("after the reboot to 7.0.0-43: %+v", f)
	}
}
