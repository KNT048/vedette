package main

import (
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The exploited CVE and the recommended-update CVE of OpenSSH the strongest-row tests use: both "before 10.6" in NVD.
const (
	sshKEVCVE  = "CVE-2099-0101"
	sshTierCVE = "CVE-2026-60001"
)

var sshKEVVuln = findings.Vuln{CVE: sshKEVCVE, Vendor: "OpenBSD", Product: "OpenSSH", Affected: []findings.Affected{
	{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: findings.VersionRange{EndExcl: "10.6"}}}}

// sshFeeds stores the exploited OpenSSH CVE (with NVD's range) and a recommended-update CVE of it (nvd-recent), as the feeds would.
func sshFeeds(t *testing.T, s *stack) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC()
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedKEVRow(ctx, tx, sshKEVCVE, "OpenBSD", "OpenSSH", "OpenBSD OpenSSH flaw", now.AddDate(0, 0, -11), false, false); err != nil {
			return err
		}
		if err := seedNVD(ctx, tx, sshKEVCVE, now.AddDate(-1, 0, 0), 0); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, sshKEVCVE, "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6"); err != nil {
			return err
		}
		if err := seedNVD(ctx, tx, sshTierCVE, now.AddDate(0, 0, -30), 8.1); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, sshTierCVE, "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6"); err != nil {
			return err
		}
		if err := seedRecentDone(ctx, tx, now); err != nil {
			return err
		}
		// The distribution feeds are on and have been read: each completed a pull and holds a row, of a package no device here runs. A
		// feed that has never completed a pull is still loading, and the plan compares no package of its distribution until it has loaded.
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET last_success = ?, status = 'ok' WHERE id IN ('alpine-osv', 'debian-tracker', 'ubuntu-osv', 'ubuntu-vex')`, store.FormatTS(now)); err != nil {
			return err
		}
		for _, f := range []struct{ source, distro, release, status, fixed string }{
			{"alpine-osv", "alpine", "3.20", "fixed", "1.0-r0"},
			{"debian-tracker", "debian", "12", "fixed", "1.0-1"},
			{"ubuntu-osv", "ubuntu", "24.04", "fixed", "1.0-1"},
			{"ubuntu-vex", "ubuntu", "24.04", "not_affected", ""},
		} {
			var fixed any
			if f.fixed != "" {
				fixed = f.fixed
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES (?, ?, ?, 'zlib', 'CVE-2026-69999', ?, ?)`,
				f.source, f.distro, f.release, f.status, fixed); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// sshRows is one combination of OpenSSH rows on one device, as each source writes them into the inventory.
type sshRows struct {
	os, banner   string // the device's OS; the scan banner's version ("" for none)
	snmp         bool
	manual       string // "" none, "plain" a person's version, "pkg" a person's package release
	manualPkg    string
	agent        string // "" none, "packaged", "wazuh" (a package row without its source package), "upstream" (no package)
	agentVersion string
	agentPkg     string
}

// addSSHDevice writes the rows through inventory's own entry points: the scan's, SNMP's and the agent's lists (UpsertSoftware), and
// a person's entry (a correction of the scan's row when there is one, else a declared row; the package release through EditSoftware).
func addSSHDevice(t *testing.T, s *stack, ip string, r sshRows) string {
	t.Helper()
	ctx := t.Context()
	addr := netip.MustParseAddr(ip)
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: addr}, Field: observe.Hostname, Value: "dev-" + strings.ReplaceAll(ip, ".", "-"),
		Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	addrs, err := s.d.Inventory.AddressMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addrs[ip]
	if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{OS: &r.os}); err != nil {
		t.Fatal(err)
	}
	keys := []string{"openbsd|openssh"}
	upsert := func(source string, it inventory.SoftwareItem) {
		t.Helper()
		it.KevKeys, it.Confidence = keys, 0.9
		if source == "agent" {
			source = "osquery" // an agent list names the agent that read it
		}
		if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{it}, source); err != nil {
			t.Fatalf("%s row: %v", source, err)
		}
	}
	if r.manual != "" && r.banner == "" { // a person's own row: declared before any reported row of the product (else 409 duplicate)
		if _, err := s.d.Inventory.AddSoftware(ctx, "it@acme.example", id, inventory.AddInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2"}); err != nil {
			t.Fatalf("declared row: %v", err)
		}
	}
	if r.banner != "" {
		upsert("nmap", inventory.SoftwareItem{Display: "OpenSSH " + r.banner, Vendor: "openbsd", Product: "openssh", Version: r.banner, CPE: "cpe:/a:openbsd:openssh:10.2"})
	}
	if r.snmp {
		upsert("snmp", inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2"})
	}
	if r.manual != "" {
		dev, err := s.d.Inventory.Device(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var row string
		for _, sw := range dev.Software {
			if strings.EqualFold(sw.Product, "openssh") { // the one line of OpenSSH, whatever source reads it
				row = sw.ID
			}
		}
		e := inventory.SoftwareEdit{}
		v := "10.2"
		e.Version = &v
		if r.manual == "pkg" {
			e.PkgVersion = &r.manualPkg
		}
		if err := s.d.Inventory.EditSoftware(ctx, "it@acme.example", id, row, e); err != nil {
			t.Fatalf("a person's entry: %v", err)
		}
	}
	switch r.agent {
	case "packaged":
		upsert("agent", inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: r.agentVersion, Packaged: true, PkgVersion: r.agentPkg, PkgSource: "openssh"})
	case "wazuh":
		upsert("agent", inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: r.agentVersion, Packaged: true})
	case "upstream":
		upsert("agent", inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2p1"})
	}
	return id
}

// The measure of the class, through the real inventory: every combination of a scan banner (also the less precise "10.2" of
// 10.2p1 / 10.2_p1-r1, a CPE on that row only, vendor and product in other case), SNMP, a person's version or package release, and an
// agent's apk/deb/rpm/Wazuh/upstream row, on Alpine, Ubuntu and Rocky devices, written through inventory's entry points and read by
// findings through MatchInput. Every surface must describe OpenSSH by the strongest source's row (agent > a person > SNMP > banner):
// the exploited finding, To fix, the finding page, the plan and the assistant's device context; a distribution's package never gets
// an upstream "upgrade to 10.6", and an upstream build does.
func TestStrongestRow_EveryCombination(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	sshFeeds(t, s)
	type osCase struct{ name, os, banner, agentVersion, agentPkg, manualPkg string }
	oses := []osCase{
		{"alpine", "Alpine Linux 3.23", "10.2", "10.2p1", "10.2_p1-r1", "10.2_p1-r1"},
		{"ubuntu", "Ubuntu 24.04 LTS", "10.2p1 Ubuntu 2ubuntu3.8", "10.2p1", "1:10.2p1-2ubuntu3.8", "1:10.2p1-2ubuntu3.8"},
		{"rocky", "Rocky Linux 9.6", "10.2", "10.2p1", "10.2p1-1.el9", "10.2p1-1.el9"},
	}
	type want struct {
		name, id, source string
		pkg              bool // the strongest row is a distribution's package
		planItems        int  // 1: an item on the strongest row; its Fixed is "10.6" for an upstream build, "" for a package
	}
	var cases []want
	n := 0
	for _, o := range oses {
		for _, banner := range []bool{false, true} {
			for _, manual := range []string{"", "plain", "pkg"} {
				for _, agent := range []string{"", "packaged", "wazuh", "upstream"} {
					for _, snmp := range []bool{false, true} {
						r := sshRows{os: o.os, snmp: snmp, manual: manual, manualPkg: o.manualPkg, agent: agent, agentVersion: o.agentVersion, agentPkg: o.agentPkg}
						var names []string
						if banner {
							r.banner, names = o.banner, append(names, "banner")
						}
						if snmp {
							names = append(names, "snmp")
						}
						if manual != "" {
							names = append(names, "manual-"+manual)
						}
						if agent != "" {
							names = append(names, "agent-"+agent)
						}
						if len(names) < 2 {
							continue
						}
						n++
						w := want{name: o.name + ": " + strings.Join(names, "+"), planItems: 1}
						switch {
						case agent != "":
							w.source, w.pkg = "agent", agent != "upstream"
						case manual != "":
							w.source, w.pkg = "manual", manual == "pkg"
						case snmp:
							w.source = "snmp"
						default:
							w.source = "nmap"
						}
						if w.source == "nmap" {
							w.planItems = 0 // a banner's version is never planned
						}
						w.id = addSSHDevice(t, s, fmt.Sprintf("10.77.%d.%d", n/200, n%200+1), r)
						cases = append(cases, w)
					}
				}
			}
		}
	}
	if err := findingsJobs(*s.d)[1].Run(ctx); err != nil { // the plan pass
		t.Fatal(err)
	}
	plan := s.d.Findings.Plan()
	failed := 0
	for _, w := range cases {
		var bad []string
		a, ok, err := findingsInventory{s.d.Inventory}.MatchInput(ctx, w.id)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", w.name, ok, err)
		}
		var eff findings.Software
		for _, sw := range a.Software {
			if strings.EqualFold(sw.Product, "openssh") {
				if eff.ID != "" {
					bad = append(bad, "inventory gave two OpenSSH rows")
				}
				eff = sw
			}
		}
		if eff.Source != w.source {
			bad = append(bad, fmt.Sprintf("effective row from %s, want %s", eff.Source, w.source))
		}
		res := findings.MatchAsset(a, []findings.Vuln{sshKEVVuln}, nil, time.Now())
		for _, m := range append(res.New, res.Existing...) {
			if m.SoftwareID != eff.ID {
				bad = append(bad, "finding on "+m.SoftwareID)
			}
		}
		if len(res.New)+len(res.Existing) != 1 {
			bad = append(bad, fmt.Sprintf("%d findings, want 1", len(res.New)+len(res.Existing)))
		}
		f := findings.RowFixes(a, []findings.Vuln{sshKEVVuln})[sshKEVCVE]
		wantKind, wantFixed := "fixed", "10.6"
		if w.pkg {
			wantKind, wantFixed = "distro", ""
		}
		if f == nil || f.SoftwareID != eff.ID || f.Kind != wantKind || !w.pkg && f.Fixed != wantFixed {
			bad = append(bad, fmt.Sprintf("to-fix %+v, want %s %s on %s", f, wantKind, wantFixed, eff.ID))
		}
		if p := findings.FixedInFor(a, sshKEVVuln); p == nil || p.Kind != wantKind {
			bad = append(bad, fmt.Sprintf("finding-page %+v, want %s", p, wantKind))
		}
		var items []findings.PlanItem
		for _, it := range plan.Items {
			if it.AssetID == w.id {
				items = append(items, it)
			}
		}
		if len(items) != w.planItems {
			bad = append(bad, fmt.Sprintf("plan %d items, want %d: %+v", len(items), w.planItems, items))
		} else if len(items) == 1 && (items[0].SoftwareID != eff.ID || items[0].Fixed != wantFixed || w.pkg && items[0].Kind != "distro") {
			bad = append(bad, fmt.Sprintf("plan item %+v, want %q on %s", items[0], wantFixed, eff.ID))
		}
		dev, err := s.d.Inventory.Device(ctx, w.id)
		if err != nil {
			t.Fatal(err)
		}
		var ssh []string
		for _, sw := range dev.Software {
			if strings.EqualFold(sw.Product, "openssh") && !sw.NotInstalled {
				ssh = append(ssh, sw.ID)
			}
		}
		if len(ssh) != 1 || ssh[0] != eff.ID {
			bad = append(bad, fmt.Sprintf("assistant context rows %v, want [%s]", ssh, eff.ID))
		}
		if len(bad) > 0 {
			failed++
			t.Errorf("%s: %s", w.name, strings.Join(bad, "; "))
		}
	}
	t.Logf("%d of %d combinations describe OpenSSH by a weaker row or name an upstream release for a package", failed, len(cases))
}

// The router's three rows as a box held them: the scan's banner "OpenSSH 10.2", the package release a person gave on Needs your input
// (a correction of the banner row) and the agent's apk row. Through inventory, findings, To fix and the plan, OpenSSH is the agent's
// row everywhere and the update is Alpine's: never "Upgrade OpenSSH from 10.2 to 10.6".
func TestWiringRouterWithThreeSourcesOfOpenSSH(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	sshFeeds(t, s)
	id := addSSHDevice(t, s, "192.168.142.40", sshRows{os: "Alpine Linux 3.23", banner: "10.2", manual: "pkg", manualPkg: "10.2_p1-r1", agent: "packaged",
		agentVersion: "10.2p1", agentPkg: "10.2_p1-r1"})
	for _, j := range findingsJobs(*s.d)[:2] { // reconcile (the exploited finding), then the plan pass
		if err := j.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	a, _, err := findingsInventory{s.d.Inventory}.MatchInput(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Software) != 1 || a.Software[0].Source != "agent" {
		t.Fatalf("MatchInput gives %+v, want the agent's row alone", a.Software)
	}
	agentRow := a.Software[0].ID
	tf, err := s.d.Findings.ToFix(ctx, true, id)
	if err != nil || len(tf.Devices) != 1 {
		t.Fatal(len(tf.Devices), err)
	}
	u := tf.Devices[0]
	if len(u.Exploited) != 1 || u.Exploited[0].SoftwareID != agentRow || u.Exploited[0].Kind != "distro" ||
		u.Exploited[0].Action != "Install the distribution's security updates for OpenSSH" {
		t.Errorf("To fix, exploited: %+v", u.Exploited)
	}
	if len(u.Planned) != 1 || u.Planned[0].SoftwareID != agentRow || u.Planned[0].Action != "Check Alpine Linux's security updates for OpenSSH" {
		t.Errorf("To fix, recommended: %+v", u.Planned)
	}
	for _, x := range append(u.Exploited, u.Planned...) {
		if strings.Contains(x.Action, "10.6") {
			t.Errorf("an upstream upgrade for a package: %q", x.Action)
		}
	}
	if f := findings.FixedInFor(a, sshKEVVuln); f == nil || f.Kind != "distro" {
		t.Errorf("finding page %+v", f)
	}
	recs, err := s.d.Findings.List(ctx, id)
	if err != nil || len(recs) != 1 || recs[0].SoftwareID != agentRow {
		t.Fatalf("finding %+v %v, want one on the agent's row", recs, err)
	}
}

// A Debian release a person gave on an Ubuntu host that has no agent (Needs your input, a correction of the scan's row): the feeds
// are asked for its source package by the product's name (feedsInventory.Distros reads the row's vendor and product), and Ubuntu's own
// data decides the plan item ("Upgrade the openssh package … to 1:10.2p1-2ubuntu3.9"). On a release whose Ubuntu rows hold none of
// that package, Ubuntu's data lists no CVE for it: the device is compared and has no item.
func TestWiringPersonsUbuntuReleaseUsesUbuntusData(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	sshFeeds(t, s)
	const ubuntuCVE = "CVE-2026-60003"
	now := time.Now().UTC()
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE feeds_source SET enabled = 1, distro_packages = '["openssh"]' WHERE id = 'ubuntu-osv'`)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("ubuntu-osv: %d rows", n)
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES (?1, ?2, ?3, 'Analyzed', ?3, ?3)`,
				[]any{ubuntuCVE, store.FormatTS(now.AddDate(0, 0, -15)), store.FormatTS(now.AddDate(0, 0, -10))}},
			{`INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES (?, 'nvd', '3.1', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')`, []any{ubuntuCVE}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '24.04', 'openssh', ?, 'fixed', '1:10.2p1-2ubuntu3.9')`, []any{ubuntuCVE}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '22.04', 'zlib', 'CVE-2026-69998', 'fixed', '1.0-1')`, nil},
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
	noble := addSSHDevice(t, s, "192.168.142.51", sshRows{os: "Ubuntu 24.04 LTS", banner: "10.2p1 Ubuntu 2ubuntu3.8", manual: "pkg", manualPkg: "1:10.2p1-2ubuntu3.8"})
	jammy := addSSHDevice(t, s, "192.168.142.52", sshRows{os: "Ubuntu 22.04 LTS", banner: "10.2p1 Ubuntu 2ubuntu3.8", manual: "pkg", manualPkg: "1:10.2p1-2ubuntu3.8"})
	dist, err := feedsInventory{inv: s.d.Inventory}.Distros(ctx)
	if err != nil || !dist["ubuntu"]["openssh"] {
		t.Fatalf("Distros = %v %v, want ubuntu openssh (the person's row names its source by its product)", dist, err)
	}
	if err := findingsJobs(*s.d)[1].Run(ctx); err != nil {
		t.Fatal(err)
	}
	plan := s.d.Findings.Plan()
	byDevice := map[string][]findings.PlanItem{}
	for _, it := range plan.Items {
		byDevice[it.AssetID] = append(byDevice[it.AssetID], it)
	}
	if its := byDevice[noble]; len(its) != 1 || its[0].Kind != "distro" || its[0].Fixed != "1:10.2p1-2ubuntu3.9" || its[0].Software != "openssh" ||
		len(its[0].CVEs) != 1 || its[0].CVEs[0].CVE != ubuntuCVE {
		t.Errorf("24.04, Ubuntu's data: %+v", its)
	}
	if its := byDevice[jammy]; len(its) != 0 {
		t.Errorf("22.04, Ubuntu's data holds rows for the release and none of openssh: %+v, want no item", its)
	}
	if plan.Unchecked != 0 {
		t.Errorf("a device was left not compared: %+v", plan)
	}
}

// Another install of the software that inventory keeps in matching (a scan reads OpenSSH 8.9p1 on another port next to the agent's
// 10.2p1 package) is a reading of the one OpenSSH line: the device shows one line, says another release differs, and matching still
// reads the 8.9p1 install; a same-release banner is neither.
func TestWiringAssistantKeepsAnotherInstall(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	sshFeeds(t, s)
	other := addSSHDevice(t, s, "192.168.142.61", sshRows{os: "Ubuntu 24.04 LTS", banner: "8.9p1", agent: "packaged", agentVersion: "10.2p1", agentPkg: "1:10.2p1-2ubuntu3.8"})
	same := addSSHDevice(t, s, "192.168.142.62", sshRows{os: "Ubuntu 24.04 LTS", banner: "10.2p1 Ubuntu 2ubuntu3.8", agent: "packaged", agentVersion: "10.2p1", agentPkg: "1:10.2p1-2ubuntu3.8"})
	sshRowsOf := func(id string) (rows []inventory.Software, banner string) {
		t.Helper()
		dev, err := s.d.Inventory.Device(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, sw := range dev.Software {
			if strings.EqualFold(sw.Product, "openssh") {
				rows = append(rows, sw)
				if sw.Source == "nmap" {
					banner = sw.ID
				}
			}
		}
		return rows, banner
	}
	if rows, banner := sshRowsOf(other); len(rows) != 1 || rows[0].Source != "agent" || banner != "" {
		t.Fatalf("another release: %+v, want the agent's line alone", rows)
	}
	lines, err := s.d.Inventory.SoftwareLines(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	var ssh *inventory.SoftwareLine
	for i := range lines {
		if strings.EqualFold(lines[i].Product, "openssh") {
			ssh = &lines[i]
		}
	}
	if ssh == nil || !ssh.Differs || len(ssh.AlsoSeen) != 1 || ssh.AlsoSeen[0].Version != "8.9p1" {
		t.Fatalf("the line must say the 8.9p1 install differs: %+v", ssh)
	}
	a, _, err := findingsInventory{s.d.Inventory}.MatchInput(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	var versions []string
	for _, sw := range a.Software {
		if strings.EqualFold(sw.Product, "openssh") {
			versions = append(versions, sw.Version)
		}
	}
	if !slices.Contains(versions, "8.9p1") || !slices.Contains(versions, "10.2p1") {
		t.Fatalf("matching reads %v, want both installs", versions)
	}
	if rows, _ := sshRowsOf(same); len(rows) != 1 || rows[0].Source != "agent" {
		t.Errorf("same release: %+v, want the agent's row alone", rows)
	}
}
