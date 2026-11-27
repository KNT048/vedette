package main

import (
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// How a version a source reads or a person gives is stored and compared, as one scenario matrix through the real wiring
// (inventory's write, the findings match, the questions). Each row is one product kind × where the version comes from × what a
// person does, and states what must hold afterwards:
//
//   - vendor firmware (Junos OS) has one release string and no distribution package: a "package release" a person types for it is
//     not new evidence and must not change how its findings are judged (basis, confirmation, range origin, a person's patched mark);
//   - a version a person gives is that person's word, whichever form it was given in (adding the device, correcting a line);
//   - a question left after the person typed the version must be one their answer can close, never "type the version again";
//   - a distribution package is judged by the distribution's fix data, and a package release a person gives there is their word;
//   - a person's claim (a version, "patched", "not affected") is checked against the evidence: one the evidence contradicts is
//     raised once with that evidence, never accepted silently and never undone later without a word, and a claim the evidence
//     agrees with stays (no confirmation churn, no answer dropped while the release is the same).
//
// A failing row is a gap in the current design, not a broken test.
func TestVersionEntryMatrix(t *testing.T) {
	t.Parallel()
	const (
		person = "op@example.test"
		junos  = "15.1R7.9"
		ranged = "CVE-2099-71001" // NVD: every Junos release before 20.4
		exact  = "CVE-2099-71002" // NVD: ranges far from 15.1 and exact releases in notations the comparison cannot place
		bare   = "CVE-2099-71003" // NVD names Junos with no version
		sshCVE = "CVE-2099-71101" // NVD: OpenSSH before 10.6p2
		apkCVE = "CVE-2099-71201" // NVD: OpenSSH before 10.6; Alpine 3.23 fixed it in 10.2_p1-r1
	)
	anyJunos := "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*"
	seed := func(t *testing.T, s *stack, cve, vendor, product string, rows [][5]string, sql2 ...string) {
		t.Helper()
		ctx := t.Context()
		now := time.Now().UTC()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			if err := seedKEVRow(ctx, tx, cve, vendor, product, vendor+" "+product+" flaw", now.AddDate(0, -2, 0), false, false); err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, cve, now.AddDate(-1, 0, 0), 0); err != nil {
				return err
			}
			for _, r := range rows {
				if err := seedRange(ctx, tx, cve, r[0], r[1], r[2], r[3], r[4]); err != nil {
					return err
				}
			}
			for _, q := range sql2 {
				if _, err := tx.ExecContext(ctx, q, cve); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	junosFeeds := func(t *testing.T, s *stack) {
		seed(t, s, ranged, "Juniper", "Junos OS", [][5]string{{anyJunos, "", "", "", "20.4"}})
		seed(t, s, exact, "Juniper", "Junos OS", [][5]string{{anyJunos, "", "", "", "12.1"}, {anyJunos, "13.1", "", "", "13.2"},
			{"cpe:2.3:o:juniper:junos:15.1x49:d10:*:*:*:*:*:*", "", "", "", ""}, {"cpe:2.3:o:juniper:junos:15.1:r1:*:*:*:*:*:*", "", "", "", ""},
			{"cpe:2.3:o:juniper:junos:15.1:f2-s1:*:*:*:*:*:*", "", "", "", ""}, {"cpe:2.3:o:juniper:junos:12.1r:*:*:*:*:*:*:*", "", "", "", ""}})
		seed(t, s, bare, "Juniper", "Junos OS", [][5]string{{"cpe:2.3:o:juniper:junos:-:*:*:*:*:*:*:*", "", "", "", ""}})
	}
	// lldpSwitch is a Juniper switch known from its LLDP frame (Juniper's card, "JUNOS 15.1R7.9"): its OS line is the device's own
	// statement, which is not a channel that confirms (only SNMP and an agent do).
	lldpSwitch := func(t *testing.T, s *stack) (asset, line string) {
		t.Helper()
		ctx := t.Context()
		const mac = "3c:8a:b0:00:71:10" // an address block IEEE assigned to Juniper Networks
		var batch []observe.Observation
		for f, v := range map[observe.Field]string{observe.MAC: mac, observe.Vendor: "Juniper Networks", observe.Kind: "switch", observe.Model: "EX4200-48T", observe.OS: "JUNOS " + junos} {
			batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr("192.0.2.71")}, Field: f, Value: v,
				Source: observe.Passive, Confidence: 0.5, SeenAt: time.Now().UTC()})
		}
		if err := s.d.Inventory.Record(ctx, batch); err != nil {
			t.Fatal(err)
		}
		if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT s.asset_id, s.id FROM inv_software s JOIN inv_observation o ON o.asset_id = s.asset_id
			WHERE o.field = 'mac' AND o.value = ? AND s.product_key = 'juniper|junos os'`, mac).Scan(&asset, &line); err != nil {
			t.Fatalf("the switch's LLDP statement is no Junos line: %v", err)
		}
		return asset, line
	}
	type fRow struct{ basis, verified, origin, state string }
	finding := func(t *testing.T, s *stack, asset, cve string) fRow {
		t.Helper()
		var r fRow
		if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT basis, verified, range_origin, state FROM fnd_finding WHERE asset_id = ? AND cve = ?`, asset, cve).
			Scan(&r.basis, &r.verified, &r.origin, &r.state); err != nil {
			t.Fatalf("%s: no finding: %v", cve, err)
		}
		return r
	}
	edit := func(t *testing.T, s *stack, asset, line string, e inventory.SoftwareEdit) error {
		t.Helper()
		err := s.d.Inventory.EditSoftware(t.Context(), person, asset, line, e)
		if err == nil {
			if err := findingsJobs(*s.d)[0].Run(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	str := func(v string) *string { return &v }
	// personsWord: the finding rests on the version the person gave and is confirmed by them (contract M-3).
	personsWord := func(t *testing.T, got fRow) {
		t.Helper()
		if got.basis != string(findings.DetectStatement) || got.verified != string(findings.VerifiedPerson) {
			t.Errorf("basis %s, verified %s: want statement confirmed by the person who gave the version", got.basis, got.verified)
		}
		if got.origin == string(findings.RangeDistro) {
			t.Errorf("range origin %s: no distribution data decided this finding, NVD's range did", got.origin)
		}
	}

	for _, tc := range []struct {
		name string
		run  func(t *testing.T, s *stack)
	}{
		{"firmware / LLDP statement / no person action: suspected on the device's own release", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, _ := lldpSwitch(t, s)
			if got := finding(t, s, asset, ranged); got.basis != string(findings.DetectDeviceVersion) || got.verified != string(findings.VerifiedNo) {
				t.Errorf("%+v: want device_version, not confirmed", got)
			}
		}},
		{"firmware / LLDP statement / person sets the same version: the person's word", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)}); err != nil {
				t.Fatal(err)
			}
			personsWord(t, finding(t, s, asset, ranged))
		}},
		{"firmware / person's version / person also fills Package release with the same text: nothing about the judgement changes", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)}); err != nil {
				t.Fatal(err)
			}
			var id string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = ?`, asset, ranged).Scan(&id); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.d.Findings.Handle(t.Context(), []string{id}, findings.ResolutionPatched, "", time.Time{}, person); err != nil {
				t.Fatal(err)
			}
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{PkgVersion: str(junos)}); err != nil {
				t.Logf("package release refused (%v): acceptable, Junos has no distribution package", err)
			}
			got := finding(t, s, asset, ranged)
			personsWord(t, got)
			if got.state != string(findings.StateHandled) {
				t.Errorf("state %s: a package release on a product with no package is no newer reading of the version; the person's patched mark must stay", got.state)
			}
			if n := s.count(`SELECT count(*) FROM inv_software_event WHERE software_id = ? AND kind = 'version_changed' AND from_version = to_version`, line); n != 0 {
				t.Errorf("%d version_changed events whose from and to read the same: the history says nothing a person can read", n)
			}
		}},
		{"firmware / LLDP statement / person fills only Package release: never a distribution-package judgement", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{PkgVersion: str(junos)}); err != nil {
				t.Logf("package release refused (%v): acceptable", err)
				return
			}
			got := finding(t, s, asset, ranged)
			if got.basis == string(findings.DetectPackage) || got.origin == string(findings.RangeDistro) {
				t.Errorf("%+v: a Junos release typed in the package field was judged as a distribution package", got)
			}
		}},
		{"firmware / person adds the device with its version: the person's word", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			r, err := s.d.Inventory.AddDevice(t.Context(), person, inventory.AddInput{Vendor: "Juniper", Product: "Junos OS", Version: junos, Name: "core-switch", IP: "192.0.2.72"})
			if err != nil {
				t.Fatal(err)
			}
			personsWord(t, finding(t, s, r.ID, ranged))
		}},
		{"firmware / person's version / person clears the entry: back to the device's own statement", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)}); err != nil {
				t.Fatal(err)
			}
			if err := s.d.Inventory.RemoveSoftware(t.Context(), person, asset, line); err != nil {
				t.Fatal(err)
			}
			if got := finding(t, s, asset, ranged); got.basis != string(findings.DetectDeviceVersion) || got.verified != string(findings.VerifiedNo) {
				t.Errorf("%+v: want device_version, not confirmed", got)
			}
		}},
		{"firmware / person typed the version as the vendor writes it: no question asks to type it again", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)}); err != nil {
				t.Fatal(err)
			}
			// version_needed and not_comparable without a build attribute offer one action only: "Add the version". The person just
			// did, in the vendor's own notation, and a second identical entry changes nothing; the question must be one their answer
			// (Affected / Not affected) closes.
			if n := s.count(`SELECT count(*) FROM fnd_question WHERE software_id = ? AND answer IS NULL
				AND (kind = 'version_needed' OR kind = 'not_comparable' AND json_extract(detail, '$.attribute') IS NULL)`, line); n != 0 {
				t.Errorf("%d open questions whose only action is to retype the version the person already typed", n)
			}
		}},
		{"firmware / person answered Not affected / then re-types the version and fills Package release: the answer stays", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)}); err != nil {
				t.Fatal(err)
			}
			var q string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_question WHERE software_id = ? AND cve = ?`, line, bare).Scan(&q); err != nil {
				t.Fatalf("the CVE with no versions is no question: %v", err)
			}
			if _, err := s.d.Findings.AnswerQuestion(t.Context(), q, findings.AnswerNotAffected, "checked the vendor advisory for 15.1", person); err != nil {
				t.Fatal(err)
			}
			_ = edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)})
			_ = edit(t, s, asset, line, inventory.SoftwareEdit{PkgVersion: str(junos)})
			if n := s.count(`SELECT count(*) FROM fnd_question WHERE id = ? AND answer = 'not_affected'`, q); n != 1 {
				t.Errorf("the person's answer for the release the line still runs was dropped")
			}
		}},
		{"app with an upstream version only / person's version on a device with no distribution / Package release with the same text", func(t *testing.T, s *stack) {
			seed(t, s, sshCVE, "OpenBSD", "OpenSSH", [][5]string{{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6p2"}})
			r, err := s.d.Inventory.AddDevice(t.Context(), person, inventory.AddInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Name: "hypervisor-01", IP: "192.0.2.73"})
			if err != nil {
				t.Fatal(err)
			}
			var line string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM inv_software WHERE asset_id = ?`, r.ID).Scan(&line); err != nil {
				t.Fatal(err)
			}
			if err := edit(t, s, r.ID, line, inventory.SoftwareEdit{Version: str("9.6")}); err != nil {
				t.Fatal(err)
			}
			if err := edit(t, s, r.ID, line, inventory.SoftwareEdit{PkgVersion: str("9.6")}); err != nil {
				t.Logf("package release refused (%v): acceptable, nothing says this is a distribution package", err)
			}
			personsWord(t, finding(t, s, r.ID, sshCVE))
		}},
		{"app with an upstream version only / scan banner / person sets the same version: the person's word", func(t *testing.T, s *stack) {
			seed(t, s, sshCVE, "OpenBSD", "OpenSSH", [][5]string{{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6p2"}})
			ip := netip.MustParseAddr("192.0.2.74")
			if err := s.d.Inventory.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.Hostname, Value: "jump-01",
				Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
				t.Fatal(err)
			}
			addrs, err := s.d.Inventory.AddressMap(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			asset := addrs[ip.String()]
			if err := s.d.Inventory.UpsertSoftware(t.Context(), asset, []inventory.SoftwareItem{{Display: "OpenSSH 9.6", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6",
				KevKeys: []string{"openbsd|openssh"}, Confidence: 0.8}}, "scan"); err != nil {
				t.Fatal(err)
			}
			var line string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM inv_software WHERE asset_id = ?`, asset).Scan(&line); err != nil {
				t.Fatal(err)
			}
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str("9.6")}); err != nil {
				t.Fatal(err)
			}
			personsWord(t, finding(t, s, asset, sshCVE))
		}},
		// A person may give wrong information; re-checking it is the box's job. A person's claim (a version, "patched") that the
		// evidence contradicts is neither trusted silently nor thrown away silently: the box says so once, with the evidence.
		{"firmware / LLDP statement / person marks a finding patched with no version change: the contradiction is raised at once", func(t *testing.T, s *stack) {
			seed(t, s, ranged, "Juniper", "Junos OS", [][5]string{{anyJunos, "", "", "", "20.4"}})
			asset, line := lldpSwitch(t, s)
			var id string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = ?`, asset, ranged).Scan(&id); err != nil {
				t.Fatal(err)
			}
			_, _, err := s.d.Findings.Handle(t.Context(), []string{id}, findings.ResolutionPatched, "", time.Time{}, person)
			if err != nil {
				return // refused, naming the release the device still reports: acceptable
			}
			// accepted: the device still states 15.1R7.9, inside the range, so the person is asked about it now (an open question on
			// the line), not surprised by a silent reopen at the next reading
			if n := s.count(`SELECT count(*) FROM fnd_question WHERE software_id = ? AND answer IS NULL`, line); n == 0 {
				t.Errorf("patched accepted while the device's own release %s is inside the affected range, and nothing asks the person about it", junos)
			}
		}},
		{"firmware / LLDP statement / person types a version the device's own statement contradicts: the contradiction is raised", func(t *testing.T, s *stack) {
			seed(t, s, ranged, "Juniper", "Junos OS", [][5]string{{anyJunos, "", "", "", "20.4"}})
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str("21.4R3")}); err != nil {
				return // refused, naming the release the device states: acceptable
			}
			if n := s.count(`SELECT count(*) FROM fnd_question WHERE software_id = ? AND answer IS NULL`, line); n == 0 {
				t.Errorf("the person's 21.4R3 replaced the device's own statement %s without a word; the finding is closed: %+v", junos, finding(t, s, asset, ranged))
			}
		}},
		{"firmware / person's version / Package release set then removed, same release throughout: no confirmation churn", func(t *testing.T, s *stack) {
			seed(t, s, ranged, "Juniper", "Junos OS", [][5]string{{anyJunos, "", "", "", "20.4"}})
			asset, line := lldpSwitch(t, s)
			for _, e := range []inventory.SoftwareEdit{{Version: str(junos)}, {PkgVersion: str(junos)}, {PkgVersion: str("")}} {
				_ = edit(t, s, asset, line, e)
			}
			var id string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = ?`, asset, ranged).Scan(&id); err != nil {
				t.Fatal(err)
			}
			c, u := s.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = ? AND kind = 'confirmed'`, id), s.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = ? AND kind = 'unconfirmed'`, id)
			if c != 1 || u != 0 {
				t.Errorf("%d confirmed and %d unconfirmed events while the compared release never changed: want one confirmation", c, u)
			}
		}},
		{"firmware / person answered Not affected / clears the entry and types the same release again: the answer stays", func(t *testing.T, s *stack) {
			junosFeeds(t, s)
			asset, line := lldpSwitch(t, s)
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)}); err != nil {
				t.Fatal(err)
			}
			var q string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_question WHERE software_id = ? AND cve = ?`, line, bare).Scan(&q); err != nil {
				t.Fatalf("the CVE with no versions is no question: %v", err)
			}
			if _, err := s.d.Findings.AnswerQuestion(t.Context(), q, findings.AnswerNotAffected, "checked the vendor advisory for 15.1", person); err != nil {
				t.Fatal(err)
			}
			if err := s.d.Inventory.RemoveSoftware(t.Context(), person, asset, line); err != nil {
				t.Fatal(err)
			}
			_ = edit(t, s, asset, line, inventory.SoftwareEdit{Version: str(junos)})
			if n := s.count(`SELECT count(*) FROM fnd_question WHERE software_id = ? AND cve = ? AND answer = 'not_affected'`, line, bare); n != 1 {
				t.Errorf("the answer for release %s was dropped although the line runs that release throughout", junos)
			}
		}},
		{"distribution package / agent on Ubuntu below the distribution's fix: confirmed by the device", func(t *testing.T, s *stack) {
			seed(t, s, sshCVE, "OpenBSD", "OpenSSH", [][5]string{{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6p2"}},
				`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '24.04', 'openssh', ?, 'fixed', '1:9.6p1-3ubuntu13.5')`)
			asset, err := s.d.Inventory.EnsureBox(t.Context(), inventory.BoxInfo{Hostname: "web-01", OS: "Ubuntu 24.04"})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.d.Inventory.UpsertSoftware(t.Context(), asset, []inventory.SoftwareItem{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1",
				KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95, Packaged: true, PkgVersion: "1:9.6p1-3ubuntu13.4", PkgSource: "openssh"}}, "osquery"); err != nil {
				t.Fatal(err)
			}
			if err := findingsJobs(*s.d)[0].Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := finding(t, s, asset, sshCVE); got.basis != string(findings.DetectPackage) || got.verified != string(findings.VerifiedDevice) {
				t.Errorf("%+v: want package, confirmed by the device", got)
			}
		}},
		{"distribution package / scan banner on Alpine / person gives the package release below the fix: the person's word", func(t *testing.T, s *stack) {
			seed(t, s, apkCVE, "OpenBSD", "OpenSSH", [][5]string{{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "", "", "10.6"}},
				`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('alpine-osv', 'alpine', '3.23', 'openssh', ?, 'fixed', '10.2_p1-r1')`)
			ip := netip.MustParseAddr("192.0.2.75")
			if err := s.d.Inventory.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.Hostname, Value: "gw-01",
				Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
				t.Fatal(err)
			}
			addrs, err := s.d.Inventory.AddressMap(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			asset := addrs[ip.String()]
			if err := s.d.Inventory.UpsertSoftware(t.Context(), asset, []inventory.SoftwareItem{{Display: "OpenSSH 10.2", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2",
				KevKeys: []string{"openbsd|openssh"}, Confidence: 0.8}}, "scan"); err != nil {
				t.Fatal(err)
			}
			alpine := "Alpine Linux 3.23"
			if err := s.d.Inventory.PatchDevice(t.Context(), person, asset, inventory.Patch{OS: &alpine}); err != nil {
				t.Fatal(err)
			}
			var line string
			if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM inv_software WHERE asset_id = ?`, asset).Scan(&line); err != nil {
				t.Fatal(err)
			}
			if err := edit(t, s, asset, line, inventory.SoftwareEdit{PkgVersion: str("10.2_p1-r0")}); err != nil {
				t.Fatal(err)
			}
			if got := finding(t, s, asset, apkCVE); got.basis != string(findings.DetectPackage) || got.verified != string(findings.VerifiedPerson) {
				t.Errorf("%+v: the release the person gave is below Alpine's own fix; want package, confirmed by that person", got)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			tc.run(t, s)
		})
	}
}
