package findings

import (
	"testing"
)

// Rows as inventory's MatchInput gives them: the effective row of each software alone (inventory INV-50). cmd/vedette
// TestStrongestRow_EveryCombination measures the choice of that row through the real inventory path; these pin what findings does
// with each kind of effective row.

var (
	sshTier = tierV("CVE-2026-60001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}})
	sshKEV  = Vuln{CVE: "CVE-2099-0101", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{
		{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}}}}
)

func sshAgentRow(pkg, src string) Software {
	return Software{ID: "s-agent", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2p1", Source: "agent", Packaged: true,
		PkgVersion: pkg, PkgSource: src, KevKeys: []string{"openbsd|openssh"}}
}

// sshCorrection is a person's package release on the scan's row (Needs your input): inventory's correction of the nmap row.
func sshCorrection(pkg string) Software {
	return Software{ID: "s-manual", Display: "OpenSSH 10.2", Vendor: "openbsd", Product: "openssh", Version: "10.2", Source: "manual",
		ReportedSource: "nmap", PkgVersion: pkg, KevKeys: []string{"openbsd|openssh"}}
}

// A distribution's package is never told to move to an upstream release: on the plan it is the distribution's own fixed version
// (Ubuntu, Debian: their data, for an agent's row and for a Debian release a person gave) or, for a distribution whose data Vedette
// does not read (Alpine, Rocky, a row without its source package), one item "install <distribution>'s security updates". To fix and
// the finding page say the same. A typed upstream version keeps its upstream upgrade.
func TestPackageRow_NoUpstreamUpgradeForAPackage(t *testing.T) {
	t.Parallel()
	ubuntuFix := distroV("CVE-2026-60002", "recent", 20, 0.01, noble("openssh", "1:10.2p1-2ubuntu3.9", false))
	for _, tc := range []struct {
		name, os  string
		row       Software
		kind      string // the plan item's kind; "" for no item
		fixed     string
		distro    string
		toFixKind string
	}{
		{"Alpine, the agent's apk row", "Alpine Linux 3.23.0", sshAgentRow("10.2_p1-r1", "openssh"), "distro", "", "Alpine Linux", "distro"},
		{"Alpine, a person's apk release", "Alpine Linux 3.23.0", sshCorrection("10.2_p1-r1"), "distro", "", "Alpine Linux", "distro"},
		{"Rocky, the agent's rpm row", "Rocky Linux 9.6", sshAgentRow("10.2p1-1.el9", "openssh"), "distro", "", "", "distro"},
		{"Ubuntu, a Wazuh row without its source package", "Ubuntu 24.04 LTS", sshAgentRow("", ""), "distro", "", "Ubuntu", "distro"},
		{"Ubuntu, the agent's deb row: Ubuntu's data", "Ubuntu 24.04 LTS", sshAgentRow("1:10.2p1-2ubuntu3.8", "openssh"), "distro", "1:10.2p1-2ubuntu3.9", "", "distro"},
		{"Ubuntu, a person's Debian release: Ubuntu's data", "Ubuntu 24.04 LTS", sshCorrection("1:10.2p1-2ubuntu3.8"), "distro", "1:10.2p1-2ubuntu3.9", "", "distro"},
		{"Alpine, a typed upstream version", "Alpine Linux 3.23.0", sshCorrection(""), "fixed", "10.6", "", "fixed"},
	} {
		a := Asset{ID: "dev", Name: "dev", OS: tc.os, Software: []Software{tc.row}}
		x := newTierIndex([]TierVuln{sshTier}).withDistro([]TierVuln{ubuntuFix}, map[string]bool{"ubuntu/24.04": true})
		items, _ := matchTiers(a, x, nil, t0)
		switch {
		case tc.kind == "" && len(items) != 0, tc.kind != "" && len(items) != 1:
			t.Errorf("%s: plan %+v", tc.name, items)
		case len(items) == 1 && (items[0].Kind != tc.kind || items[0].Fixed != tc.fixed || items[0].Distro != tc.distro || items[0].SoftwareID != tc.row.ID):
			t.Errorf("%s: plan item %+v, want %s %q %q", tc.name, items[0], tc.kind, tc.fixed, tc.distro)
		}
		if len(items) == 1 {
			u := planAction(items[0])
			if s := updateSentence(u); tc.kind == "distro" && tc.fixed == "" && s != "Install "+map[bool]string{true: tc.distro + "'s", false: "the distribution's"}[tc.distro != ""]+" security updates for OpenSSH"+map[bool]string{true: " 10.2", false: ""}[tc.row.Source == "manual"] {
				t.Errorf("%s: sentence %q", tc.name, s)
			}
		}
		fixes := RowFixes(a, []Vuln{sshKEV})
		if f := fixes[sshKEV.CVE]; f == nil || f.Kind != tc.toFixKind || f.SoftwareID != tc.row.ID {
			t.Errorf("%s: To fix %+v, want %s on %s", tc.name, f, tc.toFixKind, tc.row.ID)
		}
		if f := FixedInFor(a, sshKEV); f == nil || f.Kind != tc.toFixKind {
			t.Errorf("%s: finding page %+v, want %s", tc.name, f, tc.toFixKind)
		}
	}
}

// A package release is the distribution's only when the device runs a Linux distribution or the text is a distribution's release
// format: a FortiGate's or a Windows build a person corrected keeps its upstream wording.
func TestPackageRow_OnlyADistributionsReleaseIsAPackage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		os, pkg string
		want    bool
	}{
		{"Alpine Linux 3.23.0", "10.2_p1-r1", true},
		{"", "10.2_p1-r1", true},              // apk's format, whatever the OS
		{"", "1:10.2p1-2ubuntu3.8", true},     // Debian's
		{"", "8.7p1-38.el9", true},            // RPM's
		{"Rocky Linux 9.6", "8.7p1-38", true}, // any release on a Linux distribution
		{"FortiOS 7.2.5", "v7.2.13", false},   // a FortiGate's firmware a person gave
		{"Microsoft Windows Server 2022", "10.0.20348.2700", false},
		{"", "7.2.13", false},
	} {
		in := newSWInfo(Software{Source: "manual", Product: "X", Version: "1", PkgVersion: tc.pkg}, tc.os)
		if got := in.pkgBuilt(); got != tc.want {
			t.Errorf("%q on %q: pkgBuilt %v, want %v", tc.pkg, tc.os, got, tc.want)
		}
	}
	// a FortiGate a person corrected keeps its upstream plan item and To fix wording
	forti := Software{ID: "s-fgt", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.5", Source: "manual", PkgVersion: "v7.2.5",
		KevKeys: []string{"fortinet|fortios"}}
	a := Asset{ID: "fgt", Name: "fgt", OS: "FortiOS 7.2.5", Software: []Software{forti}}
	tier := tierV("CVE-2026-50001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.2.0", EndExcl: "7.2.9"}})
	if items, _ := planOf(a, []TierVuln{tier}, nil); len(items) != 1 || items[0].Kind != "fixed" || items[0].Fixed != "7.2.9" {
		t.Errorf("FortiGate plan %+v", items)
	}
	kev := Vuln{CVE: "CVE-2099-0202", Vendor: "Fortinet", Product: "FortiOS", Affected: []Affected{{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.2.0", EndExcl: "7.2.9"}}}}
	if f := RowFixes(a, []Vuln{kev})[kev.CVE]; f == nil || f.Kind != "fixed" || f.Fixed != "7.2.9" {
		t.Errorf("FortiGate To fix %+v", f)
	}
}

// A person's release that is not the distribution's own build of it (a Debian build on Ubuntu, a PPA build) is not one the
// distribution's data speaks for: it falls back to NVD with the distribution's security-update item, never vanishing while the device
// counts as compared. Ubuntu's own build of the same release keeps Ubuntu's fixed version.
func TestPackageRow_PersonsForeignBuildFallsBackToNVD(t *testing.T) {
	t.Parallel()
	x := newTierIndex([]TierVuln{sshTier}).withDistro([]TierVuln{distroV("CVE-2026-60002", "recent", 20, 0.01, noble("openssh", "1:10.2p1-2ubuntu3.9", false))},
		map[string]bool{"ubuntu/24.04": true})
	for _, tc := range []struct{ rel, fixed string }{
		{"1:10.2p1-1+deb13u1", ""},                     // Debian's build on an Ubuntu host
		{"1:10.2p1-2ubuntu3.8~ppa1", ""},               // a PPA build
		{"1:10.2p1-2ubuntu3.8", "1:10.2p1-2ubuntu3.9"}, // Ubuntu's own build
	} {
		a := Asset{ID: "u", Name: "u", OS: "Ubuntu 24.04 LTS", Software: []Software{sshCorrection(tc.rel)}}
		items, compared := matchTiers(a, x, nil, t0)
		if !compared || len(items) != 1 || items[0].Kind != "distro" || items[0].Fixed != tc.fixed {
			t.Errorf("%s: compared %v, items %+v; want one distro item fixed %q", tc.rel, compared, items, tc.fixed)
			continue
		}
		if tc.fixed == "" && (items[0].Distro != "Ubuntu" || len(items[0].CVEs) != 1 || items[0].CVEs[0].CVE != sshTier.CVE) {
			t.Errorf("%s: %+v, want NVD's CVE with Ubuntu's security updates", tc.rel, items[0])
		}
	}
}

// A person's Debian release names no source package; the product's own name is only a guess ("postgresql" is postgresql-16 in Ubuntu,
// "bind" is bind9). The distribution's data decides only when the feeds hold rows under the guessed name; otherwise the row is compared
// with NVD (an item "install Ubuntu's security updates"), never dropped while the device counts as compared. The guessed product is in
// the tier scope so NVD's data for it is read.
func TestPackageRow_GuessedSourceWithoutDataFallsBackToNVD(t *testing.T) {
	t.Parallel()
	pg := Software{ID: "s-pg", Display: "PostgreSQL 16.2", Vendor: "PostgreSQL", Product: "PostgreSQL", Version: "16.2", Source: "manual", PkgVersion: "16.2-1ubuntu4"}
	a := Asset{ID: "db", Name: "db", OS: "Ubuntu 24.04 LTS", Software: []Software{pg}}
	tier := tierV("CVE-2026-61001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "16.0", EndExcl: "16.4"}})
	if !NewTierScope([]Asset{a}).Keep("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*") {
		t.Fatal("the guessed product is not in the tier scope")
	}
	// Ubuntu's data holds the CVE under postgresql-16, not under the guessed "postgresql"
	ubuntu := distroV("CVE-2026-61001", "recent", 30, 0.01, noble("postgresql-16", "16.4-0ubuntu0.24.04.1", false))
	x := newTierIndex([]TierVuln{tier}).withDistro([]TierVuln{ubuntu}, map[string]bool{"ubuntu/24.04": true})
	items, compared := matchTiers(a, x, nil, t0)
	if !compared || len(items) != 1 || items[0].Kind != "distro" || items[0].Fixed != "" || items[0].Distro != "Ubuntu" || items[0].SoftwareID != "s-pg" {
		t.Fatalf("compared %v, items %+v; want one NVD item with Ubuntu's security updates", compared, items)
	}
	// a row whose guessed name holds Ubuntu rows: Ubuntu's own fixed version
	a.Software = []Software{sshCorrection("1:10.2p1-2ubuntu3.8")}
	x = newTierIndex([]TierVuln{sshTier}).withDistro([]TierVuln{distroV("CVE-2026-60002", "recent", 20, 0.01, noble("openssh", "1:10.2p1-2ubuntu3.9", false))},
		map[string]bool{"ubuntu/24.04": true})
	if items, _ := matchTiers(a, x, nil, t0); len(items) != 1 || items[0].Fixed != "1:10.2p1-2ubuntu3.9" || items[0].Software != "openssh" {
		t.Fatalf("openssh with Ubuntu rows: %+v", items)
	}
}
