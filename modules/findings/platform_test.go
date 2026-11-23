package findings

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestPlatformLimits_DataIsValid(t *testing.T) {
	t.Parallel()
	if platformLimitErr != nil {
		t.Fatal(platformLimitErr)
	}
	if l, ok := platformLimits["CVE-2026-123158"]; !ok || len(l.Only) != 1 || l.Only[0] != "alpine" {
		t.Fatalf("CVE-2026-123158 = %+v, want only alpine", l)
	}
	// the releases come from the feed's rows, unchanged (every branch OSV.dev lists for openssh, which matches Alpine's secdb
	// https://secdb.alpinelinux.org/<branch>/main.json read 2026-11-17 for v3.16–v3.24; OSV.dev has no edge, secdb's edge 10.6_p2-r0 is not here)
	want := map[string]string{"3.24": "10.3_p1-r2", "3.23": "10.2_p1-r1", "3.22": "10.0_p1-r11", "3.21": "9.9_p2-r1",
		"3.20": "9.7_p1-r6", "3.19": "9.6_p1-r3", "3.18": "9.3_p2-r4", "3.17": "9.1_p1-r7", "3.16": "9.0_p1-r6"}
	if f := distroFixes("CVE-2026-123158", alpineSSH()); f == nil || !maps.Equal(f.Releases, want) || !strings.HasPrefix(f.fixList(), "10.3_p1-r2 (3.24), 10.2_p1-r1 (3.23), ") ||
		!strings.HasSuffix(f.fixList(), "9.1_p1-r7 (3.17), 9.0_p1-r6 (3.16)") || f.sourceFor("3.20") != "Alpine Linux's security database, https://secdb.alpinelinux.org/v3.20/main.json (CC BY-SA 4.0), through OSV.dev" || f.Package != "openssh-server" {
		t.Fatalf("fixed list %+v", f)
	}
	// only the catalog's distribution and source package, fixed rows with an apk release; none at all is no list, never a guess
	other := []DistroFix{{Distro: "alpine", Release: "3.23", Package: "openssh-client", Status: "fixed", Fixed: "1.0-r0"}, {Distro: "debian", Release: "12", Package: "openssh", Status: "fixed", Fixed: "1:9.2p1-2+deb12u3"},
		{Distro: "alpine", Release: "3.22", Package: "openssh", Status: "not_affected"}, {Distro: "alpine", Release: "3.21", Package: "openssh", Status: "fixed", Fixed: "9.9p2-r1"}}
	if f := distroFixes("CVE-2026-123158", other); f != nil {
		t.Fatalf("rows of no use gave %+v", f)
	}
	if distroFixes("CVE-2026-123158", nil) != nil || distroFixes("CVE-2025-2783", alpineSSH()) != nil {
		t.Fatal("a list without rows, or for a CVE without a fixed list")
	}
	for _, bad := range []string{
		`{"CVE-2099-0001": {"only": ["alpine"], "affects": "x", "check": "y", "ask": "Is it Alpine?", "source": "https://e"}}`,                                        // no {device}
		`{"CVE-2099-0001": {"only": ["alpine"], "affects": "x", "check": "y", "ask": "Does {device} run it?", "source": "https://e", "fixed": {"distro": "ubuntu"}}}`, // not apk
		`{"CVE-2099-0001": {"only": ["alpine"], "affects": "x", "check": "y", "ask": "Does {device} run it?", "source": "https://e", "fixed": {"distro": "alpine", "package": "p", "command": "c", "source": "https://e/{branch}", "releases": {"3.23": "10.2p1"}}}}`,
		`{"CVE-2099-0001": {"only": ["alpine"], "affects": "x", "check": "y", "ask": "Does {device} run it?", "source": "https://e", "fixed": {"distro": "alpine", "package": "p", "command": "c", "source": "https://e", "releases": {"3.23": "10.2_p1-r1"}}}}`,
		`{"CVE-2099-0001": {"only": ["alpine"], "affects": "x", "check": "y", "ask": "Does {device} run it?", "source": "https://e", "fixed": {"distro": "alpine", "package": "p", "source_package": "p", "command": "c", "branch_command": "b", "source": "https://e/{branch}", "releases": {"3.23": "10.2_p1-r1"}}}}`, // a hand copy
		`{"CVE-2099-0001": {"only": ["alpine"], "affects": "x", "check": "y", "ask": "Does {device} run it?", "source": "https://e", "fixed": {"distro": "alpine", "package": "p", "command": "c", "branch_command": "b", "source": "https://e/{branch}"}}}`,                                                            // no source_package
	} {
		if _, err := loadPlatformLimits([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// Alpine's apk order for the releases the fixed lists hold.
func TestAPKVersionCompare(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"10.2_p1-r1", "10.2_p1-r1", 0}, {"10.2_p1-r0", "10.2_p1-r1", -1}, {"10.2_p1-r10", "10.2_p1-r9", 1},
		{"10.3_p1-r0", "10.2_p1-r1", 1}, {"10.0_p1-r11", "10.0_p1-r2", 1}, {"9.9_p2-r1", "9.9_p1-r5", 1},
		{"10.2-r0", "10.2_p1-r0", -1}, {"10.2_rc1-r0", "10.2-r0", -1}, {"1.0-r0", "1.0.1-r0", -1}, {"1.0a-r0", "1.0-r0", 1},
	} {
		a, okA := parseAPK(tc.a)
		b, okB := parseAPK(tc.b)
		if !okA || !okB || compareAPK(a, b) != tc.want {
			t.Errorf("%s vs %s: %v %v %d, want %d", tc.a, tc.b, okA, okB, compareAPK(a, b), tc.want)
		}
	}
	for _, bad := range []string{"10.2p1", "1:9.6p1-3ubuntu13.14", "8.7p1-38.el9_4.4", "10.2_p1", ""} {
		if _, ok := parseAPK(bad); ok {
			t.Errorf("%q read as an apk release", bad)
		}
	}
}

// sshhole is CVE-2026-123158 as the feeds give it: KEV OpenBSD|OpenSSH, NVD's range before 10.6 (kev-nvd-golden.json).
func sshhole() Vuln {
	return Vuln{CVE: "CVE-2026-123158", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{
		{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}},
	}, Distro: alpineSSH()}
}

// alpineSSH are the rows feeds' alpine-osv keeps for CVE-2026-123158: OSV.dev's record ALPINE-CVE-2026-123158 as served on
// 2026-11-17 (modules/feeds/testdata/alpine), one per branch OSV lists, source package openssh.
func alpineSSH() []DistroFix {
	var out []DistroFix
	for _, r := range [][2]string{{"3.16", "9.0_p1-r6"}, {"3.17", "9.1_p1-r7"}, {"3.18", "9.3_p2-r4"}, {"3.19", "9.6_p1-r3"}, {"3.20", "9.7_p1-r6"},
		{"3.21", "9.9_p2-r1"}, {"3.22", "10.0_p1-r11"}, {"3.23", "10.2_p1-r1"}, {"3.24", "10.3_p1-r2"}} {
		out = append(out, DistroFix{Distro: DistroAlpine, Release: r[0], Package: "openssh", Status: "fixed", Fixed: r[1]})
	}
	return out
}

func sshRow(version, banner, source string) Software {
	return Software{ID: "ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, Banner: banner, Source: source,
		CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", KevKeys: []string{"openbsd|openssh"}}
}

// The GitLab server's "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20" on the public IP is Ubuntu's glibc+PAM build: not listed,
// and the reason is there for the exposure page. Nothing about "run a scan".
func TestPlatform_UbuntuBannerRulesOutAlpineOnlyCVE(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "ext:203.0.113.4", Name: "203.0.113.4", Software: []Software{sshRow("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "")}}
	res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
	if len(res.New) != 0 || len(res.OtherPlatform) != 1 {
		t.Fatalf("new %+v, other platform %+v; want none listed, one ruled out", res.New, res.OtherPlatform)
	}
	why := res.OtherPlatform[0].Evidence.Summary
	if !strings.Contains(why, "affects only OpenSSH built with musl libc and without PAM") || !strings.Contains(why, "9.6p1 Ubuntu 3ubuntu13.20") || strings.Contains(why, "scan") {
		t.Errorf("reason = %q", why)
	}
}

// A device whose OS (osquery) is Ubuntu: its open finding of the Alpine-only CVE closes by itself (auto-resolve) with the reason.
func TestPlatform_DeviceOSClosesTheFinding(t *testing.T) {
	t.Parallel()
	sw := sshRow("9.6p1", "", "agent")
	sw.Packaged, sw.PkgVersion, sw.PkgSource = true, "1:9.6p1-3ubuntu13.20", "openssh"
	a := Asset{ID: "a", Name: "boxanna", OS: "Ubuntu 24.04.3 LTS", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sw}}
	res := MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
	if len(res.Existing) != 0 || len(res.NotAffected) != 1 {
		t.Fatalf("existing %+v, not affected %+v", res.Existing, res.NotAffected)
	}
	if n := res.NotAffected[0].Evidence.Summary; !strings.HasPrefix(n, "Not affected: CVE-2026-123158 affects only") || !strings.Contains(n, "this device runs Ubuntu 24.04.3 LTS") {
		t.Errorf("note = %q", n)
	}
}

// gw-alpine: a device whose platform is not known gives no finding: the CVE is "Could not be checked" with the question (which
// system), and an open finding closes (Asked). A Ubuntu host whose port a scan saw is no proof either way (it may forward the port to
// an Alpine container). A device that states Alpine itself (its agent, its SNMP answer) is asked for the package release instead.
func TestPlatform_UnknownPlatformAsks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a    Asset
		want UncheckedReason
	}{
		{Asset{ID: "fw", Name: "192.168.142.1", Software: []Software{sshRow("10.2", "protocol 2.0", "nmap")}}, UncheckedPlatformUnknown},
		{Asset{ID: "host", Name: "docker1", OS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("10.2", "", "nmap")}}, UncheckedPlatformUnknown},
		{Asset{ID: "bn340", Name: "gw-alpine", OS: "Alpine Linux", SNMPOS: "Alpine Linux", Software: []Software{sshRow("10.2", "protocol 2.0", "nmap")}}, UncheckedPackageUnknown},
		{Asset{ID: "alp", Name: "alp1", OS: "Alpine Linux v3.23", AgentOS: "Alpine Linux v3.23", Software: []Software{sshRow("10.2", "", "agent")}}, UncheckedPackageUnknown},
	} {
		res := MatchAsset(tc.a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
		if len(res.New)+len(res.Existing)+len(res.NotAffected)+len(res.OtherPlatform) != 0 || len(res.Asked) != 1 || len(res.Unchecked) != 1 || res.Unchecked[0].Reason != tc.want {
			t.Fatalf("%s: %+v; want asked, unchecked %s", tc.a.Name, res, tc.want)
		}
		if n := res.Asked[0].Evidence.Summary; !strings.HasPrefix(n, AskedNote) || !strings.Contains(n, tc.a.Name) || !strings.Contains(n, "Could not be checked") {
			t.Errorf("%s: note %q", tc.a.Name, n)
		}
	}
}

// Once the platform is Alpine, the package release decides against Alpine's fixed list for the device's branch: the OS a
// person set (one click on the question) or the one the device states (SNMP's "Alpine Linux", no branch: the branch whose fix has the
// same upstream version), with the release a person gave on the row (inventory's correction) or an agent's apk release. Review r1 of
// #961: every branch secdb fixes (H1: patched and unpatched 3.20/3.19, a branch with no fix, no loop after "Another system"), a
// person's OS never rules a scanned row out (M1: the Docker host), and what `apk info -e -v` prints is read (M2).
func TestPlatform_PackageReleaseDecides(t *testing.T) {
	t.Parallel()
	mine := func(pkg string) Software { // inventory's correction of the scanned row (INV-41): manual, the scan's version, the release
		s := sshRow("10.2", "", "manual")
		s.ID, s.PkgVersion, s.ReportedSource = "s-mine", pkg, "nmap"
		return s
	}
	mineAt := func(ver, pkg string) Software {
		s := mine(pkg)
		s.Version = ver
		return s
	}
	agentAPK := func(v string) Software { return sshRow(v, "", "agent") }
	scanned := func(v string) Software { return sshRow(v, "protocol 2.0", "nmap") }
	type want int
	const (
		fixed want = iota
		affected
		askedPlatform
		askedPackage
		other
	)
	for _, tc := range []struct {
		name  string
		a     Asset
		want  want
		words string
	}{
		{"gw-alpine: SNMP says Alpine Linux, release 10.2_p1-r1 given", Asset{SNMPOS: "Alpine Linux", Software: []Software{mine("10.2_p1-r1")}}, fixed, "Alpine Linux 3.23 fixed it in openssh-server 10.2_p1-r1 (the branch whose fixed release has the same upstream version"},
		{"gw-alpine: the person says Alpine Linux 3.23", Asset{ManualOS: "Alpine Linux 3.23", SNMPOS: "Alpine Linux 3.23", Software: []Software{mine("10.2_p1-r1")}}, fixed, "gw-alpine has openssh-server 10.2_p1-r1 (the package release a person gave). Source: Alpine Linux's security database, https://secdb.alpinelinux.org/v3.23/main.json"},
		{"gw-alpine: the line apk info -e -v prints", Asset{SNMPOS: "Alpine Linux", Software: []Software{mine("openssh-server-10.2_p1-r1")}}, fixed, "gw-alpine has openssh-server 10.2_p1-r1"},
		{"a release Vedette cannot read is said, not ignored", Asset{SNMPOS: "Alpine Linux", Software: []Software{mine("10.2p1")}}, askedPackage, "package_unknown 10.2p1"},
		{"one revision before the fix", Asset{ManualOS: "Alpine Linux 3.23", Software: []Software{mine("10.2_p1-r0")}}, affected, "Update openssh-server to 10.2_p1-r1 or later"},
		{"3.24 with 3.24's own unpatched 10.3_p1-r1", Asset{ManualOS: "Alpine Linux v3.24", Software: []Software{mineAt("10.3p1", "10.3_p1-r1")}}, affected, "Alpine Linux 3.24 fixed it in openssh-server 10.3_p1-r2"},
		{"3.24 with 3.23's fixed 10.2_p1-r1: 3.23's fix applies", Asset{ManualOS: "Alpine Linux v3.24", Software: []Software{mine("10.2_p1-r1")}}, fixed, "Alpine Linux 3.23 fixed it in openssh-server 10.2_p1-r1 (release 10.2_p1 is Alpine Linux 3.23's version, not Alpine Linux 3.24's"},
		{"3.21 with an older upstream than its fix and no branch of it", Asset{ManualOS: "Alpine Linux v3.21", Software: []Software{mineAt("9.9p1", "9.9_p1-r5")}}, affected, "Update openssh-server to 9.9_p2-r1"},
		{"no branch and no fix with that upstream: NVD's range decides, with why", Asset{SNMPOS: "Alpine Linux", Software: []Software{mine("10.1_p1-r0")}}, affected, "No Alpine Linux branch's fixed release has the upstream version 10.1_p1"},
		{"patched 3.20, scanned row: the package question", Asset{ManualOS: "Alpine Linux 3.20", Software: []Software{scanned("9.7p1")}}, askedPackage, "package_unknown"},
		{"patched 3.20, release given", Asset{ManualOS: "Alpine Linux 3.20", Software: []Software{mineAt("9.7p1", "9.7_p1-r6")}}, fixed, "Alpine Linux 3.20 fixed it in openssh-server 9.7_p1-r6"},
		{"unpatched 3.20, release given", Asset{ManualOS: "Alpine Linux 3.20", Software: []Software{mineAt("9.7p1", "9.7_p1-r5")}}, affected, "Update openssh-server to 9.7_p1-r6"},
		// review r2 H-1 of #961: a release is proved fixed only against a fix of its own upstream version
		{"3.20 running 3.23's unpatched 10.2_p1-r0", Asset{ManualOS: "Alpine Linux 3.20", Software: []Software{mineAt("10.2p1", "10.2_p1-r0")}}, affected, "Alpine Linux 3.23 fixed it in openssh-server 10.2_p1-r1 (release 10.2_p1 is Alpine Linux 3.23's version, not Alpine Linux 3.20's"},
		{"3.20 (SNMP) running 3.23's unpatched 10.2_p1-r0", Asset{SNMPOS: "Alpine Linux v3.20.3", Software: []Software{mineAt("10.2p1", "10.2_p1-r0")}}, affected, "Update openssh-server to 10.2_p1-r1"},
		{"3.20 running 3.23's fixed 10.2_p1-r1", Asset{ManualOS: "Alpine Linux 3.20", Software: []Software{mineAt("10.2p1", "10.2_p1-r1")}}, fixed, "Alpine Linux 3.23 fixed it in openssh-server 10.2_p1-r1 (release 10.2_p1 is Alpine Linux 3.23's version"},
		{"an upstream no branch's fix has: NVD's range decides, with why", Asset{ManualOS: "Alpine Linux 3.20", Software: []Software{mineAt("9.8p1", "9.8_p1-r0")}}, affected, "No Alpine Linux branch's fixed release has the upstream version 9.8_p1 of the release 9.8_p1-r0"},
		{"an unreadable release never turns a finding into a question", Asset{ManualOS: "Alpine Linux 3.15", Software: []Software{mineAt("8.8p1", "foo")}}, affected, `older than every release Alpine Linux fixed it in (10.3_p1-r2 (3.24), 10.2_p1-r1 (3.23), 10.0_p1-r11 (3.22), 9.9_p2-r1 (3.21), 9.7_p1-r6 (3.20), 9.6_p1-r3 (3.19), 9.3_p2-r4 (3.18), 9.1_p1-r7 (3.17), 9.0_p1-r6 (3.16)). Vedette could not read the package release you entered ("foo")`},
		{"unpatched 3.19, release given, SNMP names no branch", Asset{SNMPOS: "Alpine Linux", Software: []Software{mineAt("9.6p1", "9.6_p1-r2")}}, affected, "Alpine Linux 3.19 fixed it in openssh-server 9.6_p1-r3"},
		{"older than every fix, release given (3.15 has none)", Asset{ManualOS: "Alpine Linux 3.15", Software: []Software{mineAt("8.8p1", "8.8_p1-r9")}}, affected, "is older than every release Alpine Linux fixed it in"},
		{"older than every fix, no release", Asset{AgentOS: "Alpine Linux v3.15", Software: []Software{agentAPK("8.8")}}, affected, "older than every release Alpine Linux fixed it in"},
		{"a branch with no fix, no release: NVD's range decides", Asset{ManualOS: "Alpine Linux 3.15", Software: []Software{scanned("9.0p1")}}, affected, "Alpine Linux 3.15 has no fixed release of openssh-server"},
		{"agent's apk release on 3.21, fixed", Asset{AgentOS: "Alpine Linux v3.21", Software: []Software{agentAPK("9.9_p2-r1")}}, fixed, "the release the device's agent reports"},
		{"agent's apk release on 3.21, before the fix", Asset{AgentOS: "Alpine Linux v3.21", Software: []Software{agentAPK("9.9_p1-r5")}}, affected, "Update openssh-server to 9.9_p2-r1"},
		{"Docker host: the person's Ubuntu never rules out a forwarded port", Asset{ManualOS: "Ubuntu 24.04", Software: []Software{scanned("10.2")}}, askedPlatform, "platform_unknown"},
		{"Another system: the person's OS and the row's release rule it out", Asset{ManualOS: "Ubuntu 24.04", Software: []Software{mine("1:9.6p1-3ubuntu13.14")}}, other, "this device runs Ubuntu 24.04"},
		{"a Debian release a person gave on a device that states Ubuntu", Asset{SNMPOS: "Ubuntu 24.04", Software: []Software{mine("1:9.6p1-3ubuntu13.14")}}, other, ""},
	} {
		tc.a.ID, tc.a.Name = "a", "gw-alpine"
		res := MatchAsset(tc.a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
		var got want = -1
		var text string
		switch {
		case len(res.NotAffected) == 1 && len(res.OtherPlatform) == 1 && res.NotAffected[0].pkgFixed:
			got, text = fixed, res.NotAffected[0].Evidence.Summary
		case len(res.Existing) == 1 && res.Existing[0].Basis == BasisVersion:
			got, text = affected, res.Existing[0].Evidence.Summary
		case len(res.Asked) == 1 && len(res.Unchecked) == 1:
			got, text = askedPlatform, string(res.Unchecked[0].Reason)+" "+res.Unchecked[0].Answer
			if res.Unchecked[0].Reason == UncheckedPackageUnknown {
				got = askedPackage
			}
		case len(res.NotAffected) == 1 && len(res.OtherPlatform) == 1:
			got, text = other, res.NotAffected[0].Evidence.Summary
		}
		if got != tc.want || !strings.Contains(text, tc.words) {
			t.Errorf("%s: got %d (%q), want %d with %q; %+v", tc.name, got, text, tc.want, tc.words, res)
		}
	}
}

// Review r1 H1 and r2 M-2 of #961: an answer always moves the question on. Every one-click answer of the platform question (an Alpine
// branch), applied as the device's OS, gives the package question, and the release for that branch then decides. "Another system"
// (the device's OS and the row's package release, both typed) decides at once, also for an OS Vedette does not know.
func TestPlatform_EveryAnswerSettles(t *testing.T) {
	t.Parallel()
	f := distroFixes("CVE-2026-123158", alpineSSH())
	q := platformQuestion("CVE-2026-123158", "gw-alpine", UncheckedPlatformUnknown, "", alpineSSH())
	if q.Command == nil || *q.Command != "cat /etc/alpine-release" {
		t.Fatalf("platform question command %v", q.Command)
	}
	answered := func(os, ver, pkg string) MatchResult {
		row := sshRow(ver, "", "manual") // inventory's correction of the scanned row
		row.PkgVersion, row.ReportedSource = pkg, "nmap"
		a := Asset{ID: "a", Name: "gw-alpine", ManualOS: os, Software: []Software{row}}
		return MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
	}
	for _, ans := range q.Answers {
		if ans.OS == nil {
			if !slices.Equal(ans.Ask, []string{"os", "pkg_version"}) {
				t.Errorf("answer %+v asks nothing that settles it", ans)
			}
			continue
		}
		a := Asset{ID: "a", Name: "gw-alpine", ManualOS: *ans.OS, Software: []Software{sshRow("9.0p1", "", "nmap")}}
		res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
		if len(res.Unchecked) != 1 || res.Unchecked[0].Reason != UncheckedPackageUnknown {
			t.Errorf("%s: %+v, want the package question", *ans.OS, res)
			continue
		}
		fix := f.Releases[alpineBranch(*ans.OS)]
		if res := answered(*ans.OS, "9.0p1", fix); len(res.NotAffected) != 1 {
			t.Errorf("%s with %s: %+v, want not affected", *ans.OS, fix, res)
		}
	}
	for _, tc := range []struct {
		os, ver, pkg, words string
		out                 bool // ruled out (else: a finding the release decides)
	}{
		{"Ubuntu 24.04", "9.6p1", "1:9.6p1-3ubuntu13.14", "this device runs Ubuntu 24.04", true},
		{"Proxmox VE 8.2", "9.2p1", "1:9.2p1-2+deb12u3", "a person gave the package release 1:9.2p1-2+deb12u3 on Proxmox VE 8.2, which is not an Alpine apk release", true},
		{"Synology DSM 7.2", "8.2p1", "8.2p1", "a person gave the package release 8.2p1 on Synology DSM 7.2, which is not an Alpine apk release", true},
		{"postmarketOS v24.06", "9.7p1", "9.7_p1-r4", "Update openssh-server to 9.7_p1-r6", false}, // Alpine-based: its apk release decides
	} {
		res := answered(tc.os, tc.ver, tc.pkg)
		switch {
		case tc.out && (len(res.NotAffected) != 1 || len(res.OtherPlatform) != 1 || !strings.Contains(res.NotAffected[0].Evidence.Summary, tc.words)):
			t.Errorf("Another system %s + %s: %+v, want ruled out with %q", tc.os, tc.pkg, res, tc.words)
		case !tc.out && (len(res.Existing) != 1 || !strings.Contains(res.Existing[0].Evidence.Summary, tc.words)):
			t.Errorf("Another system %s + %s: %+v, want a finding with %q", tc.os, tc.pkg, res, tc.words)
		}
	}
}

// A CVE not on the list is untouched by a platform word.
func TestPlatform_OtherCVEsUnchanged(t *testing.T) {
	t.Parallel()
	v := sshhole()
	v.CVE = "CVE-2024-6387"
	res := MatchAsset(Asset{ID: "x", Name: "x", Software: []Software{sshRow("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "")}}, []Vuln{v}, nil, t0)
	if len(res.NameOnly) != 1 || len(res.OtherPlatform) != 0 || strings.Contains(res.NameOnly[0].said, "affects only") { // No finding
		t.Fatalf("result %+v", res)
	}
}

// Review r1 #1, #2, #11 (b, c): the device's OS is evidence only for its own inventory's rows: an agent row takes the OS, an SNMP
// row only the OS the device states itself; a row a person typed, a scan row and a row of unknown source never take it.
func TestPlatform_OSIsEvidenceOnlyForTheDevicesOwnRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source, os, stated, agent, snmp string
		out                                   bool
	}{
		{"agent row on a Ubuntu device", "agent", "Ubuntu 24.04.3 LTS", "", "Ubuntu 24.04.3 LTS", "", true},
		{"agent row, the folded OS is a guess the agent never reported (review r2 of #790)", "agent", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"agent row, a person's OS won but the agent reports Ubuntu", "agent", "Alpine Linux v3.23", "", "Ubuntu 24.04.3 LTS", "", true},
		{"scan row on a Junos switch that states its OS over SNMP", "nmap", "Juniper Junos", "JUNOS 15.1R7.9", "", "JUNOS 15.1R7.9", true},
		{"scan row, Junos only in an LLDP frame (forgeable with the device's MAC, review r1 #3)", "nmap", "", "JUNOS 15.1R7.9", "", "", false},
		{"scan row, Junos OS Evolved runs containers (review r1 #4)", "nmap", "", "JUNOS 21.4R1.12-EVO", "", "JUNOS 21.4R1.12-EVO", false},
		{"scan row, SNMP says Junos but an agent reports another OS", "nmap", "", "JUNOS 15.1R7.9", "Alpine Linux v3.23", "JUNOS 15.1R7.9", false},
		{"scan row on a device that states Ubuntu over SNMP (may forward to a container)", "nmap", "", "Ubuntu 22.04", "", "", false},
		{"manual row on a Ubuntu device (an Alpine container's sshd typed by hand)", "manual", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"scan row on a Ubuntu device", "nmap", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"row of unknown source", "", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"SNMP row, OS only a fingerprint or DHCP guess", "snmp", "Microsoft Windows", "", "", "", false},
		{"SNMP row, the device states its OS to Vedette's SNMP read", "snmp", "", "Ubuntu 22.04", "", "Ubuntu 22.04", true},
		{"SNMP row, the OS only in an LLDP frame (review r2 of #800)", "snmp", "", "Ubuntu 22.04", "", "", false},
	} {
		a := Asset{ID: "d", Name: "docker1", OS: tc.os, StatedOS: tc.stated, AgentOS: tc.agent, SNMPOS: tc.snmp, Software: []Software{sshRow("10.2", "", tc.source)}}
		res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
		if got := len(res.OtherPlatform) == 1 && len(res.New) == 0; got != tc.out {
			t.Errorf("%s: ruled out %v, want %v (new %+v)", tc.name, got, tc.out, res.New)
		}
	}
}

// An agent-read Ubuntu OpenSSH (ruled out) beside a scan-seen OpenSSH with no platform (an Alpine container's
// port): not proved, not a finding either: the scanned row's platform is asked.
func TestPlatform_ContainerPortIsAsked(t *testing.T) {
	t.Parallel()
	host := sshRow("9.6p1", "", "agent")
	host.ID, host.Packaged, host.PkgVersion, host.PkgSource = "pkg", true, "1:9.6p1-3ubuntu13.20", "openssh"
	a := Asset{ID: "d", Name: "docker1", OS: "Ubuntu 24.04.3 LTS", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{host, sshRow("10.2", "", "nmap")}}
	res := MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
	if len(res.Existing) != 0 || len(res.NotAffected) != 0 || len(res.OtherPlatform) != 0 || len(res.Asked) != 1 || res.Asked[0].SoftwareID != "ssh" {
		t.Fatalf("existing %+v, not affected %+v, other %+v, asked %+v", res.Existing, res.NotAffected, res.OtherPlatform, res.Asked)
	}
}

// Review r1 #3: a deb/rpm package is "not Alpine", never "not Debian": an entry limited to a deb/rpm family is not ruled out by
// the package format (an OS name Vedette does not know, "Linux Mint", names nothing).
func TestPlatform_PackageFormatOnlyRulesOutNonDebRPMEntries(t *testing.T) {
	t.Parallel()
	pkg := swInfo{ver: "9.6p1", packaged: true, pkgVer: "1:9.6p1-1", platformOS: "Linux Mint 22"}
	if _, out := ruledOut(platformLimit{Only: []string{"debian"}, Affects: "x"}, evidenceOf(pkg), "CVE-2099-0001"); out {
		t.Error("a Debian-only entry was ruled out by the device's deb package")
	}
	why, out := ruledOut(platformLimit{Only: []string{"alpine"}, Affects: "x"}, evidenceOf(pkg), "CVE-2099-0001")
	if !out || !strings.Contains(why, "deb or rpm package database") || strings.Contains(why, "the device's rpm") {
		t.Errorf("alpine-only entry: %q %v", why, out)
	}
}

// An agent row whose package release is an Alpine apk release (the package reporter's) is Alpine evidence, not "deb or rpm": a limit that
// excludes Alpine rules it out, and one that names only Alpine does not.
func TestPlatform_AgentApkReleaseIsAlpineEvidence(t *testing.T) {
	t.Parallel()
	apk := swInfo{ver: "10.2p1", packaged: true, pkgVer: "10.2_p1-r1"}
	if _, out := ruledOut(platformLimit{Only: []string{"alpine"}, Affects: "x"}, evidenceOf(apk), "CVE-2099-0001"); out {
		t.Error("an Alpine-only entry was ruled out by the device's apk package")
	}
	why, out := ruledOut(platformLimit{Only: []string{"debian"}, Affects: "x"}, evidenceOf(apk), "CVE-2099-0001")
	if !out || !strings.Contains(why, "Alpine apk database") || strings.Contains(why, "deb or rpm") {
		t.Errorf("debian-only entry: %q %v", why, out)
	}
}

// Review r1 #4: the word that rules a CVE out is always in the sentence shown: one past the shown text decides nothing.
func TestPlatform_RulingWordIsInTheReason(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 130) + " Ubuntu"
	res := MatchAsset(Asset{ID: "x", Name: "x", Software: []Software{sshRow("10.2", long, "scan")}}, []Vuln{sshhole()}, nil, t0)
	if len(res.OtherPlatform) != 0 || len(res.Asked) != 1 {
		t.Fatalf("a platform word past the shown text ruled it out: %+v", res)
	}
}

// Review r1 #7: the distribution's own word comes first: Ubuntu says its package is affected (fixed in a later revision), so the
// hand list does not close it.
func TestPlatform_DistributionWordBeatsTheHandList(t *testing.T) {
	t.Parallel()
	sw := sshRow("9.6p1", "", "agent")
	sw.Packaged, sw.PkgVersion, sw.PkgSource = true, "1:9.6p1-3ubuntu13.14", "openssh"
	v := sshhole()
	v.Distro = []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "fixed", Fixed: "1:9.6p1-3ubuntu13.20"}}
	res := MatchAsset(Asset{ID: "a", Name: "boxanna", OS: "Ubuntu 24.04.3 LTS", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sw}}, []Vuln{v}, nil, t0)
	if len(res.New) != 1 || len(res.OtherPlatform) != 0 {
		t.Fatalf("new %+v, other %+v; want the distribution's version finding", res.New, res.OtherPlatform)
	}
}
