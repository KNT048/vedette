package findings

import (
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
}

// sshhole is CVE-2026-123158 as the feeds give it: KEV OpenBSD|OpenSSH, NVD's range before 10.6 (kev-nvd-golden.json).
func sshhole() Vuln {
	return Vuln{CVE: "CVE-2026-123158", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{
		{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}},
	}}
}

func sshRow(version, banner, source string) Software {
	return Software{ID: "ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, Banner: banner, Source: source,
		CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", KevKeys: []string{"openbsd|openssh"}}
}

// KF-4 / N45-3: the GitLab server's "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20" on the public IP is Ubuntu's glibc+PAM build: not listed,
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

// A device whose OS (osquery) is Ubuntu: its open finding of the Alpine-only CVE closes by itself (D-530 path) with the reason.
func TestPlatform_DeviceOSClosesTheFinding(t *testing.T) {
	t.Parallel()
	sw := sshRow("9.6p1", "", "agent")
	sw.Packaged, sw.PkgVersion, sw.PkgSource = true, "1:9.6p1-3ubuntu13.20", "openssh"
	a := Asset{ID: "a", Name: "boxkien", OS: "Ubuntu 24.04.3 LTS", Software: []Software{sw}}
	res := MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
	if len(res.Existing) != 0 || len(res.NotAffected) != 1 {
		t.Fatalf("existing %+v, not affected %+v", res.Existing, res.NotAffected)
	}
	if n := res.NotAffected[0].Evidence.Summary; !strings.HasPrefix(n, "Not affected: CVE-2026-123158 affects only") || !strings.Contains(n, "this device runs Ubuntu 24.04.3 LTS") {
		t.Errorf("note = %q", n)
	}
}

// KF-5: the office firewall's "OpenSSH 10.2" says no platform: listed as suspected, with the condition and what to check. A Ubuntu
// host whose port a scan saw is no proof either (it may forward the port to an Alpine container).
func TestPlatform_UnknownPlatformKeepsTheFindingWithTheCondition(t *testing.T) {
	t.Parallel()
	for _, a := range []Asset{
		{ID: "fw", Name: "192.168.18.1", Software: []Software{sshRow("10.2", "protocol 2.0", "nmap")}},
		{ID: "host", Name: "docker1", OS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("10.2", "", "nmap")}},
		{ID: "alp", Name: "alp1", OS: "Alpine Linux v3.23", Software: []Software{sshRow("10.2", "", "agent")}},
	} {
		res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
		if len(res.New) != 1 || res.New[0].Basis != BasisVersion || len(res.OtherPlatform) != 0 {
			t.Fatalf("%s: new %+v, other %+v; want one suspected by version", a.Name, res.New, res.OtherPlatform)
		}
		s := res.New[0].Evidence.Summary
		if !strings.Contains(s, "It affects only OpenSSH built with musl libc and without PAM") || !strings.Contains(s, "check the openssh package version on that device") {
			t.Errorf("%s: summary = %q", a.Name, s)
		}
	}
}

// A CVE not on the list is untouched by a platform word.
func TestPlatform_OtherCVEsUnchanged(t *testing.T) {
	t.Parallel()
	v := sshhole()
	v.CVE = "CVE-2024-6387"
	res := MatchAsset(Asset{ID: "x", Name: "x", Software: []Software{sshRow("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "")}}, []Vuln{v}, nil, t0)
	if len(res.New) != 1 || len(res.OtherPlatform) != 0 || strings.Contains(res.New[0].Evidence.Summary, "affects only") {
		t.Fatalf("result %+v", res)
	}
}
