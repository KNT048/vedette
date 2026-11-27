package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	uncNow = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	uncOld = time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC) // published and added long before AgeLimit: a product match is aged
	uncNew = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

func uncVuln(cve, vendor, product string, added time.Time, aff ...Affected) Vuln {
	return Vuln{CVE: cve, Vendor: vendor, Product: product, Name: vendor + " " + product + " flaw", DateAdded: added, Published: added, Affected: vendorCNARows(aff),
		NVDAnswered: true}
}

// vendorCNARows marks rows as of a record the product's vendor assigned (Affected.VendorCNA): a list of exact releases is then the
// vendor's enumeration, as the tests written before the box kept the record's assigner read every list.
func vendorCNARows(aff []Affected) []Affected {
	out := make([]Affected, len(aff))
	for i, af := range aff {
		af.VendorCNA = true
		out[i] = af
	}
	return out
}

func uncAff(cpe, endExcl string) Affected {
	return Affected{CPE: cpe, Range: VersionRange{EndExcl: endExcl}}
}

func uncByCVE(us []Unchecked) map[string]Unchecked {
	out := map[string]Unchecked{}
	for _, u := range us {
		out[u.SoftwareID+" "+u.CVE] = u
	}
	return out
}

// One device, one case per reason, each one CVE.
func TestUnchecked_910_OneReasonEach(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "d", Name: "d", Software: []Software{
		// keyed "acme|widget", a version a scan read: a product match, which the age rule drops for an old CVE
		{ID: "w", Display: "Acme Widget", Vendor: "Acme", Product: "Widget", Version: "2.0", Source: "scan", KevKeys: []string{"acme|widget"}},
		// keyed to CISA's "acme|engine", but the row is Acme Engine Pro, which NVD's list does not name
		{ID: "p", Display: "Acme Engine Pro", Vendor: "Acme", Product: "Engine Pro", Version: "5.0", Source: "scan", KevKeys: []string{"acme|engine"}},
		// no key: only NVD's list names it (#910 path)
		{ID: "g", Display: "Acme Gadget", Vendor: "Acme", Product: "Gadget", Version: "9.1", Source: "manual"},
		{ID: "h", Display: "Acme Hub", Vendor: "Acme", Product: "Hub", Version: "4.2", Source: "agent"},
		// keyed, typed by a person in a form Vedette cannot order against NVD's range with an end
		{ID: "r", Display: "Acme Router", Vendor: "Acme", Product: "Router", Version: "15.2(4)M3", Source: "manual", KevKeys: []string{"acme|router"}},
	}}
	vulns := []Vuln{
		uncVuln("CVE-2020-0001", "Acme", "Widget", uncOld),                                                         // no NVD data, aged product match
		uncVuln("CVE-2020-0002", "Acme", "Widget", uncOld, Affected{CPE: "cpe:2.3:a:acme:widget:-:*:*:*:*:*:*:*"}), // no version
		uncVuln("CVE-2020-0003", "Acme", "Engine", uncOld, uncAff("cpe:2.3:a:acme:engine:*:*:*:*:*:*:*:*", "3.0")), // not named
		uncVuln("CVE-2026-0004", "Acme", "Gadget Core", uncNew, Affected{CPE: "cpe:2.3:a:acme:gadget:9.2:*:*:*:*:*:*:*"}),
		uncVuln("CVE-2026-0005", "Acme", "Hub Firmware", uncNew, Affected{CPE: "cpe:2.3:a:acme:hub:-:*:*:*:*:*:*:*"}, uncAff("cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "2.0")),
		uncVuln("CVE-2020-0006", "Acme", "Router", uncOld, uncAff("cpe:2.3:a:acme:router:*:*:*:*:*:*:*:*", "15.9")),
		// NVD has not answered for this one yet (before the pull, the feed off): listed at once as no NVD data
		// (#939, which replaces #920's "no row")
		func() Vuln { v := uncVuln("CVE-2020-0007", "Acme", "Widget", uncOld); v.NVDAnswered = false; return v }(),
	}
	res := MatchAsset(a, vulns, nil, uncNow)
	if len(res.New) != 0 || len(res.NeedVersion) != 0 || len(res.Aged) != 5 {
		t.Fatalf("no finding and no item expected, five aged: %+v", res)
	}
	want := map[string]UncheckedReason{
		"w CVE-2020-0001": UncheckedNoNVDData,
		"w CVE-2020-0002": UncheckedNoNVDVersions,
		"p CVE-2020-0003": UncheckedNotNamed,
		"g CVE-2026-0004": UncheckedNoNVDVersions, // NVD lists one exact version only, later than the row's (#913, newerThanListed): no range (r1 M1)
		"h CVE-2026-0005": UncheckedNoNVDVersions, // NVD names the row with no version
		"r CVE-2020-0006": UncheckedNotComparable, // a range with an end, a version that does not compare with it
		"w CVE-2020-0007": UncheckedNoNVDData,
	}
	got := uncByCVE(res.Unchecked)
	if len(got) != len(want) {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
	for k, r := range want {
		if got[k].Reason != r {
			t.Errorf("%s: reason %q, want %q (%+v)", k, got[k].Reason, r, res.Unchecked)
		}
	}
	if u := got["g CVE-2026-0004"]; u.Software != "Acme Gadget" || u.Version != "9.1" || u.Source != "manual" {
		t.Errorf("row = %+v", u)
	}
}

// Classic IOS states a version with no order (#919's NotComparable): listed as not comparable, with the OS row's id, unless the
// CVE has no NVD data (precedence).
func TestUnchecked_910_NetworkOSWithoutOrder(t *testing.T) {
	t.Parallel()
	a := snmpDevice("ios", "Cisco IOS 15.2(4)M3")
	vulns := []Vuln{
		uncVuln("CVE-2026-0010", "Cisco", "IOS", uncNew, uncAff("cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", "15.9")),
		uncVuln("CVE-2026-0011", "Cisco", "IOS", uncNew),
	}
	res := MatchAsset(a, vulns, nil, uncNow)
	got := uncByCVE(res.Unchecked)
	os := osSoftwareID("ios")
	if len(got) != 2 || got[os+" CVE-2026-0010"].Reason != UncheckedNotComparable || got[os+" CVE-2026-0011"].Reason != UncheckedNoNVDData ||
		got[os+" CVE-2026-0010"].Version != "15.2(4)M3" || got[os+" CVE-2026-0010"].Source != "snmp" {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
}

// Rule 1: a CVE that gives a finding or an "add the version" item on any row of the device is not in the list, even when another
// row could not check it; noise: an entry for software the device has no row keyed to or named by NVD is never listed.
func TestUnchecked_910_OnePlacePerDeviceAndCVE(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "d", Name: "d", Software: []Software{
		{ID: "x", Display: "Acme Gadget X", Vendor: "Acme", Product: "Gadget", Version: "9.1", Source: "agent"},
		{ID: "k", Display: "Acme Gadget", Vendor: "Acme", Product: "Gadget", Version: "8.0", Source: "agent", KevKeys: []string{"acme|gadget"}},
		{ID: "n", Display: "Acme Gizmo", Vendor: "Acme", Product: "Gizmo", Source: "manual", KevKeys: []string{"acme|gizmo"}},
		{ID: "z", Display: "Acme Gizmo Tool", Vendor: "Acme", Product: "Gizmo", Version: "1.0", Source: "agent"},
	}}
	vulns := []Vuln{
		// row k matches by version (8.0 < 8.5); row x is listed by an exact version only: the finding wins
		uncVuln("CVE-2026-0020", "Acme", "Gadget", uncNew, uncAff("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*", "8.5"), Affected{CPE: "cpe:2.3:a:acme:gadget:9.0:*:*:*:*:*:*:*"}),
		// row n has no version: "add the version"; row z only by NVD's exact version: the item wins
		uncVuln("CVE-2026-0021", "Acme", "Gizmo", uncNew, Affected{CPE: "cpe:2.3:a:acme:gizmo:0.9:*:*:*:*:*:*:*"}),
		// nothing on the device is keyed to or named by it
		uncVuln("CVE-2026-0022", "Other", "Thing", uncNew, uncAff("cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "2.0")),
		uncVuln("CVE-2026-0023", "Other", "Thing", uncNew),
	}
	res := MatchAsset(a, vulns, nil, uncNow)
	if len(res.New) != 1 || res.New[0].CVE != "CVE-2026-0020" || len(res.NeedVersion) != 1 || res.NeedVersion[0].CVEs[0] != "CVE-2026-0021" {
		t.Fatalf("matches = %+v", res)
	}
	if len(res.Unchecked) != 0 {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
}

// #919 r1: CISA keys CVE-2018-0171 "IOS and IOS XE" but NVD lists only classic cisco:ios; on an IOS XE device that states its
// (orderable) version it is not a finding but could not be checked: NVD names another product, so not_named, action none.
func TestUnchecked_910_NetworkOSNVDOtherProductIsNotNamed(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-snmp-os.json")
	res := MatchAsset(snmpDevice("xe", "Cisco IOS XE 17.3.1"), vulns, nil, uncNow)
	u, ok := uncByCVE(res.Unchecked)[osSoftwareID("xe")+" CVE-2018-0171"]
	if !ok || u.Reason != UncheckedNotNamed || u.Version != "17.3.1" || u.Source != "snmp" {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
	for _, m := range res.New {
		if m.CVE == "CVE-2018-0171" {
			t.Fatalf("a finding as well: %+v", m)
		}
	}
}

// Director's question (#920 r1): a package the distribution builds, keyed to a KEV entry its tracker says nothing about for the
// device's release (an entry for another release only), is not silent: NVD's upstream ranges decide it. Inside a range is a version
// finding; a partial CVE.org list that does not reach the version is no version evidence: no finding, the could-not-check list
// says NVD gives no versions that decide it.
func TestUnchecked_910_DistroPackageTheTrackerDoesNotCover(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "u", Name: "u", OS: "Ubuntu 26.04 LTS", AgentOS: "Ubuntu 26.04 LTS", Software: []Software{
		{ID: "pk", Display: "Acme Widget", Vendor: "Acme", Product: "Widget", Version: "2.0", Source: "agent", Packaged: true,
			PkgVersion: "2.0-1ubuntu1", PkgSource: "widget", KevKeys: []string{"acme|widget"}},
	}}
	other := []DistroFix{{Distro: "ubuntu", Release: "22.04", Package: "widget", Status: "fixed", Fixed: "1.9-1ubuntu0.1"}}
	inRange := uncVuln("CVE-2026-0030", "Acme", "Widget", uncNew, uncAff("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "3.0"))
	inRange.Distro = other
	// the partial list covers the 1.4 train only, so 2.0 past its end is not past a fix of a train it covers (pastRecordFix)
	partial := uncVuln("CVE-2026-0031", "Acme", "Widget", uncNew, Affected{CPE: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.4.0", EndExcl: "1.4.5"}})
	partial.Distro, partial.RangesFrom = other, RangesCVEOrgPartial
	res := MatchAsset(a, []Vuln{inRange, partial}, nil, uncNow)
	if len(res.New) != 1 || res.New[0].Basis != BasisVersion || len(res.NameOnly) != 1 || res.NameOnly[0].CVE != "CVE-2026-0031" ||
		len(res.Unchecked) != 1 || res.Unchecked[0].CVE != "CVE-2026-0031" || res.Unchecked[0].Reason != UncheckedNoNVDVersions || len(res.NeedVersion) != 0 {
		t.Fatalf("findings = %+v, unchecked = %+v", res.New, res.Unchecked)
	}
}

// A platform-limited CVE only a person's answer decides gets the question and the answers that settle it (Needs your input):
// one click sets the device's OS (per Alpine branch), or the person types the OS or the package release.
func TestPlatformQuestion_AnswersThatSettleIt(t *testing.T) {
	t.Parallel()
	feed := alpineSSH()
	q := platformQuestion("CVE-2026-123158", "gw-alpine", UncheckedPlatformUnknown, "", feed)
	if q == nil || !strings.HasPrefix(q.Text, "Is the OpenSSH on gw-alpine Alpine Linux's openssh-server package") || q.Command == nil || *q.Command != "cat /etc/alpine-release" {
		t.Fatalf("question %+v", q)
	}
	last := q.Answers[len(q.Answers)-1]
	// one per branch the feed has a fixed release for (OSV.dev's nine, no edge)
	if len(q.Answers) != 10 || q.Answers[1].Label != "Alpine Linux 3.23" || q.Answers[1].OS == nil || *q.Answers[1].OS != "Alpine Linux 3.23" ||
		q.Answers[8].Label != "Alpine Linux 3.16" || !slices.Equal(last.Ask, []string{"os", "pkg_version"}) || last.OS != nil {
		t.Fatalf("answers %+v", q.Answers)
	}
	if q := platformQuestion("CVE-2099-0001", "gw-alpine", UncheckedNoNVDVersions, "", nil); q != nil {
		t.Fatalf("a CVE that is not platform-limited asked %+v", q)
	}
	q = platformQuestion("CVE-2026-123158", "gw-alpine", UncheckedPackageUnknown, "", feed)
	if q == nil || q.Command == nil || *q.Command != "apk info -e -v openssh-server" || len(q.Answers) != 1 || !slices.Equal(q.Answers[0].Ask, []string{"pkg_version"}) || q.Error != nil ||
		!strings.Contains(q.Text, "Which openssh-server package release does gw-alpine have?") || !strings.Contains(q.Text, "10.2_p1-r1 (3.23)") {
		t.Fatalf("package question %+v", q)
	}
	// review r1 M2 of #961: a release Vedette could not read is said
	q = platformQuestion("CVE-2026-123158", "gw-alpine", UncheckedPackageUnknown, "10.2p1", feed)
	if q == nil || q.Error == nil || !strings.Contains(*q.Error, `could not read the release you entered ("10.2p1")`) || !strings.Contains(*q.Error, "openssh-server-10.3_p1-r2") {
		t.Fatalf("unreadable answer %+v", q)
	}
	// without the feed's rows (a package question stays only while alpine-osv is on and not loaded) the
	// question says so and lists no release; the platform question offers only Alpine Linux and another system, never releases made up
	if q := platformQuestion("CVE-2026-123158", "gw-alpine", UncheckedPackageUnknown, "", nil); q == nil ||
		!strings.HasPrefix(q.Text, "Alpine Linux's fixed releases of CVE-2026-123158 are not loaded yet") || strings.Contains(q.Text, "_p") || q.Command == nil {
		t.Fatalf("package question without rows %+v", q)
	}
	q = platformQuestion("CVE-2026-123158", "gw-alpine", UncheckedPlatformUnknown, "", nil)
	if q == nil || len(q.Answers) != 2 || q.Answers[0].Label != "Alpine Linux" {
		t.Fatalf("platform question without rows %+v", q)
	}
}
