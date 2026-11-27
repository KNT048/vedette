package findings

import (
	"strings"
	"testing"
)

// The box's own "not affected" from a page of plain text is decided only from a page about this CVE alone. A page that names another
// CVE (a bulletin of several, a news post, a page linked for another reason) may state ranges that belong to that other CVE while this
// CVE's own ranges are in words the box cannot read: those ranges must never settle this CVE. A page that does not name the CVE at all
// decides nothing either way.
func TestReadAdvisory_TextRangesOnlyFromAPageAboutThisCVE(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2099-0001"
	id := CheckID{Product: "juniper|junos os", Line: "21.4", Version: "21.4R3-S6"}
	page := func(text string) []FetchedPage {
		return []FetchedPage{{URL: "https://advisory.example/1", Status: "ok", Text: text, Vendor: true}}
	}
	for _, tc := range []struct {
		name, text string
		ok         bool
		verdict    string
	}{
		{"another CVE's ranges", "Junos OS: CVE-2099-0002 affects 21.4 versions before 21.4R3-S5. " + cve + " affects every 21.4 release of the SRX line.", false, ""},
		{"no CVE named", "Junos OS: 21.4 versions before 21.4R3-S5 are affected.", false, ""},
		{"no CVE named, affected", "Junos OS: 21.4 versions before 21.4R3-S7 are affected.", false, ""},
		{"this CVE alone, fixed", cve + ": Junos OS: 21.4 versions before 21.4R3-S5 are affected.", true, VerdictNotAffected},
		{"this CVE alone, affected", cve + ": Junos OS: 21.4 versions before 21.4R3-S7 are affected.", true, VerdictAffected},
		{"several CVEs, affected", "Junos OS: " + cve + " and CVE-2099-0002 affect 21.4 versions before 21.4R3-S7.", true, VerdictAffected},
	} {
		v, ok, _ := readAdvisory(page(tc.text), id, cve)
		if ok != tc.ok || v.verdict != tc.verdict {
			t.Errorf("%s: decided %v %q, want %v %q", tc.name, ok, v.verdict, tc.ok, tc.verdict)
		}
	}
}

// A quote names the version only as a whole version: "7.4.10" does not name 7.4.1, so a proposal resting on it is not confident.
func TestQuoteNamesRange_WholeVersionOnly(t *testing.T) {
	t.Parallel()
	id := CheckID{Product: "fortinet|fortios", Line: "7.4.1", Version: "7.4.1"}
	if quoteNamesRange("FortiOS 7.4.10 and earlier are affected", id) {
		t.Error("7.4.10 named 7.4.1")
	}
	if !quoteNamesRange("FortiOS 7.4.1 and earlier are affected", id) {
		t.Error("7.4.1 not named")
	}
}

// "Not affected" read from a page is the vendor's word only on the vendor's own advisory (Vendor: a reference tagged vendor-advisory,
// or a page on the vendor's host); "affected" may come from any page (it fails safe). A CSAF document follows the same rule.
func TestReadAdvisory_NotAffectedOnlyFromTheVendor(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2099-0001"
	id := CheckID{Product: "juniper|junos os", Line: "21.4", Version: "21.4R3-S6"}
	fixed := cve + ": Junos OS: 21.4 versions before 21.4R3-S5 are affected."
	affected := cve + ": Junos OS: 21.4 versions before 21.4R3-S7 are affected."
	csaf := `{"product_tree":{"branches":[{"category":"product_name","name":"Junos OS","branches":[{"category":"product_version_range",
		"name":"vers:generic/>=21.4R1|<21.4R3-S5","product":{"product_id":"P1"}}]}]},"vulnerabilities":[{"cve":"` + cve + `",
		"product_status":{"known_affected":["P1"]}}]}`
	for _, tc := range []struct {
		name, text   string
		json, vendor bool
		ok           bool
		verdict      string
	}{
		{"third party, fixed", fixed, false, false, false, ""},
		{"vendor, fixed", fixed, false, true, true, VerdictNotAffected},
		{"third party, affected", affected, false, false, true, VerdictAffected},
		{"third-party CSAF, fixed", csaf, true, false, false, ""},
		{"vendor CSAF, fixed", csaf, true, true, true, VerdictNotAffected},
	} {
		pages := []FetchedPage{{URL: "https://advisory.example/1", Status: "ok", Text: tc.text, JSON: tc.json, Vendor: tc.vendor}}
		v, ok, _ := readAdvisory(pages, id, cve)
		if ok != tc.ok || v.verdict != tc.verdict {
			t.Errorf("%s: decided %v %q, want %v %q", tc.name, ok, v.verdict, tc.ok, tc.verdict)
		}
	}
}

// A vendor's host is one whose registrable name is the vendor's: not a host that only carries the vendor's word elsewhere.
func TestVendorHost(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"supportportal.juniper.net": true, "juniper.net": true, "kb.juniper.co.jp": true, "security.paloaltonetworks.com": true,
		"juniper.example.com": false, "blog.example.org": false, "notjuniper.net": false, "": false,
	} {
		vendor := "juniper"
		if strings.Contains(host, "paloalto") {
			vendor = "palo alto networks"
		}
		if got := vendorHost(host, vendor); got != want {
			t.Errorf("vendorHost(%q, %q) = %v, want %v", host, vendor, got, want)
		}
	}
}

// "Upgrade from X to Y" names the upgrade path, not a range of affected releases: Y is the fixed release.
func TestTextRanges_UpgradeFromToIsNoRange(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]int{
		"Synology DiskStation Manager: upgrade from 7.2 to 7.2.1-69057-5 or above.": 0,
		"Customers should update from 7.0.1 to 7.0.12 as soon as possible.":         0,
		"Migrating from 6.4 to 7.0.2 resolves the issue.":                           0,
		"Affected: versions 7.0.0 to 7.0.12.":                                       1,
		"The flaw affects versions from 7.0.0 through 7.0.12.":                      1,
		"It affects FortiOS from 7.0.0 to 7.0.12.":                                  1,
	} {
		if got := len(textRanges(text)); got != want {
			t.Errorf("textRanges(%q): %d ranges, want %d", text, got, want)
		}
	}
}
