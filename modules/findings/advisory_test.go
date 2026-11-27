package findings

import "testing"

// The box's own "not affected" from a page of plain text is decided only from a page about this CVE alone. A page that names another
// CVE (a bulletin of several, a news post, a page linked for another reason) may state ranges that belong to that other CVE while this
// CVE's own ranges are in words the box cannot read: those ranges must never settle this CVE. A page that does not name the CVE at all
// decides nothing either way.
func TestReadAdvisory_TextRangesOnlyFromAPageAboutThisCVE(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2099-0001"
	id := CheckID{Product: "juniper|junos os", Line: "21.4", Version: "21.4R3-S6"}
	page := func(text string) []FetchedPage {
		return []FetchedPage{{URL: "https://advisory.example/1", Status: "ok", Text: text}}
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
