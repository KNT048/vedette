package feeds

import (
	"net/url"
	"testing"
)

func TestContract_INV1_BuiltinSourcesAreDeclaredHTTPS(t *testing.T) {
	t.Parallel()
	// Exactly the hosts listed in PRIVACY.md flow 1.
	allowed := map[string]bool{
		"www.cisa.gov": true, "api.first.org": true, "raw.githubusercontent.com": true,
		"rules.emergingthreats.net": true, "feodotracker.abuse.ch": true, "check.torproject.org": true,
		"services.nvd.nist.gov":                      true, // NVD affected versions
		"security-metadata.canonical.com":            true, // Ubuntu security data
		"security-tracker.debian.org":                true, // Debian Security Tracker
		"api.vulncheck.com":                          true, // VulnCheck KEV (BYOK, off until the customer saves a key)
		"epss.empiricalsecurity.com":                 true, // FIRST's daily file of every EPSS score
		"learn.microsoft.com":                        true, // Microsoft's Windows release information pages
		"osv-vulnerabilities.storage.googleapis.com": true, // OSV.dev's Alpine all.zip, only while a device states Alpine
		"github.com":                                 true, // the CVE Program's cvelistV5 release files (which redirect to GitHub's file host) and record files
		"gitlab.com":                                 true, // the Exploit-DB index (OffSec's public exploitdb repository)
		"codeload.github.com":                        true, // the PoC-in-GitHub index as one archive
		"api.msrc.microsoft.com":                     true, // Microsoft's list of the CVEs it flags exploited (Security Update Guide)
		"sec.cloudapps.cisco.com":                    true, // Cisco's advisory feed and the CSAF documents of its advisories
		"filestore.fortinet.com":                     true, // FortiGuard's advisory feed and the CSAF documents of its advisories
		"chromereleases.googleblog.com":              true, // Google's Chrome Releases blog (its Atom feed)
		"source.android.com":                         true, // Android's monthly security bulletins
		"www.rapid7.com":                             true, // Rapid7's blog (its RSS feed)
		"cloudblog.withgoogle.com":                   true, // Google Threat Intelligence's blog (its RSS feed)
		"www.spamhaus.org":                           true, // Spamhaus DROP (off until an administrator turns it on)
	}
	seenID, seenName := map[string]bool{}, map[string]bool{}
	for _, s := range BuiltinSources() {
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme != "https" || !allowed[u.Host] {
			t.Errorf("%s: URL %q is not an allowed https source", s.ID, s.URL)
		}
		if err := CheckURL(s.URL); err != nil {
			t.Errorf("%s: default URL fails INV-2: %v", s.ID, err)
		}
		if s.IntervalHours < 1 || s.IntervalHours > 168 { // the schedule's limits: an hour to a week
			t.Errorf("%s: default interval %d is outside the schedule's limits", s.ID, s.IntervalHours)
		}
		want := map[Kind]int{KindVulnerabilities: 24, KindIOC: 6}[s.Kind]
		if s.ID == vulnCheckFeedID { // the customer's own key, 1,000 requests a minute: a few pages every 6 hours
			want = 6
		}
		if vendorClaimFeed(s.ID) { // a vendor's word on exploitation: small lists, read every 6 hours so a claim is not a day late
			want = 6
		}
		if s.ID == dropFeedID { // Spamhaus asks for at most one download a day
			want = 24
		}
		if s.ID == "cisa-kev" || s.ID == "cve-org" { // hourly: Home promises data at most an hour old (S-FEED-1); a 304 keeps it cheap
			want = 1
		}
		if s.IntervalHours != want {
			t.Errorf("%s: default interval %d", s.ID, s.IntervalHours)
		}
		if seenID[s.ID] || seenName[s.Name] {
			t.Errorf("duplicate built-in %s / %s", s.ID, s.Name)
		}
		seenID[s.ID], seenName[s.Name] = true, true
		if s.Decoder == DecoderParser {
			if s.Parser == nil || s.Parser.Format != s.Format {
				t.Errorf("%s: missing or mismatched parser", s.ID)
			}
		} else if s.Parser != nil {
			t.Errorf("%s: dedicated decoder must not carry a parser", s.ID)
		}
	}
	if len(seenID) != 28 {
		t.Fatalf("expected the 28 built-ins of sourcesMock.ts, got %d", len(seenID))
	}
}

func TestBuiltinLookupAndBlockClass(t *testing.T) {
	t.Parallel()
	if _, ok := BuiltinByID("nope"); ok {
		t.Fatal("unknown id found")
	}
	feodo, _ := BuiltinByID("abusech-feodo")
	ipsum, _ := BuiltinByID("ipsum")
	kev, _ := BuiltinByID("cisa-kev")
	drop, _ := BuiltinByID(dropFeedID)
	if !feodo.BlockClass() || !drop.BlockClass() || ipsum.BlockClass() || kev.BlockClass() {
		t.Fatal("BlockClass: only CC0 IOC lists and Spamhaus DROP qualify")
	}
	for _, b := range BuiltinSources() { // a new box asks a source nothing that it did not choose: only DROP and BYOK feeds start off
		if b.DefaultOff != (b.ID == dropFeedID) {
			t.Errorf("%s: off by default %v", b.ID, b.DefaultOff)
		}
	}
	// Mutating the returned slice must not change the registry.
	l := BuiltinSources()
	l[0].Name = "changed"
	if s, _ := BuiltinByID("cisa-kev"); s.Name != "CISA KEV" {
		t.Fatal("registry mutated through the copy")
	}
}

func TestDefaultParserShape(t *testing.T) {
	t.Parallel()
	for _, k := range []Kind{KindVulnerabilities, KindIOC} {
		for _, f := range FormatsFor(k) {
			p := DefaultParser(k, f)
			if p.Format != f || len(p.Fields) != len(FieldIDs(k)) || !p.HasHeader || p.Delimiter != "," {
				t.Errorf("%s/%s: bad default parser %+v", k, f, p)
			}
			for id, fmap := range p.Fields {
				if !fmap.Trim || fmap.DateFormat != DateAuto && (id != "date" || fmap.DateFormat != DateDMY) {
					t.Errorf("%s/%s/%s: unexpected field map %+v", k, f, id, fmap)
				}
			}
		}
	}
}
