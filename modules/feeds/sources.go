package feeds

import "strings"

// Decoder says which parser a built-in feed needs.
type Decoder string

// Built-in decoders.
const (
	DecoderParser Decoder = "parser" // the generic custom-format parser with Source.Parser
	DecoderKEV    Decoder = "kev"    // ParseKEV
	DecoderEPSS   Decoder = "epss"   // EPSSBatchURLs and ParseEPSS (api.first.org JSON)
	DecoderNuclei Decoder = "nuclei" // ParseNucleiCVEs
	DecoderNVD    Decoder = "nvd"    // NVDPageURL and ParseNVD (NVD CVE API 2.0, ?hasKev; D-500)
	// The distribution backport data (D-516): ParseUbuntuOSV, ParseUbuntuVEX, ParseDebianTracker, read as a stream.
	DecoderUbuntuOSV     Decoder = "ubuntu-osv"
	DecoderUbuntuVEX     Decoder = "ubuntu-vex"
	DecoderDebianTracker Decoder = "debian-tracker"
)

// Source is a built-in feed (D-36). Built-ins cannot be deleted (INV-4): the
// module stores only enabled, interval_hours and a mirror URL for them.
type Source struct {
	ID            string
	Name          string
	Kind          Kind
	Format        Format
	URL           string // default address; Reset restores it
	License       string
	IntervalHours int // default schedule: 1 for the CISA list (S-FEED-1, D-485), 24 for the other vulnerability feeds, 6 for IOC
	Decoder       Decoder
	Parser        *Parser // set when Decoder == DecoderParser
	MaxRows       int     // row limit of this source; 0 means MaxRows (50,000)

	// Aggregate: the list is itself a merge of other lists (IPsum, hagezi TIF).
	// It never reaches block alone, and counts with one of its Upstreams as one source.
	Aggregate bool
	Upstreams []string // ids of built-in feeds an aggregate is known to include
	// Informational: the list says what an address is, not that it is malicious
	// (Tor exit nodes). It never counts toward block.
	Informational bool
	// Subdomains: every name the list holds stands for itself and all of its subdomains (hagezi TIF, "Domains (without
	// subdomains)": a listed bad.example also means a.b.bad.example; D-228). A source without it lists each name exactly.
	Subdomains bool
}

func (s Source) rowLimit() int {
	if s.MaxRows > 0 {
		return s.MaxRows
	}
	return MaxRows
}

// BlockClass reports a CC0 IOC list: one such source is enough for `block`
// (INV-12, "one DROP/CC0-class source").
func (s Source) BlockClass() bool { return s.Kind == KindIOC && s.License == "CC0" }

func linesParser() *Parser {
	p := DefaultParser(KindIOC, FormatLines)
	return &p
}

// nvdNotice is the licence line of the NVD feed: NVD data is public domain, and the NVD terms of use ask for this
// sentence (https://nvd.nist.gov/developers/terms-of-use).
const nvdNotice = "Public domain. This product uses the NVD API but is not endorsed or certified by the NVD."

// canonicalNotice and debianNotice are the licence lines of the distribution feeds (D-516). Canonical publishes its
// security metadata under CC BY-SA 4.0 (https://security-metadata.canonical.com/osv/LICENSE); the box keeps and shows it
// for its own operator and Vedette ships none of it. The Debian Security Tracker states no licence for its JSON; it is
// used as Trivy and Grype use it, attributed and never redistributed.
const (
	canonicalNotice = "CC BY-SA 4.0, Canonical Ltd. Ubuntu security data."
	debianNotice    = "Debian Security Tracker data; no licence stated. Attributed, not redistributed."
)

// builtinSources is the default list of sourcesMock.ts. Hosts must match the
// list in PRIVACY.md (INV-13) except where the report says otherwise.
var builtinSources = []Source{
	{ID: "cisa-kev", Name: "CISA KEV", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", License: "CC0", IntervalHours: 1, Decoder: DecoderKEV},
	{ID: "first-epss", Name: "FIRST EPSS", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://api.first.org/data/v1/epss", License: "Attribution: EPSS by FIRST", IntervalHours: 24, Decoder: DecoderEPSS},
	{ID: "nvd-kev", Name: "NVD affected versions", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://services.nvd.nist.gov/rest/json/cves/2.0", License: nvdNotice, IntervalHours: 24, Decoder: DecoderNVD},
	{ID: ubuntuOSVFeedID, Name: "Ubuntu fixed versions", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://security-metadata.canonical.com/osv/osv-all.tar.xz", License: canonicalNotice, IntervalHours: 24, Decoder: DecoderUbuntuOSV},
	{ID: ubuntuVEXFeedID, Name: "Ubuntu not affected", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://security-metadata.canonical.com/vex/vex-all.tar.xz", License: canonicalNotice, IntervalHours: 24, Decoder: DecoderUbuntuVEX},
	{ID: debianTrackerFeedID, Name: "Debian security tracker", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://security-tracker.debian.org/tracker/data/json", License: debianNotice, IntervalHours: 24, Decoder: DecoderDebianTracker},
	{ID: "nuclei-templates", Name: "nuclei-templates", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", License: "MIT", IntervalHours: 24, Decoder: DecoderNuclei},
	{ID: "ipsum", Name: "IPsum", Kind: KindIOC, Format: FormatLines, URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", License: "Unlicense", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), Aggregate: true, Upstreams: []string{"et-open", "abusech-feodo"}},
	{ID: "et-open", Name: "ET Open compromised IPs", Kind: KindIOC, Format: FormatLines, URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", License: "BSD", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
	{ID: "abusech-feodo", Name: "abuse.ch Feodo Tracker", Kind: KindIOC, Format: FormatLines, URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", License: "CC0", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
	{ID: "tor-exit", Name: "Tor exit list", Kind: KindIOC, Format: FormatLines, URL: "https://check.torproject.org/torbulkexitlist", License: "Attribution: torproject", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), Informational: true},
	{ID: "hagezi-tif", Name: "hagezi TIF", Kind: KindIOC, Format: FormatLines, URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", License: "GPL-3.0, unmodified", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), MaxRows: 250_000, Aggregate: true, Subdomains: true},
}

// BuiltinSources returns the built-in feeds in display order. The slice is a
// copy; the Parser pointers are shared and must be treated as read-only.
func BuiltinSources() []Source {
	return append([]Source(nil), builtinSources...)
}

// BuiltinByID finds a built-in feed.
func BuiltinByID(id string) (Source, bool) {
	for _, s := range builtinSources {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// ProductKey is the matching key between inventory products and KEV entries:
// lower(vendor)|lower(product) (IMPACT.md, DATA_MODEL feeds_vuln).
func ProductKey(vendor, product string) string {
	return strings.ToLower(vendor) + "|" + strings.ToLower(product)
}

// KEVMirrorURL is CISA's own GitHub mirror of the KEV catalog (the cisagov/kev-data repository), where the box looks when
// the CISA address answers 403, a server error or nothing in time (D-91). Same file, same parser, same limits.
const KEVMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

// What a pull of the CISA list records as the address that answered (feeds_source.answered_by, Feed.answered_by).
const (
	AnsweredCISA   = "CISA"
	AnsweredMirror = "CISA GitHub mirror"
)
