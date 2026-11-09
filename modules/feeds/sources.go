package feeds

import "strings"

// Decoder says which parser a built-in feed needs.
type Decoder string

// Built-in decoders.
const (
	DecoderParser Decoder = "parser" // the generic custom-format parser with Source.Parser
	DecoderKEV    Decoder = "kev"    // ParseKEV
	DecoderEPSS   Decoder = "epss"   // ParseEPSS (gzip CSV)
	DecoderNuclei Decoder = "nuclei" // ParseNucleiCVEs
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
	IntervalHours int // default schedule: 24 for vulnerabilities, 6 for IOC
	Decoder       Decoder
	Parser        *Parser // set when Decoder == DecoderParser
}

// BlockClass reports a CC0 IOC list: one such source is enough for `block`
// (INV-12, "one DROP/CC0-class source").
func (s Source) BlockClass() bool { return s.Kind == KindIOC && s.License == "CC0" }

func linesParser() *Parser {
	p := DefaultParser(KindIOC, FormatLines)
	return &p
}

// sslblParser reads abuse.ch SSLBL: "# Listingdate,DstIP,DstPort" comment, then rows.
func sslblParser() *Parser {
	p := DefaultParser(KindIOC, FormatCSV)
	p.HasHeader = false
	p.Fields["indicator"] = fm("2")
	p.Fields["first_seen"] = fm("1")
	return &p
}

// builtinSources is the default list of sourcesMock.ts. Hosts must match the
// list in PRIVACY.md (INV-13) except where the report says otherwise.
var builtinSources = []Source{
	{ID: "cisa-kev", Name: "CISA KEV", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", License: "CC0", IntervalHours: 24, Decoder: DecoderKEV},
	{ID: "first-epss", Name: "FIRST EPSS", Kind: KindVulnerabilities, Format: FormatCSV, URL: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", License: "Attribution: EPSS by FIRST", IntervalHours: 24, Decoder: DecoderEPSS},
	{ID: "nuclei-templates", Name: "nuclei-templates", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", License: "MIT", IntervalHours: 24, Decoder: DecoderNuclei},
	{ID: "ipsum", Name: "IPsum", Kind: KindIOC, Format: FormatLines, URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", License: "Unlicense", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
	{ID: "et-open", Name: "ET Open compromised IPs", Kind: KindIOC, Format: FormatLines, URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", License: "BSD", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
	{ID: "abusech-feodo", Name: "abuse.ch Feodo Tracker", Kind: KindIOC, Format: FormatLines, URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", License: "CC0", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
	{ID: "abusech-sslbl", Name: "abuse.ch SSLBL", Kind: KindIOC, Format: FormatCSV, URL: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", License: "CC0", IntervalHours: 6, Decoder: DecoderParser, Parser: sslblParser()},
	{ID: "tor-exit", Name: "Tor exit list", Kind: KindIOC, Format: FormatLines, URL: "https://check.torproject.org/torbulkexitlist", License: "Attribution: torproject", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
	{ID: "hagezi-tif", Name: "hagezi TIF", Kind: KindIOC, Format: FormatLines, URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt", License: "GPL-3.0, unmodified", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser()},
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
