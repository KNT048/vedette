package feeds

// Decoder says which parser a built-in feed needs.
type Decoder string

// Built-in decoders.
const (
	DecoderParser    Decoder = "parser"    // the generic custom-format parser with Source.Parser
	DecoderKEV       Decoder = "kev"       // ParseKEV
	DecoderNuclei    Decoder = "nuclei"    // ParseNucleiCVEs
	DecoderNVD       Decoder = "nvd"       // NVDPageURL and ParseNVD (NVD CVE API 2.0, ?hasKev: the exploited-list selector)
	DecoderCVEOrg    Decoder = "cveorg"    // the CVE Program's records (cvelistV5): the daily archive, its changes, CVERecordURL; ParseCVERecord
	DecoderVulnCheck Decoder = "vulncheck" // VulnCheckPageURL and ParseVulnCheckPage (the customer's own key)
	// The distribution backport data: ParseUbuntuOSV, ParseUbuntuVEX, ParseDebianTracker, read as a stream.
	DecoderUbuntuOSV     Decoder = "ubuntu-osv"
	DecoderUbuntuVEX     Decoder = "ubuntu-vex"
	DecoderDebianTracker Decoder = "debian-tracker"
	DecoderAlpineOSV     Decoder = "alpine-osv" // ParseAlpineOSV: OSV.dev's Alpine all.zip
	// The data of CVE tiers 2 and 3.
	DecoderEPSSAll   Decoder = "epss-all"   // ParseEPSSCSV: FIRST's daily file of every EPSS score
	DecoderNVDRecent Decoder = "nvd-recent" // RecentPageURL, WalkPageURL and ParseNVD: the catalogue's NVD records
	// Microsoft's Windows release information pages (parseWinRelPage): the releases core/winrel learns.
	DecoderWinRel Decoder = "windows-releases"
	// ParseSpamhausDROP: the networks of the Spamhaus DROP list.
	DecoderSpamhausDROP Decoder = "spamhaus-drop"
)

// Source is a built-in feed. Built-ins cannot be deleted (INV-4): the
// module stores only enabled, interval_hours and a mirror URL for them.
type Source struct {
	ID            string
	Name          string
	Kind          Kind
	Format        Format
	URL           string // default address; Reset restores it
	License       string
	IntervalHours int // default schedule: 1 for the CISA list (S-FEED-1) and CVE.org, 24 for the other vulnerability feeds, 6 for IOC (24 for Spamhaus DROP, which asks for at most one download a day)
	Decoder       Decoder
	Parser        *Parser // set when Decoder == DecoderParser
	MaxRows       int     // row limit of this source; 0 means MaxRows (50,000)
	// BYOK: the customer's own API key is needed. The feed is off until one is saved, and what it loaded goes
	// when the key is removed or the feed is turned off.
	BYOK bool
	// DefaultOff: the feed is off on a new box until an administrator turns it on (Spamhaus DROP); the box contacts its host only then.
	DefaultOff bool

	// Aggregate: the list is itself a merge of other lists (IPsum, hagezi TIF).
	// It never reaches block alone, and counts with one of its Upstreams as one source.
	Aggregate bool
	Upstreams []string // ids of built-in feeds an aggregate is known to include
	// Informational: the list says what an address is, not that it is malicious
	// (Tor exit nodes). It never counts toward block.
	Informational bool
	// Subdomains: every name the list holds stands for itself and all of its subdomains (hagezi TIF, "Domains (without
	// subdomains)": a listed bad.example also means a.b.bad.example). A source without it lists each name exactly.
	Subdomains bool
	// Weight is how sure a listing by this built-in indicator list is that the value is bad, from 0 to 1 (IOCConfidence). The lists
	// carry no confidence per line, so the weight is what the list is: a confirmed command-and-control list near certain, a curated
	// compromised-host list high, an aggregate by how many lists agree, a list that only says what an address is (Tor exit relays)
	// low. Zero for every other kind of feed.
	Weight float64
	// LevelInURL: the list's address names its level, the number of blocklists an address is on at least (IPsum's levels/N.txt). A
	// listing weighs what that level says (levelWeight); an address that names no level keeps Weight.
	LevelInURL bool
	// C2: the list is of confirmed botnet command-and-control servers (abuse.ch Feodo Tracker). A device that reaches one runs
	// malware, so logs rates such an incident critical.
	C2 bool
	// DropClass: the list is meant to be dropped outright by whoever uses it (Spamhaus DROP, "Don't Route Or Peer"): one such source
	// is enough for the verdict block, as a CC0 list is (BlockClass).
	DropClass bool
	// CreditFetch: the list is credited with the time the box fetched it wherever a listing by it is named (CreditName).
	CreditFetch bool
	// MinHours: the source allows at most one download every MinHours hours (Spamhaus DROP: once a day). Its schedule cannot be set
	// shorter, and neither the pull job nor Fetch now pulls it sooner after a good pull, nor sooner than an hour after any attempt
	// (fetchFloor). 0 for every other source.
	MinHours int
}

func (s Source) rowLimit() int {
	if s.MaxRows > 0 {
		return s.MaxRows
	}
	return MaxRows
}

// BlockClass reports a CC0 IOC list or one meant to be dropped outright (Spamhaus DROP): one such source is enough for `block`
// (INV-12, "one DROP/CC0-class source").
func (s Source) BlockClass() bool { return s.Kind == KindIOC && (s.License == "CC0" || s.DropClass) }

func linesParser() *Parser {
	p := DefaultParser(KindIOC, FormatLines)
	return &p
}

// nvdNotice is the licence line of the NVD feed: NVD data is public domain, and the NVD terms of use ask for this
// sentence (https://nvd.nist.gov/developers/terms-of-use).
const nvdNotice = "Public domain. This product uses the NVD API but is not endorsed or certified by the NVD."

// cveOrgNotice is the licence line of the CVE records feed: the CVE Program Terms of Use allow copies that reproduce MITRE's
// copyright designation and the licence (https://www.cve.org/Legal/TermsOfUse; THIRD_PARTY_NOTICES.md has the clause).
const cveOrgNotice = "CVE Program Terms of Use. CVE records © The MITRE Corporation."

// vulnCheckNotice is the licence line of the VulnCheck feed: VulnCheck KEV is free to use in a product with prominent
// attribution (https://docs.vulncheck.com/community/vulncheck-kev/attribution); the data stays on the box.
const vulnCheckNotice = "VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV), used with your own free VulnCheck Community key. Data stays on this box."

// canonicalNotice and debianNotice are the licence lines of the distribution feeds. Canonical publishes its
// security metadata under CC BY-SA 4.0 (https://security-metadata.canonical.com/osv/LICENSE); the box keeps and shows it
// for its own operator and Vedette ships none of it. The Debian Security Tracker states no licence for its JSON; it is
// used as Trivy and Grype use it, attributed and never redistributed.
const (
	canonicalNotice = "CC BY-SA 4.0, Canonical Ltd. Ubuntu security data."
	debianNotice    = "Debian Security Tracker data; no licence stated. Attributed, not redistributed."
	// alpineNotice: OSV.dev converts Alpine's secdb, CC BY-SA 4.0 (secdb.alpinelinux.org/license.txt; OSV.dev's data
	// sources page lists the same licence for it).
	alpineNotice = "CC BY-SA 4.0, Alpine Linux security database, converted by OSV.dev."
)

// winRelNotice is the licence line of the Windows releases feed: the box reads Microsoft's public release information pages
// for facts (release names, build numbers, dates, KB numbers), as a browser would, under Microsoft's Terms of Use
// (https://www.microsoft.com/legal/terms-of-use); Vedette ships none of their text.
const winRelNotice = "Facts from Microsoft's public Windows release information pages, Microsoft Terms of Use. Not endorsed by Microsoft."

// dropNotice is the licence line of the Spamhaus DROP feed: the list is free under the Spamhaus DROP terms of use
// (https://www.spamhaus.org/drop/terms/); the box fetches it from Spamhaus itself when an administrator turns it on, and Vedette
// ships and redistributes none of it.
const dropNotice = "Spamhaus DROP, (c) The Spamhaus Project. Free under the DROP terms of use (https://www.spamhaus.org/drop/terms/); fetched by this box from spamhaus.org, never redistributed."

// builtinSources is the default list of sourcesMock.ts. Hosts must match the
// list in PRIVACY.md (INV-13) except where the report says otherwise.
var builtinSources = []Source{
	{ID: "cisa-kev", Name: "CISA KEV", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", License: "CC0", IntervalHours: 1, Decoder: DecoderKEV},
	{ID: epssAllFeedID, Name: "EPSS, every CVE", Kind: KindVulnerabilities, Format: FormatCSV, URL: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", License: "Attribution: EPSS by FIRST", IntervalHours: 24, Decoder: DecoderEPSSAll},
	{ID: "nvd-kev", Name: "NVD affected versions", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://services.nvd.nist.gov/rest/json/cves/2.0", License: nvdNotice, IntervalHours: 24, Decoder: DecoderNVD},
	{ID: recentFeedID, Name: "NVD, CVEs of the last 12 months", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://services.nvd.nist.gov/rest/json/cves/2.0", License: nvdNotice, IntervalHours: 24, Decoder: DecoderNVDRecent},
	{ID: cveOrgFeedID, Name: "CVE records", Kind: KindVulnerabilities, Format: FormatJSON, URL: recordsRepo, License: cveOrgNotice, IntervalHours: 1, Decoder: DecoderCVEOrg},
	{ID: vulnCheckFeedID, Name: "VulnCheck KEV", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://api.vulncheck.com/v3/index/vulncheck-kev", License: vulnCheckNotice, IntervalHours: 6, Decoder: DecoderVulnCheck, BYOK: true},
	{ID: ubuntuOSVFeedID, Name: "Ubuntu fixed versions", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://security-metadata.canonical.com/osv/osv-all.tar.xz", License: canonicalNotice, IntervalHours: 24, Decoder: DecoderUbuntuOSV},
	{ID: ubuntuVEXFeedID, Name: "Ubuntu not affected", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://security-metadata.canonical.com/vex/vex-all.tar.xz", License: canonicalNotice, IntervalHours: 24, Decoder: DecoderUbuntuVEX},
	{ID: debianTrackerFeedID, Name: "Debian security tracker", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://security-tracker.debian.org/tracker/data/json", License: debianNotice, IntervalHours: 24, Decoder: DecoderDebianTracker},
	{ID: alpineOSVFeedID, Name: "Alpine fixed versions", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip", License: alpineNotice, IntervalHours: 24, Decoder: DecoderAlpineOSV},
	{ID: winRelFeedID, Name: "Windows releases", Kind: KindVulnerabilities, Format: FormatLines, URL: "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information", License: winRelNotice, IntervalHours: 24, Decoder: DecoderWinRel},
	{ID: oracleLineFeedID, Name: "Oracle release lines", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://www.oracle.com/a/tech/docs/security-alerts/oracle-cpu-csaf-rss.xml", License: oracleNotice, IntervalHours: 6, Decoder: DecoderOracleCSAF},
	{ID: nodeLineFeedID, Name: "Node.js release lines", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json", License: nodeLineNotice, IntervalHours: 24, Decoder: DecoderNodeLines},
	{ID: eolFeedID, Name: "endoflife.date release support", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://endoflife.date/api/v1/products/full", License: eolNotice, IntervalHours: 24, Decoder: DecoderEOL},
	{ID: "nuclei-templates", Name: "nuclei-templates", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", License: "MIT", IntervalHours: 24, Decoder: DecoderNuclei},
	{ID: metasploitFeedID, Name: "Metasploit modules", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json", License: metasploitNotice, IntervalHours: 24, Decoder: DecoderMetasploit},
	{ID: exploitDBFeedID, Name: "Exploit-DB", Kind: KindVulnerabilities, Format: FormatCSV, URL: "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", License: exploitDBNotice, IntervalHours: 24, Decoder: DecoderExploitDB},
	{ID: pocGitHubFeedID, Name: "PoC-in-GitHub", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://codeload.github.com/nomi-sec/PoC-in-GitHub/tar.gz/refs/heads/master", License: pocGitHubNotice, IntervalHours: 24, Decoder: DecoderPoCGitHub},
	{ID: msrcFeedID, Name: "Microsoft exploited CVEs", Kind: KindVulnerabilities, Format: FormatJSON, URL: "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$filter=exploited%20eq%20%27Yes%27", License: msrcNotice, IntervalHours: 6, Decoder: DecoderMSRC},
	{ID: ciscoFeedID, Name: "Cisco PSIRT advisories", Kind: KindVulnerabilities, Format: FormatRSS, URL: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", License: ciscoNotice, IntervalHours: 6, Decoder: DecoderCisco},
	{ID: fortinetFeedID, Name: "Fortinet PSIRT advisories", Kind: KindVulnerabilities, Format: FormatRSS, URL: "https://filestore.fortinet.com/fortiguard/rss/ir.xml", License: fortinetNotice, IntervalHours: 6, Decoder: DecoderFortinet},
	{ID: chromeFeedID, Name: "Chrome Releases", Kind: KindVulnerabilities, Format: FormatRSS, URL: "https://chromereleases.googleblog.com/feeds/posts/default?redirect=false", License: chromeNotice, IntervalHours: 6, Decoder: DecoderChrome},
	{ID: androidFeedID, Name: "Android Security Bulletins", Kind: KindVulnerabilities, Format: FormatLines, URL: "https://source.android.com/docs/security/bulletin/", License: androidNotice, IntervalHours: 6, Decoder: DecoderAndroid},
	{ID: rapid7FeedID, Name: "Rapid7 blog", Kind: KindVulnerabilities, Format: FormatRSS, URL: "https://www.rapid7.com/rss.xml", License: rapid7Notice, IntervalHours: 6, Decoder: DecoderRapid7},
	{ID: gtiFeedID, Name: "Google Threat Intelligence blog", Kind: KindVulnerabilities, Format: FormatRSS, URL: "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", License: gtiNotice, IntervalHours: 6, Decoder: DecoderGTI},
	{ID: "ipsum", Name: "IPsum", Kind: KindIOC, Format: FormatLines, URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", License: "Unlicense", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), Aggregate: true, Upstreams: []string{"et-open", "abusech-feodo"}, Weight: 0.9, LevelInURL: true},
	{ID: "et-open", Name: "ET Open compromised IPs", Kind: KindIOC, Format: FormatLines, URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", License: "BSD", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), Weight: 0.85},
	{ID: "abusech-feodo", Name: "abuse.ch Feodo Tracker", Kind: KindIOC, Format: FormatLines, URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", License: "CC0", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), Weight: 0.95, C2: true},
	{ID: "tor-exit", Name: "Tor exit list", Kind: KindIOC, Format: FormatLines, URL: "https://check.torproject.org/torbulkexitlist", License: "Attribution: torproject", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), Informational: true, Weight: 0.2},
	{ID: "hagezi-tif", Name: "hagezi TIF", Kind: KindIOC, Format: FormatLines, URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", License: "GPL-3.0, unmodified", IntervalHours: 6, Decoder: DecoderParser, Parser: linesParser(), MaxRows: 250_000, Aggregate: true, Subdomains: true, Weight: 0.45},
	{ID: dropFeedID, Name: "Spamhaus DROP", Kind: KindIOC, Format: FormatJSON, URL: "https://www.spamhaus.org/drop/drop_v4.json", License: dropNotice, IntervalHours: 24, Decoder: DecoderSpamhausDROP, MaxRows: dropMaxRows, DefaultOff: true, Weight: 0.9, DropClass: true, CreditFetch: true, MinHours: 24},
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

// KEVMirrorURL is CISA's own GitHub mirror of the KEV catalog (the cisagov/kev-data repository). Every check of the CISA list at its
// built-in address asks it as well as cisa.gov and keeps the newer catalog. Same file, same
// parser, same limits.
const KEVMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

// What a pull of the CISA list records as the address that answered (feeds_source.answered_by, Feed.answered_by).
const (
	AnsweredCISA   = "CISA"
	AnsweredMirror = "CISA GitHub mirror"
)
