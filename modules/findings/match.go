package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// Basis says how a finding was established.
type Basis string

// The three bases of a finding (INV-2).
const (
	BasisScan    Basis = "scan"    // a safe scan template confirmed it
	BasisVersion Basis = "version" // the known version is inside the affected range
	BasisProduct Basis = "product" // only the product matches; version unknown or not checked
	BasisPerson  Basis = "person"  // a person confirmed it (Service.Verify): evidence beyond a version match, like a scan
)

// Confidence by basis. product/vendor-only values are the mock's (match.ts).
// ConfVersion sits between a bare product match (0.5) and a scan confirmation (>= 0.95).
const (
	ConfVendorOnly = 0.3
	ConfProduct    = 0.5
	ConfVersion    = 0.7
	ConfScan       = 0.95
)

// Severity is the level given at creation.
type Severity string

// The severities the matcher assigns (INV-5). Critical and high only for a version inside the affected range;
// a match whose version could not be compared is medium.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
)

// Software is one inventory software row of an asset.
type Software struct {
	ID, Display, Vendor, Product, Version string
	// KevKeys are the KEV keys the inventory matched this software to
	// ("vendorproject|product", see productid.NormalizeKey).
	KevKeys []string
	// CPE is an optional CPE 2.3 string of the software; a malformed one is ignored.
	CPE string
	// Source is who reported the row (inventory MatchSoftware.Source: "agent", "manual", "scan", a sensor), "" when unknown.
	// Packaged: an agent read it from the device's package database (deb/rpm), so the distribution ships its fixes
	// (inventory INV-28 (3)); only an "agent" row counts.
	Source   string
	Packaged bool
	// PkgVersion and PkgSource: a packaged deb row's full Debian version ("1:9.6p1-3ubuntu13.14") and source package
	// ("openssh"), read against what Ubuntu or Debian say about the CVE (Vuln.Distro); "" otherwise.
	PkgVersion, PkgSource string
	// Banner is what a service says about its build beside the version (nmap's extrainfo, "Ubuntu Linux; protocol 2.0"); "" when
	// none. Untrusted; only read for the platform it names.
	Banner string
	// ReportedSource is, on a person's correction of a reported row (Source "manual", inventory INV-41), the source of the row it
	// replaces: the distribution and platform rules of that source still hold (builtBy, #950); "" otherwise.
	ReportedSource string
	// Correction names the person's correction this row is ("it@acme.example corrected OpenSSH 10.2 (nmap) to OpenSSH 10.2p1 on
	// 17 Nov 2026"), for the history of a finding it closes or reopens; "" otherwise.
	Correction string
	// SetBy is, on a person's entry (Source "manual"), who entered the version: a finding a person's change of it closes is
	// handled by that person, not by Vedette, and one it opens again names them; "" when not known or not a person's entry.
	SetBy string
	// Superseded names, on a reported row, a person's correction of an earlier reading of it that rests since the source moved on
	// (inventory INV-41, #950); "" otherwise.
	Superseded string
	// Key is the row's identity in inventory (source, vendor, product, version): a row that comes back with the Key of a "not installed"
	// mark is that very row (INV-6c). MarkedAt is, on a row of Asset.NotInstalled, when the person said it is not installed.
	Key      string
	MarkedAt time.Time
	MarkedBy string // on a row of Asset.NotInstalled: who said it is not installed ("" when unknown)
	// SeenAt is when the row's source last reported it (zero when unknown): for an agent's row, the day of the list its version
	// comes from, which the finding page names once no agent reports the device.
	SeenAt time.Time
	// Guess: a sensor only guessed the row (inventory's os_guess reading: an OS fingerprint, an ESXi build the build table does not
	// list); it is never matched until a person gives the software with its version.
	Guess bool
	// stated: the row holds the very release of the network OS the device states about itself (statedRow, set by deviceSoftware):
	// whoever recorded it, its version is the device's own word.
	stated bool
	// AIProduct is the catalogue product the customer's AI chose for the line when nothing else identifies it (aiidentity.go: one
	// choice per cleaned publisher and name, set on the line when findings reads its device); nil otherwise. It only opens: a version
	// inside one of its ranges is a finding, and what its ranges say otherwise decides nothing (devMatch.aiGuard).
	AIProduct *AIProduct `json:",omitempty"`
}

// builtBy is the source whose build rules the row follows: the reported row's for a person's correction of it, else its own.
func (s Software) builtBy() string {
	if s.Source == "manual" && s.ReportedSource != "" {
		return s.ReportedSource
	}
	return s.Source
}

// Asset is what the matcher needs to know about a device.
type Asset struct {
	ID    string
	Name  string // hostname, or the IP when there is none
	OS    string // current operating system as inventory folds it ("Ubuntu 26.04.1 LTS", LLDP "JUNOS 15.1R7.9"); "" when unknown
	Model string // the model the device states ("EX4200-48T"); "" when unknown (Juniper series)
	// StatedOS is the OS the device states itself (LLDP or SNMP system description, "JUNOS 15.1R7.9"), even when another
	// source's value won OS; "" when none (deviceSoftware reads it, never nmap's guess).
	StatedOS string
	// AgentOS is the OS the device's own agent reports (osquery, Wazuh, the box's own reading), even when another source's value
	// won OS (a person's); "" when no agent reported one. Only it is evidence of the platform of an agent row (#790:
	// the folded OS of a Wazuh-only device can be nmap's or DHCP's guess).
	AgentOS string
	// SNMPOS is the OS the device states in answer to Vedette's own SNMP read of its address (source snmp), "" when none: unlike an
	// LLDP frame, which any host on the wire can send with another device's MAC, it is the device answering at its own address
	// (only it may make a Junos statement count for scan-seen rows).
	SNMPOS string
	// StatedOSAt and SNMPOSAt are when the device last stated StatedOS and SNMPOS (zero when unknown): the time of the version of its
	// network OS row (deviceOS, known_version.seen_at).
	StatedOSAt, SNMPOSAt time.Time
	// MAC is the device's MAC at its own address (inventory's current MAC of a device with an IP), "" when none: with an OUI of Juniper
	// Networks it lets an LLDP statement of Junos count for the device's scan-seen rows (networkStated).
	MAC string
	// ManualOS is the OS a person set on the device (inventory INV-41), "" when none: a person's answer to "Could not be checked",
	// evidence of the platform of every row (platformOS).
	ManualOS string
	Software []Software
	// OSCorrection names a person's corrected OS ("it@acme.example set the OS to Alpine Linux 3.23 on 17 Nov 2026", inventory INV-41),
	// for the history of a finding it closes or reopens (#950); "" when none.
	OSCorrection string
	// StaleCorrections names the device's resting corrections (inventory INV-41), for the history of a finding that stops
	// matching because of one; nil when none.
	StaleCorrections []string
	// NotInstalled are the reported rows a person said are not installed on the device (inventory INV-41 (6)), as the source reports
	// them, with Correction naming the person; they are not in Software. The open findings only they produce close (INV-6c).
	NotInstalled []Software
	// rejectedBy is, per cleaned publisher and name, the products a person said the line is not ("Not this product", by
	// CatalogueProduct.key) and who said it: a finding opened through the AI's choice of one of them closes as that person's
	// (identityRejectedBy); nil when none. Shared, never changed.
	rejectedBy map[nameKey]map[string]string
	// winList is the whole stored exploited list a Windows release row's build month is read from when
	// the match gets only a part of it (Reconcile's backlog and recent writes); nil: the match's own list.
	winList []Vuln
}

// Affected is one NVD cpeMatch entry (vulnerable=true) of a CVE.
type Affected struct {
	CPE   string // CPE 2.3 criteria; a malformed one is ignored
	Range VersionRange
	// AffectedOnly: a CVE record row read beside NVD's whose product's list is not complete (feeds matchRows): a version inside it is
	// affected, a version outside it proves nothing (the record and NVD disagree: the affected answer wins). VendorList: a row of a
	// record list that states what every unlisted version is (complete): an exact version it lists decides like a range.
	AffectedOnly, VendorList bool
	// Lost: a CVE record row of a product an entry of which the record reader could not keep (feeds Range.Lost): beside AffectedOnly,
	// no other reading of the record may prove the line not affected while such a row names it (lostRow).
	Lost bool
	// VendorCNA: the CVE record's assigner is the row's vendor (feeds Range.VendorCNA): a list of exact releases it gives is the vendor's
	// enumeration, where a third party's names the build it tested (newerThanListed).
	VendorCNA bool
	// LineFix: a release a partial CVE record states fixed above this row's end, for the release line the row ends on (a lone
	// "unaffected" version above every affected row: OSV's fixed); read only by pastRecordFix.
	LineFix string
	// Platforms are the operating systems ("vendor:product") of NVD's "running on" condition of the entry's configuration: the
	// environment the affected product runs on (cpeMatch vulnerable false), never an affected product itself (platformOnly). nil for
	// none and for the CVE record's rows.
	Platforms []string
	// parsed is CPE already parsed; nil: parse when read.
	parsed *CPE
}

// cpe is the entry's parsed CPE.
func (af Affected) cpe() (CPE, error) {
	if af.parsed != nil {
		return *af.parsed, nil
	}
	return ParseCPE(af.CPE)
}

// Vuln is a KEV entry with the optional NVD affected configurations.
type Vuln struct {
	CVE string
	// Stamp changes whenever the CVE's record may say something new (feeds RecordStamps): a check of its advisories is keyed on it.
	Stamp      string
	Vendor     string // KEV vendorProject
	Product    string // KEV product
	Name       string // KEV vulnerabilityName: it names the Juniper series a Junos flaw is about
	Ransomware bool
	EPSS       float64   // 0 when unknown
	DateAdded  time.Time // when CISA added the entry to KEV; zero when unknown (Reconcile treats that as backlog)
	// Published is the day NVD published the CVE; zero when unknown, which counts as recent (never old).
	Published time.Time
	// OutsideWindow: the CVE is outside the reporting window (feeds Store.OutsideWindow). The matcher never reads such an entry
	// (inWindow): its findings close as outside_window and no question asks about it.
	OutsideWindow bool
	// HasTemplate: a safe scan template checks the CVE (nuclei). The age rule never drops such a pair (#803): the
	// scan engines plan their checks from the device's findings, so the finding must stay for a scan to confirm or clear it.
	HasTemplate bool
	Affected    []Affected
	Source      string // "" or "cisa-kev": the CISA list; "vulncheck-kev": VulnCheck KEV; names the list in evidence texts
	RangesFrom  string // where Affected comes from: "" NVD, RangesCVEOrg or RangesCVEOrgPartial the CNA's CVE.org record
	// Schemed are the ranges a vendor states in its own notation (an ESXi build per release train), read in the version scheme of
	// the product they name: the matcher decides a line by them before the generic comparison when they reach its release line
	// (schemeJudge), and FixOf names the vendor's fixed release of the device's train from them.
	Schemed []SchemedRange
	// Lines are what vendor line sources state about the CVE per release line (feeds_line_status), LineCovers the products they speak
	// about it for, LineSupport the support of those products' lines: lineJudge reads them first (M-13).
	Lines       []LineRow
	LineCovers  []LineCover
	LineSupport []LineSupport
	// Origin is who stated Affected: RangeNVD, RangeCNA or RangeADP ("" reads RangesFrom): NVD's when NVD has any, the CVE record's
	// rows read beside them marked (Affected.AffectedOnly, VendorList); the finding stores it (range_origin), RangeCNA when the record's
	// rows beside NVD's are what call it affected (recordDecided).
	Origin string
	// NVDAnswered: the feeds module recorded an answer for the CVE's affected configurations (feeds_affected_cve: NVD's, or the
	// CVE.org record's), even an empty one. False before the NVD pull, with it off or failing: an empty Affected then says nothing
	// about NVD, so the "could not be checked" list does not claim "no NVD data" (#910, #920).
	NVDAnswered bool
	// Distro is what Ubuntu and Debian say about the CVE in their own packages, and Alpine per branch (read only for
	// a CVE of the platform list, distroFixes): per release and source package, fixed in a version or not affected. Empty when the
	// distribution feeds are off or have no word on it.
	Distro []DistroFix
	// DistroLoading: the distributions one of whose feeds is on but holds no row yet (feeds' DistroLoading): a platform-limited
	// CVE whose fixed list that distribution's data gives stays a question then, instead of NVD deciding (it would raise a false finding).
	DistroLoading map[string]bool
	// DistroOn: the distributions ("ubuntu", "debian") whose feed of fixed and affected rows is on and loaded or loading (feeds' DistroOn). A
	// package such a distribution built is judged by its data alone (distroDecides); with its feeds off, NVD's ranges decide as before.
	DistroOn map[string]bool
}

// RangesCVEOrg and RangesCVEOrgPartial mark a Vuln whose affected versions come from the CNA's CVE.org record because
// NVD has none. Only a complete list (the CNA states what an unlisted version is) may prove "not affected"; on a
// partial one a version outside every row stays a product match, never closed.
const (
	RangesCVEOrg        = "cve.org"
	RangesCVEOrgPartial = "cve.org-partial"
)

// SchemedRange is one range a vendor states in its notation, read in its product's version scheme.
type SchemedRange struct {
	Product string                // the core/productid key of the product it names
	Scheme  *versionscheme.Scheme // the product's version scheme
	Span    versionscheme.Span
	Origin  string // RangeNVD, RangeCNA, RangeADP
	// Unaffected is a range the vendor states NOT affected ("0 before 24.4R1") for every device (feeds unaffectedRows); ModelOnly an
	// affected range that holds only on some models (Juniper's EX4000). Both only ever support "not affected" (schemeJudge), never "affected".
	Unaffected, ModelOnly bool
	// Platforms are the hardware a ModelOnly row holds on, as the record names it ("QRX Series", "ZX4100"); nil when not known.
	// Complete says the row is the vendor's own record stating every version it does not list unaffected (defaultStatus unaffected from
	// the product's own CNA): with Platforms, the vendor's word that the product is affected on that hardware only (otherHardware); on a
	// row that is one release, what lets a release the list does not name be closed (trainCleared).
	Platforms []string
	Complete  bool
	// Unread is a vendor's affected row of the product that does not read in its scheme (Juniper's "22.2" lessThan "22.2*"): no
	// span, never judged; it only says the rows that read are not the vendor's whole word (olderThanEveryStart does not apply).
	Unread bool
}

// rangeOrigin is the origin of the ranges the matcher compares for v (fnd_finding.range_origin).
func (v Vuln) rangeOrigin() string {
	switch {
	case v.Origin != "":
		return v.Origin
	case v.fromCVEOrg():
		return RangeCNA
	}
	return RangeNVD
}

// listName is how texts name the list the entry is on: VulnCheck's entries are never called CISA's.
func (v Vuln) listName() string {
	if v.Source == SourceVulnCheck {
		return "VulnCheck KEV"
	}
	return "CISA"
}

// SourceVulnCheck is Vuln.Source and KevInfo.Source of an entry only VulnCheck KEV lists.
const SourceVulnCheck = "vulncheck-kev"

func (v Vuln) fromCVEOrg() bool {
	return v.RangesFrom == RangesCVEOrg || v.RangesFrom == RangesCVEOrgPartial
}

// rangesBy names the source of v's affected versions in a sentence (first: at its start).
func (v Vuln) rangesBy(first bool) string {
	switch {
	case !v.fromCVEOrg():
		return "NVD"
	case first:
		return "The CVE.org record"
	}
	return "the CVE.org record"
}

// DistroFix is one distribution's word on a CVE for one source package of one release (feeds.DistroFix).
type DistroFix struct {
	Distro  string // "ubuntu", "debian" or "alpine" (DistroAlpine)
	Release string // "24.04", "12", "3.23" (an Alpine branch)
	Package string // source package
	Status  string // "fixed", "not_affected" or "open" (affected, no fix yet)
	Fixed   string // the first fixed version (status fixed)
	Pro     bool   // the fix is in Ubuntu Pro (ESM) only
	Reason  string // status open from Debian: why no security update comes (feeds.DistroReason*), "" otherwise
}

// Evidence is the explanation shown with a finding.
type Evidence struct {
	Summary   string
	Template  string // scan template id, only for basis scan
	Request   string
	Response  string
	CheckedAt time.Time
	// Agent: the version compared is the one the device's own agent reports installed (an "agent" software row: osquery, Wazuh,
	// the box's package list), not a banner, a scan's guess or a person's entry. The page then says "Detected by the
	// agent" and does not ask the person to look the version up.
	Agent bool
	// AgentRow: a product-only match (basis product) on a row the device's own agent reported: the agent gave the installed
	// version and Vedette could not compare it with NVD's data, so the page does not say the version is missing or ask to add it.
	AgentRow bool
	// Prior is, on a finding a person confirmed (basis person), the basis it had before: Undo returns to it. Stored, never sent.
	Prior Basis
	// Source is, on a version match (basis version), who stated the version when it is the device itself over a channel that
	// answers for it: SourceSNMP (the device's answer to Vedette's SNMP read with its community) or SourceAgent (the device's own
	// agent: its OS or package list); "" otherwise (a banner, an OS guess, a person's entry). Set only when the version is inside a
	// range with an end that covers it (a fix exists past it): then the finding is confirmed (INV-2, Finding.ByDevice).
	Source string
	// Read is the reading of the software row the matcher compared (who read it, its version and package release, when): stored with a
	// version match, never sent. A later proof that the same software's version moved outside every range is an update the device got
	// (Finding.FixedByUpdate) only against it; nil on a finding written before it was kept (priorReading then reads the sentence).
	Read *Reading
	// Identity is, on a finding opened through the product the customer's AI chose for the line (Software.AIProduct), that choice:
	// the finding page says "Identified by AI as <title>" and offers "Not this product". nil for any other finding.
	Identity *IdentityNote `json:",omitempty"`
}

// IdentityNote is the identification a finding rests on when the line's own names do not reach the CVE (Evidence.Identity).
type IdentityNote struct {
	Method          string // IdentityAI
	Vendor, Product string // the catalogue product chosen
	Title           string // its readable name
	// Publisher and Name are the line's cleaned publisher and name the choice is stored under (IdentityKey).
	Publisher, Name string
}

// Reading is one reading of a software row as the matcher compared it (Evidence.Read).
type Reading struct {
	Software string    // the software's name without its version ("WinRAR")
	Source   string    // the row's source (Software.Source: agent, snmp, manual, nmap, scan, ...), "" when unknown
	Version  string    // the version compared ("6.24")
	Pkg      string    // the package release of a distribution's package ("10.2_p1-r1", "1:9.6p1-3ubuntu13.14"), "" otherwise
	At       time.Time // when the source read it (Software.SeenAt), zero when unknown
}

// readingOf is the reading of row s as the matcher compares it.
func readingOf(s Software, in swInfo) *Reading {
	return &Reading{Software: softwareName(s.Display, s.Version), Source: s.Source, Version: clean(in.ver), Pkg: clean(strings.TrimSpace(s.PkgVersion)), At: s.SeenAt}
}

// The device-stated sources of Evidence.Source.
const (
	SourceSNMP  = "snmp"
	SourceAgent = "agent"
)

// deviceStated reports whether the evidence says the device itself stated the version that is inside the affected range.
func (e *Evidence) deviceStated() bool {
	return e != nil && (e.Source == SourceSNMP || e.Source == SourceAgent)
}

// Match is a finding the matcher would create: suspected, or confirmed when the device itself stated the version (Evidence.Source).
type Match struct {
	CVE             string
	SoftwareID      string
	SoftwareDisplay string
	Basis           Basis
	Confidence      float64
	Severity        Severity
	Evidence        Evidence
	why             string // The platform sentence of a match ruled out by the platform (MatchResult.OtherPlatform)
	// upstream: a match on NVD's upstream ranges of a package the distribution built that its data has no word on (awaitingDistro, or
	// upstreamJudges for data of fixed releases only): the version compared is the upstream one, never the package release
	upstream bool
	every    bool // NVD lists every version of the product as affected: the version cannot change it (#803)
	// agreed: the verdict rests on every reading of the record giving it (everyReading); the sentence names them. "" otherwise.
	agreed string
	// others: a product match whose NVD list names only other products than the row (#904, nvdOthersOnly): those products ("app
	// installer"), "" otherwise. The agent's version is then compared with nothing, so an agent row is no evidence (confirmedMatch).
	others string
	// backed: a product match that still rests on version evidence: the device's Windows revision is below the fix build NVD
	// gives for the release of the other kind on the same build (winLaterNote, e.g. CVE-2024-43572 on Server 2025 26100.1742).
	backed bool
	// gap: for a match MatchResult.NameOnly drops, why no version could be compared (nameOnlyWhy), for the history sentences; said:
	// the evidence sentence the product match had (what the finding said before name-only matches were dropped), kept for the tests of the rules behind it.
	gap, said string
	listed    bool // NameOnly: the CVE is on the device's could-not-check list (the audit line says so only then, #939)
	// ask: a platform-limited CVE that needs a person's answer on the row (outQuestion): no finding, a could-not-check row.
	// fix: the distribution's fixed releases it was asked against (from Vuln.Distro), for AskedWhy; nil when none.
	fix *platformFix
	ask askKind
	// answer: with ask, the package release a person gave that is no release of the distribution (the question says so).
	answer string
	// pkgFixed: a proof from the distribution's fixed package release, not from another platform.
	pkgFixed bool
	// each: on the proof NotAffected carries for a CVE, the proof of every software line of the product, this one included (a device
	// with two lines of the product has two sentences: each closed finding takes its own line's, never the other line's).
	each []Match
	// provedOn: for a proof from a version, the version or package release the matcher compared ("" when none: another platform, a
	// distribution's blanket word); stored on the finding it closes (Finding.ProvedVersion).
	provedOn string
	// bounded: a version match inside a range with an end (a fix to install), a CVE record's "every version" (fromZero) or below the
	// distribution's fixed package; not an
	// exact version NVD lists, a range with only a start, or every version (#910: the only match a row NVD alone ties to the entry
	// may give, viaNVD; #913).
	bounded bool
	// Lines are the matches of the same entry on the device's other software lines (another ID than SoftwareID) that stand on their
	// own (version evidence, or a CVE a safe check reads), the best match of each line: a CVE on Java 8 and Java 21 is two findings.
	Lines []Match
}

// otherLines is Match.Lines of best: of the other matches of the entry, the best one of each other software line that would stand
// as a finding by itself (the age and name-only rules of best applied to it).
func otherLines(best Match, matched []Match, v Vuln, now time.Time) []Match {
	var out []Match
	at := map[string]int{}
	for _, m := range matched {
		if m.SoftwareID == "" || m.SoftwareID == best.SoftwareID {
			continue
		}
		if aged(v, now) && !confirmedMatch(m) && !v.HasTemplate || !versionBacked(m) && !v.HasTemplate {
			continue
		}
		if i, ok := at[m.SoftwareID]; ok {
			if betterMatch(m, out[i]) {
				out[i] = m
			}
			continue
		}
		at[m.SoftwareID] = len(out)
		out = append(out, m)
	}
	return out
}

// MatchResult separates what is new from what the asset already has, so the
// caller knows which pairs to create and which only to touch (idempotent by
// (asset_id, cve), INV-6).
type MatchResult struct {
	New      []Match
	Existing []Match // pair already present (open or closed): never recreated or reopened
	// NeedVersion lists, per software, the exploited CVEs of its product that cannot be checked because the
	// software has no usable version: one item for the device, not one finding per CVE.
	NeedVersion []VersionNeeded
	// NotAffected lists the CVEs the device has a finding for that the matcher proves do not apply: every
	// software of the entry's product has a readable version outside every NVD range (or its OS release is not one
	// the entry lists), none needs a version, none matches. Evidence.Summary is the sentence that closes the finding.
	NotAffected []Match
	// Unlisted lists the CVEs the device has a finding for whose "Multiple Products" entry NVD lists only other products
	//: no finding, and no proof either (NVD's list can lag the vendor's advisory), so the finding stays open for a
	// person. Evidence.Summary is the sentence of its no_longer_matches history row.
	Unlisted []Match
	// Retired lists the Unlisted CVEs that are settled: NVD names none of the device's software of that vendor and
	// CISA added the entry at least SettledKEV ago, so NVD's list has had a year to follow the advisory. The current
	// matcher would not create such a finding on a fresh device either: the service closes an open one of basis product
	// (never version, scan or a person's) with Evidence.Summary as its note. Each one is also in Unlisted.
	Retired []Match
	// OtherPlatform lists, whatever the device already has, the CVEs ruled out only because the evidence names another platform
	// than the one the CVE affects (CVE-2026-123158 on an OpenSSH that says it is Ubuntu's build). Evidence.Summary is
	// the reason ("… affects only …; the software reports 9.6p1 Ubuntu 3ubuntu13.20."), for a page that lists none of them, such as
	// exposure's. A device that has the finding also gets it in NotAffected, with the sentence that closes it.
	OtherPlatform []Match
	// Aged lists, whatever the device already has, the matches the age rule drops (S-TIER-4): the KEV CVE was
	// published more than AgeLimit ago and the match is product-only (basis product: no version compared). No finding is made
	// for it; the service closes an open suspected finding of
	// that pair with Evidence.Summary (AgedNote first) as its note, and a later confirmed match reopens it. Exposure lists
	// them as ruled out, with the reason.
	Aged []Match
	// NotComparable lists the exploited CVEs of the network OS the device states (network-os.json) when its version has no order
	// Vedette can compare (scheme none, classic Cisco IOS "15.2(4)M3"; #910 phase 1): no finding and no "add the version" item,
	// for the "could not be checked" list (reason not_comparable); and, on the OS row whose version it orders, the entries CISA's key
	// names but whose NVD list names only another product (Reason NotComparableOtherProduct, #919).
	NotComparable []NotComparable
	// NameOnly lists, whatever the device already has, the matches that rest on the product name only: basis product with
	// no version evidence (not NVD's "every version", not a Windows fix build the revision is below), other than a CVE a scan
	// template checks on a row the agent did not report (the scan is its check). No finding is made for it; the CVE goes to
	// Unchecked like any row Vedette could not compare, and the service closes an open suspected product finding of that pair with
	// Evidence.Summary (NameOnlyNote first) as its note. A later match that compares a version reopens it.
	NameOnly []Match
	// Unchecked lists, per software row, the exploited CVEs of software the device has that gave no finding, no NeedVersion
	// item and no proof (#910 phase 1, uncheckedRow): a row CISA's key or NVD's list names that Vedette could not compare, a
	// product match the age rule drops, and NotComparable. Independent of have.
	Unchecked []Unchecked
	// Asked lists, whatever the device already has, the platform-limited CVEs no row decides until a person answers: the
	// platform is not known, or it is the distribution of the fixed list and the package release is not. No finding; each is in
	// Unchecked with its question, and the service closes an open suspected finding of the pair with Evidence.Summary (AskedNote
	// first). The answer reopens it (a release below the fix) or proves it (closed with that reason).
	Asked []Match
}

// AgeLimit is the age from which a KEV CVE becomes a finding only on confirmed evidence: published before now minus
// 365 days, judged at each match, so a CVE ages out by itself.
const AgeLimit = 365 * 24 * time.Hour

// AgedNote starts the note of a finding the age rule closed (S-TIER-4); ReopenOnMatch recognises it.
const AgedNote = "Older than 12 months and matched by the product name only"

// aged reports whether v is older than AgeLimit: its age runs from the LATER of the
// day NVD published it and the day the exploited list added it (DateAdded: CISA's, or VulnCheck's for an entry only it lists),
// so KEV news is never hidden (CVE-2008-4250 added in 2026 is recent). An unknown day of either kind is never aged: a missing
// date never closes a finding.
func aged(v Vuln, now time.Time) bool {
	cut := now.Add(-AgeLimit)
	return !v.Published.IsZero() && v.Published.Before(cut) && !v.DateAdded.IsZero() && v.DateAdded.Before(cut)
}

// confirmedMatch reports whether a matcher's match on an old KEV CVE stands: it
// compared a version (whoever gave it: the agent, the distribution, SNMP or LLDP, a person, a service's
// banner), a scan engine hit it, or NVD lists every version of the product as affected (no version could change it). Only
// a product-only match whose version would decide it is dropped: the noise of XP-era rows on Server 2025, while
// CVE-2018-13379 on an unpatched FortiGate stays. Labels are unchanged (a banner stays suspected, a typed version is the person's word). A product
// match on a row the device's own agent reported (Evidence.AgentRow) stands too: the agent gave the installed version and only
// Vedette could not compare it, which is agent evidence, not a guess (an unpatched Windows Server 2025 build 26100.1742 had
// CVE-2024-43572 and CVE-2024-43573 closed for their age). Not when NVD's list names only other products than the row (#904,
// Match.others: CVE-2015-1671 lists .NET Framework, Lync, Silverlight and Live Meeting, CISA "Microsoft Windows"): the agent's
// version is then compared with nothing NVD names, so the age rule drops it like any product-only guess.
//
// A product match on an agent row is no longer confirmed: the agent gave a version Vedette could not
// compare, which is no version evidence. confirmedMatch is versionBacked.
func confirmedMatch(m Match) bool {
	return versionBacked(m)
}

// versionBacked says whether a match rests on version evidence: a version or scan match, NVD's list of every version of the
// product (no version could change it), or a Windows fix build the device's revision is below (Match.backed).
func versionBacked(m Match) bool {
	return m.Basis != BasisProduct || m.every || m.backed
}

// Gap is, for a match MatchResult.NameOnly lists, why no version could be compared ("Vedette cannot compare version 15.2(4)M3 of …").
func (m Match) Gap() string { return m.gap }

// NameOnlyNote starts the note of a finding closed because it rested on the product name only; ReopenOnMatch recognises it.
const NameOnlyNote = "Closed: no version evidence"

// nameOnlyWhy says, for a match NameOnly drops, why no version was compared: the reason the "Could not be checked" list gives it
// (uncheckedReason), in a sentence, and plainly for a Windows build core/winrel does not know (an Insider build newer than the table).
func nameOnlyWhy(s Software, in swInfo, v Vuln, r UncheckedReason, listed bool) string {
	sw := clean(s.Display)
	switch {
	case len(v.Affected) == 0 && !v.NVDAnswered: // Vedette has not read NVD's answer, NVD may have one
		return fmt.Sprintf("Vedette is waiting for NVD's data for %s", v.CVE)
	case !listed && len(v.Affected) == 0 || r == UncheckedNoNVDData:
		return fmt.Sprintf("NVD has not published which products %s affects yet", v.CVE)
	}
	if b, ok := winUnknownBuild(s, in); ok && r == UncheckedNotComparable {
		// Vedette knows its own table and the releases Microsoft's release information lists (feed Windows releases), so a
		// build neither has is an Insider Preview build, for which Microsoft publishes no fixed builds, or newer than the list on the box
		where := "is not a Windows release Vedette knows (an Insider or other pre-release build)"
		if b > winrelNewest() {
			where = "is newer than every Windows release Vedette knows (an Insider build, or a release not yet in its list)"
		}
		return fmt.Sprintf("Windows build %d %s, so Vedette cannot compare %s with the builds NVD lists for %s", b, where, clean(in.ver), v.CVE)
	}
	switch r {
	case UncheckedNoNVDVersions:
		if versionGiven(in.ver) { // NVD may name releases or updates, just nothing Vedette can order
			return fmt.Sprintf("NVD lists %s for %s without versions Vedette can compare with %s", sw, v.CVE, clean(in.ver))
		}
		return fmt.Sprintf("NVD lists %s for %s without versions", sw, v.CVE)
	case UncheckedNotNamed: // the products may be this one under a name Vedette does not tie to it
		return fmt.Sprintf("NVD lists %s for %s, names Vedette does not tie to %s", v.CVE, nvdProducts(v.Vendor, v.Affected), sw)
	}
	if _, _, _, lone := pinnedInside(in, v, keyIDs(v)); lone != "" { // one edition listed, the device's not known
		return fmt.Sprintf("NVD lists %s for the %s edition of %s only, and Vedette cannot tell which edition this is", v.CVE, lone, sw)
	}
	return fmt.Sprintf("Vedette cannot compare version %s of %s with the versions NVD lists for %s", clean(in.ver), sw, v.CVE)
}

// nameOnlySummary is the note of a finding closed for having no version evidence: NameOnlyNote, why, and where the CVE is now.
func nameOnlySummary(v Vuln, why string, listed bool) string {
	where := fmt.Sprintf("so %s is now listed under \"Could not be checked\" for this device", v.CVE)
	if !listed {
		where = fmt.Sprintf("so Vedette does not list %s as a finding", v.CVE)
	}
	return fmt.Sprintf("%s: %s. A finding needs a version Vedette can compare or a scan that finds the flaw, %s. Vedette reopens this finding if a later match compares the version.", NameOnlyNote, why, where)
}

// agedSummary is the note of a finding the age rule closes.
func agedSummary(v Vuln) string {
	return fmt.Sprintf("%s: %s was published on %s and added to %s's list on %s, both more than 12 months ago, and Vedette could not compare a version (it matched the product name only). Vedette reopens this finding when it can compare the version (from the agent, the device or one you enter) or a scan that reads the version finds it.",
		AgedNote, v.CVE, orgtime.CalendarDay(v.Published), v.listName(), orgtime.CalendarDay(v.DateAdded))
}

// agedGapSummary is agedSummary with why no version was compared (nameOnlyWhy) and where the CVE is now.
func agedGapSummary(v Vuln, why string) string {
	return fmt.Sprintf("%s: %s was published on %s and added to %s's list on %s, both more than 12 months ago, and %s. It is listed under \"Could not be checked\" for this device; Vedette reopens this finding when it can compare the version.",
		AgedNote, v.CVE, orgtime.CalendarDay(v.Published), v.listName(), orgtime.CalendarDay(v.DateAdded), why)
}

// agedOthersSummary is the note of a finding the age rule closes because NVD's list names only other products than its row (#904).
// It names the software once; a very long display or product list is clipped by AutoResolve (MaxNote) like any note.
func agedOthersSummary(v Vuln, m Match) string {
	return fmt.Sprintf("%s: %s was published on %s and added to %s's list on %s, both more than 12 months ago, and NVD lists it for %s, not %s, so no version could be compared. Vedette reopens this finding if NVD's data names this software or a scan finds it.",
		AgedNote, v.CVE, orgtime.CalendarDay(v.Published), v.listName(), orgtime.CalendarDay(v.DateAdded), m.others, m.SoftwareDisplay)
}

// SettledKEV is how long a "Multiple Products" entry must have been in KEV before NVD's product list for it is taken as
// settled, so that an old product finding NVD's list leaves out may close by itself. Recent entries stay
// open at medium with the note, because NVD's list lags the vendor's advisory in the months after publication.
const SettledKEV = 365 * 24 * time.Hour

// VersionNeeded is a software whose product is on the exploited list but whose version is missing or unreadable.
type VersionNeeded struct {
	SoftwareID, Software string
	Version              string   // as stored; "" when missing
	CVEs                 []string // the CVEs that the version would decide, in list order, each once
}

func isMultiProduct(product string) bool {
	return strings.EqualFold(strings.TrimSpace(product), "multiple products")
}

// ValidCVE reports whether s matches ^CVE-\d{4}-\d{4,}$.
func ValidCVE(s string) bool {
	rest, ok := strings.CutPrefix(s, "CVE-")
	if !ok {
		return false
	}
	year, seq, ok := strings.Cut(rest, "-")
	if !ok || len(year) != 4 || len(seq) < 4 {
		return false
	}
	for _, part := range []string{year, seq} {
		for i := 0; i < len(part); i++ {
			if !isDigit(part[i]) {
				return false
			}
		}
	}
	return true
}

// MatchAsset matches the asset's software against the KEV entries. have holds
// the CVEs the asset already has a finding for (any status). Vulns with an
// invalid CVE id are skipped. Per CVE at most one match is produced, the
// strongest one (version before product, then input order).
//
// Per software: the KEV key must match (or, for "Multiple products", the vendor; then
// only an NVD entry naming the software itself can give a finding), or NVD's
// CPE list for the entry names the software (#910, viaNVD: CISA names a component such
// as "Chromium V8" or "Win32k", or another product); that path gives only a version
// match or a proof, never a product match nor an "add the version" item.
// Then the NVD configurations decide: the version inside a range gives
// basis version, outside every applicable range gives no finding, a given
// version that cannot be compared (no NVD data, a scheme Vedette cannot read,
// such as Cisco "15.2(4)M3") gives basis product at severity medium. A software
// with no version at all (missing, a placeholder such as "0", or words without a
// number such as "latest") gives no finding for an undecided CVE: the CVE is
// counted in the software's NeedVersion item instead, unless NVD lists every
// version of the product as affected (then basis product, medium).
func MatchAsset(a Asset, vulns []Vuln, have map[string]bool, now time.Time) MatchResult {
	return newDevMatch(a, vulns, now).result(nil, have)
}

// devMatch is one device prepared for the matcher against one list of entries: its rows read once (deviceSoftware, swInfo, KEV keys
// normalised), the rows each entry's NVD list may name, and each entry's reading of the rows, computed when first asked and kept.
// result assembles the MatchResult of the whole list or of a part of it, for the findings the device has, without reading the rows
// again. The result of a part is exactly MatchAsset of that part when the device's Windows list (Asset.winList) is the whole list, as
// the match pass gives it: an entry's reading depends on the device, the Windows list and the entry alone.
type devMatch struct {
	a         Asset
	vulns     []Vuln
	now       time.Time
	sws       []Software
	infos     []swInfo
	keys      [][]string     // rowKeys of each row
	named     []map[int]bool // #910: per row, the entries whose NVD list may name it
	allRows   []int
	namedRows map[int][]int // entry -> the rows its NVD list may name, in row order
	reads     []*entryRead  // per entry, its reading of the rows; nil until asked
	// own is, per row the AI identified (Software.AIProduct), the row read by its own names alone; nil for every other row.
	own []*ownRow
}

// ownRow is a row the AI identified as its own names alone read it: its reading, its KEV keys and the entries NVD's list may name it in.
type ownRow struct {
	info  swInfo
	keys  []string
	named map[int]bool
	// numbering: whether the row's version is of the chosen product's numbering (aiNumbering), computed once; 0 until then.
	numbering int8
}

// entryRead is one entry's reading of every row of the device (matchOne on each), before the findings the device has decide what
// becomes of it.
type entryRead struct {
	best, proved, unlisted, platform, other, asked *Match
	bestRow                                        int
	otherVer                                       string      // other's version
	unproved                                       bool        // a software of this product with a No that proves nothing, or one that needs a version
	othersOnly                                     bool        // every software keyed to the entry is one NVD's list leaves out
	needs                                          bool        // a row needs a version to tell
	unnamed                                        []string    // the rows NVD's list leaves out, for the retired-entry sentence
	unchecked                                      []Unchecked // #910: rows of the product that could not be checked
	matched                                        []Match     // every row the entry matches: each software line is its own finding (Match.Lines)
	provedEach                                     []Match     // the proof of every row proved not affected, in row order
	needRows                                       []int       // the rows that need a version, in row order
	outs                                           []rowOut    // every row the entry reached and how (coverage.go), in row order
}

func newDevMatch(a Asset, vulns []Vuln, now time.Time) *devMatch {
	sws := deviceSoftware(a) // its rows, and the network OS it states with its version
	winList := a.winList
	if winList == nil {
		winList = vulns
	}
	infos := make([]swInfo, len(sws))
	keys := make([][]string, len(sws))
	for i, s := range sws {
		infos[i] = swInfoOn(s, a)
		infos[i].platformOS = platformOS(s, a)
		if d, ok := winDevice(infos[i]); ok {
			infos[i].winNamed = winNamed(winList, d.rel.Product) // the whole list, so both Reconcile writes agree
			infos[i].winBuild = winBuildMonth(winList, d)        // From the whole list, never a part of it
		}
		keys[i] = rowKeys(s)
	}
	host := edgeHostOf(a, infos) // Whether Edge Legacy may still be on the device's Windows
	for i := range infos {
		infos[i].edgeHost = host
	}
	named := nvdCandidates(sws, vulns)
	distroCandidates(infos, vulns, named)
	var own []*ownRow
	for i, s := range sws {
		if len(s.AIProduct.ids()) == 0 { // none, or only a part of the product's family: the row reads by its own names alone
			continue
		}
		if own == nil {
			own = make([]*ownRow, len(sws))
		}
		plain := s
		plain.AIProduct = nil
		own[i] = &ownRow{info: infos[i].own(), keys: keys[i], named: nvdCandidates([]Software{plain}, vulns)[0]}
		if k := s.AIProduct.Kev; k != "" { // an exploited-list entry the AI chose reaches the row by the entry's own key
			keys[i] = append(slices.Clip(keys[i]), productid.NormalizeKey(k))
		}
	}
	allRows := make([]int, len(sws))
	namedRows := map[int][]int{}
	for i := range sws {
		allRows[i] = i
		for vi := range named[i] {
			namedRows[vi] = append(namedRows[vi], i)
		}
	}
	for vi := range namedRows {
		slices.Sort(namedRows[vi])
	}
	return &devMatch{a: a, vulns: vulns, now: now, sws: sws, infos: infos, keys: keys, named: named, allRows: allRows, namedRows: namedRows,
		reads: make([]*entryRead, len(vulns)), own: own}
}

// read is entry vi's reading of the device's rows, computed once.
func (d *devMatch) read(vi int) *entryRead {
	if e := d.reads[vi]; e != nil {
		return e
	}
	a, sws, infos, named, now := d.a, d.sws, d.infos, d.named, d.now
	v := d.vulns[vi]
	e := &entryRead{othersOnly: true, bestRow: -1}
	ek := keyOf(v)
	var key []identity // keyIDs(v), read once for the rows CISA's key reaches
	haveKey := false
	keep := func(m Match) *Match { return &m } // only a kept match leaves the loop: the loop's own stays on the stack
	rows := d.allRows
	if v.Vendor == "" && v.Product == "" { // a catalogue CVE on no list: only a row its NVD list may name can be reached
		rows = d.namedRows[vi]
	}
	for _, i := range rows {
		s := sws[i]
		keyed := keyedBy(d.keys[i], ek)
		if keyed && !haveKey {
			key, haveKey = keyIDs(v), true
		}
		info, nm := infos[i], named[i][vi]
		m, out := matchOne(a, s, info, v, keyed, key, nm, now)
		held := false // the chosen product's range holds a version of another numbering (aiGuard)
		if d.own != nil && d.own[i] != nil {
			var byAI bool
			if m, out, byAI, held = d.aiGuard(i, vi, ek, key, m, out); !byAI { // the row reads as its own names alone read it, here too
				info, nm = d.own[i].info, d.own[i].named[vi]
			}
		}
		if out != outNone {
			e.outs = append(e.outs, rowOut{row: i, out: out})
		}
		if out == outMatch && m.Basis == BasisProduct && m.others != "" && s.ID == osSoftwareID(a.ID) {
			// #919: the device's own OS, with a version its scheme orders, that CISA's key names but NVD's list does
			// not (CVE-2018-0171, "IOS and IOS XE", NVD only classic cisco:ios): could not be checked, not a product finding;
			// #910 rule 2 reads it as NVD naming another product (not_named, unless NVD gives no version at all)
			e.other, e.otherVer, e.unproved = keep(m), s.Version, true
			if r, ok := uncheckedReason(s, info, v, false); ok {
				e.unchecked = append(e.unchecked, uncheckedOf(s, v, r))
			}
			continue
		}
		switch {
		case held && out == outNone: // the line's own names say nothing: possible, for the version's numbering
			u := uncheckedOf(s, v, UncheckedNotComparable)
			u.aiNumbering = true
			e.unchecked = append(e.unchecked, u)
		case out == outRuledOut || out == outNone && (nm || keyed):
			if r, ok := uncheckedRow(a, s, info, v, nm, m, out); ok {
				e.unchecked = append(e.unchecked, uncheckedOf(s, v, r))
			} else if r, silence, ok := askRow(a, s, info, v, keyed, nm); ok && out == outNone {
				u := uncheckedOf(s, v, r)
				u.silence = silence
				e.unchecked = append(e.unchecked, u)
			}
		}
		if out != outNone && (out != outRuledOut || m.Evidence.Summary == "") {
			e.othersOnly = false
		}
		switch out {
		case outNotAffected:
			if e.proved == nil {
				e.proved = keep(m)
			}
			e.provedEach = append(e.provedEach, m)
			if m.why != "" && e.platform == nil {
				e.platform = keep(m)
			}
		case outRuledOut:
			e.unproved = true
			if m.Evidence.Summary != "" {
				if e.unlisted == nil {
					e.unlisted = keep(m)
				}
				if !slices.Contains(e.unnamed, m.SoftwareDisplay) {
					e.unnamed = append(e.unnamed, m.SoftwareDisplay)
				}
			}
		case outMatch:
			e.matched = append(e.matched, m)
			// on a tie, a match with version evidence wins (versionBacked): whether the CVE is a
			// finding never depends on the order of the rows; between two without it, the agent's row wins, so its note and
			// agent_row do not depend on the order either (#909)
			if e.best == nil || betterMatch(m, *e.best) {
				e.best, e.bestRow = keep(m), i
			}
		case outQuestion: // No finding until a person answers; listed with the question
			e.unproved = true
			if e.asked == nil {
				e.asked = keep(m)
			}
			u := uncheckedOf(s, v, m.ask.reason())
			u.Answer = m.answer
			e.unchecked = append(e.unchecked, u)
		case outNeedVersion:
			e.unproved, e.needs = true, true
			e.needRows = append(e.needRows, i)
		}
	}
	d.reads[vi] = e
	return e
}

// aiGuard is row i's reading of entry vi (and whether the AI's choice made it) when the AI chose the row's product (Software.AIProduct), from its reading m, out with that
// product: the AI's choice only opens. A version inside the chosen product's ranges (a match with version evidence) is a finding,
// labelled with the identity (Evidence.Identity), unless the row's own names already decide the entry; anything else the chosen
// product's ranges say (outside them, a version needed, a question) decides nothing, and the row reads as its own names alone read it:
// a pair the box has no other word on stays as it was, possible when it was possible, and nothing is closed on the AI's word. The
// identity proves the product, not the version's numbering: a version inside the range that is not of the product's numbering
// (aiNumbering) opens nothing either, and held says so (the CVE is possible for the version's numbering).
func (d *devMatch) aiGuard(i, vi int, ek entryKey, key []identity, m Match, out outcome) (Match, outcome, bool, bool) {
	r, s, v := d.own[i], d.sws[i], d.vulns[vi]
	keyed := keyedBy(r.keys, ek)
	if keyed && key == nil {
		key = keyIDs(v)
	}
	m0, out0 := matchOne(d.a, s, r.info, v, keyed, key, r.named[vi], d.now)
	if out == outMatch && versionBacked(m) && out0 != outNotAffected && (out0 != outMatch || !versionBacked(m0)) {
		if !d.aiNumbering(i) {
			return m0, out0, false, true
		}
		m.Evidence.Identity = s.AIProduct.note()
		m.Evidence.Summary = strings.TrimSpace(m.Evidence.Summary + " No standard data names this software: the AI identified it as " +
			clean(cmpNonEmpty(s.AIProduct.Title, s.AIProduct.Product)) + " among the products of Vedette's catalogue.")
		return m, out, true, false
	}
	return m0, out0, false, false
}

// result is the MatchResult of the entries idx of the list (every entry, in list order, when idx is nil) for a device that has a
// finding of the CVEs in have: MatchAsset of those entries.
func (d *devMatch) result(idx []int, have map[string]bool) MatchResult {
	vulns := d.vulns
	if idx != nil {
		vulns = make([]Vuln, len(idx))
		for k, vi := range idx {
			vulns[k] = d.vulns[vi]
		}
	}
	a, sws, infos, now := d.a, d.sws, d.infos, d.now
	var res MatchResult
	seen := make(map[string]bool, len(vulns))
	need := map[string]int{}     // software id -> index in res.NeedVersion
	decided := map[string]bool{} // CVE -> a finding or an "add the version" item has it (#910: NotComparable then does not list it)
	for k, v := range vulns {
		vi := k
		if idx != nil {
			vi = idx[k]
		}
		if !ValidCVE(v.CVE) || seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		e := d.read(vi)
		for _, i := range e.needRows {
			s := sws[i]
			n, ok := need[s.ID]
			if !ok {
				n = len(res.NeedVersion)
				need[s.ID] = n
				res.NeedVersion = append(res.NeedVersion, VersionNeeded{SoftwareID: s.ID, Software: clean(s.Display), Version: clean(s.Version)})
			}
			if c := res.NeedVersion[n].CVEs; len(c) == 0 || c[len(c)-1] != v.CVE {
				res.NeedVersion[n].CVEs = append(c, v.CVE)
			}
		}
		best, proved, unlisted, platform, other, asked := e.best, e.proved, e.unlisted, e.platform, e.other, e.asked
		unproved, needs, bestRow := e.unproved, e.needs, e.bestRow
		unchecked := slices.Clip(e.unchecked) // appended to below: never into the kept reading
		if best == nil && other != nil {
			res.NotComparable = append(res.NotComparable, NotComparable{CVE: v.CVE, SoftwareID: other.SoftwareID, Software: other.SoftwareDisplay,
				Version: clean(e.otherVer), Reason: NotComparableOtherProduct})
		}
		if best == nil && platform != nil && !unproved {
			r := *platform
			r.Evidence.Summary, r.why = r.why, ""
			res.OtherPlatform = append(res.OtherPlatform, r)
		}
		if best == nil && asked != nil {
			res.Asked = append(res.Asked, *asked)
		}
		switch {
		case best == nil && !needs:
			res.Unchecked = append(res.Unchecked, unchecked...)
		case best == nil: // the rows that need a version have their item; the product's other lines are still asked about
			res.Unchecked = append(res.Unchecked, d.apart(unchecked, e, false)...)
		}
		if best == nil {
			decided[v.CVE] = needs
			switch {
			case !have[v.CVE]:
			case proved != nil && !unproved: // Only a proof for every software of the product
				p := *proved
				p.each = slices.Clip(e.provedEach)
				res.NotAffected = append(res.NotAffected, p)
			case unlisted != nil:
				res.Unlisted = append(res.Unlisted, *unlisted)
				if e.othersOnly && isMultiProduct(v.Product) && settled(v, now) { // the retire rule is about "Multiple Products" only (not a series)
					r := *unlisted
					r.Evidence.Summary = fmt.Sprintf("Closed by Vedette: %s lists %s for several %s products; NVD names %s, not %s (settled: %s added it over a year ago). Vedette checks it again whenever NVD's data for it changes.",
						v.listName(), v.CVE, clean(v.Vendor), nvdProducts(v.Vendor, v.Affected), orList(e.unnamed), v.listName())
					res.Retired = append(res.Retired, r)
				}
			}
			continue
		}
		if aged(v, now) && !confirmedMatch(*best) && !v.HasTemplate { // An old KEV CVE only with a version compared or a scan hit; a scannable one stays for the scan
			r := *best
			r.said = best.Evidence.Summary
			reason, listed := uncheckedReason(sws[bestRow], infos[bestRow], v, false)
			r.gap, r.listed = nameOnlyWhy(sws[bestRow], infos[bestRow], v, reason, listed), listed
			r.Evidence.Summary = agedSummary(v)
			switch {
			case r.others != "": // #904: why the agent's version was compared with nothing
				r.Evidence.Summary = agedOthersSummary(v, r)
			case listed: // Why, plainly ("Windows build 26300 is newer than …"), and where the CVE is now
				r.Evidence.Summary = agedGapSummary(v, r.gap)
			}
			res.Aged = append(res.Aged, r)
			if !needs { // the product match nothing else decided: it was not checked either (#910), nor the product's other rows
				if r, ok := reason, listed; ok &&
					!slices.ContainsFunc(unchecked, func(u Unchecked) bool { return u.SoftwareID == sws[bestRow].ID }) {
					unchecked = append(unchecked, uncheckedOf(sws[bestRow], v, r))
				}
				res.Unchecked = append(res.Unchecked, unchecked...)
			} else {
				res.Unchecked = append(res.Unchecked, d.apart(unchecked, e, false)...)
			}
			decided[v.CVE] = needs
			continue
		}
		if !versionBacked(*best) && !v.HasTemplate { // No finding on the product name alone; a scannable CVE stays, on any row (the scan checks it, #939)
			r := *best
			reason, listed := uncheckedReason(sws[bestRow], infos[bestRow], v, false)
			if listed && isMultiProduct(v.Product) && len(rowEntries(sws[bestRow], infos[bestRow], v)) == 0 {
				listed = false // a vendor's "Multiple Products" reaches every row of the vendor: only one NVD's list names is listed (#920)
			}
			r.gap, r.said, r.listed = nameOnlyWhy(sws[bestRow], infos[bestRow], v, reason, listed), r.Evidence.Summary, listed
			r.Evidence.Summary = nameOnlySummary(v, r.gap, listed)
			res.NameOnly = append(res.NameOnly, r)
			if !needs { // like the age rule's: the CVE was not checked, nor the product's other rows
				if listed && !slices.ContainsFunc(unchecked, func(u Unchecked) bool { return u.SoftwareID == sws[bestRow].ID }) {
					unchecked = append(unchecked, uncheckedOf(sws[bestRow], v, reason))
				}
				res.Unchecked = append(res.Unchecked, unchecked...)
			} else {
				res.Unchecked = append(res.Unchecked, d.apart(unchecked, e, false)...)
			}
			decided[v.CVE] = needs
			continue
		}
		decided[v.CVE] = true
		res.Unchecked = append(res.Unchecked, d.apart(unchecked, e, true)...) // a line beside another line's finding is not decided by it
		b := *best
		b.Lines = otherLines(b, e.matched, v, now)
		if have[v.CVE] {
			res.Existing = append(res.Existing, b)
		} else {
			res.New = append(res.New, b)
		}
	}
	if os, orderable, ok := deviceOS(a); ok && !orderable {
		scheme := notComparable(os, vulns)
		res.NotComparable = append(res.NotComparable, scheme...)
		in := newSWInfo(os, "")
		byCVE := make(map[string]Vuln, len(scheme))
		for _, v := range vulns {
			if _, ok := byCVE[v.CVE]; !ok { // the first, as the loop above reads it
				byCVE[v.CVE] = v
			}
		}
		for _, n := range scheme { // the OS row is not in sws here: its entries are listed only from this
			if decided[n.CVE] { // a finding or an "add the version" item of another row decides it (#910 rule 1)
				continue
			}
			if r, ok := uncheckedReason(os, in, byCVE[n.CVE], true); ok {
				res.Unchecked = append(res.Unchecked, uncheckedOf(os, byCVE[n.CVE], r))
			}
		}
	}
	d.explainUnchecked(res.Unchecked, vulns)
	return res
}

// apart is the unchecked rows of us on no line that has its own word on the entry: a row that needs a version (its "add the version"
// item lists the entry) and, with matched, a row the entry matches (its finding). Every other line of the product is still asked about.
func (d *devMatch) apart(us []Unchecked, e *entryRead, matched bool) []Unchecked {
	taken := map[string]bool{}
	for _, i := range e.needRows {
		taken[storedLine(d.sws[i].ID)] = true
	}
	if matched {
		for _, m := range e.matched {
			taken[storedLine(m.SoftwareID)] = true
		}
	}
	var out []Unchecked
	for _, u := range us {
		if !taken[storedLine(u.SoftwareID)] {
			out = append(out, u)
		}
	}
	return out
}

// settled reports whether CISA added v to KEV at least SettledKEV before now; an unknown date is never settled.
func settled(v Vuln, now time.Time) bool {
	return !v.DateAdded.IsZero() && !v.DateAdded.After(now.Add(-SettledKEV))
}

// outcome of one software against one KEV entry.
type outcome uint8

const (
	outNone        outcome = iota // not this product, or a version outside every range
	outMatch                      // a finding
	outNeedVersion                // this product, but only a version would tell
	outRuledOut                   // this product, ruled out without a proof about the version (keeps a finding open)
	outNotAffected                // this product, and its version is proved outside every range
	outQuestion                   // a platform-limited CVE only a person's answer decides (Match.ask)
)

// nvdProducts names the products of NVD entries for a sentence: "fusion, horizon client, remote console", the first three
// in list order and how many more. Only the vendor's own products are named when NVD lists any (a Fortinet entry may also
// list a Siemens product that embeds it).
func nvdProducts(vendor string, afs []Affected) string {
	var names, own []string
	seen := map[string]bool{}
	for _, af := range afs {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		p, ok := c.Product.Literal()
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		names = append(names, strings.ReplaceAll(p, "_", " "))
		if cv, _ := c.Vendor.Literal(); productid.Norm(cv) == productid.Norm(vendor) {
			own = append(own, names[len(names)-1])
		}
	}
	if len(own) > 0 {
		names = own
	}
	if len(names) > 3 {
		return clean(strings.Join(names[:3], ", ")) + fmt.Sprintf(" and %d more", len(names)-3)
	}
	return clean(strings.Join(names, ", "))
}

func rank(b Basis) int {
	switch b {
	case BasisProduct:
		return 1
	case BasisVersion:
		return 2
	case BasisPerson:
		return 3
	case BasisScan:
		return 4
	}
	return 0
}

// betterMatch says whether m beats best for one CVE across the device's rows: the stronger basis, then version evidence
// (versionBacked), then the agent's row; otherwise the first row stays.
func betterMatch(m, best Match) bool {
	switch {
	case rank(m.Basis) != rank(best.Basis):
		return rank(m.Basis) > rank(best.Basis)
	case versionBacked(m) != versionBacked(best):
		return versionBacked(m)
	}
	return m.Evidence.AgentRow && !best.Evidence.AgentRow
}

// keyedTo reports whether the software's KEV keys match the entry: its key, or for "Multiple Products" its vendor.
func keyedTo(s Software, v Vuln) bool {
	if v.Vendor == "" && v.Product == "" || len(s.KevKeys) == 0 {
		return false // a catalogue CVE on no exploited list has no key
	}
	if strings.Contains(v.Vendor, "|") || strings.Contains(v.Product, "|") {
		return false // the key separator cannot be part of a KEV vendor or product
	}
	multi := isMultiProduct(v.Product)
	vendorPrefix := productid.Key(v.Vendor, "")
	key := productid.Key(v.Vendor, v.Product)
	for _, k := range s.KevKeys {
		k = productid.NormalizeKey(k)
		if multi && strings.HasPrefix(k, vendorPrefix) || !multi && k == key {
			return true
		}
	}
	return false
}

// entryKey is an entry's exploited-list key as keyedTo compares it, normalised once: its key, or for "Multiple Products" its vendor's
// prefix. none: no row can be keyed to it (a catalogue CVE on no list, a vendor or product holding the key separator).
type entryKey struct {
	none, multi bool
	key         string // productid.Key of vendor and product, or of the vendor alone for "Multiple Products"
}

func keyOf(v Vuln) entryKey {
	if v.Vendor == "" && v.Product == "" || strings.Contains(v.Vendor, "|") || strings.Contains(v.Product, "|") {
		return entryKey{none: true}
	}
	if isMultiProduct(v.Product) {
		return entryKey{multi: true, key: productid.Key(v.Vendor, "")}
	}
	return entryKey{key: productid.Key(v.Vendor, v.Product)}
}

// rowKeys is the row's KEV keys normalised as keyedTo compares them.
func rowKeys(s Software) []string {
	out := make([]string, len(s.KevKeys))
	for i, k := range s.KevKeys {
		out[i] = productid.NormalizeKey(k)
	}
	return out
}

// keyedBy is keyedTo on a row's keys and an entry's key normalised once (rowKeys, keyOf).
func keyedBy(keys []string, k entryKey) bool {
	if k.none {
		return false
	}
	for _, x := range keys {
		if k.multi && strings.HasPrefix(x, k.key) || !k.multi && x == k.key {
			return true
		}
	}
	return false
}

// trustedReading says whether a row's version may make a finding of a CVE on no exploited list: the device's agent, a person, the
// device's own SNMP answer, the network OS the device states (deviceSoftware's OS row, or a recorded row that holds the very release
// it states: Software.stated), or the firmware a device states through its management interface with its build (selfStated: an ESXi
// host's API). Never a version read from a banner (nmap, a scan, the passive sensor) or a row of unknown origin: for CVEs nobody is
// known to exploit, a guess is noise (a distribution's backported package answers with the upstream version in its banner).
func trustedReading(s Software) bool {
	switch s.Source {
	case "agent", "manual", "snmp":
		return true
	}
	return s.stated || strings.HasPrefix(s.ID, "os:") || selfStated(s)
}

// offListReading says whether a row may be compared with a CVE on no exploited list: a trusted reading (never a version guessed
// from the network), and for a distribution's package (an agent's package row, a package release a person gave) only through the
// distribution's own word on it: an upstream range does not see the fixes a distribution backports. A distribution whose data lists
// its fixes only (Alpine) and names none for the package leaves it to the upstream ranges (upstreamJudges).
func offListReading(s Software, in swInfo, v Vuln) bool {
	if !trustedReading(s) {
		return false
	}
	if in.pkgBuilt() {
		_, ok := distroVerdict(in, v)
		return ok || upstreamJudges(in, v)
	}
	return true
}

// matchOne reads entry v for one software row: through CISA's key (keyed: keyedTo, with key its keyIDs), else through NVD's CPE list
// when named says it may name the row (viaNVD, #910).
func matchOne(a Asset, s Software, in swInfo, v Vuln, keyed bool, key []identity, named bool, now time.Time) (Match, outcome) {
	var m Match
	var out outcome
	switch {
	case s.Guess: // a sensor's guess is never matched (observe.Software.Guess)
		return Match{}, outNone
	case keyed:
		m, out = judge(a, s, in, v, key, now)
	case named && (v.listed() || offListReading(s, in, v)):
		m, out = viaNVD(a, s, in, v, now)
	default:
		return Match{}, outNone
	}
	if out == outMatch || out == outNotAffected { // what was compared: a later proof tells an update from a better reading by it
		m.Evidence.Read = readingOf(s, in)
	}
	return m, out
}

// viaNVD is matchOne for a row CISA's key does not reach but NVD's CPE list for the entry names (#910, nvdNames): CISA wrote a
// component ("Chromium V8" for Chrome, "Win32k" for a Windows release) or another product ("IGEL OS" for CVE-2025-47827, which
// NVD lists for Windows Server 2025 with a fixed build). Whether the device is affected is NVD's answer only: a version inside a
// range or at an exact version NVD lists is a finding (basis version), a proof that it is outside closes one, and anything else
// (no comparable version, a list of every version) says nothing: no product finding and no "add the version" item, because CISA
// never named this software. A row its distribution may have built (a package database row, the Linux kernel) goes only by the
// distribution's own word: NVD's upstream ranges do not see the fixes it backports (an Android entry that also lists
// linux_kernel on Ubuntu's kernel). An Edge Legacy row is never reached: NVD writes Chromium Edge's ranges under microsoft:edge too.
func viaNVD(a Asset, s Software, in swInfo, v Vuln, now time.Time) (Match, outcome) {
	if !nvdReaches(a, s, in, v) {
		return Match{}, outNone
	}
	m, out := judge(a, s, in, v, nil, now)
	if out == outNotAffected && m.agreed == "" && !nvdNames(in, v, false) && !schemeNames(a, s, in, v) && !lineJudge(a, s, in, v).decides() {
		if _, ok := distroVerdict(in, v); !ok {
			return Match{}, outNone // reached only by a record row that says "affected" alone: its "outside" proves nothing
		}
	}
	if out == outNotAffected || (out == outMatch || out == outQuestion) && m.bounded {
		return m, out
	}
	return Match{}, outNone
}

// nvdReaches says whether viaNVD reads v for the row: the vendor's own rows name its product and may decide it (schemeNames), or
// NVD's list names it (nvdNames), it is not an Edge Legacy row, and a row its distribution may have built has the distribution's
// word. Reachability reads the same.
func nvdReaches(a Asset, s Software, in swInfo, v Vuln) bool {
	if lineJudge(a, s, in, v).decides() { // a vendor's release-line statement names the product and decides the line
		return true
	}
	if schemeNames(a, s, in, v) {
		return true
	}
	if _, ok := distroVerdict(in, v); ok { // the distribution's word on its own package, before or without NVD naming the product
		return true
	}
	if !nvdNames(in, v, true) || edgeLegacyRow(s, in) {
		return false
	}
	_, ok := distroVerdict(in, v)
	return ok || !distroBuilt(in) || upstreamJudges(in, v)
}

// nvdNames says whether an entry of NVD's list for v names the row's software (its CPE, name or alias, appliesTo) with a range
// that ends (endBound), or, for a Windows release row, any Windows release or a component Windows' monthly update services
// (winOSComponents): windowsDecide reads its release and the siblings that take the same update. An exact version NVD lists says
// nothing on this path (#913): Android's rows name the release (14.0) while its fixes come by security patch level,
// and NVD lists Edge 117.0.2045.47, the build that fixed CVE-2023-5217, as affected.
//
// A row of a complete record list (VendorList) names the row with an exact version too: the vendor stated every version's status. So
// does a CVE record's "every version is affected" (fromZero), which no NVD row writes: NVD's version-less rows have no bound at all,
// and an exact row that carries the fix the record states above its rows (LineFix): the record bounds the line there.
// affirming false leaves out the record rows that only say "affected" (AffectedOnly): viaNVD's proof of "not affected" never rests on
// them.
func nvdNames(in swInfo, v Vuln, affirming bool) bool {
	_, win := winDevice(in)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA || af.AffectedOnly && !affirming || !endBound(af.Range) && !af.Range.fromZero() && af.LineFix == "" && (!af.VendorList || !versionEvidence(af)) {
			continue
		}
		if own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids); own {
			return true
		}
		if win && winNamesWindows(c) {
			return true
		}
	}
	return false
}

// endBound says the range ends (a release fixes it) and is not one version written as a range.
func endBound(r VersionRange) bool {
	return r.EndExcl != "" || r.EndIncl != "" && r.EndIncl != r.StartIncl
}

// winNamesWindows says whether c is a Windows row or a Microsoft component Windows' monthly update services.
func winNamesWindows(c CPE) bool {
	if _, ok := winListedOf(c); ok {
		return true
	}
	vn, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	return okV && okP && productid.Norm(vn) == "microsoft" && winOSComponents[p]
}

// linuxKernel is NVD's Linux kernel.
var linuxKernel = identity{vendor: "linux", product: "linuxkernel"}

// distroBuilt says the row may be a distribution's build, whose fixes NVD's upstream ranges do not see: an agent read it from the
// package database (Software.Packaged), or it is the Linux kernel (a distribution's kernel keeps its upstream version while it
// takes the fixes).
func distroBuilt(in swInfo) bool {
	if in.packaged || slices.Contains(in.ids, linuxKernel) {
		return true
	}
	vn, okV := in.cpe.Vendor.Literal()
	p, okP := in.cpe.Product.Literal()
	return in.hasCPE && okV && okP && linuxKernel.matches(productid.Norm(vn), productid.Norm(p))
}

// nvdCandidates is, per row of sws, the entries of vulns whose NVD list names a vendor the row is known by (rowVendors): the only
// ones viaNVD can read for it. One pass over the list, so the matcher does not read every entry for every row.
func nvdCandidates(sws []Software, vulns []Vuln) []map[int]bool {
	vendors := make([][]string, len(sws))
	for i, s := range sws {
		vendors[i] = rowVendors(s)
	}
	return nvdCandidatesOf(vendors, vulns)
}

// nvdCandidatesOf is nvdCandidates for rows whose vendors (rowVendors) are already known.
func nvdCandidatesOf(rows [][]string, vulns []Vuln) []map[int]bool {
	byVendor := map[string][]int{}
	add := func(vn string, i int) {
		if l := byVendor[vn]; vn != "" && (len(l) == 0 || l[len(l)-1] != i) {
			byVendor[vn] = append(l, i)
		}
	}
	for i, v := range vulns {
		for _, vn := range entryVendors(v) {
			add(vn, i)
		}
	}
	out := make([]map[int]bool, len(rows))
	for i, vendors := range rows {
		for _, vn := range vendors {
			for _, vi := range byVendor[vn] {
				if out[i] == nil {
					out[i] = map[int]bool{}
				}
				out[i][vi] = true
			}
		}
	}
	return out
}

// distroCandidates adds to named, per row, the entries whose distribution data names the row's source package for the device's
// release (distroVerdict can read them): a CVE a distribution fixed in a package is compared with the package even when NVD has not
// named the upstream product yet.
func distroCandidates(infos []swInfo, vulns []Vuln, named []map[int]bool) {
	byPkg := map[string][]int{} // distribution|release|package -> rows; release "*" for a distribution whose every release is read
	for i, in := range infos {
		d := in.pkgDistro
		if d == nil || in.pkgVer == "" || in.pkgSrc == "" {
			continue
		}
		rel := in.pkgRel
		switch {
		case d.anyRelease:
			rel = "*"
		case rel == "":
			continue
		}
		k := d.id + "|" + rel + "|" + d.source(in.pkgSrc)
		byPkg[k] = append(byPkg[k], i)
	}
	if len(byPkg) == 0 {
		return
	}
	for vi, v := range vulns {
		for _, f := range v.Distro {
			for _, rel := range [2]string{f.Release, "*"} {
				for _, i := range byPkg[f.Distro+"|"+rel+"|"+f.Package] {
					if named[i] == nil {
						named[i] = map[int]bool{}
					}
					named[i][vi] = true
				}
			}
		}
	}
}

// entryVendors are the normalised vendors an entry's data names: its NVD or CVE record rows' CPE vendors, and the vendors of the
// products its vendor rows name (Vuln.Schemed: they reach the rows of their product, schemeNames). In data order, with repeats.
func entryVendors(v Vuln) []string {
	var out []string
	for _, af := range v.Affected {
		if vn := cpeVendor(af); vn != "" {
			out = append(out, vn)
		}
	}
	for _, r := range v.Schemed {
		if r.Unread {
			continue
		}
		vn, _, _ := strings.Cut(r.Product, "|")
		if vn = productid.Norm(vn); vn != "" {
			out = append(out, vn)
		}
	}
	for _, c := range v.LineCovers { // a vendor's line statement reaches its product's rows
		vn, _, _ := strings.Cut(c.Product, "|")
		if vn = productid.Norm(vn); vn != "" {
			out = append(out, vn)
		}
	}
	return out
}

// rowVendors are the normalised vendors of the names newSWInfo gives the row: its own, its aliases' (content/catalog/products) and its CPE's
// (Microsoft for a Windows release row; edgeIDs keeps Microsoft).
func rowVendors(s Software) []string {
	n := identity{vendor: productid.Norm(s.Vendor), product: productid.Norm(s.Product)}
	out := []string{n.vendor}
	if r := productid.NormVendor(s.Vendor); r != n.vendor { // a CVE record's range of a product the catalogue does not list
		out = append(out, r)
	}
	for _, a := range cpeAliases[n] {
		out = append(out, a.vendor)
	}
	for _, a := range s.AIProduct.ids() {
		out = append(out, a.vendor)
	}
	if s.CPE != "" {
		if c, err := ParseCPE(s.CPE); err == nil {
			if vn, ok := c.Vendor.Literal(); ok {
				out = append(out, productid.Norm(vn))
			}
		}
	}
	return out
}

// cpeVendor is the normalised vendor of an entry's CPE, read without parsing the whole name when it has no escape; "" when it has
// none.
func cpeVendor(af Affected) string {
	if af.parsed == nil && !strings.Contains(af.CPE, `\`) {
		if rest, ok := strings.CutPrefix(af.CPE, "cpe:2.3:"); ok {
			if _, rest, ok = strings.Cut(rest, ":"); ok {
				vn, _, _ := strings.Cut(rest, ":")
				return productid.Norm(vn)
			}
		}
	}
	c, err := af.cpe()
	if err != nil {
		return ""
	}
	vn, _ := c.Vendor.Literal()
	return productid.Norm(vn)
}

// keyIDs is the KEV entry's own vendor and product as an NVD identity (decide's key: it finds the entry, but a No on it alone
// proves nothing); nil for "Multiple Products".
func keyIDs(v Vuln) []identity {
	if n := (identity{vendor: productid.Norm(v.Vendor), product: productid.Norm(v.Product)}); !isMultiProduct(v.Product) && n.ok() {
		return []identity{n}
	}
	return nil
}

// judge is matchOne once the row is a candidate for v; key is keyIDs(v) for a row CISA's key reaches, nil for one only NVD's list
// names (viaNVD: CISA's name is not this software's, so an NVD row of it says nothing about the row).
func judge(a Asset, s Software, in swInfo, v Vuln, key []identity, now time.Time) (Match, outcome) {
	if named, out := otherSeries(a.Model, v); out { // CISA names other Juniper series than the device's model; no proof about the version
		note := fmt.Sprintf("%s lists %s for Juniper %s only; this device's model is %s. Check the vendor advisory and close it if it does not apply.", v.listName(), v.CVE, orList(named), clean(a.Model))
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outRuledOut
	}
	if d, ok := distroVerdict(in, v); ok { // The distribution's own word on its package comes before NVD's upstream ranges
		return distroMatch(a, s, in, v, d, now)
	}
	if distroDecides(in, v) { // the distribution built it and has no word yet: NVD's upstream range decides, never confirmed
		m, out := judgeRanges(a, s, in, v, key, now)
		return awaitingDistro(a, s, in, v, m, out)
	}
	m, out := judgeRanges(a, s, in, v, key, now)
	m.upstream = m.upstream || out == outMatch && upstreamJudges(in, v) // the upstream release of a package its distribution names no fix of
	return m, out
}

// awaitingDistro is the upstream answer (judgeRanges) on a package the distribution built that its data has no word on yet (a CVE newer
// than its last pull, a package name its rows spell otherwise, an entry it has not triaged): a missed exploited flaw costs more than a
// suspected one, so a version inside NVD's range is still a finding, but never confirmed by the device (backports keep the upstream
// number), and the evidence says why. The distribution's word, when it comes, closes or confirms it (distroVerdict decides first). A
// proof that the version is outside the ranges says nothing either: only the distribution may close its own package.
func awaitingDistro(a Asset, s Software, in swInfo, v Vuln, m Match, out outcome) (Match, outcome) {
	switch out {
	case outMatch:
		m.upstream = true
		m.Evidence.Agent, m.Evidence.Source = false, ""
		_, rel := distroOf(in)
		name := distroName(in)
		m.Evidence.Summary = fmt.Sprintf("%s runs %s %s from %s %s's packages. %s has not published its answer yet; based on the upstream version "+
			"ranges, its upstream version %s is inside the range affected by %s. %s carries fixes under its own package releases, so this is "+
			"not confirmed until %s answers.", clean(a.Name), softwareName(s.Display, in.pkgVer), clean(in.pkgVer), name, rel, name,
			clean(in.ver), v.CVE, name, name)
		return m, out
	case outNotAffected:
		return Match{}, outNone
	}
	return m, out
}

// judgeRanges is judge after the distribution's word: the platform list, the vendor's own rows, Windows' releases and NVD's ranges.
func judgeRanges(a Asset, s Software, in swInfo, v Vuln, key []identity, now time.Time) (Match, outcome) {
	if why, out := platformRuledOut(in, v.CVE); out { // The platform it runs on is not one the CVE affects; after the distribution's own word, which may contradict the hand list
		note := "Not affected: " + why + " Vedette closed this by itself and reopens it if a later match says the device is affected."
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}, why: why}, outNotAffected
	}
	ps := platformCheck(a, s, in, v.CVE, v.Distro, v.DistroLoading) // what a platform-limited CVE still needs on this row
	if ps.fixed {
		note := "Not affected: " + ps.note + " Vedette closed this by itself and reopens it if a later match says the device is affected."
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}, why: ps.note, pkgFixed: true, provedOn: strings.TrimSpace(s.PkgVersion)}, outNotAffected
	}
	if why, out := edgeLegacyOnly(s, in, v); out { // An Edge Legacy (EdgeHTML) CVE on the Chromium-based Edge
		note := "Not affected: " + why + " Vedette closed this by itself and reopens it if a later match says the device is affected."
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outNotAffected
	}
	multi := isMultiProduct(v.Product)
	w, isWin := windowsDecide(in, v, in.winNamed, now) // A Windows release row by its monthly update
	tri, within, every, proof := w.t, w.within, false, w.proof
	pinned := ""     // #939: the version is inside whatever the edition or target the row does not state
	vendorNote := "" // the proof note of the vendor's rows (schemeJudge)
	schemed := false
	var lined lineRead // a vendor's release-line statement decided (M-13)
	if lr := lineJudge(a, s, in, v); !isWin && ps.ask == askNone && !ps.below && lr.decides() {
		tri, within, vendorNote = lineDecision(s, v, lr)
		proof, schemed, lined = proofRange, true, lr
	} else if !isWin {
		if r, ok := schemeJudge(a, s, in, v); ok { // the vendor's own rows, read in the product's version scheme, decide first
			tri, within, vendorNote = schemeDecision(a, v, r)
			proof, schemed = proofRange, true
		} else {
			tri, within, every, proof = decide(in, v, key)
			if tri == Unknown && in.given && v.RangesFrom == "" {
				if r, attrs, ok, _ := pinnedInside(in, v, key); ok {
					tri, within, pinned = Yes, r, attrs
				}
			}
		}
	}
	if tri == Yes && !schemed && v.RangesFrom == "" && recordDecided(in, v) { // the record's rows beside NVD's call it affected: the texts name the record
		v.RangesFrom = RangesCVEOrgPartial
	}
	if tri == No && v.RangesFrom == RangesCVEOrgPartial && !schemed && !pastRecordFix(in, v, key) {
		tri, proof = Unknown, proofNone // the CNA's list may skip branches: outside it proves nothing, unless past a fix of a train it covers
	}
	agreed := "" // the readings every one of which gave the verdict (everyReading)
	if tri == Unknown && !schemed && !isWin && in.given && ps.ask == askNone && !ps.below {
		if ag, ok := everyReading(in, v, key, s.Display); ok {
			tri, within, agreed = ag.t, ag.within, ag.says
			if tri == No {
				proof = proofRange
			}
		}
	}
	if tri == No && lostRow(in, v, key) { // the record reader dropped a statement about the product: nothing proves it is not affected
		tri, proof, agreed, schemed = Unknown, proofNone, "", false
	}
	switch {
	case tri == No && schemed:
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: vendorNote, CheckedAt: now},
			provedOn: strings.TrimSpace(in.ver)}, outNotAffected
	case tri == No && proof == proofNone:
		if multi && listsOthersOnly(in, v) { // No proof (NVD's list can lag the advisory); the person reads why
			note := fmt.Sprintf("NVD lists %s for %s, not %s; check the vendor advisory and close it if it does not apply.", nvdProducts(v.Vendor, v.Affected), v.CVE, clean(s.Display))
			return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outRuledOut
		}
		return Match{}, outRuledOut
	case tri == No:
		note := fmt.Sprintf("Not affected: version %s of %s is outside every version range %s lists for %s. Vedette closed this by itself and reopens it if a later match says the device is affected.", clean(in.ver), clean(s.Display), v.rangesBy(false), v.CVE)
		switch {
		case proof == proofOS:
			note = fmt.Sprintf("Not affected: %s lists only operating-system releases other than this device's (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.", v.CVE, clean(a.OS))
		case proof == proofRelease:
			note = w.note
		case w.via != "":
			note = fmt.Sprintf("Not affected: version %s of %s is outside every version range NVD lists for %s (read with the ranges of %s, which takes the same monthly update). Vedette closed this by itself and reopens it if a later match says the device is affected.", clean(in.ver), clean(s.Display), v.CVE, w.via)
		}
		if hn, ok := winHotpatchNote(in, v.CVE); ok && isWin && proof != proofOS { // the build read at its month's update, not as written
			note = hn
		}
		if b := in.installClause(v, key, nil); b != "" && proof == proofRange && !isWin {
			note = strings.Replace(note, ". Vedette closed this", fmt.Sprintf(" (NVD's rows for other builds do not apply: %s). Vedette closed this", b), 1)
		}
		if agreed != "" {
			note = "Not affected: " + agreed + ". Vedette closed this by itself and reopens it if a later match says the device is affected."
		}
		m := Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}, agreed: agreed}
		if proof != proofOS { // the operating system's release, not the row's version, ruled it out
			m.provedOn = strings.TrimSpace(in.ver)
		}
		return m, outNotAffected
	case tri == Unknown && !in.given && !every && versionDecides(in, v, key):
		return Match{}, outNeedVersion // One "add the version" item per software, not one finding per CVE
		// #939: no NVD entry for the row gives a version, so adding one would decide nothing: a product match, which
		// becomes a could-not-check row (no_nvd_data, no_nvd_versions)
	}
	sw := withVersion(s.Display, s.Version) // a scan row's display already ends with its version ("OpenSSH 10.2")
	name := clean(a.Name)
	// snmpStated: the device answered Vedette's SNMP read with this exact version (never a person's correction of it, whose Source
	// is manual) and it is inside a range with an end: the device's own statement confirms the finding.
	snmpStated := false
	m := Match{
		CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Basis: BasisProduct, Confidence: ConfProduct,
		Severity: SeverityMedium,
	}
	others := ""
	if tri != Yes && !multi {
		others = nvdOthersOnly(in, v)
	}
	switch {
	case tri == Yes:
		m.Basis, m.Confidence, m.Severity, m.bounded = BasisVersion, ConfVersion, SeverityHigh, endBound(within) || within.fromZero()
		if v.Ransomware || v.EPSS >= 0.5 {
			m.Severity = SeverityCritical
		}
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. Its version is inside the range affected by %s (%s)"+suspectedClause, name, sw, v.CVE, clean(within.String()))
		if schemed {
			m.Evidence.Summary = schemeAffectedNote(a, s, in, v, within)
		}
		if lined.decides() {
			m.Evidence.Summary = lineAffectedNote(a, s, v, lined)
		}
		if pinned != "" {
			m.Evidence.Summary = fmt.Sprintf("%s runs %s. NVD lists %s for %s only; Vedette cannot tell which one this is, but the version is inside the affected range of each (%s)"+suspectedClause, name, sw, v.CVE, pinned, clean(within.String()))
		}
		if w.via != "" {
			m.Evidence.Summary = fmt.Sprintf("%s runs %s. Its version is inside the range affected by %s (%s, read with the range NVD gives %s, which takes the same monthly update)"+suspectedClause, name, sw, v.CVE, clean(within.String()), w.via)
		}
		// The device's own agent reports what is installed; a detection, not a guess. Not when NVD gives no end to the range
		// (every version: no fix to name). A platform condition still open is no match at all (outQuestion).
		if s.Source == "agent" && pinned == "" && (within.EndExcl != "" || within.EndIncl != "") {
			m.Evidence.Agent = true
			m.Evidence.Summary = agentSummary(name, s, in, v, within, w, isWin)
			if schemed {
				m.Evidence.Summary = schemeAffectedNote(a, s, in, v, within)
			}
			if lined.decides() {
				m.Evidence.Summary = lineAffectedNote(a, s, v, lined)
			}
		}
		if s.Source == SourceSNMP && pinned == "" && w.via == "" && endBound(within) {
			snmpStated = true
		}
		if pinned == "" && !schemed && !isWin {
			m.Evidence.Summary = withInstall(m.Evidence.Summary, in.installClause(v, key, &within))
		}
	case every && (!in.given || !versionKnown(in.ver)): // the version does not matter (#939: also one Vedette cannot read)
		m.every = true
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. %s lists every version of it as affected by %s"+suspectedClause, name, sw, v.rangesBy(true), v.CVE)
	case multi:
		m.Confidence = ConfVendorOnly
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. %s lists this flaw for several %s products; check the advisory to see whether yours is one of them.", name, sw, v.listName(), clean(v.Vendor))
	case others != "": // #904: CISA names the product, NVD's list only others (the "Multiple Products" sentence for a keyed entry)
		m.others = others
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. %s lists this flaw for %s, but NVD lists %s for %s only, not %s; check the vendor advisory and close it if it does not apply.",
			name, sw, v.listName(), clean(v.Vendor+" "+v.Product), v.CVE, m.others, clean(s.Display))
	case w.note != "": // Why NVD's Windows data does not decide it
		m.backed = w.later // WinLaterNote compares the device's revision with a fix build NVD gives
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. %s", name, sw, w.note)
	case len(v.Affected) == 0: // No "run a scan" (the page may show the result of the scan that just ran)
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. %s lists no affected versions for %s yet, so Vedette cannot tell whether this version is affected; compare it with the vendor advisory.", name, sw, v.rangesBy(true), v.CVE)
	default:
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. Vedette cannot compare version %s with the versions %s lists as affected by %s; compare it with the vendor advisory.", name, sw, clean(in.ver), v.rangesBy(false), v.CVE)
	}
	switch {
	case ps.ask != askNone: // Only a person's answer decides; the CVE goes to "Could not be checked" with the question
		l, fix := platformLimits[v.CVE], distroFixes(v.CVE, v.Distro)
		note := fmt.Sprintf("%s Vedette cannot check %s on %s yet: it affects only %s, and %s. It is under \"Could not be checked\" with the question; Vedette reopens this if your answer says the device is affected.",
			AskedNote, v.CVE, name, l.Affects, askGap(ps.ask, v.CVE, fix))
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}, ask: ps.ask, answer: ps.bad, bounded: m.bounded, fix: fix}, outQuestion
	case ps.below: // Below the distribution's fix for the device's branch (or older than every fix): a version finding
		m.Basis, m.Confidence, m.Severity, m.bounded, m.backed = BasisVersion, ConfVersion, SeverityHigh, true, true
		if v.Ransomware || v.EPSS >= 0.5 {
			m.Severity = SeverityCritical
		}
		m.Evidence.Summary = ps.note
		m.Evidence.Agent = s.Source == "agent" // the agent's release (or version) compared with the distribution's fix: a detection
	case ps.note != "": // The distribution lists no fix for the device's branch: NVD's range decided, and the finding says why
		m.Evidence.Summary += ps.note
	}
	m.Evidence.AgentRow = m.Basis == BasisProduct && s.Source == "agent" && in.given
	// Who stated the version confirms the finding only when it is the device itself, as it reports it now: never while a person's OS
	// correction stands (inventory INV-41 puts the person's value in every reading of the device), never an SNMP answer older than
	// SNMPFresh, and for a distribution's package only the distribution's own fix (distroMatch, ps.below), never NVD's upstream
	// range, which ignores the distribution's backports (a packaged OpenSSH 8.7p1 on Rocky 9 carries the fix of CVE-2024-6387).
	packaged := in.pkgBuilt() || s.Packaged || strings.TrimSpace(s.PkgVersion) != "" // the same "distribution package" the fix names read (pkgBuilt)
	switch {
	case m.Basis != BasisVersion || !deviceSays(a):
	case m.Evidence.Agent && ps.below:
		m.Evidence.Source = SourceAgent
	case m.Evidence.Agent && !packaged && ps.note == "":
		m.Evidence.Source = SourceAgent
	case snmpStated && !ps.below && ps.note == "" && snmpFresh(s.SeenAt, now):
		m.Evidence.Source = SourceSNMP
		m.Evidence.Summary = fmt.Sprintf("Confirmed: %s reports %s over SNMP; %s lists %s as affected by %s.", name, sw, v.rangesBy(true), rangeWords(within), v.CVE)
	}
	m.Evidence.CheckedAt = now
	return m, outMatch
}

// SNMPFresh is how recent the device's last successful SNMP answer must be for the version it states to confirm a finding: a device
// that has not answered Vedette's SNMP read for longer may run another version by now. Fifteen days, so a scan window open one day a
// week (a read about every 7 days) and one missed read never flip a finding between confirmed and suspected; a failed attempt does
// not move the time (only an answer does, the observation's seen_at).
const SNMPFresh = 15 * 24 * time.Hour

// snmpFresh says whether an SNMP answer seen at at is recent enough to confirm (SNMPFresh); an unknown time is not.
func snmpFresh(at, now time.Time) bool {
	return !at.IsZero() && !at.Before(now.Add(-SNMPFresh))
}

// deviceSays reports whether the readings of the device are its own: false while a person's OS correction stands (inventory
// INV-41 writes the person's value into the agent's, SNMP's and LLDP's statements), so no version can be the device's own word.
func deviceSays(a Asset) bool { return a.ManualOS == "" && a.OSCorrection == "" }

// rangeWords says a version range the way a person reads it in a sentence: "6.4.0 up to before 7.4.10", "versions before 7.4.10",
// "7.0.0 up to 7.0.6".
func rangeWords(r VersionRange) string {
	start := cmp.Or(r.StartIncl, r.StartExcl)
	from := ""
	switch {
	case r.StartIncl != "":
		from = clean(r.StartIncl) + " up to "
	case r.StartExcl != "":
		from = "later than " + clean(r.StartExcl) + " up to "
	default:
		from = "versions "
	}
	switch {
	case r.EndExcl != "":
		return from + "before " + clean(r.EndExcl)
	case r.EndIncl != "" && start == "":
		return "versions up to " + clean(r.EndIncl)
	case r.EndIncl != "":
		return from + clean(r.EndIncl)
	}
	return clean(r.String())
}

// agentSummary is the evidence of a version match on a row the device's own agent reported: it says what the agent reports
// and where the fix is, never "only suspected" nor "check the About screen" (Vedette already has the installed version). A Windows
// release row names the build ("The agent on WIN-LAB reports Microsoft Windows Server 2025 build 26100.1742. Microsoft fixed
// CVE-2024-43451 in build 26100.2314 …").
func agentSummary(name string, s Software, in swInfo, v Vuln, within VersionRange, w winVerdict, isWin bool) string {
	sw := clean(s.Display)
	if isWin {
		build := strings.TrimPrefix(clean(in.ver), "10.0.")
		via := ""
		if w.via != "" {
			via = fmt.Sprintf(", read with the range NVD gives %s, which takes the same monthly update", w.via)
		}
		if end := clean(within.EndExcl); end != "" {
			head := fmt.Sprintf("The agent on %s reports %s build %s. Microsoft fixed %s in build %s (NVD: %s%s)", name, sw, build, v.CVE, strings.TrimPrefix(end, "10.0."), clean(within.String()), via)
			d, _ := winDevice(in)
			switch kind, _, branch := winFix(w, d); kind { // what installing the fix takes on this release
			case "esu":
				return fmt.Sprintf("%s, an update that comes only with Extended Security Updates for %s; this device has the flaw until it installs it.", head, clean(branch))
			case "feature_update":
				return fmt.Sprintf("%s, but no update for this release carries it: this device has the flaw until it moves to %s or later.", head, clean(branch))
			}
			return head + ", so this device has the flaw until it installs that monthly update or a later one."
		}
		return fmt.Sprintf("The agent on %s reports %s build %s, inside the builds NVD lists as affected by %s (%s%s).", name, sw, build, v.CVE, clean(within.String()), via)
	}
	return fmt.Sprintf("The agent on %s reports %s installed. That version is inside the range %s lists as affected by %s (%s).",
		name, withVersion(s.Display, in.ver), v.rangesBy(false), v.CVE, clean(within.String()))
}

// decide evaluates the NVD configurations for one software. Yes carries the
// range that matched; No means every applicable configuration rules it out and
// nothing was undecidable; Unknown covers "no applicable configuration", an
// unparseable or unidentifiable entry, and anything not comparable. Only a
// definite No drops a KEV match. given says whether the software has a version at
// all (versionGiven); an Unknown without one is "add the version".
// swInfo is what the matcher derives once per software.
type swInfo struct {
	cpe    CPE
	hasCPE bool
	ver    string     // the version, or the CPE's when the software has none
	given  bool       // ver says something about the version (versionGiven); it may still be unreadable
	ids    []identity // the software's own names: inventory vendor/product and its aliases (cpeAliases)
	// os and osVer: the device's operating system as an NVD product ("canonical:ubuntu_linux", "26.04.1"), when known.
	os    identity
	osVer string
	// packaged: an agent read the software from the device's package database (Software.Packaged).
	packaged bool
	// pkgVer and pkgSrc: the full Debian version and source package of a packaged row, "" otherwise.
	pkgVer, pkgSrc string
	// pkgDistro and pkgRel: the distribution whose security data judges a packaged row (nil when the feeds supply none for the OS) and
	// the device's release as that data names it ("26.04", "12", "3.23"; "" when the OS names none).
	pkgDistro *distroData
	pkgRel    string
	// winNamed: the software is a Windows release row and NVD names its release in some entry of the list.
	winNamed bool
	// winBuild: the month of the monthly update a Windows release row's build carries, read from the list's fix builds
	// (winBuildMonth); zero when not known or not computed (FixedInFor), and then the month rule never closes.
	winBuild winBuild
	// edgeHost: what the device's own Windows says about Edge Legacy still being on it (edgeHostOf); the same for every row.
	edgeHost edgeHost
	// osName is the device's operating system as inventory folds it ("Microsoft Windows 10 Enterprise LTSC 2019 10.0.17763.6532"):
	// a Windows LTSC/LTSB edition is still serviced when its release has ended.
	osName string
	// banner: Software.Banner. platformOS: the device's OS when it is evidence of the platform this row was built for
	// (platformOS), "" otherwise.
	banner     string
	platformOS string
	// personPkg: the package release a person gave on the row (a manual row's Software.PkgVersion: inventory's correction), "" otherwise;
	// evidence of its platform.
	personPkg string
	// install: the build attributes the box derives for the row (installOf: edition, platform, architecture); zero when not derived.
	install installAttrs
}

// pkgBuilt says the row is a distribution's package: an agent read it from the package database (packaged), or a person gave a
// package release (personPkg) that is one: the device runs a Linux distribution, or the text is a distribution's release format
// (pkgReleaseText: apk "10.2_p1-r1", Debian "1:10.2p1-2ubuntu3.8", RPM "8.7p1-38.el9"). A FortiGate's "v7.2.13" or a Windows build a
// person corrected is not one and keeps its upstream wording. The distribution's own updates fix a package, under its own release
// numbers, so an upstream release is never the update to name for it (fixedInSoftware, FixOf). It does not change how
// the matcher compares the row: a person's release still goes by NVD's range unless the distribution's data decides.
func (in swInfo) pkgBuilt() bool {
	return in.packaged || in.personPkg != "" && (linuxDistro(in.osName) != "" || pkgReleaseText(in.personPkg))
}

func newSWInfo(s Software, osName string) swInfo {
	var in swInfo
	in.os, in.osVer = osIdentity(osName)
	in.osName = osName
	if s.CPE != "" {
		if c, err := ParseCPE(s.CPE); err == nil {
			in.cpe, in.hasCPE = c, true
		}
	}
	in.ver = s.Version
	if in.ver == "" && in.hasCPE {
		in.ver, _ = in.cpe.Version.Literal()
	}
	in.given = versionGiven(in.ver)
	in.banner = s.Banner
	if s.Source == "manual" {
		in.personPkg = strings.TrimSpace(s.PkgVersion)
	}
	in.packaged = s.Packaged && s.builtBy() == "agent"
	if in.packaged {
		in.pkgVer, in.pkgSrc = s.PkgVersion, s.PkgSource
		if in.pkgDistro = distroOfOS(osName); in.pkgDistro != nil {
			in.pkgRel = in.pkgDistro.rel(osName)
		}
	}
	if n := (identity{vendor: productid.Norm(s.Vendor), product: productid.Norm(s.Product)}); n.ok() {
		in.ids = append(append(append(in.ids, n), cpeAliases[n]...), edgeIDs(s.Vendor, s.Product, in.ver)...)
		if r := recordIdentity(s.Vendor, s.Product); r.ok() {
			in.ids = append(in.ids, r)
		}
	}
	in.ids = append(in.ids, s.AIProduct.ids()...)
	return in
}

// own is the row's reading without the product the AI chose for it (Software.AIProduct): what the line's own names decide.
func (in swInfo) own() swInfo {
	in.ids = slices.DeleteFunc(slices.Clone(in.ids), func(i identity) bool { return i.ai })
	return in
}

// nvdOthersOnly names the products of NVD's list for v (nvdProducts) when it has entries and every one is readable and names
// another product than the software (#904): not its own identity (CPE, name or alias, appliesTo), not the KEV entry's own vendor and
// product (decide's key), not a product of its vendor whose name starts with the software's (NVD's microsoft:edge_chromium for an
// Edge row: maybe the same product under NVD's other name), and, for a Windows row (a Windows CPE, or keyed to CISA's "Microsoft
// Windows"), no Windows row of any release or family (winListedOf) and no component Windows' monthly update services
// (winOSComponents), and no row of the device's own operating system (an Ubuntu release for a kernel row on Ubuntu,
// #909). "" otherwise: no NVD data yet, an entry that may be this software (vendor or product ANY, unreadable), or one that applies. A later Windows build keeps its agent evidence: CVE-2024-43572 lists Windows 11 24H2.
func nvdOthersOnly(in swInfo, v Vuln) string {
	if len(v.Affected) == 0 {
		return ""
	}
	_, win := windowsProduct(in.cpe)
	win = win && in.hasCPE || productid.Norm(v.Vendor) == "microsoft" && productid.Norm(v.Product) == "windows"
	ids := in.ids
	if in.hasCPE {
		cv, okV := in.cpe.Vendor.Literal()
		cp, okP := in.cpe.Product.Literal()
		if okV && okP {
			ids = append(slices.Clip(ids), identity{vendor: productid.Norm(cv), product: productid.Norm(cp)})
		}
	}
	var key []identity
	if n := (identity{vendor: productid.Norm(v.Vendor), product: productid.Norm(v.Product)}); !isMultiProduct(v.Product) && n.ok() {
		key = []identity{n}
	}
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			return ""
		}
		if win {
			if _, ok := winListedOf(c); ok {
				return ""
			}
			if vn, okV := c.Vendor.Literal(); okV && productid.Norm(vn) == "microsoft" {
				if p, okP := c.Product.Literal(); okP && winOSComponents[p] {
					return ""
				}
			}
		}
		own, known := appliesTo(c, in.cpe, in.hasCPE, in.ids)
		byKey, _ := appliesTo(c, CPE{}, false, key)
		if own || byKey || !known {
			return ""
		}
		cv, _ := c.Vendor.Literal()
		cp, _ := c.Product.Literal()
		if slices.ContainsFunc(ids, func(i identity) bool {
			return i.ok() && i.vendor == productid.Norm(cv) && strings.HasPrefix(productid.Norm(cp), i.product)
		}) {
			return ""
		}
		if distroRelease(c) && !in.os.ok() { // a distribution's row on a device whose distribution is not read (Mint, Pop!_OS, "Ubuntu", none) may be its own (#909)
			return ""
		}
		if in.os.ok() && in.os.matches(productid.Norm(cv), productid.Norm(cp)) { // the device's own OS (osRulesOut's identity): CVE-2021-3493 lists Ubuntu releases for a kernel flaw (#909)
			return ""
		}
	}
	return nvdProducts(v.Vendor, v.Affected)
}

// listsOthersOnly reports whether every NVD entry of v is readable and names another product than the software.
func listsOthersOnly(in swInfo, v Vuln) bool {
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			return false
		}
		if own, known := appliesTo(c, in.cpe, in.hasCPE, in.ids); own || !known {
			return false
		}
	}
	return len(v.Affected) > 0
}

// pinnedInside (#939): decide says Unknown only because NVD pins an edition
// (edition or sw_edition: "community", "enterprise") the row does not state, and for some product of the row's own names NVD lists at
// least two distinct editions and the version is inside a range of every one of them: whatever the edition on the device, the version
// is affected, which is version evidence. It returns the widest range that matched and the editions ("community or enterprise"). A
// lone edition ("continuous", "enterprise", "data_center") proves nothing about the others NVD leaves out because they are not
// affected: lone names it, for the could-not-check sentence. NVD's NA ("-") in an edition is the plain edition (Thunderbird not ESR,
// Jenkins not LTS) and is one of the alternatives like any named one: Thunderbird 115.9.0 inside both "esr before 140.9.0" and "-
// before 149.0" is affected whichever it is, while Jenkins 2.430 inside "- before 2.442" but past "lts before 2.426.3" stays a question
// (#906 holds there: NA never covers an edition the row leaves unstated by itself). Never for a platform pin (language, target_sw,
// target_hw, other: an AnyConnect for Windows only says nothing on macOS; the platform rules read those), never when an edition's
// ranges leave the version out, and never when an entry cannot be read.
func pinnedInside(in swInfo, v Vuln, key []identity) (r VersionRange, editions string, ok bool, lone string) {
	type state struct {
		bad  bool
		sets map[string]bool // edition -> the version is inside one of its ranges
		keys []string
		r    VersionRange
	}
	byProduct := map[string]*state{}
	var order []string
	sib := siblingsOf(&v)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			return VersionRange{}, "", false, ""
		}
		own, _, known := entryFor(c, in, key)
		if !known {
			return VersionRange{}, "", false, ""
		}
		if !own {
			continue
		}
		c, applies := in.install.judge(c, in.cpe, in.hasCPE, sib)
		if !applies {
			continue // a row about another build than the line's (install attributes)
		}
		vn, _ := c.Vendor.Literal()
		p, _ := c.Product.Literal()
		k := productid.Norm(vn) + ":" + productid.Norm(p)
		st, seen := byProduct[k]
		if !seen {
			st = &state{sets: map[string]bool{}}
			byProduct[k] = st
			order = append(order, k)
		}
		vals, liftable := pinnedValues(c, in)
		if !liftable {
			st.bad = true
			continue
		}
		t, rr := evalAffected(stripPins(c), af.Range, in.ver, in.cpe, in.hasCPE)
		if t == Unknown {
			st.bad = true
			continue
		}
		if len(vals) == 0 {
			continue // a row of every edition: it would have said Yes itself; its No is another branch
		}
		set := strings.Join(vals, " ")
		if _, had := st.sets[set]; !had {
			st.sets[set] = false
			st.keys = append(st.keys, set)
		}
		if t == Yes {
			st.sets[set] = true
			if st.r == (VersionRange{}) || explainsBetter(rr, st.r) {
				st.r = rr
			}
		}
	}
	for _, k := range order {
		st := byProduct[k]
		if st.bad || len(st.sets) == 0 || !endBound(st.r) {
			continue
		}
		all := true
		for _, set := range st.keys {
			all = all && st.sets[set]
		}
		switch {
		case all && len(st.keys) >= 2:
			return st.r, orList(st.keys), true, ""
		case all && lone == "":
			lone = st.keys[0]
		}
	}
	return VersionRange{}, "", false, lone
}

// plainEdition is how a sentence names NVD's NA ("-") in an edition: the plain edition, beside the named ones ("esr or plain").
const plainEdition = "plain"

// pinnedValues are the editions (edition, sw_edition) c pins to a value the row does not state, NA ("-") as plainEdition; liftable is
// false when c pins a platform the row does not state (language, target_sw, target_hw, other), or NA where the row states an edition.
func pinnedValues(c CPE, in swInfo) (vals []string, liftable bool) {
	cfa := c.fields()
	var sfa [11]*Attr
	if in.hasCPE {
		sfa = in.cpe.fields()
	}
	for i := 5; i < len(cfa); i++ {
		a := cfa[i]
		if a.Kind == Any || in.hasCPE && attrMatch(*a, *sfa[i]) {
			continue
		}
		if i != 5 && i != 7 { // 5 edition, 7 sw_edition
			return nil, false
		}
		if a.Kind == NA && (!in.hasCPE || sfa[i].Kind == Any) {
			vals = append(vals, plainEdition)
			continue
		}
		if a.Kind != Value {
			return nil, false
		}
		lit, _ := a.Literal()
		vals = append(vals, clean(lit))
	}
	return vals, true
}

// stripPins is c with every attribute after the version set to ANY.
func stripPins(c CPE) CPE {
	f := c.fields()
	for _, a := range f[5:] {
		*a = Attr{Kind: Any}
	}
	return c
}

// versionDecides says whether a version of the row could decide v (#939): an entry decide reads for it (its own, or
// CISA's key) gives a version (versionEvidence). Otherwise "add the version" would lead nowhere.
func versionDecides(in swInfo, v Vuln, key []identity) bool {
	return slices.ContainsFunc(v.Affected, func(af Affected) bool {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA || !versionEvidence(af) {
			return false
		}
		own, byKey, _ := entryFor(c, in, key)
		return own || byKey
	})
}

// entryFor says whether NVD entry c is about the row for decide: it names the row itself (own: its CPE, name or alias, appliesTo) or
// the KEV entry's own vendor and product (byKey: key, keyIDs; it finds the entry, a No on it alone proves nothing). known is
// appliesTo's for the row. Reachability reads the same.
func entryFor(c CPE, in swInfo, key []identity) (own, byKey, known bool) {
	own, known = appliesTo(c, in.cpe, in.hasCPE, in.ids)
	byKey, _ = appliesTo(c, CPE{}, false, key)
	return own, byKey, known
}

// decide evaluates the NVD configurations of v for one software. every is true when an applicable entry names every
// version of the product (no range, version and update ANY, nothing pinned the software contradicts): then the answer
// does not depend on the version, so a software without one is not sent to "add the version".
//
// An entry applies when it names the software's own identity (its CPE, name or alias) or the KEV entry's own vendor
// and product (key: keyIDs, nil for a row only NVD's list ties to the entry, #910). Only the first can prove: a No on an entry found by the KEV key alone is Unknown, and so is any
// answer from an entry that lists releases of a distribution the software itself is (a catalog "Ubuntu Linux 22.04"
// row keyed to the kernel), because a release is not the version of the package the CVE is about.
//
// proof says what a No rests on: proofRange when every applicable entry rules the readable version out,
// proofOS when the entry lists only releases of the device's own distribution and not its release, proofNone for a
// "Multiple Products" entry without NVD data or whose NVD list names only other products: no finding, and nothing
// closes, because NVD's list for such an entry can lag the vendor's advisory.
func decide(in swInfo, v Vuln, key []identity) (t Tri, within VersionRange, every bool, proof proofKind) {
	multi := isMultiProduct(v.Product)
	result := No
	applicable, undecidable := false, false
	// decided: a row of the software's own said Yes or No; aside: a row of another release branch did not compare with the version
	// (otherBranch) and was set aside. Rows set aside never decide alone: with no row deciding, the answer stays Unknown.
	decided, aside := false, false
	// worded: a row named by a word was set aside (wordRelease); past: a row of the software's own that the version is after the end of
	// said No. A row set aside for its word is no numbered release, yet it is the record's: only a fix the version is past outweighs it.
	worded, past := false, false
	var yes *VersionRange // the range the version is inside that explains the finding and names its fix (explainsBetter)
	jv, isJ := junosParse(in.ver)
	junosSeen := false // a Junos NVD row decided (junosEval): its exact rows say what a missing update means
	// trainOnly: an exact row of a dotted network OS was ruled out only by its train (dottedListGuess); then only a version after
	// every entry of the OS (beyond, dottedAfter) is a proof, as with Junos (junosListed)
	trainOnly, beyond := false, true
	var jl junosList
	var nos []Affected // the rows of the line's own that said No: a list of exact releases among them proves only as exactListProves says
	sib := siblingsOf(&v)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			undecidable = true // cannot tell which product this entry is about
			continue
		}
		own, byKey, known := entryFor(c, in, key)
		if !own && !byKey {
			undecidable = undecidable || !known
			continue
		}
		if naVersionApart(c, in.ver, v.Affected) || earlierMarker(c, af, v.Affected) {
			continue // the row is not about this install (NA), or it only repeats a bounded row's "and earlier" (legacy NVD)
		}
		if af.AffectedOnly || af.Lost { // only "affected" counts from it, and only for a version it states: outside it, it neither applies nor proves
			if t, r := in.eval(c, af.Range, in.ver, sib); t == Yes && own && versionEvidence(af) {
				if yes == nil || explainsBetter(r, *yes) {
					yes = &r
				}
				applicable = true
			}
			continue
		}
		applicable = true
		if isJ && isJunos(c) {
			junosSeen = true
			if row, ok := junosRow(c, af.Range); ok {
				jl.rows = append(jl.rows, row)
			} else if rel, ok := c.Version.Literal(); ok && strings.EqualFold(rel, jv.release()) {
				jl.own = true // a row of the device's release junosRow does not read: never a proof
				jl.ownDash = jl.ownDash || c.Update.Kind == NA
			} else if e, ok := junosEnd(af.Range); ok && c.Version.Kind == Any {
				jl.ends = append(jl.ends, e)
			} else if e, ok := junosRelOf(rel); ok && af.Range.IsZero() && junosRelCmp(jv, e) != 0 {
				jl.rels = append(jl.rels, e) // "12.1r": a row of another release, in a form junosRow does not read
			}
		}
		t, r := in.eval(c, af.Range, in.ver, sib)
		if t != No && (af.Range.IsZero() || af.Range.fromZero()) && everyVersion(c) {
			every = true
		}
		switch {
		case !own && t == No:
			t = Unknown // matched by the KEV key alone: the version may be of something else, so no proof
		case !byKey && distroRelease(c):
			// The software is a distribution ("Ubuntu Linux 22.04", keyed to the kernel) and the entry lists releases
			// of it that shipped an affected package: the release is not the version of that package, so it neither
			// proves nor rules out (a kernel CVE stays a product finding, medium).
			t = Unknown
		case t == Unknown && own && (!isJ || !isJunos(c)) && otherBranch(c, af.Range, in.ver):
			// A row of another release branch the version does not compare with (OpenSSL's "1.1.1" to "1.1.1zk" beside its 3.x
			// ranges, against 3.5.0): it cannot hold the version, whatever its letters mean, so it is set aside and the rows that
			// compare decide.
			aside = true
			continue
		case t == Unknown && own && wordRelease(c, af.Range, in.ver):
			// An exact row named by a word, not a number ("preview_release"): it is no numbered release, so it is set aside like a
			// row of another branch, but only a fix the version is past may then decide (past).
			aside, worded = true, true
			continue
		}
		switch t {
		case Yes:
			decided = true
			if yes == nil || explainsBetter(r, *yes) {
				yes = &r
			}
		case Unknown:
			result = Unknown
		case No:
			decided = true
			if own {
				nos = append(nos, af)
			}
			past = past || own && pastEnd(af.Range, in.ver)
			trainOnly = trainOnly || dottedListGuess(c, af.Range, in.ver)
			beyond = beyond && (osScheme(c) != schemeDotted || dottedAfter(c, af.Range, in.ver))
		}
	}
	if yes != nil {
		return Yes, *yes, every, proofNone
	}
	if !applicable && in.osVer != "" && osRulesOut(v, in) {
		p := proofNone
		if versionKnown(in.osVer) {
			p = proofOS
		}
		return No, VersionRange{}, false, p // the entry names only operating-system releases, and not this device's
	}
	if !applicable && multi {
		// CISA's "Multiple Products" names no product: only NVD's list can tie the entry to this software.
		switch {
		case len(v.Affected) == 0:
			return No, VersionRange{}, false, proofNone // NVD lists no product yet: a vendor-wide guess is noise, and proves nothing
		case undecidable:
			return Unknown, VersionRange{}, every, proofNone // an entry that may be about this software (vendor or product ANY)
		}
		return No, VersionRange{}, false, proofNone // NVD lists other products only: no finding, but no proof (its list can lag the advisory)
	}
	if !applicable || undecidable && result == No || aside && !decided || worded && !past {
		return Unknown, VersionRange{}, every, proofNone
	}
	if junosSeen && result == No { // NVD's Junos lists have gaps: a missing update is not a proof (#703)
		t, w, proved := junosListed(jv, jl)
		switch {
		case t != No:
			return t, w, every, proofNone
		case proved && exactListProves(in.ver, nos):
			return No, VersionRange{}, every, proofRange
		}
		return No, VersionRange{}, every, proofNone
	}
	if pv, ok := parseVersion(in.ver); result == No && ok && !isPlaceholder(in.ver) && pv.q.class >= 0 {
		if trainOnly && !beyond { // an enumeration read partly by its trains, which leaves releases out: no finding, no proof
			return No, VersionRange{}, every, proofNone
		}
		if !exactListProves(in.ver, nos) { // a list of exact releases that does not say what this release is: no finding, no proof
			return No, VersionRange{}, every, proofNone
		}
		return No, VersionRange{}, every, proofRange // a pre-release ("2.0.0-rc1") near a bound proves nothing
	}
	return result, VersionRange{}, every, proofNone
}

// lostRow says a row of v that names the line (its own, or the exploited list's key) is a CVE record row of a product an entry of which
// the record reader could not keep (Affected.Lost): the record's rows are not its whole word on the product, so no reading of them
// (outside every range, past a fix, a complete list, another system) nor a vendor scheme's verdict may prove the line not affected.
func lostRow(in swInfo, v Vuln, key []identity) bool {
	return slices.ContainsFunc(v.Affected, func(af Affected) bool {
		if !af.Lost {
			return false
		}
		c, err := af.cpe()
		if err != nil {
			return true
		}
		own, byKey, known := entryFor(c, in, key)
		return own || byKey || !known
	})
}

// otherBranch says row c with range r lies inside one release branch that is not version ver's: every bound starts with the same
// numbers (OpenSSL's "1.1.1" to "1.1.1zk", or an exact release), and ver starts with other numbers in the same notation ("3.5.0"). Such
// a row cannot hold ver whatever its letters or pins mean. A range open on one side spans other branches ("before 1.1.1zk"), a version
// of the same numbers is of the branch ("1.1.1w"), and a row in another notation ("2016" against "16.0.1", schemeClash) or of a
// network OS's own scheme is not another branch: none of them is.
func otherBranch(c CPE, r VersionRange, ver string) bool {
	if osScheme(c) != "" || isPlaceholder(ver) { // a placeholder ("0", "0.0.0") is no version, so of no branch
		return false
	}
	if r.IsZero() {
		lit, ok := c.Version.Literal()
		if !ok {
			return false
		}
		r = VersionRange{StartIncl: lit, EndIncl: lit}
	}
	if r.StartIncl+r.StartExcl == "" || r.EndIncl+r.EndExcl == "" || schemeClash(r, ver) {
		return false
	}
	v, ok := dottedTrain(ver)
	if !ok {
		return false
	}
	var branch []uint64
	for _, b := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl} {
		if b == "" {
			continue
		}
		n, ok := dottedTrain(b)
		if !ok || branch != nil && !slices.Equal(n, branch) {
			return false
		}
		branch = n
	}
	for i := range min(len(v), len(branch)) {
		if v[i] != branch[i] {
			return true
		}
	}
	return false // "2.4" and "2.4.57": the version may be of the branch
}

// recordDecided says the CVE record's rows read beside NVD's (AffectedOnly) are what call the line affected: without them decide does
// not say Yes. The finding then names the record as the origin of the ranges it compared.
func recordDecided(in swInfo, v Vuln) bool {
	if !slices.ContainsFunc(v.Affected, func(af Affected) bool { return af.AffectedOnly }) {
		return false
	}
	nvd := v
	nvd.Affected = slices.DeleteFunc(slices.Clone(v.Affected), func(af Affected) bool { return af.AffectedOnly })
	t, _, _, _ := decide(in, nvd, keyIDs(v))
	return t != Yes
}

// proofKind is what a No of decide rests on: only proofRange and proofOS close a finding.
type proofKind uint8

const (
	proofNone    proofKind = iota // no No, or a No that proves nothing about the version
	proofRange                    // the readable version is outside every applicable NVD entry
	proofOS                       // the entry lists only releases of the device's distribution, not its release
	proofRelease                  // the entry lists only Windows releases older than the device's, which shipped after the fix or NVD's list is settled
)

// everyVersion reports whether configuration c names the product with nothing else pinned: every version, update,
// edition, language and target.
func everyVersion(c CPE) bool {
	f := c.fields()
	for _, a := range f[3:] { // version and everything after it
		if a.Kind != Any {
			return false
		}
	}
	return true
}

// identity is a normalised vendor and product; prefix (aliases only) matches every product that starts with it.
type identity struct {
	vendor, product string
	prefix          bool
	// record: the name a CVE record writes for a product without a CPE (company words and the vendor's name in front dropped,
	// recordIdentity); it names only a record's range (part ANY), never an NVD CPE.
	record bool
	// ai: the product the customer's AI chose for the line (Software.AIProduct), not a name the line or the catalogue gives it.
	ai bool
}

// recordIdentity is a software's own names as a CVE record's product key is written (feeds' RecordProductKey: "Palo Alto Networks",
// "PAN-OS" is paloalto|panos), so a record range of a product the catalogue does not list still reaches it.
func recordIdentity(vendor, product string) identity {
	return identity{vendor: productid.NormVendor(vendor), product: productid.NormProduct(product, vendor), record: true}
}

func (i identity) ok() bool { return i.vendor != "" && i.product != "" }

func (i identity) matches(vendor, product string) bool {
	if i.vendor != vendor {
		return false
	}
	if i.prefix {
		return strings.HasPrefix(product, i.product)
	}
	return i.product == product
}

// appliesTo says whether configuration c is about this software. known is false
// when c names its vendor or product with ANY, NA or a wildcard and the software
// has no CPE to settle it: such an entry may be about this software.
func appliesTo(c, sw CPE, hasSW bool, ids []identity) (match, known bool) {
	if hasSW && c.SameProduct(sw) {
		return true, true
	}
	cv, okV := c.Vendor.Literal()
	cp, okP := c.Product.Literal()
	if !okV || !okP {
		return false, false
	}
	cv, cp = productid.Norm(cv), productid.Norm(cp)
	for _, i := range ids {
		if i.record && c.Part.Kind != Any {
			continue
		}
		if i.matches(cv, cp) {
			return true, true
		}
	}
	return false, true
}

// versionKnown reports whether ver is a real, comparable version.
func versionKnown(ver string) bool {
	_, ok := parseVersion(ver)
	return ok && !isPlaceholder(ver)
}

// versionGiven reports whether ver says anything about the version: not empty, not a placeholder ("0", "0.0.0") and
// with at least one digit ("latest", "unknown", "n/a" say nothing). A given version may still be unreadable (Cisco
// "15.2(4)M3"): that is "cannot compare" (a product finding, medium), not "add the version".
func versionGiven(ver string) bool {
	ver = strings.TrimSpace(ver)
	return strings.ContainsAny(ver, "0123456789") && !isPlaceholder(ver) && len(ver) <= maxVersionLen
}

// evalAffected evaluates one configuration CPE (with its NVD range) against the
// software. Everything the software side cannot confirm (an unknown version, a
// pinned update, edition, language or target the software does not carry) can
// only lower Yes to Unknown, never produce No.
func evalAffected(c CPE, r VersionRange, ver string, sw CPE, hasSW bool) (Tri, VersionRange) {
	if t, jr, ok := junosEval(c, r, ver); ok { // "15.1R7.9" is 15.1R7, an X train is a release of its own
		if t = pinnedAttrs(c, sw, hasSW, t); t == No {
			return No, r
		}
		return t, jr
	}
	exact := false
	if r.IsZero() {
		switch c.Version.Kind {
		case Any: // every version
		case Value:
			lit, ok := c.Version.Literal()
			if !ok {
				return Unknown, r
			}
			r = VersionRange{StartIncl: lit, EndIncl: lit}
			exact = true
		default:
			return Unknown, r
		}
	} else if c.Version.Kind != Any {
		return Unknown, r // a range next to a concrete version: contradictory data
	}
	var t Tri
	if et, ok := officeEdition(c, r, exact, ver); ok {
		t = et
	} else if et, ok := sqlServerRelease(c, r, exact, ver); ok {
		t = et
	} else if schemeClash(r, ver) {
		t = Unknown // "2016" against "16.0.1", "1607" against "10.0.14393": two ways of writing versions
	} else if c.Update.Kind == Any {
		t = r.Contains(ver)
		if t == No && exact {
			t = looseExact(r, ver)
		}
		if (t == Unknown || exact && t == No) && osScheme(c) == schemeDotted { // "up to 15.2(6)e0a" on IOS XE 17.3.1: by its numbers
			t = dottedDecide(t, r, exact, ver)
		}
	} else {
		t = evalUpdate(c, r, ver, sw, hasSW)
	}
	if t == Yes && !versionKnown(ver) {
		t = Unknown // "all versions" does not make an unknown version a version match
	}
	if exact && t != Yes && c.Update.Kind == Any && sameVersionText(r.StartIncl, ver) {
		t = Yes // the exact version NVD lists, character for character: Cisco "15.2(4)m3" needs no ordering
	}
	if t = pinnedAttrs(c, sw, hasSW, t); t == No {
		return No, r
	}
	return t, r
}

// looseExact softens a No for an exact-version configuration whose update is ANY:
// ANY covers every update, so the software "8.9p1" may be configuration "8.9".
func looseExact(r VersionRange, ver string) Tri {
	pv, ok := parseVersion(ver)
	if !ok || pv.q.class == 0 {
		return No
	}
	if r.Contains(relString(pv)) == Yes {
		return Unknown
	}
	return No
}

// evalUpdate handles a configuration pinned to an update ("8.9:p1", "2.0:beta1").
// The software side must carry the update, either as the CPE update attribute or
// as a qualifier of its version string ("8.9p1", "2.0-beta1"); otherwise Unknown.
func evalUpdate(c CPE, r VersionRange, ver string, sw CPE, hasSW bool) Tri {
	pv, ok := parseVersion(ver)
	if !ok || isPlaceholder(ver) {
		return Unknown
	}
	if r.Contains(relString(pv)) == No {
		return No // the release itself is outside ("2016" against "2000:sr1"): the update does not matter
	}
	if pv.tail != "" {
		return Unknown
	}
	// "1.9.17:-" is the release with no update: "1.9.17p2" is not it. A row whose CPE leaves the update unstated reads it
	// from its version string, as a row without a CPE does (naCovers, #901).
	if c.Update.Kind == NA && (!hasSW || naCovers(c.Update, sw.Update)) {
		if pv.q.class != 0 {
			return No
		}
		return r.Contains(ver)
	}
	if hasSW && sw.Update.Kind == Value && pv.q.class == 0 {
		if !attrMatch(c.Update, sw.Update) {
			return No
		}
		return r.Contains(ver)
	}
	cu, ok := c.Update.Literal()
	if !ok {
		return Unknown
	}
	cq, ctail, ok := parseQual(strings.ToLower(cu))
	if !ok || ctail != "" {
		return Unknown
	}
	if pv.q.class == 0 {
		if cq.class < 0 {
			return No // a plain "7.0.0" is the release, not the pre-release "7.0:rc1"
		}
		return Unknown // a plain "8.9" may be "8.9p1": the patch level is often left out
	}
	if cq != pv.q {
		if cq.class == pv.q.class && cq.sub == pv.q.sub && (cq.num == 0 || pv.q.num == 0) {
			return Unknown // same kind of update, one without a number: "beta" may be "beta1"
		}
		return No // "h1" is not "h2", Junos "r2-s1" is not "r2"
	}
	return r.Contains(relString(pv))
}

// pinnedAttrs checks the attributes the software side rarely carries (edition,
// language, software edition, target software/hardware, other). A pinned value
// the software contradicts gives No; one it does not carry lowers Yes to Unknown.
// NA ("-") is pinned like a value here: it matches the software's NA, and an unstated
// attribute lowers Yes to Unknown, because NVD's "-" often means "the plain edition"
// beside one inventory cannot tell apart (Firefox "-" vs ESR, Jenkins "-" vs LTS;
// #906). Only the Windows release rows (winUnpinned) and the
// update rule (evalUpdate) let NA cover an unstated attribute (naCovers, #901). What the
// box can derive about the build (installOf: Mozilla's edition, the system, the
// architecture) is applied before this, by swInfo.eval (judge).
func pinnedAttrs(c, sw CPE, hasSW bool, t Tri) Tri {
	cfa := c.fields()
	cf := cfa[5:]
	var sf []*Attr
	if hasSW {
		sfa := sw.fields()
		sf = sfa[5:]
	}
	for i, a := range cf {
		if a.Kind == Any {
			continue
		}
		if hasSW {
			if attrMatch(*a, *sf[i]) {
				continue
			}
			if sf[i].Kind == Value {
				return No
			}
		}
		if t == Yes {
			t = Unknown
		}
	}
	return t
}

// clean removes control characters and caps the length: names, versions and
// ranges come from agents and feeds (untrusted) and end up in evidence text.
// softwareName is a row's display name without the version it may already end with: a scan row is named as nmap reads it,
// "OpenSSH 10.2" (otherwise: "runs OpenSSH 10.2 10.2").
func softwareName(display, version string) string {
	d, v := clean(display), clean(version)
	if v != "" && d != v {
		if t, ok := strings.CutSuffix(d, " "+v); ok {
			return strings.TrimSpace(t)
		}
	}
	return d
}

// withVersion is "<software> <version>", the version once.
func withVersion(display, version string) string {
	d := softwareName(display, version)
	if v := clean(version); v != "" {
		d += " " + v
	}
	return d
}

func clean(s string) string {
	var sb strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if n++; n > 120 {
			sb.WriteString("...")
			break
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// explainsBetter says range a, which the version is inside, explains a finding better than b, which it is inside too: a range with an
// end (a release fixes it, endBound) before one without (a record's "1.25.0 or later" beside its "1.30.0 to 1.30.6"), then the one that
// ends later (widerEnd). Only the reading of the version changes: which release fixes the finding is FixOf's, which checks that a
// candidate fix leaves every range (an open-ended one included).
func explainsBetter(a, b VersionRange) bool {
	if ea, eb := endBound(a), endBound(b); ea != eb {
		return ea
	}
	return widerEnd(a, b)
}

// widerEnd says range a ends later than b; a range with no end is the widest, and a tie keeps b.
func widerEnd(a, b VersionRange) bool {
	end := func(r VersionRange) string { return cmp.Or(r.EndExcl, r.EndIncl) }
	ea, eb := end(a), end(b)
	if ea == "" || eb == "" {
		return ea == "" && eb != ""
	}
	c, ok := compareBound(ea, eb)
	return ok && c > 0
}

// orList joins names for a sentence: "A", "A or B", "A, B or C".
func orList(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}
