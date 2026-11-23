package findings

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// UncheckedReason says why an exploited CVE of software the device has could not be checked (#910 phase 1, contract.ts
// UncheckedReason). Precedence, first that applies: no NVD data, no NVD versions, NVD names other products, versions that do not
// compare.
type UncheckedReason string

// The four reasons, in precedence order (contract.ts UncheckedReason), then the two of a platform-limited CVE only a person's answer
// decides (MatchResult.Asked), which come from the platform rules, not uncheckedReason.
const (
	UncheckedNoNVDData     UncheckedReason = "no_nvd_data"     // NVD has no CPE configuration for the CVE yet (audit class 1)
	UncheckedNoNVDVersions UncheckedReason = "no_nvd_versions" // NVD names products but no affected version (audit class 2)
	UncheckedNotNamed      UncheckedReason = "not_named"       // NVD's list names none of the row's names (audit class 5, "3k")
	UncheckedNotComparable UncheckedReason = "not_comparable"  // the row's version cannot be compared with NVD's
	// UncheckedPlatformUnknown: the CVE affects only some platforms or builds and nothing says which this row is.
	UncheckedPlatformUnknown UncheckedReason = "platform_unknown"
	// UncheckedPackageUnknown: the platform is the one of the distribution's fixed list, and the package release is not known.
	UncheckedPackageUnknown UncheckedReason = "package_unknown"
)

// Unchecked is one exploited CVE of one software row of the device that gave no finding, no "add the version" item and no
// proof either way (#910 phase 1, MatchResult.Unchecked).
type Unchecked struct {
	CVE        string
	SoftwareID string // osSoftwareID for the network OS a device states without a software row (NotComparable)
	Software   string // the row's display, as on the device page
	Version    string // the row's version as stored, "" when none
	Source     string // Software.Source: "manual" lets a person retype the version (action add_version)
	Reason     UncheckedReason
	// Answer: package_unknown only, the release a person gave that Vedette could not read as one; "" otherwise.
	Answer string
	// NVDPending: no_nvd_data while NVD has not answered for the CVE (Vuln.NVDAnswered false: a new box, the NVD feed off or failing):
	// Vedette is waiting for NVD's data, NVD has not said it has none (review r2 M1 of #939).
	NVDPending bool
}

// uncheckedRow says whether row s, read against v with outcome out (matchOne), is one the device has but Vedette could not check,
// and why. Only two kinds of rows count, so the list never names an entry for software the device does not have:
//   - a row CISA's key names (keyedTo, never a vendor's "Multiple Products": there NVD's list of other products says it is not this
//     one) whose match is a No that proves nothing: NVD's ranges are for the entry's name, not for the row's;
//   - a row only NVD's list names (#910, viaNVD) by its own CPE, name or alias (rowEntries: for a Windows release row its own
//     release, not a sibling), with a version given, that gave neither a version match with a fix nor a proof: NVD lists only
//     exact versions, no end or no version, or the version does not compare. Not a row whose distribution decides (its own
//     word, or none, as for an Android entry that also lists the Linux kernel), not an Edge Legacy row, not a Juniper model CISA
//     leaves out.
//
// Neither kind counts when NVD names the row only at exact versions older than its own (newerThanListed): NVD's list does not name
// it at all, so it is no candidate (not a verdict: nothing closes, nothing is "not affected").
//
// A product match the age rule drops and the network OS a device states without an order (NotComparable) are listed by
// MatchAsset itself.
func uncheckedRow(a Asset, s Software, in swInfo, v Vuln, named bool, m Match, out outcome) (UncheckedReason, bool) {
	switch {
	case out == outRuledOut: // only a keyed row is ruled out (viaNVD says nothing instead)
		// a vendor's "Multiple Products" reaches every row of the vendor by its key: only one NVD's list names counts (r1 L4)
		if m.Evidence.Summary != "" || isMultiProduct(v.Product) && len(rowEntries(s, in, v)) == 0 {
			return "", false
		}
	case out == outNone && named && in.given: // cheapest tests first: this runs for every row NVD's vendors may name
		if edgeLegacyRow(s, in) || distroBuilt(in) || keyedTo(s, v) { // a keyed row with no outcome: its distribution decided
			return "", false
		}
		if _, ok := distroVerdict(in, v); ok {
			return "", false
		}
		if _, o := otherSeries(a.Model, v); o || len(rowEntries(s, in, v)) == 0 {
			return "", false
		}
	default:
		return "", false
	}
	if newerThanListed(rowEntries(s, in, v), in.ver) {
		return "", false
	}
	return uncheckedReason(s, in, v, false)
}

// newerThanListed says every entry of own (the entries of NVD's list that name the row, rowEntries) is one exact version, with no
// range, that the row's version is later than (laterThan): Java 8 Update 491 for CVE-2023-41993, which NVD lists for Java at
// "1.8.0 update401" only; SQL Server 2022 (16.0.1000.6) for CVE-2012-1856, listed for SQL Server 2000 to 2008. NVD's configuration
// names those versions, not the row's, so the row is not a candidate. Only later: an exact list is often the last affected
// update of each line (Oracle's "8u77 and earlier"), so an older version than every listed one stays a candidate, and so does any
// entry with a range, any version or a version that does not read.
func newerThanListed(own []Affected, ver string) bool {
	if len(own) == 0 || !versionKnown(ver) {
		return false
	}
	for _, af := range own {
		c, err := af.cpe()
		if err != nil || !af.Range.IsZero() {
			return false
		}
		lit, ok := c.Version.Literal()
		if !ok || !laterThan(c, lit, ver) {
			return false
		}
	}
	return true
}

// uncheckedReason is the reason of an unchecked row, first that applies:
//   - no_nvd_data: Vedette has no NVD entry for it: NVD answered with none, or has not answered yet (#939:
//     a new exploited CVE matched by name is listed at once; this replaces #920's "no row before NVD answered");
//   - no_nvd_versions: no entry gives a version (audit class 2);
//   - not_comparable: a Windows row of a build core/winrel does not know, when NVD lists Windows rows (winUnknownBuild);
//   - not_named: none names the row (audit class 5 and "3k", and #919's nvd_other_product);
//   - no_nvd_versions: those that name it give no version, or no range that decides (only exact versions, only a start, or a
//     partial CVE.org list);
//   - not_comparable: an entry naming it has a range with an end and the row's version did not compare with it, or the row is a
//     network OS whose version has no order (scheme): only then can typing the version as the vendor writes it help.
func uncheckedReason(s Software, in swInfo, v Vuln, scheme bool) (UncheckedReason, bool) {
	if len(v.Affected) == 0 { // before NVD answered too: Vedette has no NVD data for it yet, and says so at once (review r1 H2 of #939)
		return UncheckedNoNVDData, true
	}
	if !slices.ContainsFunc(v.Affected, versionEvidence) {
		return UncheckedNoNVDVersions, true
	}
	if _, ok := winUnknownBuild(s, in); ok && slices.ContainsFunc(v.Affected, func(af Affected) bool { // NVD lists Windows, and the build is not in the table
		c, err := af.cpe()
		return err == nil && winNamesWindows(c)
	}) {
		return UncheckedNotComparable, true
	}
	own := rowEntries(s, in, v)
	switch {
	case len(own) == 0:
		return UncheckedNotNamed, true
	case !slices.ContainsFunc(own, versionEvidence):
		return UncheckedNoNVDVersions, true
	case scheme || !versionKnown(in.ver):
		return UncheckedNotComparable, true
	case v.RangesFrom == RangesCVEOrgPartial || !slices.ContainsFunc(own, func(af Affected) bool { return endBound(af.Range) }):
		return UncheckedNoNVDVersions, true
	}
	return UncheckedNotComparable, true
}

// versionEvidence says whether an NVD entry gives a version: a range bound, or a version in its CPE.
func versionEvidence(af Affected) bool {
	if r := af.Range; r.StartIncl != "" || r.StartExcl != "" || r.EndIncl != "" || r.EndExcl != "" {
		return true
	}
	c, err := af.cpe()
	if err != nil {
		return false
	}
	_, ok := c.Version.Literal()
	return ok
}

// rowEntries are the entries of NVD's list for v that name the row itself (its CPE, name or alias, appliesTo), leaving out, for a
// Chromium-based Edge, the Edge Legacy entries: microsoft:edge with no version or one below 79, or, for a CVE published
// before the Chromium-based Edge, microsoft:edge with no version given at all (CVE-2017-0037 "Edge and Internet Explorer").
func rowEntries(s Software, in swInfo, v Vuln) []Affected {
	chromium := false
	if n, ok := edgeMajor(in.ver); ok && n >= chromiumEdgeFirst && productid.Norm(s.Vendor) == "microsoft" && strings.HasPrefix(productid.Norm(s.Product), "edge") {
		chromium = true
	}
	var out []Affected
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		if own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids); !own || chromium && edgeLegacyOf(c, af, v) {
			continue
		}
		out = append(out, af)
	}
	return out
}

func uncheckedOf(s Software, v Vuln, r UncheckedReason) Unchecked {
	return Unchecked{CVE: v.CVE, SoftwareID: s.ID, Software: clean(s.Display), Version: clean(s.Version), Source: s.Source, Reason: r,
		NVDPending: r == UncheckedNoNVDData && !v.NVDAnswered}
}

// UncheckedRow is one stored unchecked (device, software, CVE).
type UncheckedRow struct {
	AssetID string
	Unchecked
}

// ListUnchecked returns the CVEs of one device, or of every device when assetID is empty, that Vedette could not check (its questions
// about one CVE), without those the device has a finding for.
func (s *Service) ListUnchecked(ctx context.Context, assetID string) ([]UncheckedRow, error) {
	q := s.cfg.DB.Reader()
	qs, err := questionsOf(ctx, q, assetID)
	if err != nil {
		return nil, err
	}
	fs, err := findingsOf(ctx, q, assetID)
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, f := range fs {
		has[f.AssetID+"\x1f"+f.CVE] = true
	}
	out := []UncheckedRow{}
	for _, x := range qs {
		if x.CVE == "" || has[x.AssetID+"\x1f"+x.CVE] {
			continue
		}
		sw := x.SoftwareID
		if sw == "" {
			sw = osSoftwareID(x.AssetID)
		}
		out = append(out, UncheckedRow{AssetID: x.AssetID, Unchecked: Unchecked{CVE: x.CVE, SoftwareID: sw, Software: x.Detail.Software,
			Version: x.Detail.Version, Source: x.Detail.Source, Reason: UncheckedReason(x.Detail.Reason), Answer: x.Detail.Choice, NVDPending: x.Detail.NVDPending}})
	}
	return out, nil
}

// NeedVersionRow is a software line without a version Vedette can read, with how many exploited CVEs wait on it.
type NeedVersionRow struct {
	AssetID, SoftwareID, Software, Version string
	CVEs                                   int
	UpdatedAt                              time.Time
}

// ListVersionNeeded returns the software lines of one device, or of every device when assetID is empty, that need a version.
func (s *Service) ListVersionNeeded(ctx context.Context, assetID string) ([]NeedVersionRow, error) {
	qs, err := questionsOf(ctx, s.cfg.DB.Reader(), assetID)
	if err != nil {
		return nil, err
	}
	var out []NeedVersionRow
	for _, x := range qs {
		if x.Kind != QuestionVersionNeeded {
			continue
		}
		out = append(out, NeedVersionRow{AssetID: x.AssetID, SoftwareID: x.SoftwareID, Software: x.Detail.Software, Version: x.Detail.Version, CVEs: x.Cves, UpdatedAt: x.AskedAt})
	}
	return out, nil
}

// unchecked is GET /findings `unchecked` of one device, or of every device when assetID is empty (UncheckedItems).
func (h *FindingHandlers) unchecked(ctx context.Context, assetID string) ([]UncheckedItem, error) {
	rows, err := h.svc.ListUnchecked(ctx, assetID)
	if err != nil || len(rows) == 0 {
		return []UncheckedItem{}, err
	}
	var cves, ids []string
	seen := map[string]bool{}
	for _, r := range rows {
		for _, k := range []string{"c" + r.CVE, "a" + r.AssetID} {
			if !seen[k] {
				seen[k] = true
				if k[0] == 'c' {
					cves = append(cves, r.CVE)
				} else {
					ids = append(ids, r.AssetID)
				}
			}
		}
	}
	kev, err := h.feed.KevInfo(ctx, cves)
	if err != nil {
		return nil, fmt.Errorf("findings: reading KEV entries: %w", err)
	}
	assets, err := h.inv.Assets(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("findings: reading devices: %w", err)
	}
	var distro map[string][]DistroFix // the fixed releases a question names come from the distribution's feed
	if slices.ContainsFunc(rows, func(r UncheckedRow) bool {
		return r.Reason == UncheckedPlatformUnknown || r.Reason == UncheckedPackageUnknown
	}) {
		// the list the matcher reads (cached per feeds stamp in cmd/vedette); unreadable, the questions go without releases
		vulns, err := h.feed.Vulns(ctx)
		if err != nil {
			h.svc.cfg.Log.WarnContext(ctx, "reading the exploited list for the questions failed; they name no fixed release", "error", err)
		}
		distro = map[string][]DistroFix{}
		for _, v := range vulns {
			if HasPlatformLimit(v.CVE) {
				distro[v.CVE] = v.Distro
			}
		}
	}
	return UncheckedItems(rows, kev, assets, distro), nil
}


// UncheckedCVE is contract.ts UncheckedCve.
type UncheckedCVE struct {
	CVE        string  `json:"cve"`
	Name       string  `json:"name"`
	DateAdded  string  `json:"date_added"`
	Ransomware bool    `json:"ransomware"`
	Advisory   *string `json:"advisory"`
	NVDPending bool    `json:"nvd_pending,omitempty"` // review r2 M1 of #939: no_nvd_data because NVD has not answered yet
}

// UncheckedItem is contract.ts UncheckedItem: one device × software × reason.
type UncheckedItem struct {
	Asset      *AssetView      `json:"asset"`
	AssetID    string          `json:"asset_id"`
	SoftwareID *string         `json:"software_id"` // nil: the network OS the device states, which has no software row
	Software   string          `json:"software"`
	Version    *string         `json:"version"`
	Reason     UncheckedReason `json:"reason"`
	CVEs       []UncheckedCVE  `json:"cves"`
	Action     string          `json:"action"` // "add_version", "answer_platform" (Question) or "none"
	// Question is what a person answers for reasons platform_unknown and package_unknown, nil otherwise.
	Question *UncheckedQuestion `json:"question,omitempty"`
}

// UncheckedQuestion is contract.ts UncheckedQuestion: the question of a platform-limited CVE and the answers that settle it.
// Every answer is a correction of inventory (INV-41), so the next match decides.
type UncheckedQuestion struct {
	Text string `json:"text"`
	// Error says the last answer could not be read ("Vedette could not read the release you entered …"), nil otherwise.
	Error   *string           `json:"error,omitempty"`
	Command *string           `json:"command"` // what to run on the device to read the answer ("apk info -e -v openssh-server"), nil when none
	Answers []UncheckedAnswer `json:"answers"`
}

// UncheckedAnswer is one answer: OS set → one click sets the device's OS to it (PATCH /inventory/devices/{asset_id} {os}); Ask holds "os" →
// the person types the OS (same call); Ask "pkg_version" → the person types the package release of the row (PATCH
// /inventory/devices/{asset_id}/software/{software_id} {pkg_version}).
type UncheckedAnswer struct {
	Label string   `json:"label"`
	OS    *string  `json:"os,omitempty"`
	Ask   []string `json:"ask,omitempty"` // "os", "pkg_version": what the person types (both for "Another system")
}

// UncheckedItems groups rows into items, with the CISA name, date and advisory (its first link, a web address) of each CVE (kev)
// and the device (assets): devices by name, then software by display, then CVEs newest first (date_added, then id). A CVE the
// exploited list no longer has is left out (KEV entries only), so no item is empty.
// distro is the distributions' word by CVE (Vuln.Distro) for the questions of platform-limited CVEs (the fixed releases they
// name); nil when none is asked.
func UncheckedItems(rows []UncheckedRow, kev map[string]KevInfo, assets map[string]AssetView, distro map[string][]DistroFix) []UncheckedItem {
	type key struct {
		asset, sw string
		reason    UncheckedReason
		cve       string // One item per question (a platform-limited CVE), "" otherwise
	}
	idx := map[key]int{}
	out := []UncheckedItem{}
	for _, r := range rows {
		k, ok := kev[r.CVE]
		if _, err := time.Parse(time.DateOnly, k.DateAdded); !ok || err != nil {
			continue // the exploited list no longer has it (or no date to show)
		}
		c := UncheckedCVE{CVE: r.CVE, Name: k.Name, DateAdded: k.DateAdded, Ransomware: k.Ransomware, NVDPending: r.NVDPending}
		if len(k.Links) > 0 {
			if u, err := url.Parse(strings.TrimSpace(k.Links[0])); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
				l := u.String()
				c.Advisory = &l
			}
		}
		kk := key{r.AssetID, r.SoftwareID, r.Reason, ""}
		asks := r.Reason == UncheckedPlatformUnknown || r.Reason == UncheckedPackageUnknown
		if asks {
			kk.cve = r.CVE
		}
		i, seen := idx[kk]
		if !seen {
			i = len(out)
			idx[kk] = i
			it := UncheckedItem{AssetID: r.AssetID, Software: r.Software, Reason: r.Reason, Action: "none"}
			if a, ok := assets[r.AssetID]; ok {
				it.Asset = &a
			}
			if !strings.HasPrefix(r.SoftwareID, "os:") {
				id := r.SoftwareID
				it.SoftwareID = &id
			}
			if r.Version != "" {
				v := r.Version
				it.Version = &v
			}
			if r.Reason == UncheckedNotComparable && r.Source == "manual" {
				it.Action = "add_version"
			}
			if asks && it.SoftwareID != nil {
				name := r.AssetID
				if it.Asset != nil {
					name = it.Asset.Name
				}
				if q := platformQuestion(r.CVE, name, r.Reason, r.Answer, distro[r.CVE]); q != nil {
					it.Question, it.Action = q, "answer_platform"
				}
			}
			out = append(out, it)
		}
		if !slices.ContainsFunc(out[i].CVEs, func(x UncheckedCVE) bool { return x.CVE == c.CVE }) {
			out[i].CVEs = append(out[i].CVEs, c)
		}
	}
	for i := range out {
		slices.SortFunc(out[i].CVEs, func(a, b UncheckedCVE) int {
			return cmp.Or(cmp.Compare(b.DateAdded, a.DateAdded), cmp.Compare(b.CVE, a.CVE))
		})
	}
	name := func(it UncheckedItem) string {
		if it.Asset != nil {
			return strings.ToLower(it.Asset.Name)
		}
		return ""
	}
	slices.SortStableFunc(out, func(a, b UncheckedItem) int {
		return cmp.Or(cmp.Compare(boolRank(a.Asset == nil), boolRank(b.Asset == nil)), // a device gone last (r1 L6)
			cmp.Compare(name(a), name(b)), cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(strings.ToLower(a.Software), strings.ToLower(b.Software)), cmp.Compare(a.Software, b.Software),
			cmp.Compare(reasonRank(a.Reason), reasonRank(b.Reason)))
	})
	return out
}

func reasonRank(r UncheckedReason) int {
	return slices.Index([]UncheckedReason{UncheckedPlatformUnknown, UncheckedPackageUnknown, UncheckedNoNVDData, UncheckedNoNVDVersions, UncheckedNotNamed, UncheckedNotComparable}, r)
}

// edgeLegacyOf says an NVD entry is about Edge Legacy (rowEntries).
func edgeLegacyOf(c CPE, af Affected, v Vuln) bool {
	if edgeLegacyEntry(c, af.Range) {
		return true
	}
	p, _ := c.Product.Literal()
	pre := !v.Published.IsZero() && v.Published.Before(chromiumEdgeGA) || v.Published.IsZero() && cveYear(v.CVE) > 0 && cveYear(v.CVE) < 2020
	return productid.Norm(p) == "edge" && !versionEvidence(af) && pre
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}
