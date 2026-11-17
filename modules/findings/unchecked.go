package findings

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// UncheckedReason says why an exploited CVE of software the device has could not be checked (#910 phase 1, contract.ts
// UncheckedReason). Precedence, first that applies: no NVD data, no NVD versions, NVD names other products, versions that do not
// compare.
type UncheckedReason string

// The four reasons, in precedence order (contract.ts UncheckedReason).
const (
	UncheckedNoNVDData     UncheckedReason = "no_nvd_data"     // NVD has no CPE configuration for the CVE yet (audit class 1)
	UncheckedNoNVDVersions UncheckedReason = "no_nvd_versions" // NVD names products but no affected version (audit class 2)
	UncheckedNotNamed      UncheckedReason = "not_named"       // NVD's list names none of the row's names (audit class 5, "3k")
	UncheckedNotComparable UncheckedReason = "not_comparable"  // the row's version cannot be compared with NVD's
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
}

// uncheckedRow says whether row s, read against v with outcome out (matchOne), is one the device has but Vedette could not check,
// and why. Only two kinds of rows count, so the list never names an entry for software the device does not have:
//   - a row CISA's key names (keyedTo, never a vendor's "Multiple Products": there NVD's list of other products says it is not this
//     one, D-505) whose match is a No that proves nothing: NVD's ranges are for the entry's name, not for the row's;
//   - a row only NVD's list names (#910, viaNVD) by its own CPE, name or alias (rowEntries: for a Windows release row its own
//     release, not a sibling), with a version given, that gave neither a version match with a fix nor a proof: NVD lists only
//     exact versions, no end or no version, or the version does not compare. Not a row whose distribution decides (D-516: its own
//     word, or none, as for an Android entry that also lists the Linux kernel), not an Edge Legacy row, not a Juniper model CISA
//     leaves out (D-510).
//
// A product match the age rule drops (D-615) and the network OS a device states without an order (NotComparable) are listed by
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
	return uncheckedReason(s, in, v, false)
}

// uncheckedReason is the reason of an unchecked row, first that applies:
//   - no_nvd_data: NVD answered with no entry (Vuln.NVDAnswered); before it answered there is no row at all (ok false: the list
//     says nothing it cannot back, review r1 M2 of #920);
//   - no_nvd_versions: no entry gives a version (audit class 2);
//   - not_named: none names the row (audit class 5 and "3k", and #919's nvd_other_product);
//   - no_nvd_versions: those that name it give no version, or no range that decides (only exact versions, only a start, or a
//     partial CVE.org list);
//   - not_comparable: an entry naming it has a range with an end and the row's version did not compare with it, or the row is a
//     network OS whose version has no order (scheme): only then can typing the version as the vendor writes it help.
func uncheckedReason(s Software, in swInfo, v Vuln, scheme bool) (UncheckedReason, bool) {
	if len(v.Affected) == 0 {
		return UncheckedNoNVDData, v.NVDAnswered
	}
	if !slices.ContainsFunc(v.Affected, versionEvidence) {
		return UncheckedNoNVDVersions, true
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
// Chromium-based Edge, the Edge Legacy entries (D-619): microsoft:edge with no version or one below 79, or, for a CVE published
// before the Chromium-based Edge, microsoft:edge with no version given at all (CVE-2017-0037 "Edge and Internet Explorer").
func rowEntries(s Software, in swInfo, v Vuln) []Affected {
	chromium := false
	if n, ok := edgeMajor(in.ver); ok && n >= chromiumEdgeFirst && norm(s.Vendor) == "microsoft" && strings.HasPrefix(norm(s.Product), "edge") {
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
	return Unchecked{CVE: v.CVE, SoftwareID: s.ID, Software: clean(s.Display), Version: clean(s.Version), Source: s.Source, Reason: r}
}

// replaceUnchecked rewrites the unchecked rows of one device from a match run, in the run's transaction (like version-needed).
func replaceUnchecked(ctx context.Context, tx *sql.Tx, assetID string, items []Unchecked, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_unchecked WHERE asset_id = ?`, assetID); err != nil {
		return fmt.Errorf("findings: clearing unchecked rows: %w", err)
	}
	seen := map[[2]string]bool{}
	for _, u := range items {
		k := [2]string{u.SoftwareID, u.CVE}
		if seen[k] {
			continue
		}
		seen[k] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_unchecked (asset_id, software_id, software, version, source, reason, cve, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			assetID, u.SoftwareID, u.Software, u.Version, u.Source, string(u.Reason), u.CVE, store.FormatTS(now)); err != nil {
			return fmt.Errorf("findings: storing an unchecked row: %w", err)
		}
	}
	return nil
}

// uncheckedLive is the stored unchecked rows of CVEs the device has no finding for (any status): the list and Home count the
// same rows (rule 1 of #910: one place per device and CVE; a finding a person or an earlier match left wins).
const uncheckedLive = ` FROM fnd_unchecked u WHERE NOT EXISTS (SELECT 1 FROM fnd_finding f WHERE f.asset_id = u.asset_id AND f.cve = u.cve)`

// UncheckedRow is one stored unchecked (device, software, CVE).
type UncheckedRow struct {
	AssetID string
	Unchecked
}

// ListUnchecked returns the unchecked rows of one device, or of every device when assetID is empty, without those the device
// has a finding for.
func (s *Service) ListUnchecked(ctx context.Context, assetID string) ([]UncheckedRow, error) {
	q := `SELECT u.asset_id, u.software_id, u.software, u.version, u.source, u.reason, u.cve` + uncheckedLive
	var args []any
	if assetID != "" {
		q += ` AND u.asset_id = ?`
		args = append(args, assetID)
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading unchecked rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []UncheckedRow{}
	for rows.Next() {
		var r UncheckedRow
		var reason string
		if err := rows.Scan(&r.AssetID, &r.SoftwareID, &r.Software, &r.Version, &r.Source, &reason, &r.CVE); err != nil {
			return nil, fmt.Errorf("findings: reading unchecked rows: %w", err)
		}
		r.Reason = UncheckedReason(reason)
		out = append(out, r)
	}
	return out, rows.Err()
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
	return UncheckedItems(rows, kev, assets), nil
}

// uncheckedCounts is Home's line (INV-23): the distinct CVEs and devices of the list.
func uncheckedCounts(items []UncheckedItem) SummaryUnchecked {
	cves, devices := map[string]bool{}, map[string]bool{}
	for _, it := range items {
		devices[it.AssetID] = true
		for _, c := range it.CVEs {
			cves[c.CVE] = true
		}
	}
	return SummaryUnchecked{CVEs: len(cves), Devices: len(devices)}
}

// UncheckedCVE is contract.ts UncheckedCve.
type UncheckedCVE struct {
	CVE        string  `json:"cve"`
	Name       string  `json:"name"`
	DateAdded  string  `json:"date_added"`
	Ransomware bool    `json:"ransomware"`
	Advisory   *string `json:"advisory"`
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
	Action     string          `json:"action"` // "add_version" or "none"
}

// UncheckedItems groups rows into items, with the CISA name, date and advisory (its first link, a web address) of each CVE (kev)
// and the device (assets): devices by name, then software by display, then CVEs newest first (date_added, then id). A CVE the
// exploited list no longer has is left out (KEV entries only), so no item is empty.
func UncheckedItems(rows []UncheckedRow, kev map[string]KevInfo, assets map[string]AssetView) []UncheckedItem {
	type key struct {
		asset, sw string
		reason    UncheckedReason
	}
	idx := map[key]int{}
	out := []UncheckedItem{}
	for _, r := range rows {
		k, ok := kev[r.CVE]
		if _, err := time.Parse(time.DateOnly, k.DateAdded); !ok || err != nil {
			continue // the exploited list no longer has it (or no date to show)
		}
		c := UncheckedCVE{CVE: r.CVE, Name: k.Name, DateAdded: k.DateAdded, Ransomware: k.Ransomware}
		if len(k.Links) > 0 {
			if u, err := url.Parse(strings.TrimSpace(k.Links[0])); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
				l := u.String()
				c.Advisory = &l
			}
		}
		kk := key{r.AssetID, r.SoftwareID, r.Reason}
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
	return slices.Index([]UncheckedReason{UncheckedNoNVDData, UncheckedNoNVDVersions, UncheckedNotNamed, UncheckedNotComparable}, r)
}

// edgeLegacyOf says an NVD entry is about Edge Legacy (rowEntries).
func edgeLegacyOf(c CPE, af Affected, v Vuln) bool {
	if edgeLegacyEntry(c, af.Range) {
		return true
	}
	p, _ := c.Product.Literal()
	pre := !v.Published.IsZero() && v.Published.Before(chromiumEdgeGA) || v.Published.IsZero() && cveYear(v.CVE) > 0 && cveYear(v.CVE) < 2020
	return norm(p) == "edge" && !versionEvidence(af) && pre
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}
