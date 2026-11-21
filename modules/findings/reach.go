package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/knt048/vedette/core/store"
)

// ReachClass says how far an exploited-list entry can get with the software Vedette's inventory produces (#910 phase 1, the
// feed-refresh reachability audit; classes of reviews/kev-reachability-audit.md, re-defined on the matcher of #913/#919/#920).
type ReachClass string

// The classes, first that applies.
const (
	ReachNoNVDData     ReachClass = "1"  // NVD has no entry for the CVE (or has not answered yet)
	ReachNoNVDVersions ReachClass = "2"  // NVD's entries give no version (no range bound, no version in a CPE)
	ReachKeyedVersion  ReachClass = "3v" // CISA's key reaches a row and an NVD entry with a version names it: a version finding is possible
	ReachKeyedOnly     ReachClass = "3k" // CISA's key reaches a row, no NVD entry with a version names it: product match or "could not be checked"
	ReachViaNVD        ReachClass = "4"  // no row is keyed, NVD's list names one with a range that ends (viaNVD, #913)
	ReachNone          ReachClass = "5"  // no software Vedette produces meets it
)

// ReachClasses is every class in order.
var ReachClasses = []ReachClass{ReachNoNVDData, ReachNoNVDVersions, ReachKeyedVersion, ReachKeyedOnly, ReachViaNVD, ReachNone}

// Unreachable says no version comparison can happen for an entry of the class, whatever the device's version.
func (c ReachClass) Unreachable() bool { return c != ReachKeyedVersion && c != ReachViaNVD }

// ReachReport is one run of Reachability.
type ReachReport struct {
	Total  int
	Counts map[ReachClass]int
	CVEs   map[ReachClass][]string // the CVEs of each unreachable class (Unreachable), sorted
	Class  map[string]ReachClass   // every CVE's class
}

// Reachability classes every entry of vulns against the software Vedette can produce: rows (what cmd/vedette assembles from
// agent-intake's package map and Windows release rows and inventory's curated catalog, with their KEV keys) plus the network OS
// rows of network-os.json (deviceOS). It reads them through the matcher's own predicates, never a copy of its rules: newSWInfo
// (names and content/catalog/products aliases), keyedTo (CISA's key), entryFor (the entries decide reads for a keyed row: the row's own names
// and CISA's key) and versionEvidence, nvdCandidates and nvdReaches (viaNVD's gate, for every row the key does not reach, as
// matchOne). Pure: no clock, no DB.
func Reachability(vulns []Vuln, rows []Software) ReachReport {
	sws := slices.Concat(rows, networkOSRows())
	infos := make([]swInfo, len(sws))
	for i, s := range sws {
		infos[i] = newSWInfo(s, "")
	}
	named := nvdCandidates(sws, vulns)
	r := ReachReport{Counts: map[ReachClass]int{}, CVEs: map[ReachClass][]string{}, Class: make(map[string]ReachClass, len(vulns))}
	for vi, v := range vulns {
		if !ValidCVE(v.CVE) || r.Class[v.CVE] != "" {
			continue
		}
		c := reachClass(sws, infos, named, vi, v)
		r.Class[v.CVE] = c
		r.Total++
		r.Counts[c]++
		if c.Unreachable() {
			r.CVEs[c] = append(r.CVEs[c], v.CVE)
		}
	}
	for _, l := range r.CVEs {
		slices.Sort(l)
	}
	return r
}

// reachClass reads v for every row as matchOne does (a keyed row through judge, any other through viaNVD) and keeps the best
// outcome: a version comparison through the key (3v), else through NVD's list (4), else keyed without a version (3k), else none.
func reachClass(sws []Software, infos []swInfo, named []map[int]bool, vi int, v Vuln) ReachClass {
	switch {
	case len(v.Affected) == 0:
		return ReachNoNVDData
	case !slices.ContainsFunc(v.Affected, versionEvidence):
		return ReachNoNVDVersions
	}
	keyed, via := false, false
	for i, s := range sws {
		switch {
		case keyedTo(s, v):
			if versionNamed(infos[i], v) {
				return ReachKeyedVersion
			}
			keyed = true
		case named[i][vi] && !via:
			via = nvdReaches(Asset{}, s, infos[i], v)
		}
	}
	switch {
	case via:
		return ReachViaNVD
	case keyed:
		return ReachKeyedOnly
	}
	return ReachNone
}

// versionNamed says an NVD entry with a version is one decide reads for a row CISA's key reaches (entryFor: its own names, or the
// KEV entry's vendor and product), or, for a Windows release row, any Windows release or component Windows' monthly update
// services (the Windows branch of nvdNames: windowsDecide reads the release's siblings).
func versionNamed(in swInfo, v Vuln) bool {
	key := keyIDs(v)
	_, win := winDevice(in)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA || !versionEvidence(af) {
			continue
		}
		if own, byKey, _ := entryFor(c, in, key); own || byKey || win && winNamesWindows(c) {
			return true
		}
	}
	return false
}

// networkOSRows is one row per network OS of network-os.json, as deviceOS makes it for a device that states it.
func networkOSRows() []Software {
	out := make([]Software, 0, len(osRows))
	for _, d := range osRows {
		out = append(out, Software{ID: "os:reach", Display: d.Display, Vendor: d.Vendor, Product: d.Product, KevKeys: slices.Clone(d.KevKeys), CPE: d.cpe23(), Source: "snmp"})
	}
	return out
}

// ReachAudit runs the audit over the exploited list findings matches with (Feeds.Vulns) and the software rows cmd/vedette
// assembles, and stores it (StoreReach) under stamp, the feed data's stamp. Nothing while the list is empty (no pull yet).
func (s *Service) ReachAudit(ctx context.Context, stamp string, rows []Software) (bool, error) {
	vulns, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil || len(vulns) == 0 {
		return false, err
	}
	return s.StoreReach(ctx, stamp, Reachability(vulns, rows))
}

// reachKeep is how many runs fnd_reach_run keeps (the newest).
const reachKeep = 30

// StoreReach records one run of the reachability audit after a feed refresh (fnd_reach_run, #910 phase 1): the stamp of the feed
// data it read, the counts per class and the CVEs of each unreachable class, with those that were not in that class in the previous
// run ("added"), and logs one line with the counts and one per new unreachable CVE. A run whose classes (counts and unreachable CVEs)
// equal the previous run's is not stored, whatever its stamp (review r1 M3 of #923: the stamp moves on every pull of 11 feeds); false
// then. So each row is a change, its stamp the feed data it was first seen on; the newest reachKeep are kept.
func (s *Service) StoreReach(ctx context.Context, stamp string, r ReachReport) (bool, error) {
	counts := map[string]int{}
	for _, c := range ReachClasses {
		counts[string(c)] = r.Counts[c]
	}
	unreach := map[string][]string{}
	for _, c := range ReachClasses {
		if c.Unreachable() {
			unreach[string(c)] = append([]string{}, r.CVEs[c]...)
		}
	}
	cb, err := json.Marshal(counts)
	if err != nil {
		return false, fmt.Errorf("findings: reach counts: %w", err)
	}
	ub, err := json.Marshal(unreach)
	if err != nil {
		return false, fmt.Errorf("findings: reach CVEs: %w", err)
	}
	var stored bool
	added := map[string][]string{}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		stored = false
		clear(added)
		var prevCounts, prevCVEs string
		err := tx.QueryRowContext(ctx, `SELECT counts, unreachable FROM fnd_reach_run ORDER BY id DESC LIMIT 1`).Scan(&prevCounts, &prevCVEs)
		first := errors.Is(err, sql.ErrNoRows)
		if err != nil && !first {
			return fmt.Errorf("findings: reading the last reach run: %w", err)
		}
		if !first && prevCounts == string(cb) && prevCVEs == string(ub) {
			return nil // nothing moved: the last row still says it, so 30 rows are 30 changes
		}
		if !first {
			var prev map[string][]string
			if err := json.Unmarshal([]byte(prevCVEs), &prev); err != nil {
				prev = nil // an unreadable row: every CVE counts as new
			}
			for c, l := range unreach {
				for _, cve := range l {
					if !slices.Contains(prev[c], cve) {
						added[c] = append(added[c], cve)
					}
				}
			}
		}
		nb, err := json.Marshal(added)
		if err != nil {
			return fmt.Errorf("findings: reach new CVEs: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_reach_run (ran_at, stamp, total, counts, unreachable, added) VALUES (?, ?, ?, ?, ?, ?)`,
			store.FormatTS(s.now()), stamp, r.Total, string(cb), string(ub), string(nb)); err != nil {
			return fmt.Errorf("findings: storing a reach run: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_reach_run WHERE id NOT IN (SELECT id FROM fnd_reach_run ORDER BY id DESC LIMIT ?)`, reachKeep); err != nil {
			return fmt.Errorf("findings: pruning reach runs: %w", err)
		}
		stored = true
		return nil
	})
	if err != nil || !stored {
		return false, err
	}
	args := []any{"entries", r.Total}
	for _, c := range ReachClasses {
		args = append(args, "class_"+string(c), r.Counts[c])
	}
	s.cfg.Log.InfoContext(ctx, "findings: KEV reachability after a feed refresh (#910)", args...)
	for _, c := range slices.Sorted(maps.Keys(added)) {
		for _, cve := range added[c] {
			s.cfg.Log.InfoContext(ctx, "findings: a KEV entry no device can get a version comparison for (#910)", "cve", cve, "class", c, "why", reachWhy(ReachClass(c)))
		}
	}
	return true, nil
}

func reachWhy(c ReachClass) string {
	switch c {
	case ReachNoNVDData:
		return "NVD has no entry for it yet"
	case ReachNoNVDVersions:
		return "NVD's entries give no version"
	case ReachKeyedOnly:
		return "CISA names a product Vedette knows, NVD's entries with a version name none of its names or aliases"
	}
	return "no software Vedette's inventory produces is CISA's product or one NVD's list names"
}
