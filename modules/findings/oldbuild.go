package findings

import (
	"context"
	"slices"
	"strconv"
	"strings"
)

// Reported only for an older build. A third party (a lab, a CNA that is not the vendor) often assigns a CVE to the one build it tested,
// years before the release a device runs, and the vendor never says a word about it: no range, no fix, no advisory. No public data
// decides such a CVE for a later release, and the leading scanners do not report it at all (a CPE list of exact builds does not match a
// later version). Vedette keeps it possible, never closes it, and lists it apart with the facts a person decides from: the builds
// tested, the year of the report, the release the device runs, and that the record gives no word from the vendor. The counts give the
// main possible number and this group's number separately (PossibleCounts.OlderBuild), so the group is visible without reading as noise.
//
// A possible CVE is in the group when every one of these holds:
//   - its undecided reason is third_party_tested_build: every row is an exact build, and a row is not the vendor's own list;
//   - every build the rows list is older than the installed release (testedBuilds);
//   - it is on no exploited list, is not a proposal for a person, and its cause is one the record or a reading of it leaves
//     (vendor_silent, ai_unsure, needs_reading, ai_budget): a page that could not be read may hold the vendor's word;
//   - no reading of the vendor's own page is stored for it (its word, whatever it decided);
//   - the CVE record was read and gives no solution and no workaround, has no reference tagged as the vendor's (vendor advisory, release
//     notes, patch, mitigation) and no dispute or unsupported tag (vendorMarks). Without the record (no door to it, not read yet, or it
//     cannot be read) the box cannot say so: the CVE stays in the main list.
//
// It is a presentation of the list only: the question, the automatic reading and every decision stay as they are.

// OlderBuild is contract.ts PossibleOlderBuild: the builds the third party reported and the year of its report (the CVE id's year).
type OlderBuild struct {
	Tested []string `json:"tested"`
	Year   int      `json:"year"`
}

// olderBuildCauses are the causes of a CVE whose undecided state the record (or a reading of it) leaves: nothing a person or the
// device states would decide it.
var olderBuildCauses = []string{CauseVendorSilent, CauseAIUnsure, CauseNeedsReading, CauseAIBudget}

// vendorRefTags are the reference tags that name the vendor's own word (refTagOrder before the third party's advisory).
var vendorRefTags = refTagOrder[:4]

// markOlderBuilds sets OlderBuild on every item of the group, reading the CVE record of each candidate once.
func (s *Service) markOlderBuilds(ctx context.Context, items []PossibleItem, rs ReadState) {
	if s.cfg.Checker == nil {
		return
	}
	silent := map[string]bool{} // by CVE: the record gives no word from the vendor
	for i := range items {
		it := &items[i]
		ob := olderBuildOf(*it, rs)
		if ob == nil {
			continue
		}
		quiet, seen := silent[it.CVE]
		if !seen {
			rec, err := s.cfg.Checker.Record(ctx, it.CVE)
			// an exploitation signal the reporting window keeps the CVE for is never quiet, as an exploited list is not
			quiet = err == nil && recordSilent(rec) && !rec.Kept
			silent[it.CVE] = quiet
		}
		if quiet {
			it.OlderBuild = ob
		}
	}
}

// olderBuildOf is the group's facts of an item when everything but the record puts it in the group; nil otherwise.
func olderBuildOf(it PossibleItem, rs ReadState) *OlderBuild {
	q := it.Question
	u := q.Detail.Undecided
	if it.State != PossibleOpen || it.Exploited || it.Deferred != nil || u == nil || u.Reason != UndecidedThirdPartyBuild || q.CVE != it.CVE ||
		len(q.Detail.Fixes) > 0 || !slices.Contains(olderBuildCauses, PossibleCause(it, rs)) {
		return nil
	}
	if c := it.Check; c != nil && c.Reading != nil && c.Reading.VendorPage {
		return nil // a reading of the vendor's own page is the vendor's word, whatever it decided
	}
	tested := testedBuilds(u.Ranges, q.Detail.Version)
	if len(tested) == 0 {
		return nil
	}
	_, rest, _ := strings.Cut(it.CVE, "-")
	year, err := strconv.Atoi(strings.SplitN(rest, "-", 2)[0])
	if err != nil {
		return nil
	}
	return &OlderBuild{Tested: tested, Year: year}
}

// testedBuilds reads the builds of the rows a question read (Undecided.Ranges): every row one exact build ver is later than (laterThan,
// or an older release line, lineOrder), each build once as its row writes it ("3.0.4", "1.8.0 update401"). Nil when a row is a range or
// does not read, when a build is not older than ver, or when the list may have been cut (undecidedRows).
func testedBuilds(rows []string, ver string) []string {
	if len(rows) == 0 || len(rows) >= undecidedRows || !versionKnown(ver) {
		return nil
	}
	var out []string
	for _, row := range rows {
		c, err := ParseCPE(row)
		if err != nil {
			return nil
		}
		lit, ok := c.Version.Literal()
		if !ok {
			return nil
		}
		if o, ok := lineOrder(c, lit, ver); !laterThan(c, lit, ver) && (!ok || o <= 0) {
			return nil
		}
		if up, ok := c.Update.Literal(); ok && up != "" {
			lit += " " + up
		}
		if !slices.Contains(out, lit) {
			out = append(out, lit)
		}
	}
	return out
}

// vendorMarks are the CVE Program's description tags that say something beside the rows: a party (most often the vendor) disputes the
// CVE, or the product was no longer supported when the CVE was assigned (no fix will come).
var vendorMarks = []string{"** DISPUTED **", "** UNSUPPORTED WHEN ASSIGNED **"}

// recordSilent says the CVE record was read and gives no word from the vendor: no solution, no workaround, no reference tagged as the
// vendor's, no dispute or unsupported tag. A record not read (only NVD's copy held) says nothing of its solution or workaround.
func recordSilent(rec CVERecordText) bool {
	if !rec.Read || strings.TrimSpace(rec.Solution) != "" || strings.TrimSpace(rec.Workaround) != "" {
		return false
	}
	desc := strings.ToUpper(strings.Join(strings.Fields(rec.Description), " "))
	if slices.ContainsFunc(vendorMarks, func(m string) bool { return strings.Contains(desc, m) }) {
		return false
	}
	return !slices.ContainsFunc(rec.Refs, func(r RefLink) bool {
		return slices.ContainsFunc(r.Tags, func(t string) bool { return slices.Contains(vendorRefTags, refTag(t)) })
	})
}
