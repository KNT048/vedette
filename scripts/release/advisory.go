package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/internal/release"
)

// maxIndexAdvisories is the most advisories a box accepts in one index (internal/release maxAdvisories): one more and every box
// refuses the whole index.
const maxIndexAdvisories = 256

// ParseAdvisory reads one advisory file of `release index -advisory`: a JSON object with exactly the fields of an index advisory
// (id, severity, title, affects, fixed_in, url), checked by checkAdvisory.
func ParseAdvisory(raw []byte) (release.Advisory, error) {
	var a release.Advisory
	if err := jsonstrict.Decode(raw, &a); err != nil {
		return a, fmt.Errorf("advisory: %w", err)
	}
	return a, checkAdvisory(a)
}

// checkAdvisory applies the rules of the box's verifier (release.Advisory.Validate: one bad advisory makes every box refuse the
// whole index), and the rules that make the advisory show on the Updates page of every released box:
//   - fixed_in is required: the page lists an advisory only when it can compare the running version with fixed_in, and marks the
//     box "affected" when it runs a version below fixed_in;
//   - severity is critical, high, medium or low (the page shows low as medium); any other value is refused by the verifier;
//   - affects is a range of comparators ("< 0.1.1", ">= 0.1.0, < 0.1.1"); the page does not read it, but it must agree with
//     fixed_in: fixed_in itself is not in the range.
//
// The page shows the title twice (as the heading and as the text) and never shows the url, so the title says what to do.
func checkAdvisory(a release.Advisory) error {
	if err := a.Validate(); err != nil {
		switch {
		case a.ID == "" || len(a.ID) > 64:
			return fmt.Errorf("advisory id %q: 1 to 64 characters", a.ID)
		case a.Severity != "critical" && a.Severity != "high" && a.Severity != "medium" && a.Severity != "low":
			return fmt.Errorf("advisory %s: severity %q is not critical, high, medium or low; a box refuses an index with any other value", a.ID, a.Severity)
		case !strings.HasPrefix(a.URL, "https://"):
			return fmt.Errorf("advisory %s: url %q is not https", a.ID, a.URL)
		}
		return fmt.Errorf("advisory %s: a box would refuse the whole index (%w): id and title one line of at most 64 and 256 bytes, affects at most 128, fixed_in SemVer, url https without user or fragment", a.ID, err)
	}
	if a.FixedIn == "" {
		return fmt.Errorf("advisory %s: fixed_in is required: the Updates page lists an advisory only with the version that fixes it", a.ID)
	}
	if a.Title == "" {
		return fmt.Errorf("advisory %s: the title is required: it is the only text the Updates page shows", a.ID)
	}
	in, err := affectsMatch(a.Affects, a.FixedIn)
	if err != nil {
		return fmt.Errorf("advisory %s: affects %q: %w", a.ID, a.Affects, err)
	}
	if in {
		return fmt.Errorf("advisory %s: fixed_in %s is inside affects %q: the version that fixes it cannot be affected", a.ID, a.FixedIn, a.Affects)
	}
	return nil
}

// affectsMatch reports whether version v is in the range affects: comparators (<, <=, >, >=, =) each followed by a SemVer version,
// separated by commas, all of which must hold.
func affectsMatch(affects, v string) (bool, error) {
	if strings.TrimSpace(affects) == "" {
		return false, errors.New("empty: say which versions are affected, for example \"< 1.2.0\"")
	}
	ok := true
	for _, part := range strings.Split(affects, ",") {
		part = strings.TrimSpace(part)
		var op string
		for _, o := range []string{"<=", ">=", "<", ">", "="} {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		if op == "" {
			return false, fmt.Errorf("%q does not start with <, <=, >, >= or =", part)
		}
		ver := strings.TrimSpace(strings.TrimPrefix(part, op))
		c, err := release.CompareVersions(v, ver)
		if err != nil {
			return false, fmt.Errorf("%q is not a SemVer version", ver)
		}
		switch op {
		case "<":
			ok = ok && c < 0
		case "<=":
			ok = ok && c <= 0
		case ">":
			ok = ok && c > 0
		case ">=":
			ok = ok && c >= 0
		default:
			ok = ok && c == 0
		}
	}
	return ok, nil
}

// addAdvisories appends the new advisories of p to x (after the ones carried over from the previous index). An id already in the
// index is refused: an advisory once published is carried over unchanged, and a box would list the same id twice.
func addAdvisories(x *release.Index, adds []release.Advisory) error {
	seen := map[string]bool{}
	for _, a := range x.Advisories {
		seen[a.ID] = true
	}
	for _, a := range adds {
		if err := checkAdvisory(a); err != nil {
			return err
		}
		if seen[a.ID] {
			return fmt.Errorf("advisory %s is already in the index: a published advisory carries over unchanged, give a new one a new id", a.ID)
		}
		seen[a.ID] = true
		x.Advisories = append(x.Advisories, a)
	}
	if len(x.Advisories) > maxIndexAdvisories {
		return fmt.Errorf("the index would carry %d advisories; a box refuses more than %d", len(x.Advisories), maxIndexAdvisories)
	}
	return nil
}

// checkStrandedBoxesTold refuses an index that announces a release whose min_upgrade_from is above the latest release a channel of
// the previous index offers, unless an advisory tells the boxes on that release: they cannot update to the new release (their update
// check says only that there is nothing to install), so the index must carry an advisory they show as affected.
//
// Only the boxes that can be stranded are looked at. A box follows one channel and is offered only that channel's latest, so an
// ordinary release (min_upgrade_from below its own version: an intermediate release is needed first) strands only the boxes of the
// channel it is published on. A release that starts a new schema epoch (min_upgrade_from is its own version) ends the earlier epoch
// for every box, so the boxes on the latest release of every channel are looked at.
//
// An advisory tells a box on release L about this release V with min_upgrade_from M when the box shows it as affected (fixed_in above
// L) and it names a fix this release brings: fixed_in at or above M (a version the box cannot update to) and not above V. An advisory
// carried over from an earlier index whose fixed_in is above V is about something V does not fix: it would tell the box to wait for a
// later release, not to install V fresh; one fixed below M points at a release the box is not offered.
func checkStrandedBoxesTold(prev, x *release.Index, channel, version string, manifestRaw []byte) error {
	if prev == nil || version == "" {
		return nil
	}
	var m struct {
		MinUpgradeFrom string `json:"min_upgrade_from"`
	}
	if err := json.Unmarshal(manifestRaw, &m); err != nil || m.MinUpgradeFrom == "" {
		return nil //nolint:nilerr // a manifest that does not parse was refused before, and none without min_upgrade_from strands a box
	}
	newEpoch := m.MinUpgradeFrom == version
	for _, name := range slices.Sorted(maps.Keys(prev.Channels)) {
		if name != channel && !newEpoch {
			continue
		}
		ch := prev.Channels[name]
		c, err := release.CompareVersions(ch.Latest, m.MinUpgradeFrom)
		if err != nil || c >= 0 {
			continue
		}
		if !slices.ContainsFunc(x.Advisories, func(a release.Advisory) bool { return tellsStranded(a, ch.Latest, m.MinUpgradeFrom, version) }) {
			return fmt.Errorf("release %s sets min_upgrade_from %s, so a box on %s (the latest of channel %s in the published index) cannot update to it "+
				"and its Updates page would say nothing: add an advisory such a box shows as affected (-advisory FILE with fixed_in from %s to %s, "+
				"normally %s; RELEASE_ADVISORY of make release-manifest)", version, m.MinUpgradeFrom, ch.Latest, name, m.MinUpgradeFrom, version, version)
		}
	}
	return nil
}

// tellsStranded reports whether a box running running shows a as affected and a names a fix in [minUp, version].
func tellsStranded(a release.Advisory, running, minUp, version string) bool {
	above, err1 := release.CompareVersions(a.FixedIn, running)
	low, err2 := release.CompareVersions(a.FixedIn, minUp)
	high, err3 := release.CompareVersions(a.FixedIn, version)
	return err1 == nil && err2 == nil && err3 == nil && above > 0 && low >= 0 && high <= 0
}
