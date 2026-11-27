package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"
)

// The reporting window (feeds' window.go, M-15). Feeds marks each catalogue CVE of a match set that is outside it (Vuln.OutsideWindow):
// published before the last 12 months with no evidence of exploitation in the wild and no public exploit in that time, while an
// administrator has not asked for CVEs of every age. The matcher never reads such an entry, so it is neither a finding nor a question
// (not "undecided": out of scope, counted apart in the coverage). A finding of it that is still detected goes away as outside_window
// (not relevant, by Vedette, audited like any close), unless a safe check proved it or a person confirmed it (Transition): nothing is
// deleted, and the finding opens again when its CVE comes back inside the window and the match detects it. A finding's pin keeps its
// CVE's data in the catalogue (its page, its history, a report), never inside the window.

// inWindow splits a match set: the entries the matcher reads, and the CVEs outside the reporting window.
func inWindow(vulns []Vuln) ([]Vuln, map[string]bool) {
	outside := map[string]bool{}
	for _, v := range vulns {
		if v.OutsideWindow {
			outside[v.CVE] = true
		}
	}
	if len(outside) == 0 {
		return vulns, outside
	}
	in := make([]Vuln, 0, len(vulns)-len(outside))
	for _, v := range vulns {
		if !v.OutsideWindow {
			in = append(in, v)
		}
	}
	return in, outside
}

// matchSet is Feeds.MatchSet without the entries outside the reporting window, and their CVEs.
func (s *Service) matchSet(ctx context.Context, scope MatchScope) ([]Vuln, map[string]bool, error) {
	vulns, err := s.cfg.Feeds.MatchSet(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	in, outside := inWindow(vulns)
	return in, outside, nil
}

// closeOutside takes every detected finding of a CVE outside the reporting window (of device assetID; "": every device) away as
// outside_window, in one write. It returns how many it closed.
func (s *Service) closeOutside(ctx context.Context, assetID string, outside map[string]bool) (int, error) {
	if len(outside) == 0 {
		return 0, nil
	}
	cves, err := json.Marshal(slices.Sorted(maps.Keys(outside)))
	if err != nil {
		return 0, fmt.Errorf("findings: the reporting window: %w", err)
	}
	closed := 0
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		closed = 0
		fs, err := queryFindings(ctx, tx, `(?1 = '' OR asset_id = ?1) AND detected = 1 AND cve IN (SELECT value FROM json_each(?2))`, assetID, string(cves))
		if err != nil {
			return err
		}
		for _, f := range fs {
			_, evs, err := s.step(ctx, tx, f, false, Trigger{Kind: TrGone, At: now, Via: ViaOutsideWindow}, emit)
			if err != nil {
				return fmt.Errorf("findings: %s on %s: %w", f.CVE, f.AssetID, err)
			}
			if slices.ContainsFunc(evs, func(e Event) bool { return e.Kind == EvHandled }) {
				closed++
			}
		}
		return nil
	})
	return closed, err
}
