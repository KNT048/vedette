package scan

import (
	"context"
	"fmt"

	"github.com/knt048/vedette/modules/scan/pack"
)

// checkCount is what a vulnerability check of one device can do, counted by distinct CVE of its findings: Suspected of them are not
// confirmed yet and Checkable of those have a safe template to confirm or rule them out; Again of its confirmed (or mitigated) ones
// have a template to run again, to see whether a fix holds. It is the one rule every start follows (Scan now, the schedule, the
// counts the pages show through GET /scans/targets): a device with nothing to check is never part of a run.
type checkCount struct{ Suspected, Checkable, Again int }

func (c checkCount) any() bool { return c.Checkable+c.Again > 0 }

// templatesOf is the safe templates a check of the device sends for one of its findings: none for a finding a person closed
// (dismissed) or a CVE the installed pack has no template for. plan and checkCounts both read it.
func (s *Service) templatesOf(f FindingRef) []pack.Template {
	if dismissed(f.Status) || s.cfg.Pack == nil {
		return nil
	}
	return s.cfg.Pack.ForCVE(f.CVE)
}

// checkCounts counts, for every device with findings, what a check of it can do (one read of every finding), and the number of open
// (suspected or confirmed) findings the target list shows.
func (s *Service) checkCounts(ctx context.Context) (counts map[string]checkCount, open map[string]int, err error) {
	counts, open = map[string]checkCount{}, map[string]int{}
	if s.cfg.Findings == nil {
		return counts, open, nil
	}
	all, err := s.cfg.Findings.List(ctx, "")
	if err != nil {
		return nil, nil, fmt.Errorf("scan: reading the findings: %w", err)
	}
	seen := map[string]bool{}
	for _, f := range all {
		if f.Status == "confirmed" || f.Status == "suspected" {
			open[f.AssetID]++
		}
		// as plan does: a closed finding is passed over, each CVE of a device counts once
		if dismissed(f.Status) || seen[f.AssetID+"|"+f.CVE] {
			continue
		}
		seen[f.AssetID+"|"+f.CVE] = true
		c := counts[f.AssetID]
		has := len(s.templatesOf(f)) > 0
		switch {
		case f.Status == "suspected":
			c.Suspected++
			if has {
				c.Checkable++
			}
		case has:
			c.Again++
		}
		counts[f.AssetID] = c
	}
	return counts, open, nil
}

// errNothingToCheck is the 400 of a Scan now whose picked devices have nothing a check could confirm, rule out or check again.
func errNothingToCheck(labels []string) error {
	what, its := fmt.Sprintf("these %d devices", len(labels)), "their"
	if len(labels) == 1 {
		what, its = clip(labels[0], 80), "its"
	}
	return apiErr(400, "nothing_to_check", "Nothing to check on %s: no safe check exists for %s findings yet, so no vulnerability check started.", what, its)
}
