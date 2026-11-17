package findings

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
)

// ToFixLimit is how many devices GET /findings/to-fix lists at most (the most urgent first); Truncated says more had something.
const ToFixLimit = 500

// ToFix is the Findings page's "To fix" list (kien G8): every device that needs an update or an action, the most urgent first, each
// with its actions (DeviceUpdates), so a person reads "device → what to do" without opening a finding. Built from the same groupings
// as DeviceUpdates (RowFixes, D-545; the plan's items, D-613); nothing is stored.
type ToFix struct {
	Devices   []DeviceUpdates
	Truncated bool // more devices had something than ToFixLimit
	PlanRan   bool // the plan job compared the devices since the start; false: no device lists its recommended updates yet
	PlanOff   bool // the feeds module is off: no recommended update is listed (as GET /findings/plan)
}

// Proved reports whether an action rests on a finding the box proved (a scan, or a version the device reported inside the range):
// an update named for a finding is something to do; findings without a named update and without proof are the person's to check
// (the page's "Needs your input"), not "to fix".
func (u UpdateAction) Proved() bool { return u.Confirmed+u.Detected > 0 }

// actionable is what "To fix" lists of a device: its exploited actions with a named update, and the ones without an update that
// the box proved.
func (d DeviceUpdates) actionable() []UpdateAction {
	out := slices.Clone(d.Exploited)
	for _, u := range d.NoUpdate {
		if u.Proved() {
			out = append(out, u)
		}
	}
	return out
}

// ToFix lists every device with open findings or recommended updates, the most urgent first (urgency); assetID "" for every device,
// else that one only (the device's Software tab). feedsOn as for DeviceUpdates.
func (s *Service) ToFix(ctx context.Context, feedsOn bool, assetID string) (ToFix, error) {
	recs, err := s.List(ctx, assetID)
	if err != nil {
		return ToFix{}, err
	}
	open := map[string][]Record{}
	var ids []string
	for _, r := range recs {
		if r.Status.Open() {
			if _, seen := open[r.AssetID]; !seen {
				ids = append(ids, r.AssetID)
			}
			open[r.AssetID] = append(open[r.AssetID], r)
		}
	}
	out := ToFix{PlanOff: !feedsOn}
	if feedsOn {
		s.plan.mu.RLock()
		out.PlanRan = s.plan.ran
		for id, d := range s.plan.devices {
			if _, seen := open[id]; !seen && len(d.items) > 0 && (assetID == "" || id == assetID) {
				ids = append(ids, id)
				open[id] = nil
			}
		}
		s.plan.mu.RUnlock()
	}
	var vulns []Vuln
	if len(recs) > 0 {
		if vulns, err = s.cfg.Feeds.Vulns(ctx); err != nil {
			return ToFix{}, fmt.Errorf("findings: to fix: reading the exploited list: %w", err)
		}
	}
	for _, id := range ids {
		a, ok, err := s.cfg.Inventory.MatchInput(ctx, id)
		if err != nil {
			return ToFix{}, fmt.Errorf("findings: to fix: reading device %s: %w", id, err)
		}
		if !ok { // the device is gone; its findings go with it (Reconcile)
			continue
		}
		d := DeviceUpdates{AssetID: id, Open: len(open[id])}
		if len(open[id]) > 0 {
			d.Exploited, d.NoUpdate = exploitedUpdates(a, open[id], vulns, s.now())
		}
		if feedsOn {
			d.Planned, d.PlanRan, d.PlanCompared = s.plannedUpdates(id)
		} else {
			d.PlanOff = true
		}
		if len(d.Exploited)+len(d.NoUpdate)+len(d.Planned) > 0 {
			out.Devices = append(out.Devices, d)
		}
	}
	slices.SortStableFunc(out.Devices, func(p, q DeviceUpdates) int {
		return cmp.Or(urgency(q).compare(urgency(p)), strings.Compare(p.AssetID, q.AssetID))
	})
	if len(out.Devices) > ToFixLimit {
		out.Devices, out.Truncated = out.Devices[:ToFixLimit], true
	}
	return out, nil
}

// urgent is how urgent a device is: what it has to fix (exploited, proved or with a named update) before what it may plan.
type urgent struct{ act, worst, ransomware, proved, cves, planWorst, likely, planCVEs int }

func urgency(d DeviceUpdates) urgent {
	var u urgent
	for _, a := range d.actionable() {
		u.act = 1
		u.worst = max(u.worst, sevRank(Severity(a.Worst)))
		u.ransomware += a.Ransomware
		u.proved += a.Confirmed + a.Detected
		u.cves += len(a.CVEs)
	}
	for _, a := range d.Planned {
		u.planWorst = max(u.planWorst, sevRank(Severity(a.Worst)))
		u.likely += a.Likely
		u.planCVEs += len(a.CVEs)
	}
	return u
}

// compare orders by: something to fix, the worst exploited severity, ransomware, proved findings, exploited CVEs; then the plan's
// worst severity, its likely CVEs and its CVEs.
func (u urgent) compare(o urgent) int {
	return cmp.Or(cmp.Compare(u.act, o.act), cmp.Compare(u.worst, o.worst), cmp.Compare(u.ransomware, o.ransomware), cmp.Compare(u.proved, o.proved),
		cmp.Compare(u.cves, o.cves), cmp.Compare(u.planWorst, o.planWorst), cmp.Compare(u.likely, o.likely), cmp.Compare(u.planCVEs, o.planCVEs))
}
