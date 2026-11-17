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
// else that one only (the device's Software tab and findings panel). feedsOn as for DeviceUpdates.
//
// Cost (review r1 of #943): one pass over the findings and one over the plan rank every device cheaply (preRank: its worst open
// severity, ransomware, open findings; then its plan); only the ToFixLimit first get the per-device work (MatchInput, MatchAsset,
// RowFixes), so the page never pays it for more than ToFixLimit devices, and Truncated says more had something.
func (s *Service) ToFix(ctx context.Context, feedsOn bool, assetID string) (ToFix, error) {
	return s.toFix(ctx, feedsOn, assetID, ToFixLimit)
}

// toFix is ToFix with the cap as a parameter (the tests use a small one).
func (s *Service) toFix(ctx context.Context, feedsOn bool, assetID string, limit int) (ToFix, error) {
	recs, err := s.List(ctx, assetID)
	if err != nil {
		return ToFix{}, err
	}
	open := map[string][]Record{}
	for _, r := range recs {
		if r.Status.Open() {
			open[r.AssetID] = append(open[r.AssetID], r)
		}
	}
	out := ToFix{PlanOff: !feedsOn}
	plan := map[string]planRank{} // device -> what its plan items weigh, as urgency reads them
	if feedsOn {
		s.plan.mu.RLock()
		out.PlanRan = s.plan.ran
		for id, d := range s.plan.devices {
			if len(d.items) == 0 || (assetID != "" && id != assetID) {
				continue
			}
			var p planRank
			for _, it := range d.items {
				for _, c := range it.CVEs {
					p.cves++
					if c.Tier == "likely" {
						p.likely++
					}
					if c.Severity != nil {
						p.worst = max(p.worst, sevRank(Severity(*c.Severity)))
					}
				}
			}
			plan[id] = p
		}
		s.plan.mu.RUnlock()
	}
	var vulns []Vuln
	ransom := map[string]bool{}
	if len(open) > 0 {
		if vulns, err = s.cfg.Feeds.Vulns(ctx); err != nil {
			return ToFix{}, fmt.Errorf("findings: to fix: reading the exploited list: %w", err)
		}
		for _, v := range vulns {
			ransom[v.CVE] = v.Ransomware
		}
	}
	ids := preRank(open, plan, ransom)
	if len(ids) > limit {
		ids, out.Truncated = ids[:limit], true
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
			withProducts(a, d.Planned)
		} else {
			d.PlanOff = true
		}
		if len(d.Exploited)+len(d.NoUpdate)+len(d.Planned) > 0 {
			out.Devices = append(out.Devices, d)
		}
	}
	sortByUrgency(out.Devices)
	return out, nil
}

// sortByUrgency orders devices the most urgent first (urgent.compare), ties by id.
func sortByUrgency(ds []DeviceUpdates) {
	slices.SortStableFunc(ds, func(p, q DeviceUpdates) int {
		return cmp.Or(urgency(q).compare(urgency(p)), strings.Compare(p.AssetID, q.AssetID))
	})
}

// planRank is what a device's plan items weigh: their worst severity, likely CVEs and CVEs (urgency's plan keys).
type planRank struct{ worst, likely, cves int }

// preRank orders the devices from what is read without the per-device work, by the same keys as urgency (review r2 of #943): first
// whether the device has something to fix (an open finding the box proved or can name an update for: any basis but a product-only
// match, or the agent's evidence), then that part's worst severity, ransomware, proved findings and CVEs; then its plan's worst
// severity, likely CVEs and CVEs; ties by id. A device with only product-only guesses (To fix does not list it) never pushes out one
// with something to fix.
func preRank(open map[string][]Record, plan map[string]planRank, ransom map[string]bool) []string {
	type pre struct {
		id                              string
		act, worst, ransomware, n, cves int
		plan                            planRank
	}
	seen := map[string]*pre{}
	for id, rs := range open {
		p := &pre{id: id, plan: plan[id]}
		for _, r := range rs {
			if r.Basis == BasisProduct && (r.Evidence == nil || !r.Evidence.Agent) {
				continue // a product-only match: no update is named, nothing proved (Needs your input)
			}
			p.act = 1
			p.worst = max(p.worst, sevRank(r.Severity))
			if ransom[r.CVE] {
				p.ransomware++
			}
			if r.Basis == BasisScan || (r.Evidence != nil && r.Evidence.Agent) {
				p.n++
			}
			p.cves++
		}
		seen[id] = p
	}
	for id, pl := range plan {
		if seen[id] == nil {
			seen[id] = &pre{id: id, plan: pl}
		}
	}
	list := make([]*pre, 0, len(seen))
	for _, p := range seen {
		list = append(list, p)
	}
	slices.SortFunc(list, func(p, q *pre) int {
		return cmp.Or(cmp.Compare(q.act, p.act), cmp.Compare(q.worst, p.worst), cmp.Compare(q.ransomware, p.ransomware), cmp.Compare(q.n, p.n),
			cmp.Compare(q.cves, p.cves), cmp.Compare(q.plan.worst, p.plan.worst), cmp.Compare(q.plan.likely, p.plan.likely), cmp.Compare(q.plan.cves, p.plan.cves),
			strings.Compare(p.id, q.id))
	})
	ids := make([]string, len(list))
	for i, p := range list {
		ids[i] = p.id
	}
	return ids
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

// withProducts sets UpdateAction.Product of planned actions from the device's software rows (the plan items carry only the row id).
func withProducts(a Asset, us []UpdateAction) {
	sws := map[string]Software{}
	for _, sw := range deviceSoftware(a) {
		sws[sw.ID] = sw
	}
	for i := range us {
		us[i].Product = productKey(sws[us[i].SoftwareID])
	}
}
