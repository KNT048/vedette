package findings

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// ToFixLimit is how many devices GET /findings/to-fix lists at most (the most urgent first); Truncated says more had something.
const ToFixLimit = 500

// ToFix is the Findings page's "To fix" list: every device that needs an update or an action, the most urgent first, each
// with its actions (DeviceUpdates), so a person reads "device → what to do" without opening a finding. Built from the same groupings
// as DeviceUpdates (RowFixes; the plan's items); nothing is stored.
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

// actionable is what "To fix" counts of a device as exploited: its actions with a named update, and the ones without an update that
// the box proved, each cut to the CVEs attackers use (an action of a public exploit or a critical flaw on an edge device is listed
// on the card but is not an exploited CVE to fix; an action with none left is dropped).
func (d DeviceUpdates) actionable() []UpdateAction {
	var out []UpdateAction
	for _, u := range slices.Concat(d.Exploited, slices.DeleteFunc(slices.Clone(d.NoUpdate), func(u UpdateAction) bool { return !u.Proved() })) {
		if len(u.Layers) != len(u.CVEs) { // layers not stated: every CVE counts, as before urgency layers
			out = append(out, u)
			continue
		}
		var cves []string
		for i, c := range u.CVEs {
			if u.Layers[i] <= UrgencyExploited {
				cves = append(cves, c)
			}
		}
		if len(cves) > 0 {
			u.CVEs = cves
			out = append(out, u)
		}
	}
	return out
}

// ToFix lists every device with open findings or recommended updates, the most urgent first (urgency); assetID "" for every device,
// else that one only (the device's Software tab and findings panel). feedsOn as for DeviceUpdates.
//
// Cost (review r2 of #949): every device's classification (the per-device work: MatchInput, MatchAsset, RowFixes) is computed once
// and cached until a finding is written (gen), the plan changes (plan.ver), the feeds switch moves or riskTTL passes (classified); the
// page shows the ToFixLimit most urgent of them and says Truncated when there were more. The risk marker reads the same cached
// classification (RiskMap), so the two never disagree, whatever the number of devices.
func (s *Service) ToFix(ctx context.Context, feedsOn bool, assetID string) (ToFix, error) {
	return s.toFix(ctx, feedsOn, assetID, ToFixLimit)
}

// toFix is ToFix with the display cap as a parameter (the tests use a small one).
func (s *Service) toFix(ctx context.Context, feedsOn bool, assetID string, limit int) (ToFix, error) {
	if assetID != "" {
		return s.classify(ctx, feedsOn, assetID)
	}
	all, err := s.classified(ctx, feedsOn)
	if err != nil {
		return ToFix{}, err
	}
	out := all.tf
	if len(out.Devices) > limit {
		out.Devices, out.Truncated = out.Devices[:limit], true
	}
	return out, nil
}

// classify is To fix's classification (assetID "": every device, no cap; else that one): per device, its open findings grouped by
// their update and proof (exploitedUpdates) and its plan items, the most urgent first. The one place the rule lives: To fix's page,
// its cards and the risk marker (RiskOf) all read it.
func (s *Service) classify(ctx context.Context, feedsOn bool, assetID string) (ToFix, error) {
	recs, err := s.List(ctx, assetID)
	if err != nil {
		return ToFix{}, err
	}
	ignored, err := s.ignoredDevices(ctx) // a person's ignored devices are left out of To fix and the risk marker
	if err != nil {
		return ToFix{}, fmt.Errorf("findings: to fix: %w", err)
	}
	open := map[string][]Record{}
	for _, r := range recs {
		// a finding of a CVE nobody exploits yet (urgency 5) is a recommended update (Planned), never one to fix, as DeviceUpdates has it
		if r.Status.Open() && Announced(r.Row) && !ignored[r.AssetID] {
			open[r.AssetID] = append(open[r.AssetID], r)
		}
	}
	out := ToFix{PlanOff: !feedsOn}
	seen := map[string]bool{}
	for id := range open {
		seen[id] = true
	}
	if feedsOn {
		s.plan.mu.RLock()
		out.PlanRan = s.plan.ran
		plans := maps.Clone(s.plan.devices)
		s.plan.mu.RUnlock()
		for id, d := range plans {
			if len(d.items) > 0 && (assetID == "" || id == assetID) {
				seen[id] = true
			}
		}
	}
	var vulns []Vuln
	if len(open) > 0 {
		if vulns, err = s.cfg.Feeds.Vulns(ctx); err != nil {
			return ToFix{}, fmt.Errorf("findings: to fix: reading the exploited list: %w", err)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(seen)) {
		a, ok, err := s.cfg.Inventory.MatchInput(ctx, id)
		if err != nil {
			return ToFix{}, fmt.Errorf("findings: to fix: reading device %s: %w", id, err)
		}
		if !ok || ignored[id] { // the device is gone (its findings go with it, Reconcile), or ignored
			continue
		}
		d := DeviceUpdates{AssetID: id, Open: len(open[id])}
		if len(open[id]) > 0 {
			d.Exploited, d.NoUpdate = exploitedUpdates(a, open[id], vulns, s.now(), s.safeCheck)
		}
		if feedsOn {
			d.Planned, d.PlanRan, d.PlanCompared = s.plannedUpdates(id)
			withRows(a, d.Planned)
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

// classifiedCache is the last classification of every device (classify with assetID "") and the risk map read from it, with the key
// they were computed under.
type classifiedCache struct {
	mu      sync.Mutex
	gen     uint64
	planVer uint64
	feedsOn bool
	at      time.Time
	tf      ToFix
	risk    map[string]AssetRisk
}

// classified is classify for every device, cached until a finding is written (gen), the plan changes (plan.ver), the feeds switch
// moves or riskTTL passes. The key is read before the work, so a change during it is computed again at the next call. The answer is
// shared: read it, never change it.
func (s *Service) classified(ctx context.Context, feedsOn bool) (*classifiedCache, error) {
	gen := s.gen.Load()
	s.plan.mu.RLock()
	planVer := s.plan.ver
	s.plan.mu.RUnlock()
	now := s.now()
	c := &s.toFixCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.risk != nil && c.gen == gen && c.planVer == planVer && c.feedsOn == feedsOn && now.Sub(c.at) < riskTTL && now.Sub(c.at) >= 0 {
		return c, nil
	}
	tf, err := s.classify(ctx, feedsOn, "")
	if err != nil {
		return nil, err
	}
	risk := map[string]AssetRisk{}
	for _, d := range tf.Devices {
		if r := RiskOf(d); r != (AssetRisk{}) {
			risk[d.AssetID] = r
		}
	}
	c.gen, c.planVer, c.feedsOn, c.at, c.tf, c.risk = gen, planVer, feedsOn, now, tf, risk
	return c, nil
}

// sortByUrgency orders devices the most urgent first (urgent.compare), ties by id.
func sortByUrgency(ds []DeviceUpdates) {
	slices.SortStableFunc(ds, func(p, q DeviceUpdates) int {
		return cmp.Or(urgency(q).compare(urgency(p)), strings.Compare(p.AssetID, q.AssetID))
	})
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

// withRows sets UpdateAction.Product and Source of planned actions from the device's software rows (the plan items carry only the
// row id).
func withRows(a Asset, us []UpdateAction) {
	sws := map[string]Software{}
	for _, sw := range deviceSoftware(a) {
		sws[sw.ID] = sw
	}
	for i := range us {
		us[i].Product, us[i].Source = productKey(sws[us[i].SoftwareID]), sws[us[i].SoftwareID].Source
	}
}
