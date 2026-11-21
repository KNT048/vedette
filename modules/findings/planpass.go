package findings

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

// PlanEvery is the pause between two runs of the plan job: a run does a full pass when the feeds' match stamp changed (a pull
// of epss-all, nvd-recent or an exploited list), on its first run and at least every ReconcileEvery, else it compares again only the
// devices marked since (MarkPlan: every software change, a device discovered or updated, a match event), else nothing. A device
// change reaches the page within PlanEvery. The stamp is the tier data's (Feeds.TierStamp: epss-all, nvd-recent, nvd-kev, the feeds
// module switch), not the hourly exploited-list pulls, whose new CVEs the hourly full pass takes out (review r1 #7 of #804).
const PlanEvery = 5 * time.Minute

// planState is the last comparison of the tier data with the devices, in memory: nothing of it is stored (the page reads it, nothing
// alerts on it), so a restart shows "Not compared yet" until the plan job's first run, which the scheduler starts at once.
type planState struct {
	mu      sync.RWMutex
	ran     bool      // a full pass finished since the start
	stamp   string    // the tier data's stamp it read
	fullAt  time.Time // when the last full pass finished
	lastRun time.Time // when the job last ran: a longer gap (the findings module was off) makes the next run a full pass
	devices map[string]planDevice
	ver     uint64          // moves on every change of devices: the risk marker's cache (RiskMap) is dropped when it does
	dirty   map[string]bool // devices to compare again at the next run
	dropped map[string]bool // devices deleted since the run started: never written back by it (review r1 #4 of #804)
}

type planDevice struct {
	items    []PlanItem
	compared bool // the device has a row the plan compares
}

// PlanView is what GET /findings/plan reads: the items of every device, and how many devices were compared or not.
type PlanView struct {
	Ran                 bool
	Items               []PlanItem
	Compared, Unchecked int
}

// Plan returns the last comparison (Ran false: none since the start). The items are shared: read them, never change them.
func (s *Service) Plan() PlanView {
	s.plan.mu.RLock()
	defer s.plan.mu.RUnlock()
	v := PlanView{Ran: s.plan.ran}
	for _, id := range slices.Sorted(maps.Keys(s.plan.devices)) {
		d := s.plan.devices[id]
		v.Items = append(v.Items, d.items...)
		if d.compared {
			v.Compared++
		} else {
			v.Unchecked++
		}
	}
	sortPlanItems(v.Items)
	return v
}

// MarkPlan asks the next plan run to compare the device again: cmd/vedette calls it on inventory.software.changed and on a
// device discovered or updated, so a version upgrade or a new product reaches "Updates to plan" within PlanEvery (review r1 #1 of
// #804: inventory.match.changed fires only for exploited-list keys).
func (s *Service) MarkPlan(assetID string) { s.markPlan(assetID) }

// markPlan asks the next plan run to compare these devices again.
func (s *Service) markPlan(ids ...string) {
	s.plan.mu.Lock()
	defer s.plan.mu.Unlock()
	if s.plan.dirty == nil {
		s.plan.dirty = map[string]bool{}
	}
	for _, id := range ids {
		s.plan.dirty[id] = true
	}
}

// dropPlan forgets a deleted device's items at once.
func (s *Service) dropPlan(id string) {
	s.plan.mu.Lock()
	defer s.plan.mu.Unlock()
	delete(s.plan.devices, id)
	s.plan.ver++
	delete(s.plan.dirty, id)
	if s.plan.dropped == nil {
		s.plan.dropped = map[string]bool{}
	}
	s.plan.dropped[id] = true
}

// RefreshPlan is the plan job (PlanEvery). It reads the devices (Inventory), the exploited list (Feeds.Vulns: a CVE on it is a finding,
// never a plan item) and only the tier CVEs of the products the devices run (Feeds.TierVulns with a TierScope), and keeps the result in
// memory. Nothing is written: no finding, no event, no alert (S-TIER-2). While the exploited list is not loaded it compares nothing (a
// KEV CVE would show as tier 2). A device that cannot be read is left as it was and compared again at the next run.
func (s *Service) RefreshPlan(ctx context.Context) error {
	stamp, err := s.cfg.Feeds.TierStamp(ctx)
	if err != nil {
		return fmt.Errorf("findings: plan: reading the tier data's stamp: %w", err)
	}
	start := s.now()
	s.plan.mu.Lock()
	full := !s.plan.ran || s.plan.stamp != stamp || start.Sub(s.plan.fullAt) >= ReconcileEvery || start.Sub(s.plan.lastRun) > 2*PlanEvery
	dirty := s.plan.dirty
	s.plan.dirty, s.plan.dropped, s.plan.lastRun = nil, nil, start
	s.plan.mu.Unlock()
	if !full && len(dirty) == 0 {
		return nil
	}
	retry := dirty
	defer func() { // what this run could not do is done by the next one
		if len(retry) > 0 {
			s.markPlan(slices.Collect(maps.Keys(retry))...)
		}
	}()
	ids := slices.Sorted(maps.Keys(dirty))
	if full {
		if ids, err = s.cfg.Inventory.AssetIDs(ctx); err != nil {
			return fmt.Errorf("findings: plan: listing devices: %w", err)
		}
	}
	kevs, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return fmt.Errorf("findings: plan: reading the exploited list: %w", err)
	}
	if len(kevs) == 0 {
		return nil // nothing to tell a tier CVE from an exploited one yet
	}
	kev := make(map[string]bool, len(kevs))
	for _, v := range kevs {
		kev[v.CVE] = true
	}
	recs, err := s.List(ctx, "")
	if err != nil {
		return fmt.Errorf("findings: plan: reading the findings: %w", err)
	}
	open := map[string]map[string]bool{} // device -> its open exploited findings' CVEs: the updates To fix names (tierIndex.withOpen)
	for _, r := range recs {
		if r.Status.Open() {
			if open[r.AssetID] == nil {
				open[r.AssetID] = map[string]bool{}
			}
			open[r.AssetID][r.CVE] = true
		}
	}
	var assets []Asset
	gone := map[string]bool{}
	var failed []error
	unread := map[string]bool{}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, ok, err := s.cfg.Inventory.MatchInput(ctx, id)
		switch {
		case err != nil:
			failed = append(failed, fmt.Errorf("device %q: %w", id, err))
			unread[id] = true
			continue
		case !ok:
			gone[id] = true
			continue
		}
		assets = append(assets, a)
	}
	var pkgs []DistroPackage // The distributions' packages, judged by the distribution's own data (plandistro.go)
	for _, a := range assets {
		d, rel, ps := DevicePackages(a)
		for _, p := range ps {
			pkgs = append(pkgs, DistroPackage{Distro: d, Release: rel, Package: p})
		}
	}
	var dt DistroTier
	if len(pkgs) > 0 {
		if dt, err = s.cfg.Feeds.TierDistro(ctx, pkgs); err != nil {
			return fmt.Errorf("findings: plan: reading the distributions' tier data: %w", err)
		}
	}
	dx := (&tierIndex{}).withKnown(dt.Known, dt.Loading).withDistro(dt.Vulns, dt.Covered)
	skip := map[string]map[string]bool{} // the packages the distribution's data alone decides: NVD's entries of them are not read
	for _, a := range assets {
		d, _, judged, wait := dx.distroWords(a)
		for id := range judged {
			if !d.fixedOnly {
				wait[id] = true
			}
		}
		skip[a.ID] = wait
	}
	scope := newTierScope(assets, skip)
	var tv []TierVuln
	if !scope.Empty() {
		if tv, err = s.cfg.Feeds.TierVulns(ctx, scope.Keep); err != nil {
			return fmt.Errorf("findings: plan: reading the tier data: %w", err)
		}
	}
	x := newTierIndex(tv).withKnown(dt.Known, dt.Loading).withDistro(dt.Vulns, dt.Covered).withKEV(kevs, open)
	now := s.now()
	got := make(map[string]planDevice, len(assets))
	items := 0
	kinds := map[string]int{}
	for _, a := range assets {
		its, compared := matchTiers(a, x, kev, now)
		got[a.ID] = planDevice{items: its, compared: compared}
		items += len(its)
		for _, it := range its {
			kinds[it.Kind]++
		}
	}
	s.plan.mu.Lock()
	for id := range s.plan.dropped { // deleted while this run read it
		delete(got, id)
		delete(unread, id)
	}
	if full {
		for id, d := range s.plan.devices { // a device that could not be read keeps what it had
			if unread[id] {
				got[id] = d
			}
		}
		s.plan.devices, s.plan.ran, s.plan.stamp, s.plan.fullAt = got, true, stamp, now
		s.plan.ver++
	} else {
		s.plan.ver++
		if s.plan.devices == nil {
			s.plan.devices = map[string]planDevice{}
		}
		maps.Copy(s.plan.devices, got)
		for id := range gone {
			delete(s.plan.devices, id)
		}
	}
	s.plan.mu.Unlock()
	retry = unread
	compared := 0
	for _, d := range got {
		if d.compared {
			compared++
		}
	}
	s.cfg.Log.InfoContext(ctx, "findings: plan pass done", "full", full, "devices", len(assets), "compared", compared, "tier_cves_read", len(tv),
		"distro_packages", len(pkgs), "distro_cves_read", len(dt.Vulns), "items", items, "items_fixed", kinds["fixed"], "items_windows", kinds["windows"],
		"items_esu", kinds["esu"], "items_distro", kinds["distro"], "took", s.now().Sub(start))
	return errors.Join(failed...)
}
