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

// PlanEvery is the pause between two runs of the plan job (D-617): a run does a full pass when the feeds' match stamp changed (a pull
// of epss-all, nvd-recent or an exploited list), on its first run and at least every ReconcileEvery, else it compares again only the
// devices whose software changed since (OnMatchChanged), else nothing. A device change reaches the page within PlanEvery.
const PlanEvery = 5 * time.Minute

// planState is the last comparison of the tier data with the devices, in memory: nothing of it is stored (the page reads it, nothing
// alerts on it), so a restart shows "Not compared yet" until the plan job's first run, which the scheduler starts at once.
type planState struct {
	mu      sync.RWMutex
	ran     bool      // a full pass finished since the start
	stamp   string    // the feeds' match stamp it read
	fullAt  time.Time // when the last full pass finished
	devices map[string]planDevice
	dirty   map[string]bool // devices to compare again at the next run
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
	delete(s.plan.dirty, id)
}

// RefreshPlan is the plan job (PlanEvery). It reads the devices (Inventory), the exploited list (Feeds.Vulns: a CVE on it is a finding,
// never a plan item) and only the tier CVEs of the products the devices run (Feeds.TierVulns with a TierScope), and keeps the result in
// memory. Nothing is written: no finding, no event, no alert (S-TIER-2). While the exploited list is not loaded it compares nothing (a
// KEV CVE would show as tier 2). A device that cannot be read is left as it was and compared again at the next run.
func (s *Service) RefreshPlan(ctx context.Context) error {
	stamp, err := s.cfg.Feeds.MatchStamp(ctx)
	if err != nil {
		return fmt.Errorf("findings: plan: reading the feeds' stamp: %w", err)
	}
	start := s.now()
	s.plan.mu.Lock()
	full := !s.plan.ran || s.plan.stamp != stamp || start.Sub(s.plan.fullAt) >= ReconcileEvery
	dirty := s.plan.dirty
	s.plan.dirty = nil
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
	scope := NewTierScope(assets)
	var tv []TierVuln
	if !scope.Empty() {
		if tv, err = s.cfg.Feeds.TierVulns(ctx, scope.Keep); err != nil {
			return fmt.Errorf("findings: plan: reading the tier data: %w", err)
		}
	}
	x := newTierIndex(tv)
	now := s.now()
	got := make(map[string]planDevice, len(assets))
	items := 0
	for _, a := range assets {
		its, compared := matchTiers(a, x, kev, now)
		got[a.ID] = planDevice{items: its, compared: compared}
		items += len(its)
	}
	s.plan.mu.Lock()
	if full {
		for id, d := range s.plan.devices { // a device that could not be read keeps what it had
			if unread[id] {
				got[id] = d
			}
		}
		s.plan.devices, s.plan.ran, s.plan.stamp, s.plan.fullAt = got, true, stamp, now
	} else {
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
	s.cfg.Log.InfoContext(ctx, "findings: plan pass done", "full", full, "devices", len(assets), "tier_cves_read", len(tv), "items", items, "took", s.now().Sub(start))
	return errors.Join(failed...)
}
