package findings

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// GET /findings/overview: Home at a glance, from the same functions as the lists (open findings by status, device statuses, the Needs
// your input queue, the fix blocks). Home is opened many times a day on a small box, so the answer is kept until a finding changes
// (Service.gen) or overviewTTL passes; notify's open incidents are read at every call.

// The sizes of Home's lists (contract.ts FIRST_TOP, TREND_DAYS).
const (
	FirstTop    = 5
	TrendDays   = 30
	overviewTTL = 60 * time.Second
)

// DeviceStatusCounts is Overview.devices.by_status: devices by their badge.
type DeviceStatusCounts struct {
	StatusCounts
	Possible int `json:"possible"` // devices whose only open items are possible CVEs
}

// FirstItem is one block of Home's "Fix first".
type FirstItem struct {
	Device deviceRefJS `json:"device"`
	Block  FixBlockJS  `json:"block"`
}

// Overview is contract.ts Overview.
type Overview struct {
	Open struct {
		Findings int          `json:"findings"`
		ByStatus StatusCounts `json:"by_status"`
	} `json:"open"`
	Devices struct {
		Total    int                `json:"total"`
		NotAdded int                `json:"not_added"`
		ByStatus DeviceStatusCounts `json:"by_status"`
		// Affected: devices with an open finding by their most urgent status, the Vedette box included like any device.
		Affected StatusCounts `json:"affected"`
	} `json:"devices"`
	Input       int               `json:"input"`
	Possible    PossibleCounts    `json:"possible"` // possible CVEs counted apart from the open findings
	First       []FirstItem       `json:"first"`
	Trend       []int             `json:"trend"`
	TrendStart  string            `json:"trend_start"`
	Alerts      *SummaryAlerts    `json:"alerts"`
	Incidents   *SummaryIncidents `json:"incidents"`
	FirstRun    *FirstRunSummary  `json:"first_run_summary"`
	GeneratedAt string            `json:"generated_at"`
}

type overviewCache struct {
	val      *Overview
	gen      uint64
	notifyOn bool
	at       time.Time
}

// Overview returns Home's answer: the kept one while nothing changed, else a new one; the incidents are read now.
func (h *FindingHandlers) Overview(ctx context.Context) (*Overview, error) {
	h.sumMu.Lock()
	defer h.sumMu.Unlock()
	now := h.svc.now()
	gen := h.svc.gen.Load()
	notifyOn := h.gate == nil || h.gate.Enabled(NotifyModule)
	h.mu.RLock()
	c, src := h.ov, h.home
	h.mu.RUnlock()
	if c.val == nil || c.gen != gen || c.notifyOn != notifyOn || now.Sub(c.at) >= overviewTTL || now.Before(c.at) {
		o, err := h.computeOverview(ctx, src, notifyOn, now)
		if err != nil {
			return nil, err
		}
		c = overviewCache{val: o, gen: gen, notifyOn: notifyOn, at: now}
		h.mu.Lock()
		h.ov = c
		h.mu.Unlock()
	}
	o := *c.val
	if src.Incidents != nil && notifyOn {
		open, urgent, err := src.Incidents(ctx)
		if err != nil {
			return nil, fmt.Errorf("findings: overview: counting incidents: %w", err)
		}
		o.Incidents = &SummaryIncidents{Open: open, Urgent: urgent}
	}
	return &o, nil
}

func (h *FindingHandlers) computeOverview(ctx context.Context, src HomeSources, notifyOn bool, now time.Time) (*Overview, error) {
	var out *Overview
	err := h.svc.readTx(ctx, func(ctx context.Context) error {
		var err error
		out, err = h.overviewIn(ctx, src, notifyOn, now)
		return err
	})
	return out, err
}

func (h *FindingHandlers) overviewIn(ctx context.Context, src HomeSources, notifyOn bool, now time.Time) (*Overview, error) {
	s := h.svc
	o := &Overview{First: []FirstItem{}, GeneratedAt: store.FormatTS(now)}
	ignored, err := s.ignoredDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("findings: overview: %w", err)
	}
	gs, err := s.lineGroups(ctx, ListFilter{})
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		o.Open.Findings += g.All
	}
	if err := s.openByLayer(ctx, &o.Open.ByStatus); err != nil {
		return nil, err
	}
	statuses, err := s.deviceStatuses(ctx, nil)
	if err != nil {
		return nil, err
	}
	for id, st := range statuses {
		if ignored[id] {
			continue
		}
		l, ok := layerOf(st.Code)
		if ok {
			o.Devices.Affected.add(l, 1)
		}
		if ok {
			o.Devices.ByStatus.add(l, 1)
		} else {
			o.Devices.ByStatus.Possible++
		}
	}
	items, err := s.inputItems(ctx, "", false)
	if err != nil {
		return nil, err
	}
	for _, it := range items { // one item per device that waits for an answer; the card of devices not added with no finding is a review
		if it.Kind != KindDevicesNotAdded {
			o.Input++
		}
	}
	pi, err := s.possibleItems(ctx, "")
	if err != nil {
		return nil, err
	}
	rs := s.ReadState(ctx)
	s.markOlderBuilds(ctx, pi, rs)
	o.Possible = countPossible(pi, rs)
	if o.First, err = s.firstBlocks(ctx, gs); err != nil {
		return nil, err
	}
	if o.Trend, err = s.trend(ctx, now, ignored); err != nil {
		return nil, err
	}
	if o.TrendStart, err = s.trendStart(ctx, now); err != nil {
		return nil, err
	}
	if src.Devices != nil {
		if o.Devices.Total, o.Devices.NotAdded, err = src.Devices(ctx); err != nil {
			return nil, fmt.Errorf("findings: overview: counting devices: %w", err)
		}
	} else {
		all, err := s.cfg.Inventory.AssetIDs(ctx)
		if err != nil {
			return nil, fmt.Errorf("findings: overview: counting devices: %w", err)
		}
		o.Devices.Total = len(all)
	}
	if src.Alerts != nil && notifyOn {
		sent, failed, err := src.Alerts(ctx, now.Add(-alertDays*24*time.Hour))
		if err != nil {
			return nil, fmt.Errorf("findings: overview: counting alerts: %w", err)
		}
		o.Alerts = &SummaryAlerts{Sent: sent, Failed: failed, Days: alertDays}
	}
	if src.FirstRun != nil && notifyOn {
		f, err := src.FirstRun(ctx, now.Add(-firstRunDays*24*time.Hour))
		if err != nil {
			return nil, fmt.Errorf("findings: overview: reading the first-run summary: %w", err)
		}
		if f != nil && f.Channels == nil {
			f.Channels = []string{}
		}
		o.FirstRun = f
	}
	return o, nil
}

// openByLayer counts the open findings of devices nobody ignored by status.
func (s *Service) openByLayer(ctx context.Context, c *StatusCounts) error {
	rows, args, _, _, err := s.where(ctx, StateOpen, ListFilter{})
	if err != nil {
		return err
	}
	r, err := s.rd(ctx).QueryContext(ctx, `SELECT urgency, count(*) FROM fnd_finding WHERE `+rows+` GROUP BY urgency`, args...)
	if err != nil {
		return fmt.Errorf("findings: overview: counting open findings: %w", err)
	}
	for r.Next() {
		var l, n int
		if err := r.Scan(&l, &n); err != nil {
			_ = r.Close()
			return fmt.Errorf("findings: overview: counting open findings: %w", err)
		}
		c.add(l, n)
	}
	return errors.Join(r.Err(), r.Close())
}

// firstBlocks is "Fix first": the FirstTop most urgent fix blocks across devices, then those with the most findings.
func (s *Service) firstBlocks(ctx context.Context, gs []lineGroup) ([]FirstItem, error) {
	type bk struct{ asset, software, key string }
	type agg struct {
		k          bk
		n, urgency int
	}
	byKey := map[bk]*agg{}
	for _, g := range gs {
		k := bk{g.Asset, g.Software, g.Block}
		a := byKey[k]
		if a == nil {
			a = &agg{k: k, urgency: g.Urgency}
			byKey[k] = a
		}
		a.n += g.All
		a.urgency = min(a.urgency, g.Urgency)
	}
	all := make([]*agg, 0, len(byKey))
	for _, a := range byKey {
		all = append(all, a)
	}
	slices.SortFunc(all, func(a, b *agg) int {
		return cmp.Or(cmp.Compare(a.urgency, b.urgency), cmp.Compare(b.n, a.n), cmp.Compare(a.k.asset, b.k.asset), cmp.Compare(a.k.key, b.k.key))
	})
	all = all[:min(len(all), FirstTop)]
	assets := map[string]bool{}
	for _, a := range all {
		assets[a.k.asset] = true
	}
	if len(assets) == 0 {
		return []FirstItem{}, nil
	}
	cards, err := s.deviceCards(ctx, ListFilter{}, keys(assets), blocksOf(gs))
	if err != nil {
		return nil, err
	}
	out := make([]FirstItem, 0, len(all))
	for _, a := range all {
		for _, c := range cards {
			if c.Device.ID != a.k.asset {
				continue
			}
			for _, b := range c.Blocks {
				sw := ""
				if b.Software != nil {
					sw = b.Software.ID
				}
				if b.Fix.Key == clipBytes(a.k.key, 400) && sw == a.k.software {
					out = append(out, FirstItem{Device: c.Device, Block: b})
				}
			}
		}
	}
	return out, nil
}

// trendStart is the first day of the trend that holds data (YYYY-MM-DD in the organization's time zone): the first of its TrendDays
// days, or the day this box began keeping findings when that is later. A box installed today has no "was 0 on 25 Oct".
func (s *Service) trendStart(ctx context.Context, now time.Time) (string, error) {
	loc := orgtime.At(ctx, s.cfg.Zone)
	y, m, d := now.UTC().In(loc).Date()
	first := time.Date(y, m, d-(TrendDays-1), 0, 0, 0, 0, loc)
	since, err := s.cfg.DB.ModuleSince(ctx, "findings")
	if err != nil {
		return "", fmt.Errorf("findings: overview: trend start: %w", err)
	}
	if since.In(loc).After(first) {
		sy, sm, sd := since.In(loc).Date()
		first = time.Date(sy, sm, sd, 0, 0, 0, 0, loc)
	}
	return first.Format(time.DateOnly), nil
}

// trend is the open findings at the end of each of the last TrendDays days of the organization's time zone, the last one now: those
// first seen by then and not handled by then. A finding reopened after a handling counts as open since it was first seen (fnd_finding
// keeps one resolved_at): the line is a trend, the last point is exact.
func (s *Service) trend(ctx context.Context, now time.Time, ignored map[string]bool) ([]int, error) {
	loc := orgtime.At(ctx, s.cfg.Zone)
	now = now.UTC()
	y, m, d := now.In(loc).Date()
	start := time.Date(y, m, d-(TrendDays-1), 0, 0, 0, 0, loc)
	ends := make([]time.Time, TrendDays)
	for i := range ends {
		ends[i] = start.AddDate(0, 0, i+1)
	}
	ends[TrendDays-1] = now
	out := make([]int, TrendDays)
	ig, _ := json.Marshal(nonNilStrings(keysOf(ignored)))
	r, err := s.rd(ctx).QueryContext(ctx, `SELECT first_seen, ifnull(resolved_at, '') FROM fnd_finding
		WHERE asset_id NOT IN (SELECT value FROM json_each(?)) AND first_seen <= ? AND (state = 'open' OR resolved_at >= ?)`,
		string(ig), store.FormatTS(now), store.FormatTS(start))
	if err != nil {
		return nil, fmt.Errorf("findings: overview: trend: %w", err)
	}
	open := 0
	for r.Next() {
		var fs, rs string
		if err := r.Scan(&fs, &rs); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: overview: trend: %w", err)
		}
		first, err := parseTS(fs)
		if err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: overview: trend: %w", err)
		}
		var resolved time.Time
		if rs != "" {
			if resolved, err = parseTS(rs); err != nil {
				_ = r.Close()
				return nil, fmt.Errorf("findings: overview: trend: %w", err)
			}
			if resolved.After(now) {
				resolved = now
			}
		} else {
			open++
		}
		for i, e := range ends {
			if !first.After(e) && (resolved.IsZero() || resolved.After(e)) {
				out[i]++
			}
		}
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: overview: trend: %w", err)
	}
	out[TrendDays-1] = open
	return out, nil
}
