package main

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/apijson"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/store"
	idsmodule "github.com/knt048/vedette/modules/ids"
	"github.com/knt048/vedette/modules/notify"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
)

// detectionWindow is the window of the Intrusion detection overview.
const detectionWindow = 7 * 24 * time.Hour

// detectionHandlers answers GET /detection/overview, which core owns so that it answers while any detection module is off: it reads
// each detection module through its own service (honeypot, logs, sensor-passive, ids) and the incidents of notify, and reports a module
// that is off as off.
type detectionHandlers struct{ d deps }

func newDetectionHandlers(d deps) *detectionHandlers { return &detectionHandlers{d: d} }

// The overview as the contract (web/src/features/detection/contract.ts) shapes it.
type (
	detWatcher struct {
		ID          string  `json:"id"`
		Module      string  `json:"module"`
		State       string  `json:"state"`
		Detail      string  `json:"detail"`
		LastInputAt *string `json:"last_input_at"`
		Detections  int     `json:"detections_7d"`
		Action      *string `json:"action"`
	}
	detKind struct {
		Kind      string `json:"kind"`
		Incidents int    `json:"incidents"`
		New       int    `json:"new"`
	}
	detDevice struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	detMirrorHit struct {
		TS       string     `json:"ts"`
		SrcIP    string     `json:"src_ip"`
		Device   *detDevice `json:"device"`
		Dest     string     `json:"dest"`
		DestKind string     `json:"dest_kind"`
		SeenVia  string     `json:"seen_via"`
		Feeds    []string   `json:"feeds"`
	}
	detOverview struct {
		GeneratedAt string       `json:"generated_at"`
		WindowDays  int          `json:"window_days"`
		Watchers    []detWatcher `json:"watchers"`
		Kinds       []detKind    `json:"kinds"`
		MirrorHits  struct {
			Total  int            `json:"total"`
			Latest []detMirrorHit `json:"latest"`
		} `json:"mirror_port_hits"`
		Alerts struct {
			Total    int `json:"total"`
			Affected int `json:"affected"`
		} `json:"alerts"`
	}
)

func (h *detectionHandlers) on(id string) bool { return h.d.Reg == nil || h.d.Reg.Enabled(id) }

func (h *detectionHandlers) available(id string) bool {
	if h.d.Reg == nil {
		return true
	}
	for _, m := range h.d.Reg.List() {
		if m.ID == id {
			return m.Available
		}
	}
	return false
}

func ptr[T any](v T) *T { return &v }

func tsPtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	return ptr(store.FormatTS(t))
}

func watcher(id, module, state, detail, action string) detWatcher {
	w := detWatcher{ID: id, Module: module, State: state, Detail: detail}
	if action != "" {
		w.Action = ptr(action)
	}
	return w
}

// DetectionGetDetectionOverview implements detection_get_detection_overview (viewer).
func (h *detectionHandlers) DetectionGetDetectionOverview(ctx context.Context) (*oas.DetectionGetDetectionOverviewOK, error) {
	out, err := apijson.Into[oas.DetectionGetDetectionOverviewOK](h.overview(ctx))
	if err != nil {
		return nil, fmt.Errorf("detection: the overview: %w", err)
	}
	return out, nil
}

// overview never fails as a whole: a module that cannot be read makes its own watcher "failed" (and its counts zero).
func (h *detectionHandlers) overview(ctx context.Context) detOverview {
	now := clockOf(&h.d).UTC()
	since := now.Add(-detectionWindow)
	var v detOverview
	v.GeneratedAt, v.WindowDays = store.FormatTS(now), 7

	// Incidents of the window by kind (notify).
	counts := map[notify.IncidentKind]notify.KindCount{}
	if h.on(notify.ModuleID) {
		kc, err := newNotify(&h.d).KindCounts(ctx, since)
		if err != nil { // the counts show zero; the watchers still say what they can (a read error never fails the whole page)
			h.d.Log.WarnContext(ctx, "detection: counting the incidents by kind", "err", err)
		}
		for _, c := range kc {
			counts[c.Kind] = c
		}
	}
	for _, k := range notify.IncidentKinds {
		v.Kinds = append(v.Kinds, detKind{Kind: string(k), Incidents: counts[k].Incidents, New: counts[k].New})
	}

	// Mirror port hits (logs matches them).
	var hits []detMirrorHit
	logsSvc := logsService(h.d)
	if h.on("logs") && logsSvc != nil {
		all, err := logsSvc.IocHits(ctx, since, 0)
		if err != nil {
			h.d.Log.WarnContext(ctx, "detection: reading the mirror port hits", "err", err)
		}
		for _, x := range all {
			if !strings.HasPrefix(x.SeenVia, "span_") {
				continue
			}
			m := detMirrorHit{TS: store.FormatTS(x.TS), SrcIP: x.SrcIP, Dest: x.Dest, DestKind: x.DestKind, SeenVia: x.SeenVia, Feeds: x.Feeds}
			if m.Feeds == nil {
				m.Feeds = []string{}
			}
			if x.AssetID != nil && x.AssetName != nil {
				m.Device = &detDevice{ID: *x.AssetID, Name: *x.AssetName}
			}
			hits = append(hits, m)
		}
		slices.SortStableFunc(hits, func(a, b detMirrorHit) int { return strings.Compare(b.TS, a.TS) })
	}
	v.MirrorHits.Total = len(hits)
	v.MirrorHits.Latest = hits[:min(5, len(hits))]
	if v.MirrorHits.Latest == nil {
		v.MirrorHits.Latest = []detMirrorHit{}
	}

	traps := h.traps(ctx)
	logsW, ipsSources := h.logs(ctx, counts)
	mirror := h.mirror(ctx, len(hits))
	ipsW, sum := h.ips(ctx, since, ipsSources)
	v.Alerts.Total, v.Alerts.Affected = sum.Alerts, sum.Affected
	v.Watchers = []detWatcher{traps, logsW, mirror, ipsW}
	return v
}

// traps is the honeypot's watcher: its Trap IPs and their hits.
func (h *detectionHandlers) traps(ctx context.Context) detWatcher {
	const id, mod = "traps", "honeypot"
	if !h.available(mod) {
		return watcher(id, mod, "unavailable", "This install cannot run traps: they need the system helper of an appliance install.", "")
	}
	if !h.on(mod) {
		return watcher(id, mod, "off", "The Honeypot module is off.", "turn_on")
	}
	if h.d.Honeypot == nil {
		return watcher(id, mod, "failed", "The trap state could not be read.", "fix")
	}
	ov, err := h.d.Honeypot.Overview(ctx)
	if err != nil {
		h.d.Log.WarnContext(ctx, "detection: reading the honeypot overview", "err", err)
		return watcher(id, mod, "failed", "The trap state could not be read.", "fix")
	}
	var last string
	hits := 0
	for _, t := range ov.Traps {
		hits += t.Hits7d
		if t.LastHitAt != nil && *t.LastHitAt > last {
			last = *t.LastHitAt
		}
	}
	set := func(w detWatcher) detWatcher {
		w.Detections = hits
		if last != "" {
			w.LastInputAt = ptr(last)
		}
		return w
	}
	t := ov.TrapIPs
	switch {
	case t.Enabled == 0:
		return set(watcher(id, mod, "not_set_up", "No Trap IP is switched on.", "set_up"))
	case t.Listening > 0:
		action := "view"
		if t.Failing > 0 {
			action = "fix"
		}
		return set(watcher(id, mod, "watching", strconv.Itoa(t.Listening)+" of "+strconv.Itoa(t.Enabled)+" Trap IPs are listening.", action))
	case t.Failing > 0:
		why := "No Trap IP could be set up."
		if ov.Problem != nil && *ov.Problem != "" {
			why = *ov.Problem
		}
		return set(watcher(id, mod, "failed", why, "fix"))
	}
	return set(watcher(id, mod, "quiet", "The Trap IPs are starting.", "view"))
}

// ipsSource is a log source of a kind that writes IPS events.
type ipsSource struct {
	name      string
	receiving bool
	last      time.Time
}

// logs is the logs module's watcher: the log sources and what they raised. It also returns the sources whose kind writes IPS events.
// ipsFeed is what the IPS watcher knows of its input: whether the logs module is on, whether its sources could be read, and the ones
// of a kind that writes IPS events.
type ipsFeed struct {
	logsOn, read bool
	sources      []ipsSource
}

func (h *detectionHandlers) logs(ctx context.Context, counts map[notify.IncidentKind]notify.KindCount) (detWatcher, ipsFeed) {
	const id, mod = "logs", "logs"
	if !h.on(mod) {
		return watcher(id, mod, "off", "The Logs module is off.", "turn_on"), ipsFeed{}
	}
	failed := watcher(id, mod, "failed", "The log sources could not be read.", "fix")
	svc := logsService(h.d)
	if svc == nil {
		return failed, ipsFeed{logsOn: true}
	}
	sv, err := svc.Sources(ctx)
	if err != nil {
		h.d.Log.WarnContext(ctx, "detection: reading the log sources", "err", err)
		return failed, ipsFeed{logsOn: true}
	}
	det := counts[notify.IncidentBadAddress].Incidents + counts[notify.IncidentLogAnomaly].Incidents
	var last time.Time
	sending := 0
	var ips []ipsSource
	for _, s := range sv.Sources {
		var at time.Time
		if s.LastReceived != nil {
			at = *s.LastReceived
			last = maxT(last, at)
		}
		if s.State == "receiving" {
			sending++
		}
		if idsmodule.NativeIPS(s.Kind) {
			ips = append(ips, ipsSource{name: s.Name, receiving: s.State == "receiving", last: at})
		}
	}
	n := len(sv.Sources)
	var w detWatcher
	switch {
	case n == 0:
		w = watcher(id, mod, "not_set_up", "No device sends its logs to the box yet.", "set_up")
	case sending == 0:
		w = watcher(id, mod, "quiet", "None of the "+strconv.Itoa(n)+" log sources sent anything in the last hour.", "fix")
	default:
		action := "view"
		if sending < n {
			action = "fix"
		}
		w = watcher(id, mod, "watching", strconv.Itoa(sending)+" of "+strconv.Itoa(n)+" log sources are sending.", action)
	}
	w.Detections, w.LastInputAt = det, tsPtr(last)
	return w, ipsFeed{logsOn: true, read: true, sources: ips}
}

func maxT(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// mirror is the passive sensor's mirror (SPAN) port watcher.
func (h *detectionHandlers) mirror(ctx context.Context, hits int) detWatcher {
	const id, mod = "mirror_port", "sensor-passive"
	if !h.on(mod) {
		return watcher(id, mod, "off", "The network sensor module is off.", "turn_on")
	}
	if h.d.SensorPassive == nil {
		return watcher(id, mod, "failed", "The mirror port state could not be read.", "fix")
	}
	st, err := h.d.SensorPassive.SpanStats(ctx)
	var w detWatcher
	switch {
	case err != nil:
		h.d.Log.WarnContext(ctx, "detection: reading the mirror port state", "err", err)
		w = watcher(id, mod, "failed", "The mirror port state could not be read.", "fix")
	case st.Verdict == sensorpassive.VerdictOff:
		w = watcher(id, mod, "not_set_up", "No network card is set as a mirror port.", "set_up")
	case st.Verdict == sensorpassive.VerdictOK:
		w = watcher(id, mod, "watching", "The mirror port carries the traffic of "+strconv.Itoa(st.OtherMACs)+" other devices.", "view")
	case st.Verdict == sensorpassive.VerdictNoLink:
		w = watcher(id, mod, "quiet", "The mirror port has no cable link.", "fix")
	case st.Verdict == sensorpassive.VerdictOwnOnly:
		w = watcher(id, mod, "quiet", "The mirror port only sees the box's own traffic.", "fix")
	default:
		w = watcher(id, mod, "quiet", "The mirror port carries no traffic.", "fix")
	}
	w.Detections, w.LastInputAt = hits, tsPtr(st.LastPacket)
	return w
}

// ips is the ids module's watcher: the IPS events read from the firewall logs.
func (h *detectionHandlers) ips(ctx context.Context, since time.Time, feed ipsFeed) (detWatcher, idsmodule.Summary) {
	const id, mod = "ips_events", idsmodule.ModuleID
	if !h.on(mod) {
		return watcher(id, mod, "off", "Reading IPS events from firewall logs is off.", "turn_on"), idsmodule.Summary{}
	}
	sum, err := idsService(h.d).Summarize(ctx, since)
	if err != nil {
		h.d.Log.WarnContext(ctx, "detection: reading the intrusion alerts", "err", err)
		return watcher(id, mod, "failed", "The intrusion alerts could not be read.", "fix"), idsmodule.Summary{}
	}
	sources := feed.sources
	var w detWatcher
	var names, sending []string
	for _, s := range sources {
		names = append(names, s.name)
		if s.receiving {
			sending = append(sending, s.name)
		}
	}
	slices.SortFunc(names, cmp.Compare)
	slices.SortFunc(sending, cmp.Compare)
	switch {
	case !feed.logsOn: // IPS events arrive in received logs: Logs is what to turn on (its page says how)
		w = watcher(id, mod, "not_set_up", "The Logs module is off: IPS events are read from the logs your firewalls send to the box.", "set_up")
	case !feed.read:
		w = watcher(id, mod, "failed", "The log sources could not be read.", "fix")
	case len(sources) == 0:
		w = watcher(id, mod, "not_set_up", "No firewall that writes IPS events sends its logs to the box.", "set_up")
	case len(sending) == 0:
		w = watcher(id, mod, "quiet", clip300(strings.Join(names, ", ")+" sent nothing in the last hour."), "fix")
	default:
		w = watcher(id, mod, "watching", clip300("IPS events are read from "+strings.Join(sending, ", ")+"."), "view")
	}
	w.Detections, w.LastInputAt = sum.Alerts, tsPtr(sum.LastEvent)
	return w, sum
}

func clip300(s string) string {
	if r := []rune(s); len(r) > 300 {
		return string(r[:299]) + "…"
	}
	return s
}
