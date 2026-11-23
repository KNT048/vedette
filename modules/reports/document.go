package reports

import (
	"cmp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxRows caps each list of a document. The counts are of everything; a report of a very large estate stays bounded.
const MaxRows = 100

// maxTop is how many incidents the Detections section names.
const maxTop = 5

const day = 24 * time.Hour

// tsLayout is the one time format of the API and the database: UTC, milliseconds.
const tsLayout = "2006-01-02T15:04:05.000Z"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

// clip cleans text that came from the network (a device name, a product) for a report: control and bidirectional characters out,
// one line, bounded. Every renderer still escapes it (the page is React; the email goes through notify's cleaner).
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}

// openCodes are the open statuses by urgency layer (findings.LayerCode): layer 1 is index 0.
var openCodes = []string{"under_attack", "exploited", "public_exploit", "critical_edge", "update_recommended"}

// layerCode is the open status of a stored urgency layer; a layer out of range reads as update recommended (the least urgent).
func layerCode(layer int) string {
	if layer < 1 || layer > len(openCodes) {
		return openCodes[len(openCodes)-1]
	}
	return openCodes[layer-1]
}

func layerOf(code string) int {
	if i := slices.Index(openCodes, code); i >= 0 {
		return i + 1
	}
	return len(openCodes) + 1
}

var resolutionOrder = []string{"patched", "mitigated", "accepted", "false_positive", "not_relevant"}

// periodOf is the time a document made at now covers: the last 7 or 30 days up to now, or the last whole calendar month in loc.
func periodOf(kind string, now time.Time, loc *time.Location) (from, to time.Time) {
	switch kind {
	case PeriodMonth:
		n := now.In(loc)
		to = time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, loc)
		return to.AddDate(0, -1, 0).UTC(), to.UTC()
	case PeriodLast30:
		return now.Add(-30 * day), now
	default:
		return now.Add(-7 * day), now
	}
}

// docInput is everything the document reads, already fetched.
type docInput struct {
	def      Definition
	org      string
	now      time.Time
	loc      *time.Location
	findings []FindingView
	devices  []Device
	// reasons reads the urgency reasons of the findings the document lists; nil reads none (the reasons line is then empty).
	reasons    func(ids []string) map[string][]Reason
	exposure   *ReportExposure // nil: the section could not be read or is off; built by the service
	detections detectionsIn
	sources    []SourceOn
	feeds      []FeedHealth
}

type detectionsIn struct {
	on     bool
	counts []DetectionCount
	top    []Detection
}

// history is what a finding's events say about the period: whether it was open at the start and at the end, and its last handling
// inside the period (nil when it was not handled in it).
type history struct {
	openAtFrom, openAtTo bool
	existsAtFrom         bool
	handled              *Handled // the last handling in (from, to]
	handledAtTo          *Handled // the handling in force at to; nil when open at to
}

// historyOf replays a finding's state events. A finding exists from its first sighting; a handled event closes it unless it only adds a
// person's note to a handling Vedette credited (the credit stays: findings M-3); reopened and acceptance_expired open it. A finding
// with no state events (made before events were kept) is read from its first sighting and its handling now.
func historyOf(f FindingView, from, to time.Time) history {
	var h history
	inPeriod := func(t time.Time) bool { return t.After(from) && !t.After(to) }
	h.existsAtFrom = !f.FirstSeen.After(from)
	var states []FindingEvent
	for _, e := range f.Events {
		switch e.Kind {
		case "created", "handled", "reopened", "acceptance_expired":
			states = append(states, e)
		}
	}
	if len(states) == 0 {
		closedAt := func(t time.Time) bool {
			return f.Handled != nil && !parseTS(f.Handled.At).After(t)
		}
		h.openAtFrom = h.existsAtFrom && !closedAt(from)
		h.openAtTo = !f.FirstSeen.After(to) && !closedAt(to)
		if f.Handled != nil && inPeriod(parseTS(f.Handled.At)) {
			h.handled = f.Handled
		}
		if !h.openAtTo && !f.FirstSeen.After(to) {
			h.handledAtTo = f.Handled
		}
		return h
	}
	var cur *Handled // the handling in force; nil = open
	open := true
	var fromDone bool
	for _, e := range states {
		if !fromDone && e.At.After(from) {
			h.openAtFrom, fromDone = open, true
		}
		if e.At.After(to) {
			break
		}
		switch e.Kind {
		case "created", "reopened", "acceptance_expired":
			open, cur = true, nil
		case "handled":
			if e.Handled == nil {
				continue
			}
			if !open && cur != nil && cur.Resolution == e.Handled.Resolution && e.Handled.Via == "person" && credit(cur.Via) {
				// a person's note on Vedette's patch credit: the credit stays, the note joins it
				if cur.Note == nil && e.Handled.Note != nil {
					prev, c := cur, *cur
					c.Note = e.Handled.Note
					cur = &c
					if h.handled == prev {
						h.handled = cur
					}
				}
				continue
			}
			x := *e.Handled
			open, cur = false, &x
			if inPeriod(e.At) {
				h.handled = cur
			}
		}
	}
	if !fromDone {
		h.openAtFrom = open
	}
	h.openAtFrom = h.openAtFrom && h.existsAtFrom
	h.openAtTo = open && !f.FirstSeen.After(to)
	if !open {
		h.handledAtTo = cur
	}
	return h
}

// credit reports whether a way of handling is Vedette's patch credit (findings Via.Credit).
func credit(via string) bool {
	switch via {
	case "version_moved", "software_removed", "distro_fixed", "scan_clear":
		return true
	}
	return false
}

func parseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// row is one finding with what the period says about it.
type row struct {
	f FindingView
	h history
}

func (r row) product() string { return clip(cmp.Or(r.f.Product, r.f.Fix.Product, r.f.CVE), 200) }

func (r row) device() DeviceRef {
	d := r.f.Device
	return DeviceRef{ID: d.ID, Name: clip(d.Name, 200), Added: d.Added}
}

func (r row) score() float64 {
	if r.f.Severity == nil {
		return -1
	}
	return r.f.Severity.Score
}

// listed is the finding as the document lists it, with status: an open status while open at the end of the period, else how it was
// handled then.
func (r row) listed(reasons map[string][]Reason) ReportFinding {
	status := layerCode(r.f.Urgency)
	if !r.h.openAtTo && r.h.handledAtTo != nil {
		status = r.h.handledAtTo.Resolution
	}
	rs := reasons[r.f.ID]
	if rs == nil || !r.h.openAtTo {
		rs = []Reason{}
	}
	out := ReportFinding{FindingID: r.f.ID, CVE: clip(r.f.CVE, 40), Device: r.device(), Product: r.product(), Status: status, Reasons: rs,
		Severity: r.f.Severity, Verification: r.f.Verification, Fix: r.f.Fix, FirstSeen: ts(r.f.FirstSeen)}
	if v := clip(r.f.Version, 80); v != "" {
		out.Version = &v
	}
	return out
}

// byUrgency orders open findings most urgent first: the layer, then the CVSS score, then the CVE and the device.
func byUrgency(a, b row) int {
	return cmp.Or(cmp.Compare(a.f.Urgency, b.f.Urgency), cmp.Compare(b.score(), a.score()), strings.Compare(a.f.CVE, b.f.CVE),
		strings.Compare(a.f.Device.Name, b.f.Device.Name), strings.Compare(a.f.ID, b.f.ID))
}

// buildDocument makes the document of the definition at in.now. Each section is one pass over the same rows, so the summary counts
// what the sections list: open now = Still open's total, new = New's total, handled = Handled's total.
func buildDocument(in docInput) Document {
	o := in.def.Options
	from, to := periodOf(o.Period, in.now, in.loc)
	inPeriod := func(t time.Time) bool { return t.After(from) && !t.After(to) }
	doc := Document{DefinitionID: in.def.ID, Title: clip(in.def.Name, 120), GeneratedAt: ts(in.now), Org: clip(in.org, 120),
		Period: DocPeriod{Kind: o.Period, From: ts(from), To: ts(to), TZ: clip(in.loc.String(), 64)}, Options: o}

	var open, fresh, handled []row
	before := 0
	for _, f := range in.findings {
		if !o.IncludeNotAdded && !f.Device.Added {
			continue
		}
		r := row{f: f, h: historyOf(f, from, to)}
		// "Include not relevant" off: a finding Vedette or a person found not relevant in the period counts nowhere (it was never a
		// real flaw), so the summary's arithmetic stays whole.
		if !o.IncludeNotRelevant && r.h.handled != nil && r.h.handled.Resolution == "not_relevant" {
			continue
		}
		if r.h.openAtFrom {
			before++
		}
		if r.h.openAtTo {
			open = append(open, r)
		}
		if inPeriod(f.FirstSeen) {
			fresh = append(fresh, r)
		}
		if r.h.handled != nil {
			handled = append(handled, r)
		}
	}
	slices.SortStableFunc(open, byUrgency)
	slices.SortStableFunc(fresh, func(a, b row) int {
		if a.h.openAtTo != b.h.openAtTo { // still open first, then what was handled since
			if a.h.openAtTo {
				return -1
			}
			return 1
		}
		return cmp.Or(byUrgency(a, b), b.f.FirstSeen.Compare(a.f.FirstSeen))
	})
	slices.SortStableFunc(handled, func(a, b row) int {
		return cmp.Or(strings.Compare(b.h.handled.At, a.h.handled.At), strings.Compare(a.f.Device.Name, b.f.Device.Name), strings.Compare(a.f.CVE, b.f.CVE))
	})

	s := o.Sections
	var reasons map[string][]Reason
	if in.reasons != nil {
		var ids []string
		add := func(rs []row) {
			for _, r := range rs[:min(len(rs), MaxRows)] {
				if r.h.openAtTo && r.f.Urgency >= 1 && r.f.Urgency <= 4 { // layer 5 has no reason to show
					ids = append(ids, r.f.ID)
				}
			}
		}
		if s.Open || s.Summary {
			add(open)
		}
		if s.New {
			add(fresh)
		}
		slices.Sort(ids)
		if ids = slices.Compact(ids); len(ids) > 0 {
			reasons = in.reasons(ids)
		}
	}

	if s.Summary {
		doc.Summary = summaryOf(open, len(fresh), len(handled), before)
	}
	if s.Handled {
		doc.Handled = handledOf(handled)
	}
	if s.Open {
		doc.Open = openOf(open, o.Grouping, reasons)
	}
	if s.New {
		items := make([]ReportFinding, 0, min(len(fresh), MaxRows))
		for _, r := range fresh[:min(len(fresh), MaxRows)] {
			items = append(items, r.listed(reasons))
		}
		doc.New = &ReportNew{Total: len(fresh), Items: items, More: max(0, len(fresh)-MaxRows)}
	}
	if s.Exposure {
		doc.Exposure = in.exposure
		if doc.Exposure == nil {
			doc.Exposure = &ReportExposure{ModuleOn: false, Targets: []ExposureTarget{}}
		}
	}
	if s.Detections {
		doc.Detections = detectionsOf(in, o)
	}
	if s.Coverage {
		doc.Coverage = coverageOf(in, o)
	}
	return doc
}

func summaryOf(open []row, fresh, handled, before int) *ReportSummary {
	sum := &ReportSummary{OpenByStatus: []StatusCount{}, OpenNow: len(open), OpenBefore: before, New: fresh, Handled: handled, First: []FirstThing{}}
	by := map[string]int{}
	for _, r := range open {
		by[layerCode(r.f.Urgency)]++
	}
	for _, c := range openCodes {
		if by[c] > 0 {
			sum.OpenByStatus = append(sum.OpenByStatus, StatusCount{Status: c, N: by[c]})
		}
	}
	// The three things to do first: one CVE on one product each, in the order of the most urgent finding of each.
	type group struct {
		first   row
		devices []DeviceRef
		seen    map[string]bool
		n       int
	}
	var order []string
	groups := map[string]*group{}
	for _, r := range open {
		k := r.f.CVE + "|" + r.product()
		g := groups[k]
		if g == nil {
			if len(order) == 3 {
				continue
			}
			g = &group{first: r, seen: map[string]bool{}}
			groups[k] = g
			order = append(order, k)
		}
		g.n++
		if !g.seen[r.f.Device.ID] {
			g.seen[r.f.Device.ID] = true
			if len(g.devices) < 3 {
				g.devices = append(g.devices, r.device())
			}
		}
	}
	for _, k := range order {
		g := groups[k]
		f := g.first
		sum.First = append(sum.First, FirstThing{Status: layerCode(f.f.Urgency), CVE: clip(f.f.CVE, 40), FindingID: f.f.ID, Product: f.product(),
			Severity: f.f.Severity, Fix: f.f.Fix, Devices: g.devices, DeviceCount: len(g.seen), FindingCount: g.n})
	}
	return sum
}

func handledOf(rows []row) *ReportHandled {
	out := &ReportHandled{Totals: []HandledTotal{}, Devices: []HandledDevice{}, More: max(0, len(rows)-MaxRows)}
	type key struct{ res, via string }
	totals := map[key]int{}
	var days []float64
	for _, r := range rows {
		h := r.h.handled
		totals[key{h.Resolution, h.Via}]++
		if h.Resolution == "patched" || h.Resolution == "mitigated" {
			if at := parseTS(h.At); !at.IsZero() && !at.Before(r.f.FirstSeen) {
				days = append(days, at.Sub(r.f.FirstSeen).Hours()/24)
			}
		}
	}
	for k, n := range totals {
		out.Totals = append(out.Totals, HandledTotal{Resolution: k.res, Via: k.via, N: n})
	}
	sort.Slice(out.Totals, func(i, j int) bool {
		a, b := out.Totals[i], out.Totals[j]
		if a.N != b.N {
			return a.N > b.N
		}
		if a.Resolution != b.Resolution {
			return slices.Index(resolutionOrder, a.Resolution) < slices.Index(resolutionOrder, b.Resolution)
		}
		return a.Via < b.Via
	})
	at := map[string]int{}
	for _, r := range rows[:min(len(rows), MaxRows)] {
		d := r.device()
		i, ok := at[d.ID]
		if !ok {
			i = len(out.Devices)
			at[d.ID] = i
			out.Devices = append(out.Devices, HandledDevice{Device: d, Items: []HandledItem{}})
		}
		out.Devices[i].Items = append(out.Devices[i].Items, HandledItem{FindingID: r.f.ID, CVE: clip(r.f.CVE, 40), Product: r.product(),
			Severity: r.f.Severity, Handled: *r.h.handled})
	}
	if len(days) > 0 {
		slices.Sort(days)
		m := days[len(days)/2]
		if len(days)%2 == 0 {
			m = (days[len(days)/2-1] + days[len(days)/2]) / 2
		}
		m = float64(int(m*10+0.5)) / 10
		out.MedianDays = &m
	}
	return out
}

func openOf(open []row, grouping string, reasons map[string][]Reason) *ReportOpen {
	out := &ReportOpen{Grouping: grouping, Total: len(open), Groups: []OpenGroup{}, More: max(0, len(open)-MaxRows)}
	at := map[string]int{}
	for _, r := range open[:min(len(open), MaxRows)] {
		key, label := r.f.Device.ID, r.device().Name
		if grouping == groupCVE {
			key, label = r.f.CVE, clip(r.f.CVE, 40)
		}
		i, ok := at[key]
		if !ok {
			i = len(out.Groups)
			at[key] = i
			out.Groups = append(out.Groups, OpenGroup{Key: key, Label: label, Status: layerCode(r.f.Urgency), Items: []ReportFinding{}})
		}
		g := &out.Groups[i]
		if layerOf(layerCode(r.f.Urgency)) < layerOf(g.Status) {
			g.Status = layerCode(r.f.Urgency)
		}
		g.Items = append(g.Items, r.listed(reasons))
	}
	return out
}

// detectionKinds are the incident kinds the document names (the detection contract); a kind a producer added later is left out.
var detectionKinds = []string{"trap", "bad_address", "log_anomaly", "unknown_device", "intrusion"}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func detectionsOf(in docInput, o Options) *ReportDetections {
	out := &ReportDetections{ModuleOn: in.detections.on, ByKind: []KindCountAt{}, Top: []TopDetection{}}
	for _, c := range in.detections.counts {
		if c.N > 0 && slices.Contains(detectionKinds, c.Kind) {
			out.ByKind = append(out.ByKind, KindCountAt{Kind: c.Kind, N: c.N, LastAt: ts(c.LastAt)})
		}
	}
	devs := map[string]Device{}
	for _, d := range in.devices {
		devs[d.ID] = d
	}
	for _, t := range in.detections.top {
		if len(out.Top) == maxTop {
			break
		}
		if !slices.Contains(detectionKinds, t.Kind) {
			continue
		}
		sev := t.Severity
		if _, ok := severityRank[sev]; !ok {
			sev = "info"
		}
		d := TopDetection{Kind: t.Kind, Title: clip(t.Title, 200), Severity: sev, At: ts(t.At)}
		if t.DeviceID != "" {
			dev, known := devs[t.DeviceID]
			ref := DeviceRef{ID: t.DeviceID, Name: clip(cmp.Or(dev.Name, t.DeviceName, t.DeviceID), 200), Added: !known || dev.Approved}
			if ref.Added || o.IncludeNotAdded {
				d.Device = &ref
			}
		}
		out.Top = append(out.Top, d)
	}
	return out
}

func coverageOf(in docInput, o Options) *ReportCoverage {
	out := &ReportCoverage{Sources: in.sources, Feeds: []FeedState{}}
	if out.Sources == nil {
		out.Sources = []SourceOn{}
	}
	for _, d := range in.devices {
		if !d.Approved && !o.IncludeNotAdded {
			continue
		}
		out.Devices++
		if d.Agent {
			out.WithAgent++
		}
		if !d.Approved {
			out.NotAdded++
		}
	}
	for _, f := range in.feeds {
		st := FeedState{ID: f.ID, Name: clip(f.Name, 80), Stale: f.Stale}
		if !f.LastOK.IsZero() {
			at := ts(f.LastOK)
			st.LastOKAt = &at
		}
		out.Feeds = append(out.Feeds, st)
	}
	return out
}
