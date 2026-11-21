package reports

import (
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxRows caps each list of a report. The counts are of everything; a report of a very large estate stays one page and bounded.
const MaxRows = 100

const day = 24 * time.Hour

// tsLayout is the one time format of the API and the database: UTC, milliseconds.
const tsLayout = "2006-01-02T15:04:05.000Z"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

var eolOS = regexp.MustCompile(`(?i)windows 10|server 2016`)

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// clip cleans text that came from the network (a device name, a product) for a report: control and bidirectional characters out,
// one line, bounded. Every renderer still escapes it (the print page is React; the email goes through notify's cleaner).
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

// weeklyInput is everything BuildWeekly reads, already fetched.
type weeklyInput struct {
	devices  []Device
	findings []Finding
	kev      []KEVEntry
	kevAt    time.Time
	kevNew   int // KEV.NewlyExploited: the Home headline
	kevInUse int
	now      time.Time

	fixes       map[string]Fix                    // by finding id; nil = none known
	fixesFor    func(fs []Finding) map[string]Fix // reads the fixes of the findings it is given (Service.fill); asked only for the top products
	week        IncidentWeek
	incidentsOn bool // notify answered: the report has a "what happened" section even when it is empty
}

// buildWeekly computes the weekly report (INV-1) at in.now, with its ApprovedOnly view: the same figures over the approved devices
// and their findings, for a reader who leaves the devices not in the Devices list out. No AI text is in it.
func buildWeekly(in weeklyInput) WeeklyReport {
	r := computeWeekly(in)
	a := r
	if r.Counts.DevicesUnapprove > 0 { // otherwise the view is the report itself: no second read of the fixes
		a = computeWeekly(approvedOnly(in))
	}
	r.ApprovedOnly = &WeeklyView{Counts: a.Counts, TopRisks: a.TopRisks, Actions: a.Actions}
	return r
}

// approvedOnly is in without the devices not approved yet and their findings (a finding whose device is unknown stays, as its row
// says approved). The incidents are not device data: the view does not carry them.
func approvedOnly(in weeklyInput) weeklyInput {
	out := in
	out.devices, out.findings = nil, nil
	out.incidentsOn = false
	left := map[string]bool{}
	for _, d := range in.devices {
		if d.Approved {
			out.devices = append(out.devices, d)
		} else {
			left[d.ID] = true
		}
	}
	for _, f := range in.findings {
		if !left[f.AssetID] {
			out.findings = append(out.findings, f)
		}
	}
	// kevInUse is Home's count of newly exploited products in use (feeds groups the last 7 days' KEV entries by key, as below). The
	// view takes off the products only devices not approved yet have; kevNew is about the list, not the devices, and stays.
	now, cutoff := in.now.UTC(), in.now.UTC().Add(-7*day)
	newKey := map[string]bool{}
	for _, k := range in.kev {
		if !k.DateAdded.Add(day-time.Second).Before(cutoff) && !k.DateAdded.After(now) {
			newKey[k.Key] = true
		}
	}
	onApproved, onLeft := map[string]bool{}, map[string]bool{}
	for _, d := range in.devices {
		for _, k := range d.KevKeys {
			if !newKey[k] {
				continue
			}
			if d.Approved {
				onApproved[k] = true
			} else {
				onLeft[k] = true
			}
		}
	}
	for k := range onLeft {
		if !onApproved[k] && out.kevInUse > 0 {
			out.kevInUse--
		}
	}
	return out
}

// capViews keeps, of rows already in report order, the first MaxRows of each view a reader can pick (all, approved devices only,
// not relevant left out, both): filtering a list cut for one view must not leave another view short (INV-11, INV-16). At most
// 4 × MaxRows rows; the reader cuts its view to MaxRows again.
func capViews(rows []FindingRow) []FindingRow {
	var all, appr, rel, both int
	out := rows[:0:0]
	for _, r := range rows {
		relevant := r.Status != "not_relevant"
		if all < MaxRows || (r.DeviceApproved && appr < MaxRows) || (relevant && rel < MaxRows) || (r.DeviceApproved && relevant && both < MaxRows) {
			out = append(out, r)
		}
		all++
		if r.DeviceApproved {
			appr++
		}
		if relevant {
			rel++
		}
		if r.DeviceApproved && relevant {
			both++
		}
	}
	return out
}

// computeWeekly computes the figures and lists of the weekly report over the devices and findings it is given.
func computeWeekly(in weeklyInput) WeeklyReport {
	now, from := in.now.UTC(), in.now.UTC().Add(-7*day)
	inWeek := func(t time.Time) bool { return !t.IsZero() && t.After(from) && !t.After(now) }
	names := make(map[string]string, len(in.devices))
	noDevice := map[string]bool{}
	unapprovedDev := map[string]bool{}
	for _, d := range in.devices {
		names[d.ID] = clip(d.Name, 80)
		noDevice[d.ID] = d.NoDevice
		unapprovedDev[d.ID] = !d.Approved
	}
	products := make(map[string]string, len(in.kev))
	for _, k := range in.kev {
		name := k.Display // the name Findings shows
		if name == "" {
			name = k.Vendor + " " + k.Product
		}
		products[k.CVE] = clip(name, 80)
	}
	row := func(f Finding, status string) FindingRow {
		dev, ok := names[f.AssetID]
		if !ok {
			dev = clip(f.AssetID, 80)
		}
		prod, ok := products[f.CVE]
		if !ok {
			prod = clip(f.CVE, 40)
		}
		return FindingRow{ID: f.ID, CVE: clip(f.CVE, 40), Device: dev, AssetID: f.AssetID, Product: prod, Status: status, Severity: f.Severity, Since: ts(f.FirstSeen), Agent: f.Agent, DeviceApproved: !unapprovedDev[f.AssetID], noDevice: noDevice[f.AssetID], notExploited: !f.Exploited()}
	}
	order := func(rows []FindingRow) []FindingRow {
		sort.SliceStable(rows, func(i, j int) bool {
			a, b := rows[i], rows[j]
			if severityRank[a.Severity] != severityRank[b.Severity] {
				return severityRank[a.Severity] < severityRank[b.Severity]
			}
			if a.Since != b.Since {
				return a.Since > b.Since
			}
			return a.ID < b.ID
		})
		return rows
	}
	var newRows, resolvedRows, openRows []FindingRow
	var openConfirmed, openSuspected, accepted, nr, nrNew, nrResolved int
	var acceptedUntil time.Time
	for _, f := range in.findings {
		if f.FirstSeen.After(now) {
			continue
		}
		if f.Status == "not_relevant" && (inWeek(f.FirstSeen) || inWeek(f.ResolvedAt)) {
			nr++
			if inWeek(f.FirstSeen) {
				nrNew++
			}
			if inWeek(f.ResolvedAt) {
				nrResolved++
			}
		}
		if inWeek(f.FirstSeen) {
			newRows = append(newRows, row(f, f.Status))
		}
		if inWeek(f.ResolvedAt) && f.Status == "risk_accepted" { // not resolved: it comes back by itself
			accepted++
			if acceptedUntil.IsZero() || (!f.AcceptedUntil.IsZero() && f.AcceptedUntil.Before(acceptedUntil)) {
				acceptedUntil = f.AcceptedUntil
			}
		} else if inWeek(f.ResolvedAt) {
			r := row(f, f.Status)
			r.By = clip(f.ResolvedBy, 80)
			if f.ResolvedBy == "system" { // Vedette's own close (a version proof, an update it saw): the line names it, not an account
				r.By = "Vedette"
			}
			resolvedRows = append(resolvedRows, r)
		}
		switch f.Status {
		case "confirmed":
			openConfirmed++
			openRows = append(openRows, row(f, "confirmed"))
		case "suspected":
			openSuspected++
			openRows = append(openRows, row(f, "suspected"))
		}
	}
	newN, resolvedN := len(newRows), len(resolvedRows)
	newRows, resolvedRows, openRows = capViews(order(newRows)), capViews(order(resolvedRows)), order(openRows)

	var unapproved, eol, devicesNew int
	for _, d := range in.devices {
		if !d.Approved {
			unapproved++
		}
		if eolOS.MatchString(d.OS) {
			eol++
		}
		if inWeek(d.FirstSeen) {
			devicesNew++
		}
	}

	fixes := in.fixes
	if fixes == nil && in.fixesFor != nil { // the release is read only for the products the page names, never for a whole large estate
		top, _ := topRisks(openRows, nil)
		named := map[string]bool{}
		for _, r := range top {
			named[r.Product] = true
		}
		byID := make(map[string]Finding, len(in.findings))
		for _, f := range in.findings {
			byID[f.ID] = f
		}
		devs := map[string]bool{} // every open finding of those devices: a phone's CVEs carry several product names and one release must clear them all
		for _, r := range openRows {
			if named[r.Product] {
				devs[r.AssetID] = true
			}
		}
		var ask []Finding
		for _, r := range openRows {
			if devs[r.AssetID] {
				ask = append(ask, byID[r.ID])
			}
		}
		fixes = in.fixesFor(ask)
	}
	risks, kinds := topRisks(openRows, fixes)
	var actions []ActionItem
	for i, r := range risks {
		actions = append(actions, ActionItem{Kind: kinds[i], CVE: r.CVE, Device: r.Device, FindingID: r.FindingID, Product: r.Product, Count: r.Open, Text: r.Action})
	}
	if unapproved > 0 {
		actions = append(actions, ActionItem{Kind: "review_devices", Count: unapproved})
	}
	if eol > 0 {
		actions = append(actions, ActionItem{Kind: "plan_os", Count: eol})
	}
	openRows = capViews(openRows)

	kevAt := in.kevAt
	if kevAt.IsZero() {
		kevAt = now
	}
	sources := []Source{{ID: "inventory", At: ts(now)}, {ID: "findings", At: ts(now)}, {ID: "kev", At: ts(kevAt)}}
	for _, f := range in.findings { // VulnCheck KEV is named among the sources when a finding of the report comes from it
		if f.Source == "vulncheck-kev" && (f.ResolvedAt.IsZero() || inWeek(f.ResolvedAt) || inWeek(f.FirstSeen)) {
			sources = append(sources, Source{ID: "vulncheck-kev", At: ts(kevAt)})
			break
		}
	}
	var happened *Happened
	if in.incidentsOn {
		happened = buildHappened(in.week)
		sources = append(sources, Source{ID: "incidents", At: ts(now)})
	}
	return WeeklyReport{
		Period: Period{From: ts(from), To: ts(now)}, GeneratedAt: ts(now),
		Counts: Counts{NewFindings: newN, Resolved: resolvedN, Accepted: accepted, AcceptedUntil: isoDay(acceptedUntil), OpenConfirmed: openConfirmed, OpenSuspected: openSuspected,
			Devices: len(in.devices), DevicesUnapprove: unapproved, DevicesNew: devicesNew, KevNew: in.kevNew, KevMatched: in.kevInUse,
			NotRelevant: nr, NotRelevantNew: nrNew, NotRelevantResolved: nrResolved},
		TopRisks: risks, NewFindings: nonNil(newRows), Resolved: nonNil(resolvedRows), Open: nonNil(openRows), Actions: nonNilA(actions),
		Happened: happened, Sources: sources,
	}
}

func capRows(r []FindingRow) []FindingRow {
	if len(r) > MaxRows {
		return r[:MaxRows]
	}
	return r
}

func nonNil(r []FindingRow) []FindingRow {
	if r == nil {
		return []FindingRow{}
	}
	return r
}

func nonNilA(a []ActionItem) []ActionItem {
	if a == nil {
		return []ActionItem{}
	}
	return a
}

// isoDay is t as YYYY-MM-DD, or "" when zero.
func isoDay(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.DateOnly)
}
