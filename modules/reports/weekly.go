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

// buildWeekly computes the weekly report (INV-1) at in.now. No AI text is in it.
func buildWeekly(in weeklyInput) WeeklyReport {
	now, from := in.now.UTC(), in.now.UTC().Add(-7*day)
	inWeek := func(t time.Time) bool { return !t.IsZero() && t.After(from) && !t.After(now) }
	names := make(map[string]string, len(in.devices))
	noDevice := map[string]bool{}
	for _, d := range in.devices {
		names[d.ID] = clip(d.Name, 80)
		noDevice[d.ID] = d.NoDevice
	}
	products := make(map[string]string, len(in.kev))
	for _, k := range in.kev {
		name := k.Display // the name Findings shows (D-485)
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
		return FindingRow{ID: f.ID, CVE: clip(f.CVE, 40), Device: dev, AssetID: f.AssetID, Product: prod, Status: status, Severity: f.Severity, Since: ts(f.FirstSeen), noDevice: noDevice[f.AssetID]}
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
	var openConfirmed, openSuspected, accepted int
	var acceptedUntil time.Time
	for _, f := range in.findings {
		if f.FirstSeen.After(now) {
			continue
		}
		if inWeek(f.FirstSeen) {
			newRows = append(newRows, row(f, f.Status))
		}
		if inWeek(f.ResolvedAt) && f.Status == "risk_accepted" { // not resolved: it comes back by itself (D-498)
			accepted++
			if acceptedUntil.IsZero() || (!f.AcceptedUntil.IsZero() && f.AcceptedUntil.Before(acceptedUntil)) {
				acceptedUntil = f.AcceptedUntil
			}
		} else if inWeek(f.ResolvedAt) {
			r := row(f, f.Status)
			r.By = clip(f.ResolvedBy, 80)
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
	newRows, resolvedRows, openRows = capRows(order(newRows)), capRows(order(resolvedRows)), order(openRows)

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
	openRows = capRows(openRows)

	kevAt := in.kevAt
	if kevAt.IsZero() {
		kevAt = now
	}
	sources := []Source{{ID: "inventory", At: ts(now)}, {ID: "findings", At: ts(now)}, {ID: "kev", At: ts(kevAt)}}
	for _, f := range in.findings { // VulnCheck KEV is named among the sources when a finding of the report comes from it (D-557)
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
			Devices: len(in.devices), DevicesUnapprove: unapproved, DevicesNew: devicesNew, KevNew: in.kevNew, KevMatched: in.kevInUse},
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
