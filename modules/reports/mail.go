package reports

import (
	"fmt"
	"strings"
	"time"
)

// maxMailHandled is how many handled lines the email lists; the page has them all.
const maxMailHandled = 10

var statusLabels = map[string]string{
	"under_attack": "Under attack here", "exploited": "Exploited in the wild", "public_exploit": "Public exploit available",
	"critical_edge": "Critical on an edge device", "update_recommended": "Update recommended",
	"patched": "Patched", "mitigated": "Mitigated", "accepted": "Risk accepted", "not_relevant": "Not relevant", "false_positive": "False positive",
}

var howLabels = map[string]string{
	"distro_fixed": "the distribution's package is fixed", "scan_clear": "the safe check came back clear",
	"data_corrected": "the match was corrected", "not_installed": "the software is not installed",
}

func dayMonth(at string) string {
	t := parseTS(at)
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2 Jan")
}

// HandledLine is who handled a finding and how, from the stored fields, in the words the pages use: "Patched by Vedette: version moved
// 6.24 → 7.23 (18 Nov)", "Patched by Vedette: WinRAR was removed (18 Nov)", "Mitigated by ana@example.com (17 Nov): firewall rule".
func HandledLine(h Handled, software string) string {
	status := statusLabels[h.Resolution]
	if h.Resolution == "accepted" && h.AcceptedUntil != nil {
		status = "Risk accepted until " + *h.AcceptedUntil
	}
	by := h.By
	if by == "system" {
		by = "Vedette"
	}
	var how string
	switch h.Via {
	case "person":
	case "version_moved":
		how = fmt.Sprintf("version moved %s → %s", deref(h.FromVersion, "?"), deref(h.ToVersion, "?"))
	case "software_removed":
		how = "the software was removed"
		if software != "" {
			how = software + " was removed"
		}
	default:
		how = howLabels[h.Via]
	}
	line := fmt.Sprintf("%s by %s (%s)", status, by, dayMonth(h.At))
	if how != "" {
		line = fmt.Sprintf("%s by %s: %s (%s)", status, by, how, dayMonth(h.At))
	}
	if h.Note != nil && *h.Note != "" {
		line += ": " + clip(*h.Note, 200)
	}
	return line
}

func deref(s *string, or string) string {
	if s == nil || *s == "" {
		return or
	}
	return *s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// firstLine is one of the things to do first, as a sentence: what, where and the fix.
func firstLine(f FirstThing) string {
	where := ""
	if len(f.Devices) > 0 {
		where = " on " + f.Devices[0].Name
		if f.DeviceCount > 1 {
			where += fmt.Sprintf(" and %s", plural(f.DeviceCount-1, "more device", "more devices"))
		}
	}
	fix := ""
	switch {
	case f.Fix.Version != nil && (f.Fix.Kind == "update" || f.Fix.Kind == "distro_update" || f.Fix.Kind == "feature_update"):
		fix = ": update to " + *f.Fix.Version
	case f.Fix.Kind == "os_update" && f.Fix.Ref != nil:
		fix = ": install " + *f.Fix.Ref
	case f.Fix.Kind == "none_yet":
		fix = ": no fix is published yet; follow the vendor advisory"
	}
	return fmt.Sprintf("%s: %s in %s%s%s", statusLabels[f.Status], f.CVE, f.Product, where, fix)
}

// digest is the email of a document: what to do first, what was handled with who and how, and the figures, with a link to the
// sent document. Names come from the network; buildDocument cleaned them and notify cleans them again.
func digest(d Document, sentID string) Mail {
	m := Mail{Path: "/reports/sent/" + sentID}
	from, to := parseTS(d.Period.From), parseTS(d.Period.To)
	period := fmt.Sprintf("%s to %s", from.UTC().Format("2 Jan"), to.Add(-time.Millisecond).UTC().Format("2 Jan 2006"))
	m.Title = fmt.Sprintf("%s, %s", d.Title, period)
	var what, items []string
	if s := d.Summary; s != nil {
		m.Title = fmt.Sprintf("%s: %d open, %d handled (%s)", d.Title, s.OpenNow, s.Handled, period)
		what = append(what, fmt.Sprintf("Open now: %d (%d at the start of the period). New: %d. Handled: %d.", s.OpenNow, s.OpenBefore, s.New, s.Handled))
		var parts []string
		for _, c := range s.OpenByStatus {
			parts = append(parts, fmt.Sprintf("%s: %d", statusLabels[c.Status], c.N))
		}
		if len(parts) > 0 {
			what = append(what, strings.Join(parts, ", ")+".")
		}
		for i, f := range s.First {
			if i == 0 {
				m.Action = "Do first: " + firstLine(f)
				continue
			}
			items = append(items, firstLine(f))
		}
	}
	if h := d.Handled; h != nil {
		n := 0
		for _, dev := range h.Devices {
			for _, it := range dev.Items {
				if n == maxMailHandled {
					break
				}
				items = append(items, fmt.Sprintf("%s on %s: %s", it.Product, dev.Device.Name, HandledLine(it.Handled, it.Product)))
				n++
			}
		}
		if total := countHandled(h); total > n {
			items = append(items, fmt.Sprintf("%s more on the report page.", plural(total-n, "handled finding", "handled findings")))
		}
	}
	if x := d.Detections; x != nil && x.ModuleOn {
		n := 0
		for _, k := range x.ByKind {
			n += k.N
		}
		what = append(what, fmt.Sprintf("Detections: %s.", plural(n, "incident", "incidents")))
	}
	if len(what) == 0 {
		what = append(what, "The report is on the page linked below.")
	}
	m.What, m.Items = strings.Join(what, "\n"), items
	return m
}

func countHandled(h *ReportHandled) int {
	n := 0
	for _, t := range h.Totals {
		n += t.N
	}
	return n
}
