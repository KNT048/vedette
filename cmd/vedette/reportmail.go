package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify/channel"
	"github.com/knt048/vedette/modules/reports"
)

// The periodic report as an email: the document the reports module made, section by section in the words of the report page
// (web/src/features/reports/SecurityReport.tsx, locales/en/reports.json), as a channel.Doc that the email channel sends as HTML with a
// plain-text alternative. Every value is data: the channel cleans, cuts and escapes it.

// reportOpenLayer is the urgency layer of an open status of the report (findings' status ids).
var reportOpenLayer = map[string]int{"under_attack": findings.UrgencyUnderAttack, "exploited": findings.UrgencyExploited,
	"public_exploit": findings.UrgencyPublicExploit, "critical_edge": findings.UrgencyCriticalEdge, "update_recommended": findings.UrgencyUpdate}

var reportHandledStatus = map[string]string{"patched": "Patched", "mitigated": "Mitigated", "accepted": "Risk accepted",
	"not_relevant": "Not relevant", "false_positive": "False positive"}

// reportStatus is the badge of a status as the pages name it.
func reportStatus(s string) string {
	if l, ok := reportOpenLayer[s]; ok {
		return findings.StatusName(l)
	}
	if n, ok := reportHandledStatus[s]; ok {
		return n
	}
	return s
}

// reportReasons is the reasons line of a listed finding, built by findings' own ReasonsLine from the reasons the document keeps.
func reportReasons(rs []reports.Reason) string {
	var v findings.View
	for _, r := range rs {
		since, err := time.Parse(time.DateOnly, r.Date)
		if err != nil {
			continue
		}
		vr := findings.ViewReason{Reason: findings.Reason{Layer: r.Layer, Source: r.Source, Since: since}, Name: r.Name}
		if r.Detail != nil {
			vr.Detail = *r.Detail
		}
		if r.Due != nil {
			vr.Due = *r.Due
		}
		v.Reasons = append(v.Reasons, vr)
	}
	return v.ReasonsLine()
}

// reportVerification is the second line under the status on every screen, in findings' words (View.VerificationLine, BasisWords).
func reportVerification(v reports.Verification) string {
	switch v.Verified {
	case "scan":
		return "Confirmed by a safe check"
	case "device":
		return "Confirmed: the device reports this version"
	case "person":
		if v.By != nil && *v.By != "" {
			return "Confirmed by " + *v.By
		}
		return "Confirmed by a person"
	}
	// findings' own words: a basis that is empty or unknown is read as a scan banner, as the finding's view (and so every screen) reads it
	return "Not confirmed yet: based on " + findings.BasisWords(findings.DetectionBasis(v.Basis))
}

func reportSeverity(c *reports.CveSeverity) string {
	if c == nil {
		return "Not scored yet"
	}
	band := c.Band
	if band != "" {
		band = strings.ToUpper(band[:1]) + band[1:]
	}
	return strings.TrimSpace(band + " " + strconv.FormatFloat(c.Score, 'f', 1, 64))
}

// reportFix is the fix line of the report page and the finding page (web findings fixLine, useFixTitle), from being the listed
// finding's own version ("" when the line names no device's version).
func reportFix(f reports.Fix, from string) string {
	to, ref := reportText(f.Version), reportText(f.Ref)
	switch f.Kind {
	case "update":
		switch {
		case to == "":
			return "Update " + f.Product + " to a fixed release"
		case from != "":
			return "Update " + f.Product + " " + from + " → " + to
		}
		return "Update " + f.Product + " to " + to
	case "distro_update":
		if to != "" {
			return "Install the " + f.Product + " package " + to + " or later"
		}
		return "Install the distribution's security updates for " + f.Product
	case "os_update":
		switch {
		case ref != "":
			return "Install " + ref + " on " + f.Product
		case to != "":
			return "Update " + f.Product + " to build " + to
		}
		return "Install the latest cumulative update on " + f.Product
	case "feature_update":
		if to != "" {
			return "Move " + f.Product + " to release " + to
		}
		return "Move " + f.Product + " to a later release"
	case "none_yet":
		return "No fix known yet for " + f.Product
	}
	return "No fix data for " + f.Product
}

func reportDevice(d reports.DeviceRef) string {
	if !d.Added {
		return d.Name + " (not added yet)"
	}
	return d.Name
}

func reportDay(at string, loc *time.Location) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return ""
	}
	return orgtime.Day(t, loc)
}

func reportPlural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// reportFindingRow is one finding of Still open or New: the same badge, reasons line and verification line as the finding page.
func reportFindingRow(f reports.ReportFinding, loc *time.Location, withDevice bool) []string {
	product := f.Product
	if f.Version != nil && *f.Version != "" {
		product += " " + *f.Version
	}
	row := []string{f.CVE + " · " + product}
	if withDevice {
		row = append(row, reportDevice(f.Device))
	}
	return append(row, reportStatus(f.Status), reportReasons(f.Reasons), reportVerification(f.Verification), reportSeverity(f.Severity), reportFix(f.Fix, reportText(f.Version)),
		reportDay(f.FirstSeen, loc))
}

// reportFindingHead is the head of a findings table: the status badge, the reasons line and the verification line of every screen.
var reportFindingHead = []string{"Finding", "Status", "Why", "How Vedette knows", "Severity", "Fix", "First seen"}

// reportMailDoc renders a report document for the email channel; link is added by the channel (the sent report's page).
func reportMailDoc(d reports.Document) *channel.Doc {
	loc := time.UTC
	if l, err := time.LoadLocation(d.Period.TZ); err == nil && d.Period.TZ != "" {
		loc = l
	}
	from, _ := time.Parse(time.RFC3339Nano, d.Period.From)
	to, _ := time.Parse(time.RFC3339Nano, d.Period.To)
	doc := &channel.Doc{Heading: d.Title}
	period := fmt.Sprintf("%s – %s", orgtime.Day(from, loc), orgtime.Day(to.Add(-time.Millisecond), loc))
	if d.Org != "" {
		period = d.Org + " · " + period
	}
	doc.Intro = append(doc.Intro, period)
	if gen, err := time.Parse(time.RFC3339Nano, d.GeneratedAt); err == nil {
		doc.Footer = fmt.Sprintf("Made by Vedette %s (%s).", orgtime.Stamp(gen, loc), loc.String())
	}
	if a := d.AISummary; a != nil && len(a.Paragraphs) > 0 {
		doc.Sections = append(doc.Sections, channel.DocSection{Title: "Commentary", Paragraphs: a.Paragraphs})
	}
	if s := d.Summary; s != nil {
		sec := channel.DocSection{Title: "Summary"}
		sec.Paragraphs = append(sec.Paragraphs, reports.FlowLine(*s))
		if h := d.Handled; h != nil && h.MedianDays != nil {
			sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("Median days to fix: %s.", strconv.FormatFloat(*h.MedianDays, 'f', -1, 64)))
		}
		if len(s.OpenByStatus) > 0 {
			t := channel.DocTable{Caption: "Open findings by status", Head: []string{"Status", "Findings"}}
			for _, c := range s.OpenByStatus {
				t.Rows = append(t.Rows, []string{reportStatus(c.Status), strconv.Itoa(c.N)})
			}
			sec.Tables = append(sec.Tables, t)
		}
		if len(s.First) == 0 {
			sec.Paragraphs = append(sec.Paragraphs, "Do these first: nothing urgent is open.")
		} else {
			t := channel.DocTable{Caption: "Do these first", Head: []string{"Status", "Finding", "Devices", "Fix"}}
			for _, f := range s.First {
				var names []string
				for _, dv := range f.Devices {
					names = append(names, reportDevice(dv))
				}
				on := strings.Join(names, ", ")
				if more := f.DeviceCount - len(f.Devices); more > 0 {
					on += fmt.Sprintf(" and %s", reportPlural(more, "more device", "more devices"))
				}
				t.Rows = append(t.Rows, []string{reportStatus(f.Status), f.CVE + " · " + f.Product, on, reportFix(f.Fix, "")})
			}
			sec.Tables = append(sec.Tables, t)
		}
		doc.Sections = append(doc.Sections, sec)
	}
	if h := d.Handled; h != nil {
		sec := channel.DocSection{Title: "Handled this period"}
		n := 0
		t := channel.DocTable{Head: []string{"Device", "Finding", "Handled"}}
		for _, dv := range h.Devices {
			for _, it := range dv.Items {
				n++
				t.Rows = append(t.Rows, []string{reportDevice(dv.Device), it.CVE + " · " + it.Product, reports.ItemLine(it, loc)})
			}
		}
		if n == 0 {
			sec.Paragraphs = append(sec.Paragraphs, "Nothing was handled in this period.")
		}
		sec.Tables = append(sec.Tables, t)
		if h.NotRelevantLeftOut > 0 {
			sec.Paragraphs = append(sec.Paragraphs, reportPlural(h.NotRelevantLeftOut, "finding closed as not relevant in this period is left out (Settings: Include not relevant).",
				"findings closed as not relevant in this period are left out (Settings: Include not relevant)."))
		}
		if h.More > 0 {
			sec.More = reportPlural(h.More, "more handled finding is not listed.", "more handled findings are not listed.")
		}
		doc.Sections = append(doc.Sections, sec)
	}
	if o := d.Open; o != nil {
		sec := channel.DocSection{Title: "Still open"}
		if o.Total == 0 {
			sec.Paragraphs = append(sec.Paragraphs, "No finding is open.")
		}
		byDevice := o.Grouping != "cve"
		for _, g := range o.Groups {
			t := channel.DocTable{Caption: g.Label + " · " + reportPlural(len(g.Items), "finding", "findings"), Head: reportFindingHead}
			if !byDevice { // grouped by CVE: each row names its device
				t.Head = append([]string{"Finding", "Device"}, reportFindingHead[1:]...)
			}
			for _, f := range g.Items {
				t.Rows = append(t.Rows, reportFindingRow(f, loc, !byDevice))
			}
			sec.Tables = append(sec.Tables, t)
		}
		if o.More > 0 {
			sec.More = reportPlural(o.More, "more open finding is not listed.", "more open findings are not listed.")
		}
		doc.Sections = append(doc.Sections, sec)
	}
	if nw := d.New; nw != nil {
		sec := channel.DocSection{Title: "New this period"}
		if nw.Total == 0 {
			sec.Paragraphs = append(sec.Paragraphs, "No new finding in this period.")
		}
		t := channel.DocTable{Head: append([]string{"Finding", "Device"}, reportFindingHead[1:]...)}
		for _, f := range nw.Items {
			t.Rows = append(t.Rows, reportFindingRow(f, loc, true))
		}
		sec.Tables = append(sec.Tables, t)
		if nw.More > 0 {
			sec.More = reportPlural(nw.More, "more new finding is not listed.", "more new findings are not listed.")
		}
		doc.Sections = append(doc.Sections, sec)
	}
	if x := d.Exposure; x != nil {
		doc.Sections = append(doc.Sections, reportExposureSection(x, loc))
	}
	if x := d.Detections; x != nil {
		doc.Sections = append(doc.Sections, reportDetectionsSection(x, loc))
	}
	if c := d.Coverage; c != nil {
		doc.Sections = append(doc.Sections, reportCoverageSection(c, loc))
	}
	return doc
}

var reportProof = map[string]string{"proven": "Ownership proved", "covered": "Covered by its domain", "missing": "No ownership proof",
	"expired": "Proof expired", "not_current": "Proof not checked lately"}

func reportExposureSection(x *reports.ReportExposure, loc *time.Location) channel.DocSection {
	sec := channel.DocSection{Title: "External exposure"}
	switch {
	case !x.ModuleOn:
		sec.Paragraphs = append(sec.Paragraphs, "External exposure scanning is off, so this report does not cover what the Internet sees.")
		return sec
	case len(x.Targets) == 0:
		sec.Paragraphs = append(sec.Paragraphs, "No external target is set up yet.")
		return sec
	}
	targets := channel.DocTable{Head: []string{"Target", "Proof", "Last scan", "Open ports", "Open issues"}}
	ports := channel.DocTable{Caption: "Ports", Head: []string{"Target", "Port", "Service", "Software", "Change", "Certificate"}}
	for _, t := range x.Targets {
		name := t.Value
		if t.Parent != nil && *t.Parent != "" {
			name += " (under " + *t.Parent + ")"
		}
		scan := "Not scanned yet"
		if t.LastScanAt != nil {
			scan = reportDay(*t.LastScanAt, loc)
		}
		open := 0
		for _, s := range t.Services {
			if s.Change == nil || *s.Change != "closed" {
				open++
			}
			change := ""
			if s.Change != nil {
				change = map[string]string{"new": "Opened", "closed": "Closed"}[*s.Change]
			}
			cert := ""
			if s.CertExpiresAt != nil {
				cert = "Until " + reportDay(*s.CertExpiresAt, loc)
			}
			soft := strings.TrimSpace(reportText(s.Product) + " " + reportText(s.Version))
			ports.Rows = append(ports.Rows, []string{t.Value, fmt.Sprintf("%s %d/%s", s.IP, s.Port, s.Proto), reportText(s.Name), soft, change, cert})
		}
		var issues []string
		for _, is := range t.Issues {
			line := fmt.Sprintf("%d %s (%s)", is.Open, is.Severity, is.Engine)
			if is.New > 0 {
				line += fmt.Sprintf(", %d new", is.New)
			}
			issues = append(issues, line)
		}
		if len(issues) == 0 {
			issues = []string{"No open issue"}
		}
		proof := reportProof[t.Proof]
		if proof == "" {
			proof = t.Proof
		}
		portsCell := reportPlural(open, "open port", "open ports")
		if t.LastScanAt == nil && open == 0 && len(t.Issues) == 0 { // nothing was checked: no count to claim
			portsCell, issues = "–", []string{"–"}
		}
		targets.Rows = append(targets.Rows, []string{name, proof, scan, portsCell, strings.Join(issues, "; ")})
	}
	sec.Tables = append(sec.Tables, targets, ports)
	return sec
}

func reportText(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var reportDetectionKind = map[string]string{"trap": "Trap touched", "bad_address": "Known bad address", "log_anomaly": "Unusual log activity",
	"unknown_device": "Unknown device", "intrusion": "Intrusion attempt"}

func reportKind(k string) string {
	if n, ok := reportDetectionKind[k]; ok {
		return n
	}
	return k
}

func reportDetectionsSection(x *reports.ReportDetections, loc *time.Location) channel.DocSection {
	sec := channel.DocSection{Title: "Detections"}
	if !x.ModuleOn {
		sec.Paragraphs = append(sec.Paragraphs, "Detection is off, so this report does not cover attacks on your network.")
		return sec
	}
	if len(x.ByKind) == 0 {
		sec.Paragraphs = append(sec.Paragraphs, "Nothing was detected in this period.")
		return sec
	}
	kinds := channel.DocTable{Head: []string{"What", "Times", "Last"}}
	for _, k := range x.ByKind {
		kinds.Rows = append(kinds.Rows, []string{reportKind(k.Kind), strconv.Itoa(k.N), reportDay(k.LastAt, loc)})
	}
	sec.Tables = append(sec.Tables, kinds)
	if len(x.Top) > 0 {
		top := channel.DocTable{Caption: "Notable", Head: []string{"What", "Severity", "Device", "When"}}
		for _, t := range x.Top {
			dev := ""
			if t.Device != nil {
				dev = reportDevice(*t.Device)
			}
			if t.DeviceCount > 1 { // one device's name would read as the only one
				dev = fmt.Sprintf("%d devices", t.DeviceCount)
			}
			top.Rows = append(top.Rows, []string{reportKind(t.Kind) + ": " + t.Title, t.Severity, dev, reportDay(t.At, loc)})
		}
		sec.Tables = append(sec.Tables, top)
	}
	return sec
}

var reportSource = map[string]string{"sensor-passive": "Network listening", "sensor-active": "Network scans", "agent-intake": "Device agents",
	"honeypot": "Traps", "logs": "Logs", "exposure": "External exposure", "ids": "Intrusion detection"}

func reportCoverageSection(c *reports.ReportCoverage, loc *time.Location) channel.DocSection {
	sec := channel.DocSection{Title: "Coverage"}
	sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("Devices: %d. With an agent: %d of %d. Not added yet: %d.", c.Devices, c.WithAgent, c.Devices, c.NotAdded))
	if no := c.Devices - c.WithAgent; no > 0 {
		sec.Paragraphs = append(sec.Paragraphs, reportPlural(no, "device has no agent: Vedette knows its software only from scans.",
			"devices have no agent: Vedette knows their software only from scans."))
	}
	src := channel.DocTable{Caption: "What Vedette watches", Head: []string{"Source", "State"}}
	for _, s := range c.Sources {
		state := "Off"
		if s.On {
			state = "On"
		}
		name := reportSource[s.ID]
		if name == "" {
			name = s.ID
		}
		src.Rows = append(src.Rows, []string{name, state})
	}
	feeds := channel.DocTable{Caption: "Vulnerability data", Head: []string{"Source", "State"}}
	for _, f := range c.Feeds {
		state := "Never updated"
		if f.LastOKAt != nil {
			state = "Updated " + reportDay(*f.LastOKAt, loc)
			if f.Stale {
				state = "Out of date: last update " + reportDay(*f.LastOKAt, loc)
			}
		}
		feeds.Rows = append(feeds.Rows, []string{f.Name, state})
	}
	sec.Tables = append(sec.Tables, src, feeds)
	return sec
}
