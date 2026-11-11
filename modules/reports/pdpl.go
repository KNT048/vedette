package reports

import (
	"sort"
	"time"
)

// The law behind the assessment (checked against the official text on 2026-11-06, D-23): Law 91/2025/QH15 on personal data
// protection and Decree 356/2025/NĐ-CP. Article 41 of the decree decides which enterprises are exempt from, or may choose to do,
// what Articles 21, 22 and 33(2) of the law require.

// Regime is how the impact-assessment and data-protection-officer duties apply to the organisation (INV-6): required, optional
// or exempt. It is computed, never decided by the AI.
func Regime(o PdplOrg) string {
	if o.ProcessingService || o.Sensitive || o.DataVolume == "gte100k" {
		return "required"
	}
	switch o.Size {
	case "household", "micro":
		return "exempt"
	case "small", "startup":
		return "optional"
	}
	return "required"
}

type pdplInput struct {
	devices  []Device
	findings []Finding
	kev      []KEVEntry
	modules  Modules
	org      PdplOrg
	id       string
	now      time.Time
}

// buildPdpl computes the self-assessment from what the box sees. It says what is seen and never that the organisation complies
// (FORBID-3): a measure without data is unknown, and duties that need a person stay done=null.
func buildPdpl(in pdplInput) PdplReport {
	var unapproved, fragile int
	var eol, rdp, unapprovedNames []string
	kinds := map[string]int{}
	srcs := map[string]int{}
	hasFirewall := false
	for _, d := range in.devices {
		name := clip(d.Name, 80)
		kinds[d.Kind]++
		for _, s := range d.Sources {
			srcs[s]++
		}
		if !d.Approved {
			unapproved++
			unapprovedNames = append(unapprovedNames, name)
		}
		if d.Fragile {
			fragile++
		}
		if d.Kind == "firewall" {
			hasFirewall = true
		}
		if eolOS.MatchString(d.OS) {
			eol = append(eol, name)
		}
		for _, p := range d.Ports {
			if p == 3389 {
				rdp = append(rdp, name)
				break
			}
		}
	}
	w := buildWeekly(weeklyInput{devices: in.devices, findings: in.findings, kev: in.kev, now: in.now})
	var risks []FindingRow
	var cves []string
	for _, f := range in.findings {
		if (f.Status == "confirmed" || f.Status == "suspected") && !f.FirstSeen.After(in.now) {
			cves = append(cves, clip(f.CVE, 40))
		}
	}
	risks = w.Open // already ordered and capped

	m := func(id, status string, list []string) Measure {
		n := len(list)
		if len(list) > 4 {
			list = list[:4]
		}
		return Measure{ID: id, Status: status, N: n, Names: nonNilS(list)}
	}
	onOrUnknown := func(mod string) string {
		if in.modules != nil && in.modules.Enabled(mod) {
			return "ok"
		}
		return "unknown"
	}
	fw := "attention"
	if hasFirewall {
		fw = "ok"
	}
	// Something found is "attention" whatever the sources; "nothing found" is "ok" only when the box could look: with no devices, or
	// with the module that supplies the data off, nothing found means nothing seen (INV-8, D-237).
	seen := func(list []string, needs ...string) string {
		if len(list) > 0 {
			return "attention"
		}
		if len(in.devices) == 0 || in.modules == nil {
			return "unknown"
		}
		for _, mod := range needs {
			if !in.modules.Enabled(mod) {
				return "unknown"
			}
		}
		return "ok"
	}
	if !hasFirewall && len(in.devices) == 0 {
		fw = "unknown"
	}
	measures := []Measure{
		m("firewall", fw, nil),
		m("patching", seen(cves, "feeds"), cves),
		m("eol", seen(eol), eol),
		m("unapproved", seen(unapprovedNames), unapprovedNames),
		m("remote", seen(rdp, "scan"), rdp),
		m("logging", onOrUnknown("logs"), nil),
		m("honeypot", onOrUnknown("honeypot"), nil),
		m("scan", onOrUnknown("scan"), nil),
		m("backup", "unknown", nil), // the box cannot see backups
	}

	regime := Regime(in.org)
	dpoDone := in.org.ContactName != "" && in.org.ContactEmail != ""
	obligations := []Obligation{
		{ID: "dpia", Applies: true, Regime: regime},
		{ID: "dpo", Applies: true, Regime: regime, Done: &dpoDone},
		{ID: "breach", Applies: true, Regime: "required"},
		{ID: "consent", Applies: true, Regime: "required"},
		{ID: "sensitive", Applies: in.org.Sensitive, Regime: "required"},
		{ID: "cross_border", Applies: in.org.CrossBorder, Regime: "required"},
		{ID: "processors", Applies: in.org.Processors, Regime: "required"},
	}

	byKind := make([]KindCount, 0, len(kinds))
	for k, n := range kinds {
		byKind = append(byKind, KindCount{Kind: k, N: n})
	}
	sort.Slice(byKind, func(i, j int) bool {
		if byKind[i].N != byKind[j].N {
			return byKind[i].N > byKind[j].N
		}
		return byKind[i].Kind < byKind[j].Kind
	})
	sources := make([]SourceCount, 0, len(srcs))
	for s, n := range srcs {
		sources = append(sources, SourceCount{Source: s, N: n})
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].N != sources[j].N {
			return sources[i].N > sources[j].N
		}
		return sources[i].Source < sources[j].Source
	})
	key := []KeySystem{}
	for _, d := range in.devices {
		if (d.Kind == "server" || d.Kind == "nas" || d.Kind == "firewall") && len(key) < 50 {
			os := "–"
			if d.OS != "" {
				os = clip(d.OS, 80)
			}
			key = append(key, KeySystem{ID: d.ID, Name: clip(d.Name, 80), IP: clip(d.IP, 45), Kind: d.Kind, OS: os})
		}
	}
	cov := []Coverage{}
	for _, mod := range []string{"inventory", "scan", "logs", "honeypot", "exposure"} {
		cov = append(cov, Coverage{Module: mod, On: in.modules != nil && in.modules.Enabled(mod)})
	}
	return PdplReport{
		ID: in.id, GeneratedAt: ts(in.now), Org: in.org,
		Inventory: PdplInventory{Total: len(in.devices), Approved: len(in.devices) - unapproved, Unapproved: unapproved, Fragile: fragile,
			ByKind: byKind, KeySystems: key, Sources: sources},
		Measures: measures, Risks: risks, Obligations: obligations, Coverage: cov,
	}
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
