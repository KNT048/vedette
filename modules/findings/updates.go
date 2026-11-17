package findings

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// "What do I upgrade on this device to clear its CVEs" (J4 Ask my AI, kien G9; the Findings page and the device's Software tab, G8):
// one answer per device, built from the groupings the product already shows. The open exploited findings are grouped by the update
// that fixes them (RowFixes, the FindingRow.fix of D-545), and the device's "Updates to plan" items (PlanItem, D-617) are listed as the
// plan job last compared them. Nothing is stored; it is read when asked.

// How a finding's CVE is known on the device (G9), mapped from what the finding stores (basis, evidence.agent, evidence.agent_row)
// and the source of the software row it is on. Never "needs confirming" for a version the device itself reported.
const (
	// ProofConfirmed: a safe scan proved it (basis scan).
	ProofConfirmed = "confirmed"
	// ProofDetected: the device itself reported the installed version: its agent (osquery, Wazuh, the box's package list:
	// evidence.agent or evidence.agent_row, D-548, D-612), or a version the plan also trusts (tierSource: a person's entry, the
	// device's SNMP answer, the OS the device states), and that version is inside the affected range.
	ProofDetected = "detected"
	// ProofSuspected: a network guess: a version read from a banner or a fingerprint, or the product name only.
	ProofSuspected = "suspected"
)

// UpdateAction is one update on one device: what to install and what it clears.
type UpdateAction struct {
	// Group is the key the pages already use: RowFix.Group for an exploited update, PlanItem.Group for a planned one,
	// "<device id>/<software id>" for findings no update is named for ("<device id>/" when no software row matches any more).
	Group string
	// SoftwareID is the device's software row the action is about ("" when none matches), so the Software tab can show it on the
	// row (G8); Software and Version are that row's display name and installed version.
	SoftwareID string
	Software   string
	Version    string
	// Fixed is the release or build to install ("" for a distribution's updates without a version, and for no named update).
	Fixed string
	// Kind: exploited: RowFix.Kind (fixed, esu, feature_update, distro); planned: PlanItem.Kind (fixed, windows, esu, distro);
	// "none" for findings no update is named for.
	Kind    string
	Windows bool   // a Windows release row: the update is the monthly cumulative update
	Distro  string // distro: "Ubuntu" or "Debian", "" for the distribution's
	Pro     bool   // distro: a fix is in Ubuntu Pro (ESM) only
	// Action is the sentence the pages use ("Upgrade Mozilla Firefox from 115.0 to 128.1 or later").
	Action string
	// CVEs are the CVEs the update clears, worst first; FindingIDs the open findings of them in the same order (exploited only).
	CVEs       []string
	FindingIDs []string
	// Worst is the highest severity among them: the finding's (critical, high, medium, low) for exploited ones, NVD's CVSS
	// severity in lower case for planned ones ("" when NVD scored none).
	Worst string
	// Ransomware counts the exploited CVEs known to be used in ransomware; Likely the planned CVEs whose EPSS says they are
	// likely to be exploited soon.
	Ransomware, Likely int
	// How each exploited finding is known (Proof*); zero for planned ones (every plan CVE is compared on a trusted version).
	Confirmed, Detected, Suspected int
}

// DeviceUpdates is the answer for one device.
type DeviceUpdates struct {
	AssetID string
	Open    int // open (confirmed or suspected) findings of the device
	// Exploited: open findings one named update fixes, one action per update, worst first.
	Exploited []UpdateAction
	// NoUpdate: open findings no update is named for (a product-only match, NVD names no release that clears them, the CVE left
	// the list), one action per software row, worst first: the vendor's advice decides.
	NoUpdate []UpdateAction
	// Planned: the device's "Updates to plan" items (CVEs on no exploited list), as GET /findings/plan lists them.
	Planned []UpdateAction
	PlanRan bool // the plan job compared the devices since the start; false: Planned is not known yet
}

// DeviceUpdates returns what to install on one device to clear its CVEs. ok is false when the device does not exist.
func (s *Service) DeviceUpdates(ctx context.Context, assetID string) (DeviceUpdates, bool, error) {
	a, ok, err := s.cfg.Inventory.MatchInput(ctx, assetID)
	if err != nil {
		return DeviceUpdates{}, false, fmt.Errorf("findings: device updates: reading the device: %w", err)
	}
	if !ok {
		return DeviceUpdates{}, false, nil
	}
	recs, err := s.List(ctx, assetID)
	if err != nil {
		return DeviceUpdates{}, false, err
	}
	out := DeviceUpdates{AssetID: assetID}
	var open []Record
	for _, r := range recs {
		if r.Status.Open() {
			open = append(open, r)
		}
	}
	out.Open = len(open)
	if len(open) > 0 {
		vulns, err := s.cfg.Feeds.Vulns(ctx)
		if err != nil {
			return DeviceUpdates{}, false, fmt.Errorf("findings: device updates: reading the exploited list: %w", err)
		}
		out.Exploited, out.NoUpdate = exploitedUpdates(a, open, vulns, s.now())
	}
	out.Planned, out.PlanRan = s.plannedUpdates(assetID)
	return out, true, nil
}

// exploitedUpdates groups the open findings of a device by the update that fixes them, as GET /findings does (addFixes: RowFixes on
// the CVEs of the open findings that are not product-only matches), and the rest by the software row they are on.
func exploitedUpdates(a Asset, open []Record, vulns []Vuln, now time.Time) (fixed, none []UpdateAction) {
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	var mine, fixable []Vuln
	have := map[string]bool{}
	for _, r := range open {
		v, ok := byCVE[r.CVE]
		if !ok {
			continue
		}
		mine, have[r.CVE] = append(mine, v), true
		if r.Basis != BasisProduct { // review r1 #1 of D-545: a product match is not proved fixed by an update
			fixable = append(fixable, v)
		}
	}
	fixes := RowFixes(a, fixable)
	sws := map[string]Software{}
	for _, sw := range deviceSoftware(a) {
		sws[sw.ID] = sw
	}
	rowOf := map[string]Software{} // CVE -> the row the matcher matches it on (the finding's row, as matchedRow reads it)
	if len(mine) > 0 {
		r := MatchAsset(a, mine, have, now)
		for _, m := range slices.Concat(r.New, r.Existing) {
			if sw, ok := sws[m.SoftwareID]; ok {
				rowOf[m.CVE] = sw
			} else if m.SoftwareID != "" {
				rowOf[m.CVE] = Software{ID: m.SoftwareID, Display: m.SoftwareDisplay}
			}
		}
	}
	type member struct {
		r   Record
		ran bool
	}
	groups := map[string]*UpdateAction{}
	members := map[string][]member{}
	var order []string
	for _, r := range open {
		row, known := rowOf[r.CVE]
		var key string
		var act UpdateAction
		if f := fixes[r.CVE]; f != nil {
			if sw, ok := sws[f.SoftwareID]; ok {
				row, known = sw, true
			}
			key = "fix:" + f.Group
			act = UpdateAction{Group: f.Group, SoftwareID: f.SoftwareID, Software: f.Software, Version: f.Version, Fixed: f.Fixed, Kind: f.Kind,
				Windows: f.Windows, Distro: f.Distro, Pro: f.Pro}
		} else {
			key = "row:" + row.ID
			act = UpdateAction{Group: a.ID + "/" + row.ID, SoftwareID: row.ID, Software: clean(row.Display), Version: clean(row.Version), Kind: "none"}
		}
		g := groups[key]
		if g == nil {
			g = &act
			groups[key] = g
			order = append(order, key)
		}
		switch proofOf(r, row, known) {
		case ProofConfirmed:
			g.Confirmed++
		case ProofDetected:
			g.Detected++
		default:
			g.Suspected++
		}
		members[key] = append(members[key], member{r, byCVE[r.CVE].Ransomware})
	}
	for _, key := range order {
		g, ms := groups[key], members[key]
		slices.SortStableFunc(ms, func(p, q member) int {
			return cmp.Or(cmp.Compare(sevRank(q.r.Severity), sevRank(p.r.Severity)), strings.Compare(p.r.CVE, q.r.CVE))
		})
		for _, m := range ms {
			g.CVEs, g.FindingIDs = append(g.CVEs, m.r.CVE), append(g.FindingIDs, m.r.ID)
			if m.ran {
				g.Ransomware++
			}
		}
		g.Worst = string(ms[0].r.Severity)
		g.Action = updateSentence(*g)
		if g.Kind == "none" {
			none = append(none, *g)
		} else {
			fixed = append(fixed, *g)
		}
	}
	return sortUpdates(fixed), sortUpdates(none)
}

// proofOf says how a finding's CVE is known (Proof*): from its basis and evidence, then the source of its software row.
func proofOf(r Record, row Software, known bool) string {
	switch {
	case r.Basis == BasisScan:
		return ProofConfirmed
	case r.Evidence != nil && (r.Evidence.Agent || r.Evidence.AgentRow):
		return ProofDetected
	case r.Basis == BasisVersion && known && tierSource(row):
		return ProofDetected
	}
	return ProofSuspected
}

// plannedUpdates are the device's plan items of the last pass, with the CVEs GET /findings/plan still lists (a CVE that crossed the
// 12-month line since the pass is left out, review r1 #2 of #804), in the plan's order.
func (s *Service) plannedUpdates(assetID string) ([]UpdateAction, bool) {
	s.plan.mu.RLock()
	ran, items := s.plan.ran, slices.Clone(s.plan.devices[assetID].items)
	s.plan.mu.RUnlock()
	cut := s.now().Add(-AgeLimit).UTC().Format(time.DateOnly)
	var kept []PlanItem
	for _, it := range items {
		var cves []PlanCVE
		for _, c := range it.CVEs {
			if c.Published >= cut || c.Basis == "scan" {
				cves = append(cves, c)
			}
		}
		if len(cves) > 0 {
			it.CVEs = cves
			kept = append(kept, it)
		}
	}
	sortPlanItems(kept)
	var out []UpdateAction
	for _, it := range kept {
		u := UpdateAction{Group: it.Group, SoftwareID: it.SoftwareID, Software: it.Software, Version: it.Version, Fixed: it.Fixed, Kind: it.Kind,
			Windows: it.Kind == "windows" || it.Kind == "esu", Pro: it.Pro}
		worst := -1
		for _, c := range it.CVEs {
			u.CVEs = append(u.CVEs, c.CVE)
			if c.Tier == "likely" {
				u.Likely++
			}
			if c.Severity != nil && sevRank(Severity(*c.Severity)) > worst {
				worst, u.Worst = sevRank(Severity(*c.Severity)), *c.Severity
			}
		}
		u.Action = updateSentence(u)
		out = append(out, u)
	}
	return out, ran
}

// sortUpdates orders actions worst first, then by how many CVEs they clear, then ransomware, then the software's name.
func sortUpdates(us []UpdateAction) []UpdateAction {
	slices.SortStableFunc(us, func(p, q UpdateAction) int {
		return cmp.Or(cmp.Compare(sevRank(Severity(q.Worst)), sevRank(Severity(p.Worst))), cmp.Compare(len(q.CVEs), len(p.CVEs)),
			cmp.Compare(q.Ransomware, p.Ransomware), strings.Compare(p.Software, q.Software), strings.Compare(p.Group, q.Group))
	})
	return us
}

// updateSentence is what to install, in the words of the Findings page (fix.* and plan.action.* of findings.json).
func updateSentence(u UpdateAction) string {
	sw, fixed := u.Software, u.Fixed
	if sw == "" {
		sw = "the software"
	}
	if u.Windows {
		fixed = strings.TrimPrefix(fixed, "10.0.")
	}
	switch u.Kind {
	case "none":
		return "No update is named that fixes these: follow the vendor's advice for " + sw
	case "distro":
		switch {
		case fixed != "" && u.Pro:
			return fmt.Sprintf("Upgrade the %s package from %s to %s or later (Ubuntu Pro)", sw, u.Version, fixed)
		case fixed != "":
			return fmt.Sprintf("Upgrade the %s package from %s to %s or later", sw, u.Version, fixed)
		case u.Distro != "":
			return fmt.Sprintf("Install %s's security updates for %s", u.Distro, sw)
		}
		return "Install the distribution's security updates for " + sw
	case "feature_update":
		return fmt.Sprintf("Upgrade %s to %s: some of these get no update for this release", sw, fixed)
	case "esu":
		return fmt.Sprintf("Install the Extended Security Update for %s (build %s or later; it needs an ESU subscription)", sw, fixed)
	case "windows":
		return fmt.Sprintf("Install the latest cumulative update for %s (build %s or later)", sw, fixed)
	}
	if u.Windows {
		return fmt.Sprintf("Install the latest cumulative update for %s (build %s or later)", sw, fixed)
	}
	return fmt.Sprintf("Upgrade %s from %s to %s or later", sw, u.Version, fixed)
}
