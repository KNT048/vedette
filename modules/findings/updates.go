package findings

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// "What do I upgrade on this device to clear its CVEs" (Ask my AI; the Findings page and the device's Software tab):
// one answer per device, built from the groupings the product already shows. The open exploited findings are grouped by the update
// that fixes them (RowFixes, the FindingRow.fix), and the device's "Updates to plan" items (PlanItem) are listed as the
// plan job last compared them. Nothing is stored; it is read when asked.

// How a finding's CVE is known on the device, mapped from what the finding stores (basis, evidence.agent, evidence.agent_row)
// and the source of the software row it is on. Never "needs confirming" for a version the device itself reported.
const (
	// ProofConfirmed: a safe scan proved it (basis scan), a person confirmed it (basis person), or the version the device itself
	// reports confirmed it (Finding.ByDevice): the same "confirmed" the finding's status says.
	ProofConfirmed = "confirmed"
	// ProofDetected: the device itself reported the installed version (its agent: osquery, Wazuh, the box's package list,
	// evidence.agent; or a version the plan also trusts, tierSource: a person's entry, the device's SNMP answer, the OS the
	// device states) and that version is inside the affected range.
	ProofDetected = "detected"
	// ProofReported: the device's agent reported the installed version, but the box has not proved it affected: it could not compare
	// it with the vulnerability's data (evidence.agent_row), or the range has no end or a platform condition is open (an agent
	// row without evidence.agent). Not a guess, and not proved either: the finding's evidence says what to check.
	ProofReported = "reported"
	// ProofSuspected: a network guess: a version read from a banner or a fingerprint, or the product name only.
	ProofSuspected = "suspected"
)

// UpdateAction is one update on one device: what to install and what it clears.
type UpdateAction struct {
	// Group is the key the pages already use: RowFix.Group for an exploited update, PlanItem.Group for a planned one,
	// "<device id>/<software id>" for findings no update is named for ("<device id>/" when no software row matches any more).
	Group string
	// SoftwareID is the device's software row the action is about ("" when none matches), so the Software tab can show it on the
	// row; Software and Version are that row's display name and installed version.
	SoftwareID string
	Software   string
	Version    string
	// Product is the software row's identity across devices, "vendor|product" in lower case ("" when no row matches): what "By fix"
	// groups one update on several devices by, whatever each device calls the row (#943).
	Product string
	// Source is who reported the row (Software.Source: "agent", "manual", "scan", a sensor; "" when none): the page's "I updated it"
	// follows it (the agent reports the new version by itself, a scan re-reads it, a person types it).
	Source string
	// Fixed is the release or build to install ("" for a distribution's updates without a version, and for no named update).
	Fixed string
	// Kind: exploited: RowFix.Kind (fixed, esu, feature_update, distro); planned: PlanItem.Kind (fixed, windows, esu, distro);
	// "none" for findings no update is named for.
	Kind    string
	Windows bool   // a Windows release row: the update is the monthly cumulative update
	Distro  string // distro: "Ubuntu" or "Debian", "" for the distribution's
	Pro     bool   // distro: a fix is in Ubuntu Pro (ESM) only
	// DistroData (planned distro): PlanItem.DistroData: the distribution's fixed release, no fix from it yet, or no data from it.
	DistroData string
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
	Confirmed, Detected, Reported, Suspected int
	// Checkable counts the exploited CVEs a safe vulnerability check exists for (ServiceConfig.SafeCheck): "Run the check" is offered only
	// then; zero for planned ones.
	Checkable int
	// NVDLag (planned Windows updates, PlanItem.NVDLag): the update is newer than every fix NVD names, so it fixes at least CVEs; the
	// newest update's CVEs are not analysed by NVD yet.
	NVDLag bool
	// KB is the KB number of a Windows update's Fixed build when Microsoft's release information lists it; "" otherwise.
	KB string
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
	// PlanCompared: the last plan pass compared this device (it has a row the plan trusts, and it existed at that pass). False with
	// PlanRan: Planned is empty because nothing was compared, not because nothing is to plan (the page's unchecked devices).
	PlanCompared bool
	// PlanOff: the feeds module is off, so, as on GET /findings/plan, no recommended update is listed.
	PlanOff bool
}

// DeviceUpdates returns what to install on one device to clear its CVEs. ok is false when the device does not exist. feedsOn says the
// feeds module is on: while it is off the recommended updates are not listed, as GET /findings/plan lists none.
func (s *Service) DeviceUpdates(ctx context.Context, assetID string, feedsOn bool) (DeviceUpdates, bool, error) {
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
		if r.Status.Open() && Announced(r.Row) { // a finding of a CVE on no list is a recommended update (Planned), never exploited
			open = append(open, r)
		}
	}
	out.Open = len(open)
	if len(open) > 0 {
		vulns, err := s.cfg.Feeds.Vulns(ctx)
		if err != nil {
			return DeviceUpdates{}, false, fmt.Errorf("findings: device updates: reading the exploited list: %w", err)
		}
		out.Exploited, out.NoUpdate = exploitedUpdates(a, open, vulns, s.now(), s.safeCheck)
	}
	if feedsOn {
		out.Planned, out.PlanRan, out.PlanCompared = s.plannedUpdates(assetID)
		withRows(a, out.Planned)
	} else {
		out.PlanOff = true
	}
	return out, true, nil
}

// exploitedUpdates groups the open findings of a device by the update that fixes them, as GET /findings does (addFixes: RowFixes on
// the CVEs of the open findings that are not product-only matches), and the rest by the software row they are on.
func exploitedUpdates(a Asset, open []Record, vulns []Vuln, now time.Time, check func(Vuln) bool) (fixed, none []UpdateAction) {
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
		if r.Basis != BasisProduct { // A product match is not proved fixed by an update
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
		for _, m := range slices.Concat(r.New, r.Existing, r.NameOnly) { // NameOnly: a finding a person reopened keeps its row
			if sw, ok := sws[m.SoftwareID]; ok {
				rowOf[m.CVE] = sw
			} else if m.SoftwareID != "" {
				rowOf[m.CVE] = Software{ID: m.SoftwareID, Display: m.SoftwareDisplay}
			}
		}
	}
	if len(mine) > 0 && len(a.NotInstalled) > 0 { // INV-6c: a finding left open on a row a person said is not installed (a scan confirmed it, or a person kept it) keeps the row's name
		gone := a
		gone.Software, gone.NotInstalled = a.NotInstalled, nil
		r := MatchAsset(gone, mine, have, now)
		for _, m := range slices.Concat(r.New, r.Existing) {
			if _, done := rowOf[m.CVE]; done {
				continue
			}
			for _, sw := range a.NotInstalled {
				if sw.ID == m.SoftwareID {
					rowOf[m.CVE], sws[sw.ID] = sw, sw
				}
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
		matched, ok := rowOf[r.CVE]
		f := fixes[r.CVE]
		row, known := proofRow(matched, ok, f, sws)
		var key string
		var act UpdateAction
		if f != nil {
			key = "fix:" + f.Group
			act = UpdateAction{Group: f.Group, SoftwareID: f.SoftwareID, Software: f.Software, Version: f.Version, Fixed: f.Fixed, Kind: f.Kind,
				Windows: f.Windows, Distro: f.Distro, Pro: f.Pro, KB: f.KB, Product: productKey(sws[f.SoftwareID]), Source: sws[f.SoftwareID].Source}
		} else {
			key = "row:" + row.ID
			act = UpdateAction{Group: a.ID + "/" + row.ID, SoftwareID: row.ID, Software: clean(row.Display), Version: clean(row.Version), Kind: "none", Product: productKey(row), Source: row.Source}
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
		case ProofReported:
			g.Reported++
		default:
			g.Suspected++
		}
		if check(byCVE[r.CVE]) {
			g.Checkable++
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

// productKey is a software row's identity across devices (UpdateAction.Product): "vendor|product" in lower case, "" for none.
func productKey(s Software) string {
	if s.Vendor == "" && s.Product == "" {
		return ""
	}
	return productid.Key(s.Vendor, s.Product)
}

// proofRow is the row whose source says how a finding is known: the row it matched on (MatchAsset), the fix group's row only when it
// matched on none (#935: a group may hold a CVE the matcher matched on another row of the same product).
func proofRow(matched Software, ok bool, f *RowFix, sws map[string]Software) (Software, bool) {
	if ok {
		return matched, true
	}
	if f != nil {
		if sw, found := sws[f.SoftwareID]; found {
			return sw, true
		}
	}
	return Software{}, false
}

// proofOf says how a finding's CVE is known (Proof*): from its basis and evidence, then the source of its software row. An agent's
// row is "detected" only when the matcher said so (evidence.agent): it leaves it unset while the range has no end or a
// platform condition is open (the person still has to check it), and such a finding, like a product-only match on an agent row
// (evidence.agent_row), is "reported" (#935). A person's entry, the device's SNMP answer or the OS it states
// (tierSource, not an agent row) inside the range is "detected".
func proofOf(r Record, row Software, known bool) string {
	agentRow := known && row.Source == "agent"
	switch {
	case r.Basis == BasisScan, r.Basis == BasisPerson, r.ByDevice():
		return ProofConfirmed
	case r.Evidence != nil && r.Evidence.Agent:
		return ProofDetected
	case r.Basis == BasisVersion && known && !agentRow && tierSource(row):
		return ProofDetected
	case r.Evidence != nil && r.Evidence.AgentRow, agentRow:
		return ProofReported
	}
	return ProofSuspected
}

// plannedUpdates are the device's plan items of the last pass, with the CVEs GET /findings/plan still lists (a CVE that crossed the
// 12-month line since the pass is left out, #804), in the plan's order. compared: the last pass compared the device.
func (s *Service) plannedUpdates(assetID string) (out []UpdateAction, ran, compared bool) {
	s.plan.mu.RLock()
	d := s.plan.devices[assetID]
	ran, compared = s.plan.ran, d.compared
	items := slices.Clone(d.items)
	s.plan.mu.RUnlock()
	kept := listedPlanItems(items, s.now())
	sortPlanItems(kept)
	for _, it := range kept {
		u := planAction(it)
		u.Action = updateSentence(u)
		out = append(out, u)
	}
	return out, ran, compared
}

// listedPlanItems are the items with the CVEs GET /findings/plan still lists at now: a CVE that crossed the 12-month line since the
// pass is left out (#804), and an item left with none is dropped; an item that never had one (awaitsNVD: Microsoft's newest Windows
// update, its CVEs not analysed yet) is kept. To fix, the device's updates and the risk marker
// (RiskMap) read the plan through it.
func listedPlanItems(items []PlanItem, now time.Time) []PlanItem {
	cut := now.Add(-AgeLimit).UTC().Format(time.DateOnly)
	var kept []PlanItem
	for _, it := range items {
		var cves []PlanCVE
		for _, c := range it.CVEs {
			if c.Published >= cut || c.Basis == "scan" {
				cves = append(cves, c)
			}
		}
		if len(cves) > 0 || awaitsNVD(it) {
			it.CVEs = cves
			kept = append(kept, it)
		}
	}
	return kept
}

// planAction is the action of one plan item (without its sentence): its CVEs, how many are likely, and the worst severity.
func planAction(it PlanItem) UpdateAction {
	u := UpdateAction{Group: it.Group, SoftwareID: it.SoftwareID, Software: it.Software, Version: it.Version, Fixed: it.Fixed, Kind: it.Kind,
		Windows: it.Kind == "windows" || it.Kind == "esu", Distro: it.Distro, Pro: it.Pro, NVDLag: it.NVDLag, KB: it.KB, DistroData: it.DistroData}
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
	return u
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
	build := "" // a Windows update names the device's build and the fixed one, as every other upgrade does ("from v7.2.13 to 7.6.7")
	if u.Windows {
		fixed = strings.TrimPrefix(fixed, "10.0.")
		build = "build " + fixed
		if v := strings.TrimPrefix(u.Version, "10.0."); v != "" {
			build = "from build " + v + " to " + fixed
		}
		build += " or later"
		if u.KB != "" { // the number an admin looks the update up by
			build += "; " + u.KB
		}
	}
	switch u.Kind {
	case "none":
		return "No update is named that fixes these: follow the vendor's advice for " + sw
	case "distro":
		dist := "the distribution"
		if u.Distro != "" {
			dist = u.Distro
		}
		switch {
		case u.DistroData == DistroDataNoFix: // the distribution's data says affected, with no fix yet
			return fmt.Sprintf("No fix from %s yet for %s (%s)", dist, sw, u.Version)
		case u.DistroData == DistroDataNone && u.Distro != "": // no data from the distribution: NVD's upstream ranges, so check, never "install"
			return fmt.Sprintf("Check %s's security updates for %s", u.Distro, sw)
		case u.DistroData == DistroDataNone:
			return "Check the distribution's security updates for " + sw
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
		return fmt.Sprintf("Install the Extended Security Update for %s (%s; it needs an ESU subscription)", sw, build)
	case "windows":
		return fmt.Sprintf("Install the latest cumulative update for %s (%s)", sw, build)
	}
	if u.Windows {
		return fmt.Sprintf("Install the latest cumulative update for %s (%s)", sw, build)
	}
	return fmt.Sprintf("Upgrade %s from %s to %s or later", sw, u.Version, fixed)
}
