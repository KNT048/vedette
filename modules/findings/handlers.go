package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/server"
)

// MitigationModule is the id of the module whose Guidance fills the "What to do" fields.
const MitigationModule = "mitigation"

// FeedsModule is the id of the module that holds the tier data of GET /findings/plan.
const FeedsModule = "feeds"

// FindingHandlers implements the findings operations: GET /findings, GET /findings/{id}, POST /findings/{id}/status
// and the bulk POST /findings/status. Embed it in the composite handler. POST /findings/{id}/applied|ai belong
// to mitigation (core/server/modules.go).
type FindingHandlers struct {
	svc  *Service
	inv  Inventory
	feed Feeds
	gate server.ModuleGate

	mu           sync.RWMutex
	guide        Guidance
	agents       AgentReports
	scanReach    ScanReach
	summaryState // GET /findings/summary (summary.go); sum and home under mu
}

// NewFindingHandlers returns the handlers. gate says whether mitigation is on: while it is off the registered
// Guidance is ignored and the "What to do" fields are empty. A nil gate means always on.
func NewFindingHandlers(svc *Service, inv Inventory, feeds Feeds, gate server.ModuleGate) *FindingHandlers {
	return &FindingHandlers{svc: svc, inv: inv, feed: feeds, gate: gate}
}

// SetGuidance registers the "What to do" provider (mitigation does it at start-up). Nil removes it.
func (h *FindingHandlers) SetGuidance(g Guidance) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.guide = g
}

func (h *FindingHandlers) guidance() Guidance {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.guide == nil || (h.gate != nil && !h.gate.Enabled(MitigationModule)) {
		return nil
	}
	return h.guide
}

// ToAPIError turns a library API error into the *apierr.Error of the response; other errors pass
// through (the server answers them as 500 internal without detail).
func ToAPIError(err error) error {
	var ae *APIError
	if errors.Is(err, ErrInvalidUser) {
		return apierr.Invalid("The acting user is not valid.")
	}
	if errors.As(err, &ae) {
		return apierr.New(ae.HTTP, ae.Code, ae.Message)
	}
	return err
}

// rows adds the device, the KEV entry and the CVSS score to records, with one call to each source.
func (h *FindingHandlers) rows(ctx context.Context, recs []Record) ([]Row, error) {
	ids := make([]string, 0, len(recs))
	cves := make([]string, 0, len(recs))
	seenA, seenC := map[string]bool{}, map[string]bool{}
	for _, r := range recs {
		if !seenA[r.AssetID] {
			seenA[r.AssetID] = true
			ids = append(ids, r.AssetID)
		}
		if !seenC[r.CVE] {
			seenC[r.CVE] = true
			cves = append(cves, r.CVE)
		}
	}
	var assets map[string]AssetView
	var kev map[string]KevInfo
	var scores map[string]CVSS
	if len(recs) > 0 {
		var err error
		if assets, err = h.inv.Assets(ctx, ids); err != nil {
			return nil, fmt.Errorf("findings: reading devices: %w", err)
		}
		if kev, err = h.feed.KevInfo(ctx, cves); err != nil {
			return nil, fmt.Errorf("findings: reading KEV entries: %w", err)
		}
		if scores, err = h.feed.CVSS(ctx, cves); err != nil {
			return nil, fmt.Errorf("findings: reading CVSS scores: %w", err)
		}
	}
	out := make([]Row, 0, len(recs))
	for _, r := range recs {
		var a *AssetView
		if v, ok := assets[r.AssetID]; ok {
			a = &v
		}
		var k *KevInfo
		if v, ok := kev[r.CVE]; ok {
			k = &v
		}
		var c *CVSS
		if v, ok := scores[r.CVE]; ok {
			c = &v
		}
		out = append(out, newRow(r, a, k, c))
	}
	return out, nil
}

// Detail composes FindingDetail for a stored finding: the row plus, while mitigation is on, its
// "What to do" part (POST-3). Mitigation's handlers call it to answer after their own change.
func (h *FindingHandlers) Detail(ctx context.Context, rec Record) (Detail, error) {
	rs, err := h.rows(ctx, []Record{rec})
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Row: rs[0]}
	// The device with its software: the reads below only inform the page, so a failed one leaves what the page always had.
	a, ok, err := h.inv.MatchInput(ctx, rec.AssetID)
	found := err == nil && ok
	var v *Vuln // the stored entry: the matched row of the finding, its fix, a Multiple Products label
	if found && d.Kev != nil {
		if vulns, err := h.feed.Vulns(ctx); err == nil {
			for i := range vulns {
				if vulns[i].CVE == rec.CVE {
					v = &vulns[i]
					break
				}
			}
		}
	}
	var row Software
	matched := false
	if found && d.Kev != nil {
		row, matched = findingRow(a, *d.Kev, v)
	}
	if matched {
		d.Known = knownVersion(a, row) // M2-3: the guidance and the page say the version the box has, never "find which version"
		d.KnownVersion = d.Known
	}
	if g := h.guidance(); g != nil {
		if d.Guide, err = g.Guidance(ctx, d.Row); err != nil {
			return Detail{}, fmt.Errorf("findings: reading the recommendation: %w", err)
		}
	}
	d.Normalize()
	d.addAppliedToHistory()
	if rec.Status == StatusSuspected {
		d.SuspectedWhy = h.suspectedWhy(ctx, rec, d)
	}
	if !found {
		return d, nil
	}
	if d.Asset != nil && matched && row.Display != "" {
		aa := *d.Asset
		aa.Display = clean(row.Display)
		d.Asset = &aa
	}
	if rec.Status.Open() && v != nil {
		d.FixedIn = FixedInFor(a, *v) // the release that fixes it on this device, from NVD's ranges; closed: nothing to upgrade
	}
	return d, nil
}

// suspectedWhy is WhySuspected with the facts of the box: whether a check exists comes from the KEV entry (known only with it), how the
// scan stands to the device from the registered ScanReach.
func (h *FindingHandlers) suspectedWhy(ctx context.Context, rec Record, d Detail) *string {
	h.mu.RLock()
	reach := h.scanReach
	h.mu.RUnlock()
	checkKnown, hasCheck := d.Kev != nil, d.Kev != nil && d.Kev.HasTemplate
	where := ""
	if reach != nil && checkKnown && hasCheck {
		where = reach(ctx, rec.AssetID)
	}
	s := WhySuspected(rec.Basis, d.Known, checkKnown, hasCheck, where, h.svc.now())
	return &s
}

// matchedOn names the device's software row the finding's KEV entry is keyed to, as the matcher reads the device (its rows and the network
// OS it states, deviceSoftware): the Device panel of the finding names it, not the device's first software by name, which
// showed "Microsoft Edge" for a Windows CVE. A "Multiple Products" entry is keyed to every row of its vendor, so there it is the row the
// matcher matches through NVD's list (review r1 #2 of #807: MatchAsset on that entry alone, v the stored entry), as it is for an entry no
// row is keyed to (#910: NVD's list names the row). "" when no row is keyed to the entry and the entry is not read or the matcher
// matches none (the panel then keeps AssetView.Display: the device's OS, else its kind, never an arbitrary software row, #905).
func matchedOn(a Asset, k KevInfo, v *Vuln) string {
	if s, ok := matchedRow(a, k, v); ok {
		return clean(s.Display)
	}
	return ""
}

// findingRow is the row the finding was matched on, the one its evidence speaks of (review r1 M3 of #896): the row the matcher
// matches the stored entry on, on the device as it is now. Without the entry, or when the matcher no longer matches, the keyed row
// with a version from the most trusted source (agent, a person, SNMP, a scan), else matchedRow's.
func findingRow(a Asset, k KevInfo, v *Vuln) (Software, bool) {
	sws := deviceSoftware(a)
	if v != nil {
		r := MatchAsset(a, []Vuln{*v}, map[string]bool{v.CVE: true}, time.Now())
		for _, m := range slices.Concat(r.New, r.Existing) {
			if m.CVE != v.CVE || m.SoftwareID == "" {
				continue
			}
			for _, s := range sws {
				if s.ID == m.SoftwareID {
					return s, true
				}
			}
		}
	}
	if isMultiProduct(k.Product) {
		return matchedRow(a, k, v)
	}
	trust := map[string]int{"agent": 4, "manual": 3, "snmp": 2, "scan": 1, "nmap": 1}
	key := Vuln{Vendor: k.Vendor, Product: k.Product}
	best, bestRank := Software{}, -1
	for _, s := range sws {
		if !keyedTo(s, key) || !versionGiven(s.Version) {
			continue
		}
		r := trust[s.Source]
		if s.ID == osSoftwareID(a.ID) {
			r = 2 // the OS the device states itself
		}
		if r > bestRank {
			best, bestRank = s, r
		}
	}
	if bestRank >= 0 {
		return best, true
	}
	return matchedRow(a, k, v)
}

// matchedRow is the software row matchedOn names; ok is false when there is none. With the stored entry, the row the matcher matches
// it on (the finding's row, as FixedInFor and RowFixes read it: a version match through NVD's list beats a keyed row's product match,
// #910, review r1 L1 of #913); else, or when it matches none, a row keyed to the entry (never for "Multiple Products").
func matchedRow(a Asset, k KevInfo, v *Vuln) (Software, bool) {
	sws := deviceSoftware(a)
	if v != nil {
		r := MatchAsset(a, []Vuln{*v}, map[string]bool{v.CVE: true}, time.Now())
		for _, m := range slices.Concat(r.New, r.Existing) {
			if m.CVE != v.CVE || m.SoftwareDisplay == "" {
				continue
			}
			for _, s := range sws {
				if s.ID == m.SoftwareID {
					return s, true
				}
			}
			return Software{ID: m.SoftwareID, Display: m.SoftwareDisplay}, true
		}
	}
	if isMultiProduct(k.Product) {
		return Software{}, false
	}
	key := Vuln{Vendor: k.Vendor, Product: k.Product}
	for _, s := range sws {
		if keyedTo(s, key) {
			return s, true
		}
	}
	return Software{}, false
}

// addFixes sets Row.Fix on the open findings of the list: per device, the update that fixes its open findings of one software
// together (RowFixes). Like fixedIn it only informs the page: a device or a list it cannot read leaves the rows without one.
func (h *FindingHandlers) addFixes(ctx context.Context, rows []Row) {
	byAsset := map[string][]int{}
	var order []string
	for i, r := range rows {
		if !r.Status.Open() || r.Basis == BasisProduct { // review r1 #1: a product match is not proved fixed by an update
			continue
		}
		if _, ok := byAsset[r.AssetID]; !ok {
			order = append(order, r.AssetID)
		}
		byAsset[r.AssetID] = append(byAsset[r.AssetID], i)
	}
	if len(order) == 0 {
		return
	}
	vulns, err := h.feed.Vulns(ctx)
	if err != nil {
		return
	}
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	for _, id := range order {
		var mine []Vuln
		for _, i := range byAsset[id] {
			if v, ok := byCVE[rows[i].CVE]; ok {
				mine = append(mine, v)
			}
		}
		if len(mine) < 2 { // one finding is its own item: nothing to group
			continue
		}
		a, ok, err := h.inv.MatchInput(ctx, id)
		if err != nil || !ok {
			continue
		}
		fixes := RowFixes(a, mine)
		for _, i := range byAsset[id] {
			rows[i].Fix = fixes[rows[i].CVE]
		}
	}
}

// DetailByID is Detail for a finding id; an unknown id is a 404 API error.
func (h *FindingHandlers) DetailByID(ctx context.Context, id string) (Detail, error) {
	rec, err := h.svc.Get(ctx, id)
	if err != nil {
		return Detail{}, ToAPIError(err)
	}
	return h.Detail(ctx, rec)
}

// FindingsGetFindings implements findings_get_findings: the findings, newest first, all of them or
// those of one device (?asset=). No paging, like the mock.
func (h *FindingHandlers) FindingsGetFindings(ctx context.Context, params oas.FindingsGetFindingsParams) (*oas.FindingsGetFindingsOK, error) {
	recs, err := h.svc.List(ctx, params.Asset.Or(""))
	if err != nil {
		return nil, err
	}
	rows, err := h.rows(ctx, recs)
	if err != nil {
		return nil, err
	}
	h.addFixes(ctx, rows)
	need, err := h.versionNeeded(ctx, params.Asset.Or(""))
	if err != nil {
		return nil, err
	}
	unchecked, err := h.unchecked(ctx, params.Asset.Or(""))
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsGetFindingsOK](struct {
		Items         []Row             `json:"items"`
		VersionNeeded []versionNeededJS `json:"version_needed"`
		Unchecked     []UncheckedItem   `json:"unchecked"` // #910 phase 1 (contract.ts UncheckedItem)
	}{rows, need, unchecked})
}

// versionNeededJS is contract.ts VersionNeeded.
type versionNeededJS struct {
	Asset      *AssetView `json:"asset"`
	AssetID    string     `json:"asset_id"`
	SoftwareID string     `json:"software_id"`
	Software   string     `json:"software"`
	Version    *string    `json:"version"` // nil: missing; else the version Vedette could not read
	CVEs       int        `json:"cves"`
}

func (h *FindingHandlers) versionNeeded(ctx context.Context, assetID string) ([]versionNeededJS, error) {
	items, err := h.svc.ListVersionNeeded(ctx, assetID)
	if err != nil || len(items) == 0 {
		return []versionNeededJS{}, err
	}
	ids := make([]string, 0, len(items))
	for _, n := range items {
		ids = append(ids, n.AssetID)
	}
	assets, err := h.inv.Assets(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("findings: reading devices: %w", err)
	}
	out := make([]versionNeededJS, 0, len(items))
	for _, n := range items {
		j := versionNeededJS{AssetID: n.AssetID, SoftwareID: n.SoftwareID, Software: n.Software, CVEs: n.CVEs}
		if a, ok := assets[n.AssetID]; ok {
			j.Asset = &a
		}
		if n.Version != "" {
			j.Version = &n.Version
		}
		out = append(out, j)
	}
	return out, nil
}

// FindingsGetFindingsID implements findings_get_findings_id.
func (h *FindingHandlers) FindingsGetFindingsID(ctx context.Context, params oas.FindingsGetFindingsIDParams) (*oas.FindingsGetFindingsIDOK, error) {
	d, err := h.DetailByID(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsGetFindingsIDOK](d)
}

// FindingsPostFindingsIDStatus implements findings_post_findings_id_status (operator).
func (h *FindingHandlers) FindingsPostFindingsIDStatus(ctx context.Context, req *oas.FindingsPostFindingsIDStatusReq, params oas.FindingsPostFindingsIDStatusParams) (*oas.FindingsPostFindingsIDStatusOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if strings.ContainsRune(req.Note, 0) {
		return nil, apierr.Invalid("The note contains a character that is not allowed.")
	}
	rec, err := h.svc.setStatus(ctx, params.ID, Action(req.Action), req.Note, p.Email, req.Until.Or(time.Time{}))
	if err != nil {
		return nil, ToAPIError(err)
	}
	d, err := h.Detail(ctx, rec)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsPostFindingsIDStatusOK](d)
}

// FindingsPostFindingsIDConfirm implements findings_post_findings_id_confirm (admin): a person confirms a suspected finding.
func (h *FindingHandlers) FindingsPostFindingsIDConfirm(ctx context.Context, req *oas.FindingsPostFindingsIDConfirmReq, params oas.FindingsPostFindingsIDConfirmParams) (*oas.FindingsPostFindingsIDConfirmOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if strings.ContainsRune(req.Note, 0) {
		return nil, apierr.Invalid("The note contains a character that is not allowed.")
	}
	if strings.ContainsFunc(req.Note, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) {
		return nil, apierr.Invalid("The note contains a character that is not allowed.")
	}
	rec, err := h.svc.ConfirmByPerson(ctx, params.ID, req.Note, p.Email)
	if err != nil {
		return nil, ToAPIError(err)
	}
	d, err := h.Detail(ctx, rec)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsPostFindingsIDConfirmOK](d)
}

// FindingsPostFindingsIDUnconfirm implements findings_post_findings_id_unconfirm (admin): Undo of a person's confirmation.
func (h *FindingHandlers) FindingsPostFindingsIDUnconfirm(ctx context.Context, params oas.FindingsPostFindingsIDUnconfirmParams) (*oas.FindingsPostFindingsIDUnconfirmOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	rec, err := h.svc.UnconfirmByPerson(ctx, params.ID, p.Email)
	if err != nil {
		return nil, ToAPIError(err)
	}
	d, err := h.Detail(ctx, rec)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsPostFindingsIDUnconfirmOK](d)
}

// Guidance is the optional "What to do" provider. mitigation registers one with FindingHandlers.SetGuidance
// while it is on; without one the "What to do" fields of a finding are null or empty (POST-3).
type Guidance interface {
	Guidance(ctx context.Context, r Row) (Guide, error)
}

// AgentReports says whether an agent of this box reads a device's software now: its osquery node calls (not silent past
// agent-intake's stale limit), the Wazuh pull delivers to it, or it is the box itself. False when none does, agent-intake is off or the
// device's state cannot be read: the same answer as the "No agent reports the software of <device> to Vedette now" line of the
// finding page (agent-intake ReportState). cmd/vedette sets it; nil means unknown, and nothing is said.
type AgentReports func(ctx context.Context, assetID string) bool

// SetScanReach registers how the vulnerability scan stands to a device (the binary, at start-up): the "why only suspected" line of the
// finding page says it. Nil: the line does not mention the scan.
func (h *FindingHandlers) SetScanReach(f ScanReach) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scanReach = f
}

// SetAgents registers the agent check of GET /findings/plan (the binary, at start-up).
func (h *FindingHandlers) SetAgents(f AgentReports) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.agents = f
}

// FindingsGetFindingsPlan implements findings_get_findings_plan (S-TIER-1, S-TIER-2): "Updates to
// plan", the last comparison of the plan job (Service.Plan), filtered by tier and device. compared is false until the job's first run
// since the start; the counts of devices are of every device, whatever the filter. The feeds module off: no item and no feed data is
// read (modules.md), the page says the module is off.
func (h *FindingHandlers) FindingsGetFindingsPlan(ctx context.Context, params oas.FindingsGetFindingsPlanParams) (*oas.FindingsGetFindingsPlanOK, error) {
	st := TierStatus{EPSS: "module_off", Recent: "module_off"}
	feedsOn := h.gate == nil || h.gate.Enabled(FeedsModule)
	if feedsOn {
		var err error
		if st, err = h.feed.TierStatus(ctx); err != nil {
			return nil, fmt.Errorf("findings: reading the tier data: %w", err)
		}
	}
	// day writes a calendar day (FIRST's day of the scores, the first day of the recent window), stored at 00:00 UTC
	day := func(t time.Time) *string {
		if t.IsZero() {
			return nil
		}
		d := t.UTC().Format(time.DateOnly)
		return &d
	}
	zone := orgtime.At(ctx, h.svc.cfg.Zone)
	state := func(s string) string {
		switch s {
		case "ready", "loading", "module_off":
			return s
		}
		return "off"
	}
	view := h.svc.Plan()
	tier := string(params.Tier.Or(oas.FindingsGetFindingsPlanTierAll))
	asset := params.Asset.Or("")
	wantDone := params.Done.Or(oas.FindingsGetFindingsPlanDoneFalse) == oas.FindingsGetFindingsPlanDoneTrue
	cut := h.svc.now().Add(-AgeLimit).UTC().Format(time.DateOnly)
	items, ids, old := []any{}, []string{}, 0
	type shown struct {
		it     PlanItem
		cves   []PlanCVE // the CVEs of the asked tier
		likely bool      // some CVE of the item is likely (any tier asked)
		recent bool
	}
	var keep []shown
	for _, it := range view.Items {
		if !feedsOn || asset != "" && it.AssetID != asset {
			continue
		}
		if wantDone { // "Mark as done" is "Patched" on the findings now: nothing is listed under Done
			continue
		}
		// Microsoft's newest Windows update with no CVE analysed yet: a recent item (its CVEs are this month's), never a likely one
		k := shown{it: it, recent: awaitsNVD(it)}
		for _, c := range it.CVEs {
			// a CVE that crossed the 12-month line since the pass is not listed (review r1 #2 of #804): only a scan may list an older
			// one, and no scan basis exists yet
			if c.Published < cut && c.Basis != "scan" {
				continue
			}
			k.likely, k.recent = k.likely || c.Tier == "likely", k.recent || c.Tier == "recent"
			if tier == "all" || c.Tier == tier {
				k.cves = append(k.cves, c)
			}
		}
		if !k.likely && !k.recent {
			continue
		}
		keep = append(keep, k)
		if !slices.Contains(ids, it.AssetID) {
			ids = append(ids, it.AssetID)
		}
	}
	names, err := h.inv.Assets(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the devices of the plan: %w", err)
	}
	var risks map[string]DeviceStatus // each device's badge, so the page needs no device list
	if len(keep) > 0 {
		risks = h.risks(ctx, feedsOn)
	}
	counts := map[string]int{"likely": 0, "recent": 0, "all": 0, "done": 0} // M2-9: every tab's number from one answer
	h.mu.RLock()
	agents := h.agents
	h.mu.RUnlock()
	gone := map[string]bool{} // device -> no agent reports it now; asked once per device whose items rest on an agent's row
	agentGone := func(id string) bool {
		g, ok := gone[id]
		if !ok {
			g = agents != nil && !agents(ctx, id)
			gone[id] = g
		}
		return g
	}
	for _, k := range keep {
		a, ok := names[k.it.AssetID]
		if !ok {
			continue // deleted since the last pass
		}
		counts["all"]++
		if k.likely {
			counts["likely"]++
		}
		if k.recent {
			counts["recent"]++
		}
		if len(k.cves) == 0 && (!awaitsNVD(k.it) || tier == "likely") {
			continue // not of the asked tier
		}
		likely := 0
		for _, c := range k.cves {
			if c.Tier == "likely" {
				likely++
			}
			if c.Published < cut && c.Basis == "scan" {
				old++
			}
		}
		// The version of an agent's row is the last list an agent sent once none reports the device: the item says so, with that day
		var reported *string
		lastOnly := (slices.ContainsFunc(k.cves, func(c PlanCVE) bool { return c.Basis == planAgent }) || awaitsNVD(k.it) && k.it.Basis == planAgent || k.it.agentRow) && agentGone(a.ID)
		cves := k.cves
		if cves == nil {
			cves = []PlanCVE{}
		}
		if lastOnly && !k.it.Reported.IsZero() { // an instant: its day in the organization's zone, the day the finding page shows
			d := orgtime.ISODay(k.it.Reported, zone)
			reported = &d
		}
		items = append(items, map[string]any{"group": k.it.Group, "asset": map[string]any{"id": a.ID, "name": a.Name}, "risk": riskOfView(risks, a), "software": k.it.Software,
			"version": k.it.Version, "fixed": k.it.Fixed, "kind": k.it.Kind, "distro": k.it.Distro, "pro": k.it.Pro, "nvd_lag": k.it.NVDLag, "kb": k.it.KB, "cves": cves, "likely": likely, "recent": len(k.cves) - likely,
			"agent_gone": lastOnly, "agent_reported": reported, "distro_data": k.it.DistroData, "done": nil})
	}
	return Into[oas.FindingsGetFindingsPlanOK](map[string]any{
		"items": items, "counts": counts, "compared": view.Ran, "compared_devices": view.Compared, "unchecked_devices": view.Unchecked, "old_evidence": old,
		"data": map[string]any{"epss": state(st.EPSS), "recent": state(st.Recent), "epss_date": day(st.EPSSDate), "recent_since": day(st.RecentSince)},
	})
}
