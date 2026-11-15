package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
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

	mu    sync.RWMutex
	guide Guidance
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

// rows adds the device and the KEV entry to records, with one call to each source.
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
	if len(recs) > 0 {
		var err error
		if assets, err = h.inv.Assets(ctx, ids); err != nil {
			return nil, fmt.Errorf("findings: reading devices: %w", err)
		}
		if kev, err = h.feed.KevInfo(ctx, cves); err != nil {
			return nil, fmt.Errorf("findings: reading KEV entries: %w", err)
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
		out = append(out, newRow(r, a, k))
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
	if g := h.guidance(); g != nil {
		if d.Guide, err = g.Guidance(ctx, d.Row); err != nil {
			return Detail{}, fmt.Errorf("findings: reading the recommendation: %w", err)
		}
	}
	d.Normalize()
	d.addAppliedToHistory()
	// The device with its software: both reads below only inform the page, so a failed one leaves what the page always had.
	if a, ok, err := h.inv.MatchInput(ctx, rec.AssetID); err == nil && ok {
		if d.Asset != nil && d.Kev != nil {
			if sw := matchedOn(a, *d.Kev); sw != "" {
				aa := *d.Asset
				aa.Display = sw
				d.Asset = &aa
			}
		}
		d.FixedIn = h.fixedIn(ctx, rec, a)
	}
	return d, nil
}

// matchedOn names the device's software row the finding's KEV entry is keyed to, as the matcher reads the device (its rows and the network
// OS it states, deviceSoftware): the Device panel of the finding names it (N53-1, D-619), not the device's first software by name, which
// showed "Microsoft Edge" for a Windows CVE. "" when no row is keyed to the entry (the panel then keeps inventory's display).
func matchedOn(a Asset, k KevInfo) string {
	v := Vuln{Vendor: k.Vendor, Product: k.Product}
	for _, s := range deviceSoftware(a) {
		if keyedTo(s, v) {
			return clean(s.Display)
		}
	}
	return ""
}

// fixedIn is the release that fixes the finding on its device a, from NVD's ranges (D-488). It only informs the page, so
// a failed read gives nil, the text the page always had, and never an error. Closed findings have nothing to upgrade.
func (h *FindingHandlers) fixedIn(ctx context.Context, rec Record, a Asset) *FixedIn {
	if !rec.Status.Open() {
		return nil
	}
	vulns, err := h.feed.Vulns(ctx)
	if err != nil {
		return nil
	}
	for _, v := range vulns {
		if v.CVE == rec.CVE {
			return FixedInFor(a, v)
		}
	}
	return nil
}

// addFixes sets Row.Fix on the open findings of the list (D-545): per device, the update that fixes its open findings of one software
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
	return Into[oas.FindingsGetFindingsOK](struct {
		Items         []Row             `json:"items"`
		VersionNeeded []versionNeededJS `json:"version_needed"`
	}{rows, need})
}

// versionNeededJS is contract.ts VersionNeeded (D-500).
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

// FindingsPostFindingsStatus implements findings_post_findings_status (operator): one action and one note for the open
// findings among up to MaxBulk ids, one history and audit row each, all or nothing; closed ones are skipped (INV-10).
func (h *FindingHandlers) FindingsPostFindingsStatus(ctx context.Context, req *oas.FindingsPostFindingsStatusReq) (*oas.FindingsPostFindingsStatusOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if strings.ContainsRune(req.Note, 0) {
		return nil, apierr.Invalid("The note contains a character that is not allowed.")
	}
	n, skipped, err := h.svc.setStatusMany(ctx, req.Ids, Action(req.Action), req.Note, p.Email, req.Until.Or(time.Time{}))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return &oas.FindingsPostFindingsStatusOK{Updated: n, Skipped: skipped}, nil
}

// Guidance is the optional "What to do" provider. mitigation registers one with FindingHandlers.SetGuidance
// while it is on; without one the "What to do" fields of a finding are null or empty (POST-3).
type Guidance interface {
	Guidance(ctx context.Context, r Row) (Guide, error)
}

// FindingsGetFindingsPlan implements findings_get_findings_plan (S-TIER-1, S-TIER-2; D-613, D-615, D-616, D-617): "Updates to
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
	day := func(t time.Time) *string {
		if t.IsZero() {
			return nil
		}
		d := t.UTC().Format(time.DateOnly)
		return &d
	}
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
	cut := h.svc.now().Add(-AgeLimit).UTC().Format(time.DateOnly)
	items, ids, old := []any{}, []string{}, 0
	type shown struct {
		it   PlanItem
		cves []PlanCVE
	}
	var keep []shown
	for _, it := range view.Items {
		if !feedsOn || asset != "" && it.AssetID != asset {
			continue
		}
		var cves []PlanCVE
		for _, c := range it.CVEs {
			// a CVE that crossed the 12-month line since the pass is not listed (review r1 #2 of #804): only a scan may list an older
			// one, and no scan basis exists yet (D-617 (2))
			if c.Published < cut && c.Basis != "scan" {
				continue
			}
			if tier == "all" || c.Tier == tier {
				cves = append(cves, c)
			}
		}
		if len(cves) == 0 {
			continue
		}
		keep = append(keep, shown{it, cves})
		if !slices.Contains(ids, it.AssetID) {
			ids = append(ids, it.AssetID)
		}
	}
	names, err := h.inv.Assets(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the devices of the plan: %w", err)
	}
	for _, k := range keep {
		a, ok := names[k.it.AssetID]
		if !ok {
			continue // deleted since the last pass
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
		items = append(items, map[string]any{"group": k.it.Group, "asset": map[string]any{"id": a.ID, "name": a.Name}, "software": k.it.Software,
			"version": k.it.Version, "fixed": k.it.Fixed, "kind": k.it.Kind, "cves": k.cves, "likely": likely, "recent": len(k.cves) - likely})
	}
	return Into[oas.FindingsGetFindingsPlanOK](map[string]any{
		"items": items, "compared": view.Ran, "compared_devices": view.Compared, "unchecked_devices": view.Unchecked, "old_evidence": old,
		"data": map[string]any{"epss": state(st.EPSS), "recent": state(st.Recent), "epss_date": day(st.EPSSDate), "recent_since": day(st.RecentSince)},
	})
}
