package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// MitigationModule is the id of the module whose Guidance fills the "What to do" fields.
const MitigationModule = "mitigation"

// FeedsModule is the id of the feeds module (the catalogue the match pass reads).
const FeedsModule = "feeds"

// FindingHandlers implements the findings operations: the lists, the finding's View and detail, handling, Home. Embed it in the
// composite handler. POST /findings/{id}/applied|ai belong to mitigation (core/server/modules.go).
type FindingHandlers struct {
	svc  *Service
	inv  Inventory
	feed Feeds
	gate server.ModuleGate

	mu           sync.RWMutex
	guide        Guidance
	scanReach    ScanReach
	summaryState // GET /findings/overview (overview.go); ov and home under mu
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
	} else if found && d.SoftwareID != "" {
		// A finding on no exploited list (update recommended) has no entry to match again: its stored line is the row, so the page
		// and the guidance still say the version the box has and name the software instead of "the software".
		if l, ok := deviceLines(a)[d.SoftwareID]; ok {
			row, matched = l.sw, true
		}
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
	if rec.Status.Open() && v == nil && d.Kev == nil && matched {
		v = h.catalogueEntry(ctx, rec.CVE)
		if v != nil {
			// A finding on no exploited list: its fix is read on its own line, as the match pass stored it (FixOf), so the page names the
			// same release, the distribution's fixed package and a kernel's restart as every list, and the distribution as its source.
			d.FixedIn = FixedInOn(a, row, *v)
		}
		return d, nil
	}
	if rec.Status.Open() && v != nil {
		d.FixedIn = FixedInFor(a, *v) // the release that fixes it on this device, from NVD's ranges; closed: nothing to upgrade
	}
	return d, nil
}

// catalogueEntry is the catalogue's entry of one CVE on no exploited list (its ranges and the distributions' word on it), as the match
// pass compares it; nil when the feeds have none or cannot be read (the page then shows what it always had).
func (h *FindingHandlers) catalogueEntry(ctx context.Context, cve string) *Vuln {
	vulns, err := h.feed.MatchSet(ctx, MatchScope{Pinned: []string{cve}})
	if err != nil {
		return nil
	}
	for i := range vulns {
		if vulns[i].CVE == cve {
			return &vulns[i]
		}
	}
	return nil
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

// matchedRow names the device's software row the finding's KEV entry is keyed to, as the matcher reads the device (its rows and the
// network OS it states, deviceSoftware), not the device's first software by name; ok is false when there is none. With the stored entry, the row the matcher matches
// it on (the finding's row, as FixedInFor reads it: a version match through NVD's list beats a keyed row's product match,
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

// DetailByID is Detail for a finding id; an unknown id is a 404 API error.
func (h *FindingHandlers) DetailByID(ctx context.Context, id string) (Detail, error) {
	rec, err := h.svc.Get(ctx, id)
	if err != nil {
		return Detail{}, ToAPIError(err)
	}
	return h.Detail(ctx, rec)
}

// FindingsGetFindings implements findings_get_findings: one device's findings in every state, newest first, each with its history
// (?asset= is required). The web reads it before and after a version entry, "I updated it" or "Not installed" to say what changed.
func (h *FindingHandlers) FindingsGetFindings(ctx context.Context, params oas.FindingsGetFindingsParams) (*oas.FindingsGetFindingsOK, error) {
	recs, err := h.svc.List(ctx, params.Asset)
	if err != nil {
		return nil, err
	}
	rows, err := h.rows(ctx, recs)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsGetFindingsOK](struct {
		Items []Row `json:"items"`
	}{rows})
}

// FindingsGetFindingsID implements findings_get_findings_id.
func (h *FindingHandlers) FindingsGetFindingsID(ctx context.Context, params oas.FindingsGetFindingsIDParams) (*oas.FindingsGetFindingsIDOK, error) {
	d, err := h.DetailByID(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsGetFindingsIDOK](d)
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
