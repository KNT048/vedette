package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// MitigationModule is the id of the module whose Guidance fills the "What to do" fields.
const MitigationModule = "mitigation"

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
	return d, nil
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

// FindingsPostFindingsIDStatus implements findings_post_findings_id_status (operator).
func (h *FindingHandlers) FindingsPostFindingsIDStatus(ctx context.Context, req *oas.FindingsPostFindingsIDStatusReq, params oas.FindingsPostFindingsIDStatusParams) (*oas.FindingsPostFindingsIDStatusOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if strings.ContainsRune(req.Note, 0) {
		return nil, apierr.Invalid("The note contains a character that is not allowed.")
	}
	rec, err := h.svc.SetStatus(ctx, params.ID, Action(req.Action), req.Note, p.Email)
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
	n, skipped, err := h.svc.SetStatusMany(ctx, req.Ids, Action(req.Action), req.Note, p.Email)
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
