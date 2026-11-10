package scan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ScanHandlers implements the operations of the scan module (modules/scan/CONTRACT.md). Embed it in the composite
// handler. Roles are enforced by the server pipeline before a handler runs, never here.
//
//nolint:revive // the name is distinct on purpose: it is embedded in cmd/vedette next to the other modules' handlers
type ScanHandlers struct {
	svc *Service
}

// NewScanHandlers returns the handlers of svc.
func NewScanHandlers(svc *Service) *ScanHandlers { return &ScanHandlers{svc: svc} }

// into turns a value of this package into the generated response type of an operation. The generated decoder
// rejects anything that does not fit the OpenAPI schema, so a drift between this code and the contract fails loudly.
func into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("scan: encoding response: %w", err)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("scan: response does not fit the API schema: %w", err)
	}
	return &out, nil
}

// actor is the signed-in user the audit trail names.
func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// ScanGetScansConfig implements scan_get_scans_config (viewer).
func (h *ScanHandlers) ScanGetScansConfig(ctx context.Context) (*oas.ScanGetScansConfigOK, error) {
	v, err := h.svc.Config(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ScanGetScansConfigOK](v)
}

// ScanPutScansConfig implements scan_put_scans_config (admin): a partial update.
func (h *ScanHandlers) ScanPutScansConfig(ctx context.Context, req *oas.ScanPutScansConfigReq) (*oas.ScanPutScansConfigOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SaveConfig(ctx, user, patchOf(req))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ScanPutScansConfigOK](v)
}

func opt[T any](ok bool, v T) *T {
	if !ok {
		return nil
	}
	return &v
}

// patchOf turns the request into a Patch: an absent field keeps the stored value.
func patchOf(r *oas.ScanPutScansConfigReq) Patch {
	p := Patch{
		Rate:               opt(r.Rate.Set, r.Rate.Value),
		Exclusions:         r.Exclusions,
		StopOnUnresponsive: opt(r.StopOnUnresponsive.Set, r.StopOnUnresponsive.Value),
		UnresponsiveAfter:  opt(r.UnresponsiveAfter.Set, r.UnresponsiveAfter.Value),
		AutoRescan:         opt(r.AutoRescan.Set, r.AutoRescan.Value),
		DangerousChecks:    opt(r.DangerousChecks.Set, r.DangerousChecks.Value),
	}
	if w, ok := r.Window.Get(); ok {
		p.Days = w.Days
		p.From = opt(w.From.Set, w.From.Value)
		p.To = opt(w.To.Set, w.To.Value)
	}
	if s, ok := r.Schedule.Get(); ok {
		p.SchedEnabled = opt(s.Enabled.Set, s.Enabled.Value)
		p.SchedFrequency = opt(s.Frequency.Set, string(s.Frequency.Value))
		p.SchedWeekday = opt(s.Weekday.Set, s.Weekday.Value)
		p.SchedAt = opt(s.At.Set, s.At.Value)
	}
	return p
}
