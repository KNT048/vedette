package exposure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ExposureHandlers implements the 12 exposure operations (modules/exposure/CONTRACT.md). Embed it in the
// composite handler. Roles are enforced by the server pipeline before a handler runs, never here.
//
//nolint:revive // the name is distinct on purpose: it is embedded in cmd/vedette next to inventory.Handlers
type ExposureHandlers struct {
	svc *Service
}

// NewExposureHandlers returns the handlers of svc.
func NewExposureHandlers(svc *Service) *ExposureHandlers { return &ExposureHandlers{svc: svc} }

// into turns a value of this package into the generated response type of an operation. The generated
// decoder rejects anything that does not fit the OpenAPI schema, so a drift between this code and the
// contract fails loudly instead of sending a wrong body.
func into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("exposure: encoding response: %w", err)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("exposure: response does not fit the API schema: %w", err)
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

// ExposureGetExposureTargets implements exposure_get_exposure_targets: every target and the auto-detect state.
func (h *ExposureHandlers) ExposureGetExposureTargets(ctx context.Context) (*oas.ExposureGetExposureTargetsOK, error) {
	items, err := h.svc.Targets(ctx)
	if err != nil {
		return nil, err
	}
	box, err := h.svc.Settings(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ExposureGetExposureTargetsOK](struct {
		Items []TargetView `json:"items"`
		BoxIP BoxIP        `json:"box_ip"`
	}{items, box})
}

// ExposurePostExposureTargets implements exposure_post_exposure_targets: add a domain (admin).
func (h *ExposureHandlers) ExposurePostExposureTargets(ctx context.Context, req *oas.ExposurePostExposureTargetsReq) (*oas.ExposurePostExposureTargetsCreated, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddDomain(ctx, user, req.Value)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTargetsCreated](v)
}

// ExposurePostExposureBoxIPVerify implements exposure_post_exposure_box_ip_verify: "Detect now" (admin).
func (h *ExposureHandlers) ExposurePostExposureBoxIPVerify(ctx context.Context) (*oas.ExposurePostExposureBoxIPVerifyOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.attempt(ctx); err != nil {
		return nil, ToAPIError(err)
	}
	r, err := h.svc.Detect(ctx, user, true)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureBoxIPVerifyOK](r)
}

// ExposurePutExposureBoxIPSettings implements exposure_put_exposure_box_ip_settings: auto-detect on or off
// and its interval (admin).
func (h *ExposureHandlers) ExposurePutExposureBoxIPSettings(ctx context.Context, req *oas.ExposurePutExposureBoxIPSettingsReq) (*oas.ExposurePutExposureBoxIPSettingsOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	b, err := h.svc.SaveSettings(ctx, user, req.Auto, req.IntervalMin)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePutExposureBoxIPSettingsOK](b)
}

// ExposureGetExposureTargetsID implements exposure_get_exposure_targets_id.
func (h *ExposureHandlers) ExposureGetExposureTargetsID(ctx context.Context, params oas.ExposureGetExposureTargetsIDParams) (*oas.ExposureGetExposureTargetsIDOK, error) {
	v, err := h.svc.Target(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTargetsIDOK](v)
}

// ExposureDeleteExposureTargetsID implements exposure_delete_exposure_targets_id (admin). It is also how an
// IP leaves the inventory.
func (h *ExposureHandlers) ExposureDeleteExposureTargetsID(ctx context.Context, params oas.ExposureDeleteExposureTargetsIDParams) error {
	user, err := actor(ctx)
	if err != nil {
		return err
	}
	return ToAPIError(h.svc.Delete(ctx, user, params.ID))
}

// ExposurePostExposureTargetsIDVerify implements exposure_post_exposure_targets_id_verify (operator).
func (h *ExposureHandlers) ExposurePostExposureTargetsIDVerify(ctx context.Context, params oas.ExposurePostExposureTargetsIDVerifyParams) (*oas.ExposurePostExposureTargetsIDVerifyOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Verify(ctx, user, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTargetsIDVerifyOK](r)
}

// ExposurePostExposureTargetsIDCommitment implements exposure_post_exposure_targets_id_commitment (admin).
func (h *ExposureHandlers) ExposurePostExposureTargetsIDCommitment(ctx context.Context, req *oas.ExposurePostExposureTargetsIDCommitmentReq, params oas.ExposurePostExposureTargetsIDCommitmentParams) (*oas.ExposurePostExposureTargetsIDCommitmentOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Commit(ctx, user, params.ID, req.Confirm)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTargetsIDCommitmentOK](v)
}

// ExposurePostExposureTargetsIDScan implements exposure_post_exposure_targets_id_scan (operator).
func (h *ExposureHandlers) ExposurePostExposureTargetsIDScan(ctx context.Context, params oas.ExposurePostExposureTargetsIDScanParams) (*oas.ExposurePostExposureTargetsIDScanOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.svc.Scan(ctx, user, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTargetsIDScanOK](s)
}

// ExposureGetExposureTargetsIDSnapshots implements exposure_get_exposure_targets_id_snapshots.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDSnapshots(ctx context.Context, params oas.ExposureGetExposureTargetsIDSnapshotsParams) (*oas.ExposureGetExposureTargetsIDSnapshotsOK, error) {
	items, err := h.svc.Snapshots(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTargetsIDSnapshotsOK](struct {
		Items []SnapshotMeta `json:"items"`
	}{items})
}

// ExposureGetExposureTargetsIDSnapshotsDate implements exposure_get_exposure_targets_id_snapshots_date.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDSnapshotsDate(ctx context.Context, params oas.ExposureGetExposureTargetsIDSnapshotsDateParams) (*oas.ExposureGetExposureTargetsIDSnapshotsDateOK, error) {
	s, err := h.svc.SnapshotOf(ctx, params.ID, params.Date)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTargetsIDSnapshotsDateOK](s)
}

// ExposureGetExposureTargetsIDDiff implements exposure_get_exposure_targets_id_diff.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDDiff(ctx context.Context, params oas.ExposureGetExposureTargetsIDDiffParams) (*oas.ExposureGetExposureTargetsIDDiffOK, error) {
	d, err := h.svc.Diff(ctx, params.ID, params.From, params.To)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTargetsIDDiffOK](d)
}
