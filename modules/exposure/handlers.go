package exposure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ExposureHandlers implements the 19 exposure operations (modules/exposure/CONTRACT.md). Embed it in the
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
	ignored, err := h.svc.Ignored(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ExposureGetExposureTargetsOK](struct {
		Items   []TargetView `json:"items"`
		BoxIP   BoxIP        `json:"box_ip"`
		Ignored []IgnoredIP  `json:"ignored"`
		Gateway *GatewayView `json:"gateway"`
	}{items, box, ignored, h.svc.GatewayNote(ctx, items)})
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
// With ?ignore=true an IP also goes on the Ignored list (D-79 (3)).
func (h *ExposureHandlers) ExposureDeleteExposureTargetsID(ctx context.Context, params oas.ExposureDeleteExposureTargetsIDParams) error {
	user, err := actor(ctx)
	if err != nil {
		return err
	}
	ignore := params.Ignore.Set && params.Ignore.Value == oas.ExposureDeleteExposureTargetsIDIgnoreTrue
	return ToAPIError(h.svc.Remove(ctx, user, params.ID, ignore))
}

// ExposureDeleteExposureBoxIPIgnoredIP implements exposure_delete_exposure_box_ip_ignored_ip: Restore (admin). It only
// lets detection add the IP again.
func (h *ExposureHandlers) ExposureDeleteExposureBoxIPIgnoredIP(ctx context.Context, params oas.ExposureDeleteExposureBoxIPIgnoredIPParams) error {
	user, err := actor(ctx)
	if err != nil {
		return err
	}
	return ToAPIError(h.svc.Restore(ctx, user, params.IP))
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

// ExposurePostExposureTargetsIDScan implements exposure_post_exposure_targets_id_scan (operator): the gate answers synchronously as always,
// then the scan starts in the background and the answer is 202 with the run (INV-18). For the first scan of a target an
// administrator's press is the D-26 confirmation (D-473): the body carries the notice version the page showed.
func (h *ExposureHandlers) ExposurePostExposureTargetsIDScan(ctx context.Context, req oas.OptExposurePostExposureTargetsIDScanReq, params oas.ExposurePostExposureTargetsIDScanParams) (*oas.ExposurePostExposureTargetsIDScanAccepted, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	who := Actor{ID: p.ID, Email: p.Email, Admin: p.Role == routes.Admin}
	run, err := h.svc.StartScan(ctx, who, params.ID, req.Value.NoticeVersion.Value)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTargetsIDScanAccepted](run)
}

// ExposurePutExposureTargetsIDTerms implements exposure_put_exposure_targets_id_terms (admin with two-step): accept the testing terms
// of a verified target, with or without the disruptive tick (FULL-1, D-566).
func (h *ExposureHandlers) ExposurePutExposureTargetsIDTerms(ctx context.Context, req *oas.ExposurePutExposureTargetsIDTermsReq, params oas.ExposurePutExposureTargetsIDTermsParams) (*oas.ExposurePutExposureTargetsIDTermsOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	v, err := h.svc.AcceptTerms(ctx, Actor{ID: p.ID, Email: p.Email, Admin: p.Role == routes.Admin}, params.ID, req.Version, req.Disruptive)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePutExposureTargetsIDTermsOK](v)
}

// ExposureDeleteExposureTargetsIDTerms implements exposure_delete_exposure_targets_id_terms (admin): withdraw the testing terms.
func (h *ExposureHandlers) ExposureDeleteExposureTargetsIDTerms(ctx context.Context, params oas.ExposureDeleteExposureTargetsIDTermsParams) (*oas.ExposureDeleteExposureTargetsIDTermsOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.RevokeTerms(ctx, user, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureDeleteExposureTargetsIDTermsOK](v)
}

// ExposureGetExposureScan implements exposure_get_exposure_scan (viewer): the run that runs now or the last one, null before the first.
func (h *ExposureHandlers) ExposureGetExposureScan(_ context.Context) (oas.NilExposureGetExposureScanOK, error) {
	run := h.svc.CurrentScan()
	if run == nil {
		return oas.NilExposureGetExposureScanOK{Null: true}, nil
	}
	out, err := into[oas.ExposureGetExposureScanOK](*run)
	if err != nil {
		return oas.NilExposureGetExposureScanOK{}, err
	}
	return oas.NewNilExposureGetExposureScanOK(*out), nil
}

// ExposurePostExposureScanStop implements exposure_post_exposure_scan_stop (operator): cancels the run that runs now; 409 not_running when none does.
func (h *ExposureHandlers) ExposurePostExposureScanStop(ctx context.Context) (*oas.ExposurePostExposureScanStopOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	run, ok := h.svc.StopScan(ctx, user)
	if !ok {
		return nil, ToAPIError(ErrNotRunning)
	}
	return into[oas.ExposurePostExposureScanStopOK](run)
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

// ExposureGetExposureTargetsIDOutside implements exposure_get_exposure_targets_id_outside (viewer): Shodan's last answer about this
// IP of the box, null when nobody has asked (D-558, INV-21). It sends nothing.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDOutside(ctx context.Context, params oas.ExposureGetExposureTargetsIDOutsideParams) (oas.NilExposureGetExposureTargetsIDOutsideOK, error) {
	v, err := h.svc.Outside(ctx, params.ID)
	if err != nil {
		return oas.NilExposureGetExposureTargetsIDOutsideOK{}, ToAPIError(err)
	}
	if v == nil {
		return oas.NilExposureGetExposureTargetsIDOutsideOK{Null: true}, nil
	}
	out, err := into[oas.ExposureGetExposureTargetsIDOutsideOK](*v)
	if err != nil {
		return oas.NilExposureGetExposureTargetsIDOutsideOK{}, err
	}
	return oas.NewNilExposureGetExposureTargetsIDOutsideOK(*out), nil
}

// ExposurePostExposureTargetsIDOutside implements exposure_post_exposure_targets_id_outside (admin): an administrator's click sends
// this IP of the box to Shodan InternetDB (D-558, INV-21).
func (h *ExposureHandlers) ExposurePostExposureTargetsIDOutside(ctx context.Context, params oas.ExposurePostExposureTargetsIDOutsideParams) (*oas.ExposurePostExposureTargetsIDOutsideOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.CheckOutside(ctx, user, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTargetsIDOutsideOK](v)
}

// ExposureGetExposureGreenbone implements exposure_get_exposure_greenbone: the optional deep scan's state and this box's preflight.
func (h *ExposureHandlers) ExposureGetExposureGreenbone(ctx context.Context) (*oas.ExposureGetExposureGreenboneOK, error) {
	v, err := h.svc.GreenboneSetting(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ExposureGetExposureGreenboneOK](v)
}

// ExposurePutExposureGreenbone implements exposure_put_exposure_greenbone: turn Greenbone on or off (admin).
func (h *ExposureHandlers) ExposurePutExposureGreenbone(ctx context.Context, req *oas.ExposurePutExposureGreenboneReq) (*oas.ExposurePutExposureGreenboneOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetGreenbone(ctx, user, req.Enabled)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePutExposureGreenboneOK](v)
}
