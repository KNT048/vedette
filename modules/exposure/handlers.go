package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ExposureHandlers implements the exposure operations (modules/exposure/CONTRACT.md). Embed it in the
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

// ExposurePostExposureTargets implements exposure_post_exposure_targets: add a domain or a public IP (admin).
func (h *ExposureHandlers) ExposurePostExposureTargets(ctx context.Context, req *oas.ExposurePostExposureTargetsReq) (*oas.ExposurePostExposureTargetsCreated, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddTarget(ctx, user, Kind(req.Kind.Value), req.Value)
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
// With ?ignore=true an IP also goes on the Ignored list.
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
// administrator's press is the commitment confirmation: the body carries the notice version the page showed.
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

// ExposurePostExposureTargetsIDOpenvas implements exposure_post_exposure_targets_id_openvas: OpenVAS on its own is not a kind of
// run yet, so it answers 501 not_implemented.
func (h *ExposureHandlers) ExposurePostExposureTargetsIDOpenvas(context.Context, oas.ExposurePostExposureTargetsIDOpenvasParams) (*oas.ExposurePostExposureTargetsIDOpenvasAccepted, error) {
	return nil, ToAPIError(ErrNotImplemented)
}

// ExposurePutExposureTargetsIDTerms implements exposure_put_exposure_targets_id_terms (admin with two-step): accept the testing terms
// of a verified target, with or without the disruptive tick.
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

// ExposureDeleteExposureTargetsIDQueue implements exposure_delete_exposure_targets_id_queue (operator): the scan of the target that
// waits in the queue leaves it (INV-36).
func (h *ExposureHandlers) ExposureDeleteExposureTargetsIDQueue(ctx context.Context, params oas.ExposureDeleteExposureTargetsIDQueueParams) error {
	user, err := actor(ctx)
	if err != nil {
		return err
	}
	return ToAPIError(h.svc.Unqueue(ctx, user, params.ID))
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
func (h *ExposureHandlers) ExposureGetExposureScan(ctx context.Context) (oas.NilExposureGetExposureScanOK, error) {
	run := h.svc.CurrentScan(ctx)
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

// ExposureGetExposureTargetsIDSnapshots implements exposure_get_exposure_targets_id_snapshots: results are rows now
// (GET /exposure/tree/{id}/services, issues, hosts, addresses, scans), so the snapshots answer 501 not_implemented.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDSnapshots(context.Context, oas.ExposureGetExposureTargetsIDSnapshotsParams) (*oas.ExposureGetExposureTargetsIDSnapshotsOK, error) {
	return nil, ToAPIError(ErrNotImplemented)
}

// ExposureGetExposureTargetsIDSnapshotsDate implements exposure_get_exposure_targets_id_snapshots_date: 501, see the snapshots.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDSnapshotsDate(context.Context, oas.ExposureGetExposureTargetsIDSnapshotsDateParams) (*oas.ExposureGetExposureTargetsIDSnapshotsDateOK, error) {
	return nil, ToAPIError(ErrNotImplemented)
}

// ExposureGetExposureTargetsIDDiff implements exposure_get_exposure_targets_id_diff: what changed is first and last seen and the
// state of each row, so the diff of two days answers 501 not_implemented.
func (h *ExposureHandlers) ExposureGetExposureTargetsIDDiff(context.Context, oas.ExposureGetExposureTargetsIDDiffParams) (*oas.ExposureGetExposureTargetsIDDiffOK, error) {
	return nil, ToAPIError(ErrNotImplemented)
}

// ExposureGetExposureTargetsIDOutside implements exposure_get_exposure_targets_id_outside (viewer): Shodan's last answer about this
// IP of the box, null when nobody has asked (INV-21). It sends nothing.
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
// this IP of the box to Shodan InternetDB (INV-21).
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

// ---- the target tree: the rows of a node ----

// items is the {items} answer of a list.
type items[T any] struct {
	Items []T `json:"items"`
}

// ExposureGetExposureTreeIDScans implements exposure_get_exposure_tree_id_scans (viewer): the runs of the node, newest first.
func (h *ExposureHandlers) ExposureGetExposureTreeIDScans(ctx context.Context, params oas.ExposureGetExposureTreeIDScansParams) (*oas.ExposureGetExposureTreeIDScansOK, error) {
	v, err := h.svc.Scans(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeIDScansOK](items[ScanView]{v})
}

// ExposureGetExposureTreeIDHosts implements exposure_get_exposure_tree_id_hosts (viewer): the names found under the node.
func (h *ExposureHandlers) ExposureGetExposureTreeIDHosts(ctx context.Context, params oas.ExposureGetExposureTreeIDHostsParams) (*oas.ExposureGetExposureTreeIDHostsOK, error) {
	v, err := h.svc.Hosts(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeIDHostsOK](items[HostView]{v})
}

// ExposureGetExposureTreeIDAddresses implements exposure_get_exposure_tree_id_addresses (viewer): the addresses of the node and its names.
func (h *ExposureHandlers) ExposureGetExposureTreeIDAddresses(ctx context.Context, params oas.ExposureGetExposureTreeIDAddressesParams) (*oas.ExposureGetExposureTreeIDAddressesOK, error) {
	v, err := h.svc.Addresses(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeIDAddressesOK](items[AddressView]{v})
}

// ExposureGetExposureTreeIDServices implements exposure_get_exposure_tree_id_services (viewer): the services, open and closed.
func (h *ExposureHandlers) ExposureGetExposureTreeIDServices(ctx context.Context, params oas.ExposureGetExposureTreeIDServicesParams) (*oas.ExposureGetExposureTreeIDServicesOK, error) {
	v, err := h.svc.Services(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeIDServicesOK](items[ServiceView]{v})
}

// ExposureGetExposureTreeIDIssues implements exposure_get_exposure_tree_id_issues (viewer): the issues of every engine.
func (h *ExposureHandlers) ExposureGetExposureTreeIDIssues(ctx context.Context, params oas.ExposureGetExposureTreeIDIssuesParams) (*oas.ExposureGetExposureTreeIDIssuesOK, error) {
	v, err := h.svc.Issues(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeIDIssuesOK](items[IssueView]{v})
}

// ExposurePostExposureTreeIDScan implements exposure_post_exposure_tree_id_scan (operator): Scan now queues a run of the node; 202 with
// the scan. The refusals are those of POST /exposure/targets/{id}/scan.
func (h *ExposureHandlers) ExposurePostExposureTreeIDScan(ctx context.Context, req oas.OptExposurePostExposureTreeIDScanReq, params oas.ExposurePostExposureTreeIDScanParams) (*oas.ExposurePostExposureTreeIDScanAccepted, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	who := Actor{ID: p.ID, Email: p.Email, Admin: p.Role == routes.Admin}
	run, err := h.svc.StartScan(ctx, who, params.ID, req.Value.NoticeVersion.Value)
	if err != nil {
		return nil, ToAPIError(err)
	}
	v, err := h.svc.scanView(ctx, run.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTreeIDScanAccepted](v)
}

// ExposureGetExposureTree implements exposure_get_exposure_tree (viewer): every target as a node of the tree, with the box-IP settings,
// the Ignored list and the gateway.
func (h *ExposureHandlers) ExposureGetExposureTree(ctx context.Context) (*oas.ExposureGetExposureTreeOK, error) {
	v, err := h.svc.Tree(ctx)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeOK](v)
}

// ExposurePostExposureTree implements exposure_post_exposure_tree (admin): add a domain (under its nearest parent, with its scope) or a
// typed public IP.
func (h *ExposureHandlers) ExposurePostExposureTree(ctx context.Context, req *oas.ExposurePostExposureTreeReq) (*oas.ExposurePostExposureTreeCreated, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddNode(ctx, user, NewNode{Kind: Kind(req.Kind.Value), Value: req.Value, Scope: ScopeMode(req.ScopeMode.Value)})
	if err != nil {
		return nil, ToAPIError(err)
	}
	n, err := h.svc.Node(ctx, v.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTreeCreated](n)
}

// ExposureGetExposureTreeID implements exposure_get_exposure_tree_id (viewer): one node.
func (h *ExposureHandlers) ExposureGetExposureTreeID(ctx context.Context, params oas.ExposureGetExposureTreeIDParams) (*oas.ExposureGetExposureTreeIDOK, error) {
	n, err := h.svc.Node(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureGetExposureTreeIDOK](n)
}

// ExposurePatchExposureTreeID implements exposure_patch_exposure_tree_id (admin): the scope, the switch and the chosen names.
func (h *ExposureHandlers) ExposurePatchExposureTreeID(ctx context.Context, req *oas.ExposurePatchExposureTreeIDReq, params oas.ExposurePatchExposureTreeIDParams) (*oas.ExposurePatchExposureTreeIDOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var e NodeEdit
	if req.ScopeMode.Set {
		m := ScopeMode(req.ScopeMode.Value)
		e.Scope = &m
	}
	if req.Enabled.Set {
		on := req.Enabled.Value
		e.Enabled = &on
	}
	if req.Selected != nil {
		sel := req.Selected
		e.Selected = &sel
	}
	if _, err := h.svc.EditNode(ctx, user, params.ID, e); err != nil {
		return nil, ToAPIError(err)
	}
	n, err := h.svc.Node(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePatchExposureTreeIDOK](n)
}

// ExposureDeleteExposureTreeID implements exposure_delete_exposure_tree_id (admin): the node goes with its rows, consents and schedule; its
// children move up. ?ignore=true also puts an IP on the Ignored list.
func (h *ExposureHandlers) ExposureDeleteExposureTreeID(ctx context.Context, params oas.ExposureDeleteExposureTreeIDParams) error {
	user, err := actor(ctx)
	if err != nil {
		return err
	}
	ignore := params.Ignore.Set && params.Ignore.Value == oas.ExposureDeleteExposureTreeIDIgnoreTrue
	return ToAPIError(h.svc.Remove(ctx, user, params.ID, ignore))
}

// ExposurePostExposureTreeIDVerify implements exposure_post_exposure_tree_id_verify (operator): check the ownership proof now.
func (h *ExposureHandlers) ExposurePostExposureTreeIDVerify(ctx context.Context, params oas.ExposurePostExposureTreeIDVerifyParams) (*oas.ExposurePostExposureTreeIDVerifyOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Verify(ctx, user, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	n, err := h.svc.Node(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureTreeIDVerifyOK](struct {
		Verified bool     `json:"verified"`
		Message  string   `json:"message"`
		Node     NodeView `json:"node"`
	}{r.Verified, r.Message, n})
}

// ExposurePutExposureTreeIDTerms implements exposure_put_exposure_tree_id_terms (admin with two-step): accept the testing terms.
func (h *ExposureHandlers) ExposurePutExposureTreeIDTerms(ctx context.Context, req *oas.ExposurePutExposureTreeIDTermsReq, params oas.ExposurePutExposureTreeIDTermsParams) (*oas.ExposurePutExposureTreeIDTermsOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if _, err := h.svc.AcceptTerms(ctx, Actor{ID: p.ID, Email: p.Email, Admin: p.Role == routes.Admin}, params.ID, req.Version, req.Disruptive); err != nil {
		return nil, ToAPIError(err)
	}
	n, err := h.svc.Node(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePutExposureTreeIDTermsOK](n)
}

// ExposureDeleteExposureTreeIDTerms implements exposure_delete_exposure_tree_id_terms (admin): withdraw the testing terms.
func (h *ExposureHandlers) ExposureDeleteExposureTreeIDTerms(ctx context.Context, params oas.ExposureDeleteExposureTreeIDTermsParams) (*oas.ExposureDeleteExposureTreeIDTermsOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.svc.RevokeTerms(ctx, user, params.ID); err != nil {
		return nil, ToAPIError(err)
	}
	n, err := h.svc.Node(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposureDeleteExposureTreeIDTermsOK](n)
}

// ExposurePostExposureIssuesHandle implements exposure_post_exposure_issues_handle (operator): handle open issues with one resolution.
func (h *ExposureHandlers) ExposurePostExposureIssuesHandle(ctx context.Context, req *oas.ExposurePostExposureIssuesHandleReq) (*oas.ExposurePostExposureIssuesHandleOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	until := ""
	if req.AcceptedUntil.Set {
		until = req.AcceptedUntil.Value.Format(time.DateOnly)
	}
	r, err := h.svc.HandleIssues(ctx, user, req.Ids, Resolution(req.Resolution), req.Note, until)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureIssuesHandleOK](r)
}

// ExposurePostExposureIssuesReopen implements exposure_post_exposure_issues_reopen (operator): reopen handled issues.
func (h *ExposureHandlers) ExposurePostExposureIssuesReopen(ctx context.Context, req *oas.ExposurePostExposureIssuesReopenReq) (*oas.ExposurePostExposureIssuesReopenOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.ReopenIssues(ctx, user, req.Ids)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ExposurePostExposureIssuesReopenOK](r)
}
