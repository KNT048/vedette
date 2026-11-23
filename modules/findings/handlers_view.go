package findings

import (
	"context"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// The handlers of the findings model (contract.ts, "The findings model"): the lists grouped on the server, the view of one finding,
// handling, the queue's answers and Home's overview. Each answer goes through Into, so a drift from the contract fails loudly.

// FindingsGetFindingsDevices implements findings_get_findings_devices (By device, and the Ignored devices tab).
func (h *FindingHandlers) FindingsGetFindingsDevices(ctx context.Context, p oas.FindingsGetFindingsDevicesParams) (*oas.FindingsGetFindingsDevicesOK, error) {
	layers, err := parseLayers(p.Status.Or(""))
	if err != nil {
		return nil, ToAPIError(err)
	}
	f := ListFilter{Layers: layers, Device: p.Device.Or(""), Ignored: string(p.Ignored.Or("")) == "true", Q: p.Q.Or("")}
	out, err := h.svc.ByDevice(ctx, f, ParsePage(p.Offset.Or(""), p.Limit.Or("")))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsDevicesOK](out)
}

// FindingsGetFindingsFixes implements findings_get_findings_fixes (By fix).
func (h *FindingHandlers) FindingsGetFindingsFixes(ctx context.Context, p oas.FindingsGetFindingsFixesParams) (*oas.FindingsGetFindingsFixesOK, error) {
	layers, err := parseLayers(p.Status.Or(""))
	if err != nil {
		return nil, ToAPIError(err)
	}
	out, err := h.svc.ByFix(ctx, ListFilter{Layers: layers, Q: p.Q.Or("")}, ParsePage(p.Offset.Or(""), p.Limit.Or("")))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsFixesOK](out)
}

// FindingsGetFindingsInput implements findings_get_findings_input (Needs your input).
func (h *FindingHandlers) FindingsGetFindingsInput(ctx context.Context, p oas.FindingsGetFindingsInputParams) (*oas.FindingsGetFindingsInputOK, error) {
	out, err := h.svc.Input(ctx, p.Device.Or(""), ParsePage(p.Offset.Or(""), p.Limit.Or("")))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsInputOK](out)
}

// FindingsGetFindingsHandled implements findings_get_findings_handled (Handled).
func (h *FindingHandlers) FindingsGetFindingsHandled(ctx context.Context, p oas.FindingsGetFindingsHandledParams) (*oas.FindingsGetFindingsHandledOK, error) {
	rs, err := parseResolutions(p.Resolution.Or(""))
	if err != nil {
		return nil, ToAPIError(err)
	}
	f := HandledFilter{Q: p.Q.Or(""), Resolutions: rs, Device: p.Device.Or(""), From: p.From.Or(time.Time{}), To: p.To.Or(time.Time{})}
	out, err := h.svc.Handled(ctx, f, ParsePage(p.Offset.Or(""), p.Limit.Or("")))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsHandledOK](out)
}

// FindingsGetFindingsOverview implements findings_get_findings_overview (Home and the nav badges).
func (h *FindingHandlers) FindingsGetFindingsOverview(ctx context.Context) (*oas.FindingsGetFindingsOverviewOK, error) {
	o, err := h.Overview(ctx)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsOverviewOK](o)
}

// FindingsGetFindingsIDView implements findings_get_findings_id_view.
func (h *FindingHandlers) FindingsGetFindingsIDView(ctx context.Context, p oas.FindingsGetFindingsIDViewParams) (*oas.FindingsGetFindingsIDViewOK, error) {
	v, err := h.svc.View(ctx, p.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsIDViewOK](v.JSON())
}

// cleanNote refuses a note with a NUL or a control character other than a newline or a tab.
func cleanNote(note string) error {
	if strings.ContainsFunc(note, func(r rune) bool { return r == 0 || unicode.IsControl(r) && r != '\n' && r != '\t' }) {
		return apierr.Invalid("The note contains a character that is not allowed.")
	}
	return nil
}

// FindingsPostFindingsHandle implements findings_post_findings_handle (operator): findings of one device, by ids or by one of its fixes.
func (h *FindingHandlers) FindingsPostFindingsHandle(ctx context.Context, req *oas.FindingsPostFindingsHandleReq) (*oas.FindingsPostFindingsHandleOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := cleanNote(req.Note); err != nil {
		return nil, err
	}
	device, fix := req.Device.Or(""), req.Fix.Or("")
	ids := req.Ids
	switch {
	case len(ids) > 0 && (device != "" || fix != ""):
		return nil, apierr.Invalid("Name the findings by their ids, or by a device and one of its fixes, not both.")
	case len(ids) == 0 && (device == "" || fix == ""):
		return nil, apierr.Invalid("Name the findings by their ids, or by a device and one of its fixes.")
	case len(ids) == 0:
		var err error
		if ids, err = h.svc.FixFindings(ctx, device, fix); err != nil {
			return nil, ToAPIError(err)
		}
		if len(ids) == 0 {
			return &oas.FindingsPostFindingsHandleOK{}, nil // nothing open under that fix any more: nothing to do
		}
	}
	res := Resolution(req.Resolution)
	until := req.Until.Or(time.Time{})
	if res == ResolutionAccepted {
		if err := validUntil(until, h.svc.now()); err != nil {
			return nil, ToAPIError(err)
		}
	} else if !until.IsZero() {
		return nil, ToAPIError(ErrBadUntil)
	}
	n, skipped, err := h.svc.Handle(ctx, ids, res, req.Note, until, p.Email)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return &oas.FindingsPostFindingsHandleOK{Handled: n, Skipped: skipped}, nil
}

// FindingsPostFindingsIDReopen implements findings_post_findings_id_reopen (operator).
func (h *FindingHandlers) FindingsPostFindingsIDReopen(ctx context.Context, req *oas.FindingsPostFindingsIDReopenReq, params oas.FindingsPostFindingsIDReopenParams) (*oas.FindingsPostFindingsIDReopenOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := cleanNote(req.Note); err != nil {
		return nil, err
	}
	if _, err := h.svc.Reopen(ctx, params.ID, req.Note, p.Email); err != nil {
		return nil, ToAPIError(err)
	}
	v, err := h.svc.View(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsPostFindingsIDReopenOK](v.JSON())
}

// FindingsPostFindingsIDVerify implements findings_post_findings_id_verify (admin): Confirm vulnerability on a person's word.
func (h *FindingHandlers) FindingsPostFindingsIDVerify(ctx context.Context, req *oas.FindingsPostFindingsIDVerifyReq, params oas.FindingsPostFindingsIDVerifyParams) (*oas.FindingsPostFindingsIDVerifyOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := cleanNote(req.Note); err != nil {
		return nil, err
	}
	if _, err := h.svc.Verify(ctx, params.ID, req.Note, p.Email); err != nil {
		return nil, ToAPIError(err)
	}
	v, err := h.svc.View(ctx, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsPostFindingsIDVerifyOK](v.JSON())
}

// FindingsPostFindingsQuestionsIDAnswer implements findings_post_findings_questions_id_answer: not affected (operator) closes the
// question; affected records a finding confirmed by the person and needs an admin, as Confirm vulnerability does.
func (h *FindingHandlers) FindingsPostFindingsQuestionsIDAnswer(ctx context.Context, req *oas.FindingsPostFindingsQuestionsIDAnswerReq, params oas.FindingsPostFindingsQuestionsIDAnswerParams) (*oas.FindingsPostFindingsQuestionsIDAnswerOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := cleanNote(req.Note); err != nil {
		return nil, err
	}
	answer := string(req.Answer)
	if answer == AnswerAffected && p.Role != routes.Admin {
		return nil, apierr.Forbidden()
	}
	id, err := h.svc.AnswerQuestion(ctx, params.ID, answer, req.Note, p.Email)
	if err != nil {
		return nil, ToAPIError(err)
	}
	out := &oas.FindingsPostFindingsQuestionsIDAnswerOK{Finding: oas.NilString{Null: true}}
	if id != "" {
		out.Finding = oas.NewNilString(id)
	}
	return out, nil
}
