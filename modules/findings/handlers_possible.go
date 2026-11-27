package findings

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// FindingsGetFindingsPossible implements findings_get_findings_possible: the possible CVEs, with the counts of the device or of all.
func (h *FindingHandlers) FindingsGetFindingsPossible(ctx context.Context, p oas.FindingsGetFindingsPossibleParams) (*oas.FindingsGetFindingsPossibleOK, error) {
	f := PossibleFilter{Device: p.Device.Or(""), Q: p.Q.Or("")}
	if st, ok := p.State.Get(); ok {
		f.State = string(st)
	}
	out, err := h.svc.Possible(ctx, f, ParsePage(p.Offset.Or(""), p.Limit.Or("")))
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsPossibleOK](out)
}

// FindingsGetFindingsPossibleAudit implements findings_get_findings_possible_audit: the possible CVEs by undecided reason.
func (h *FindingHandlers) FindingsGetFindingsPossibleAudit(ctx context.Context) (*oas.FindingsGetFindingsPossibleAuditOK, error) {
	groups, err := h.svc.PossibleAudit(ctx)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsGetFindingsPossibleAuditOK](map[string]any{"groups": groups})
}

// FindingsGetFindingsCoverage implements findings_get_findings_coverage (admin): the decision coverage of the last match pass, at null
// before the first one.
func (h *FindingHandlers) FindingsGetFindingsCoverage(context.Context) (*oas.FindingsGetFindingsCoverageOK, error) {
	c, ok := h.svc.Coverage()
	var at *time.Time
	if ok {
		at = &c.At
	}
	return Into[oas.FindingsGetFindingsCoverageOK](struct {
		Coverage
		At *time.Time `json:"at"`
	}{c, at})
}

// possibleCheckState is contract.ts PossibleCheckState.
type possibleCheckState struct {
	Ready  bool      `json:"ready"`
	Reason *string   `json:"reason"`
	Run    *CheckRun `json:"run"`
}

// FindingsGetFindingsPossibleCheck implements findings_get_findings_possible_check: whether a check can run and how the last stands.
func (h *FindingHandlers) FindingsGetFindingsPossibleCheck(ctx context.Context) (*oas.FindingsGetFindingsPossibleCheckOK, error) {
	run, ready := h.svc.CheckStatus(ctx)
	out := possibleCheckState{Ready: ready == nil, Run: run}
	if ready != nil {
		msg := ready.Error()
		out.Reason = &msg
	}
	return Into[oas.FindingsGetFindingsPossibleCheckOK](out)
}

// FindingsPostFindingsPossibleCheck implements findings_post_findings_possible_check (operator): starts a check in the background.
func (h *FindingHandlers) FindingsPostFindingsPossibleCheck(ctx context.Context, req *oas.FindingsPostFindingsPossibleCheckReq) (*oas.FindingsPostFindingsPossibleCheckOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	run, err := h.svc.StartPossibleCheck(ctx, req.Device.Or(""), p.Email)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return Into[oas.FindingsPostFindingsPossibleCheckOK](run)
}

// FindingsPostFindingsPossibleIDConfirm implements findings_post_findings_possible_id_confirm: a person confirms one AI proposal.
func (h *FindingHandlers) FindingsPostFindingsPossibleIDConfirm(ctx context.Context, params oas.FindingsPostFindingsPossibleIDConfirmParams) (*oas.FindingsPostFindingsPossibleIDConfirmOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	id, err := h.svc.ConfirmProposal(ctx, params.ID, p.Email, p.Role == routes.Admin)
	if err != nil {
		return nil, ToAPIError(err)
	}
	out := &oas.FindingsPostFindingsPossibleIDConfirmOK{Finding: oas.NilString{Null: true}}
	if id != "" {
		out.Finding = oas.NewNilString(id)
	}
	return out, nil
}

// FindingsPostFindingsPossibleConfirm implements findings_post_findings_possible_confirm: every proposal of one class at once.
func (h *FindingHandlers) FindingsPostFindingsPossibleConfirm(ctx context.Context, req *oas.FindingsPostFindingsPossibleConfirmReq) (*oas.FindingsPostFindingsPossibleConfirmOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	n, err := h.svc.ConfirmProposals(ctx, req.Device.Or(""), string(req.Verdict), string(req.Confidence), p.Email, p.Role == routes.Admin)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return &oas.FindingsPostFindingsPossibleConfirmOK{Confirmed: n}, nil
}

// FindingsPostFindingsPossibleChecksKeyReject implements findings_post_findings_possible_checks_key_reject: a person rejects a proposal.
func (h *FindingHandlers) FindingsPostFindingsPossibleChecksKeyReject(ctx context.Context, params oas.FindingsPostFindingsPossibleChecksKeyRejectParams) (*oas.FindingsPostFindingsPossibleChecksKeyRejectOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := h.svc.RejectProposal(ctx, params.Key, p.Email); err != nil {
		return nil, ToAPIError(err)
	}
	return &oas.FindingsPostFindingsPossibleChecksKeyRejectOK{Ok: true}, nil
}
