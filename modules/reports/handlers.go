package reports

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/apijson"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ReportsHandlers implements the reports operations (modules/reports/CONTRACT.md). Embed it in the composite handler. Roles
// are enforced by the server pipeline before a handler runs, never here.
//
//nolint:revive // the name is distinct on purpose: it is embedded in cmd/vedette next to the other modules' handlers
type ReportsHandlers struct {
	svc *Service
}

// NewReportsHandlers returns the handlers of svc.
func NewReportsHandlers(svc *Service) *ReportsHandlers { return &ReportsHandlers{svc: svc} }

// into turns a value of this package into the generated response type of an operation; the generated decoder rejects anything
// that does not fit the OpenAPI schema, so a drift fails loudly instead of sending a wrong body.
func into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	out, err := apijson.Into[T](v)
	if err != nil {
		return nil, fmt.Errorf("reports: %w", err)
	}
	return out, nil
}

// body re-reads a generated request type as the types of this package.
func body[D any](req any) (D, error) {
	var d D
	b, err := json.Marshal(req)
	if err != nil {
		return d, fmt.Errorf("reports: encoding request: %w", err)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, apierr.Invalid("The request body is not valid.")
	}
	return d, nil
}

func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// ReportsGetReportsDefinition implements reports_get_reports_definition.
func (h *ReportsHandlers) ReportsGetReportsDefinition(ctx context.Context) (*oas.ReportsGetReportsDefinitionOK, error) {
	v, err := h.svc.Definition(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsDefinitionOK](v)
}

// ReportsPutReportsDefinition implements reports_put_reports_definition (admin).
func (h *ReportsHandlers) ReportsPutReportsDefinition(ctx context.Context, req *oas.ReportsPutReportsDefinitionReq) (*oas.ReportsPutReportsDefinitionOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[DefinitionInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SaveDefinition(ctx, user, in)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPutReportsDefinitionOK](v)
}

// ReportsGetReportsDocument implements reports_get_reports_document.
func (h *ReportsHandlers) ReportsGetReportsDocument(ctx context.Context) (*oas.ReportsGetReportsDocumentOK, error) {
	v, err := h.svc.Document(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsDocumentOK](v)
}

// ReportsPostReportsSend implements reports_post_reports_send (operator).
func (h *ReportsHandlers) ReportsPostReportsSend(ctx context.Context) (*oas.ReportsPostReportsSendOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SendNow(ctx, user)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPostReportsSendOK](v)
}

// ReportsGetReportsHistory implements reports_get_reports_history.
func (h *ReportsHandlers) ReportsGetReportsHistory(ctx context.Context) (*oas.ReportsGetReportsHistoryOK, error) {
	items, err := h.svc.History(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsHistoryOK](struct {
		Items []SentItem `json:"items"`
	}{items})
}

// ReportsGetReportsHistoryID implements reports_get_reports_history_id.
func (h *ReportsHandlers) ReportsGetReportsHistoryID(ctx context.Context, params oas.ReportsGetReportsHistoryIDParams) (*oas.ReportsGetReportsHistoryIDOK, error) {
	v, err := h.svc.Sent(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsHistoryIDOK](v)
}

// ReportsGetReportsPdpl implements reports_get_reports_pdpl.
func (h *ReportsHandlers) ReportsGetReportsPdpl(ctx context.Context) (*oas.ReportsGetReportsPdplOK, error) {
	v, err := h.svc.Pdpl(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsPdplOK](v)
}

// ReportsPutReportsPdplOrg implements reports_put_reports_pdpl_org (operator).
func (h *ReportsHandlers) ReportsPutReportsPdplOrg(ctx context.Context, req *oas.ReportsPutReportsPdplOrgReq) (*oas.ReportsPutReportsPdplOrgOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[PdplOrg](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SavePdplOrg(ctx, user, in)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPutReportsPdplOrgOK](v)
}

// ReportsPostReportsPdplGenerate implements reports_post_reports_pdpl_generate (operator).
func (h *ReportsHandlers) ReportsPostReportsPdplGenerate(ctx context.Context) (*oas.ReportsPostReportsPdplGenerateOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.GeneratePdpl(ctx, user)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPostReportsPdplGenerateOK](v)
}

// ReportsPostReportsPdplAiSummary implements reports_post_reports_pdpl_ai_summary (operator).
func (h *ReportsHandlers) ReportsPostReportsPdplAiSummary(ctx context.Context) (*oas.ReportsPostReportsPdplAiSummaryOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.PdplAI(ctx, user)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPostReportsPdplAiSummaryOK](v)
}
