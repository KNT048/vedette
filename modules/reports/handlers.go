package reports

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ReportsHandlers implements the 11 reports operations (modules/reports/CONTRACT.md). Embed it in the composite handler. Roles
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
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("reports: encoding response: %w", err)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("reports: response does not fit the API schema: %w", err)
	}
	return &out, nil
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

// ReportsGetReportsWeeklyPreview implements reports_get_reports_weekly_preview.
func (h *ReportsHandlers) ReportsGetReportsWeeklyPreview(ctx context.Context) (*oas.ReportsGetReportsWeeklyPreviewOK, error) {
	v, err := h.svc.Preview(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsWeeklyPreviewOK](v)
}

// ReportsPostReportsWeeklyAiSummary implements reports_post_reports_weekly_ai_summary.
func (h *ReportsHandlers) ReportsPostReportsWeeklyAiSummary(ctx context.Context) (*oas.ReportsPostReportsWeeklyAiSummaryOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.WeeklyAI(ctx, user)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPostReportsWeeklyAiSummaryOK](v)
}

// ReportsGetReportsSchedule implements reports_get_reports_schedule.
func (h *ReportsHandlers) ReportsGetReportsSchedule(ctx context.Context) (*oas.ReportsGetReportsScheduleOK, error) {
	v, err := h.svc.Schedule(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsScheduleOK](v)
}

// ReportsPutReportsSchedule implements reports_put_reports_schedule (admin).
func (h *ReportsHandlers) ReportsPutReportsSchedule(ctx context.Context, req *oas.ReportsPutReportsScheduleReq) (*oas.ReportsPutReportsScheduleOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[ScheduleInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SaveSchedule(ctx, user, in)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPutReportsScheduleOK](v)
}

// ReportsGetReportsWeeklyHistory implements reports_get_reports_weekly_history.
func (h *ReportsHandlers) ReportsGetReportsWeeklyHistory(ctx context.Context) (*oas.ReportsGetReportsWeeklyHistoryOK, error) {
	items, err := h.svc.History(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsWeeklyHistoryOK](struct {
		Items []HistoryItem `json:"items"`
	}{items})
}

// ReportsGetReportsWeeklyHistoryID implements reports_get_reports_weekly_history_id.
func (h *ReportsHandlers) ReportsGetReportsWeeklyHistoryID(ctx context.Context, params oas.ReportsGetReportsWeeklyHistoryIDParams) (*oas.ReportsGetReportsWeeklyHistoryIDOK, error) {
	v, err := h.svc.HistoryEntry(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsGetReportsWeeklyHistoryIDOK](v)
}

// ReportsPostReportsWeeklySend implements reports_post_reports_weekly_send (operator).
func (h *ReportsHandlers) ReportsPostReportsWeeklySend(ctx context.Context) (*oas.ReportsPostReportsWeeklySendOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SendNow(ctx, user)
	if err != nil {
		return nil, err
	}
	return into[oas.ReportsPostReportsWeeklySendOK](v)
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
