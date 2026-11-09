package notify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/notify/channel"
)

// NotifyHandlers implements the 12 operations of the notify module. Embed it in the composite handler of
// cmd/vedette. The role of each route comes from the route table, so nothing here checks roles.
//
// ogen generates a separate struct per operation for the same schema, so answers are built from the
// domain types (their JSON names are the wire names) and decoded into the generated ones; request
// bodies go the other way.
//
//nolint:revive // the name is distinct on purpose: cmd/vedette embeds every module's handler struct and two fields named Handlers would not compile
type NotifyHandlers struct{ svc *Service }

// NewNotifyHandlers returns the handlers of the module.
func NewNotifyHandlers(svc *Service) *NotifyHandlers { return &NotifyHandlers{svc: svc} }

// convert re-reads v, through its JSON form, as T.
func convert[T any](v any) (*T, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("notify: encode: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("notify: decode: %w", err)
	}
	return out, nil
}

// actor is the signed-in user's email; the route table guarantees a principal on these routes.
func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// NotifyGetNotifyIncidents implements GET /notify/incidents (viewer).
func (h *NotifyHandlers) NotifyGetNotifyIncidents(ctx context.Context) (*oas.NotifyGetNotifyIncidentsOK, error) {
	l, err := h.svc.Incidents(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyIncidentsOK](struct {
		Incidents []Incident `json:"incidents"`
	}{l})
}

// NotifyGetNotifyIncidentsID implements GET /notify/incidents/{id} (viewer).
func (h *NotifyHandlers) NotifyGetNotifyIncidentsID(ctx context.Context, params oas.NotifyGetNotifyIncidentsIDParams) (*oas.NotifyGetNotifyIncidentsIDOK, error) {
	d, err := h.svc.IncidentDetail(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyIncidentsIDOK](d)
}

// NotifyPatchNotifyIncidentsID implements PATCH /notify/incidents/{id} (operator).
func (h *NotifyHandlers) NotifyPatchNotifyIncidentsID(ctx context.Context, req *oas.NotifyPatchNotifyIncidentsIDReq, params oas.NotifyPatchNotifyIncidentsIDParams) (*oas.NotifyPatchNotifyIncidentsIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.HandleIncident(ctx, who, params.ID, IncidentStatus(req.Status), req.Note.Or(""))
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPatchNotifyIncidentsIDOK](d)
}

// NotifyGetNotifyHistory implements GET /notify/history (admin).
func (h *NotifyHandlers) NotifyGetNotifyHistory(ctx context.Context) (*oas.NotifyGetNotifyHistoryOK, error) {
	v, err := h.svc.History(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyHistoryOK](v)
}

// NotifyPostNotifyHistoryIDResend implements POST /notify/history/{id}/resend (operator).
func (h *NotifyHandlers) NotifyPostNotifyHistoryIDResend(ctx context.Context, params oas.NotifyPostNotifyHistoryIDResendParams) (*oas.NotifyPostNotifyHistoryIDResendOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	it, err := h.svc.Resend(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyHistoryIDResendOK](it)
}

// NotifyGetNotifyFindingsIDNotices implements GET /notify/findings/{id}/notices (viewer).
func (h *NotifyHandlers) NotifyGetNotifyFindingsIDNotices(ctx context.Context, params oas.NotifyGetNotifyFindingsIDNoticesParams) (*oas.NotifyGetNotifyFindingsIDNoticesOK, error) {
	l, err := h.svc.FindingNotices(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyFindingsIDNoticesOK](struct {
		Sends []SendView `json:"sends"`
	}{l})
}

// NotifyGetNotifyAlertsIDTarget implements GET /notify/alerts/{id}/target (viewer).
func (h *NotifyHandlers) NotifyGetNotifyAlertsIDTarget(ctx context.Context, params oas.NotifyGetNotifyAlertsIDTargetParams) (*oas.NotifyGetNotifyAlertsIDTargetOK, error) {
	to, err := h.svc.AlertTarget(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return &oas.NotifyGetNotifyAlertsIDTargetOK{To: to}, nil
}

// NotifyGetNotifyChannels implements GET /notify/channels (admin).
func (h *NotifyHandlers) NotifyGetNotifyChannels(ctx context.Context) (*oas.NotifyGetNotifyChannelsOK, error) {
	v, err := h.svc.Channels(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyChannelsOK](v)
}

// channelBody is the request body of PUT /notify/channels/{type}.
type channelBody struct {
	Enabled     bool              `json:"enabled"`
	Fields      map[string]string `json:"fields"`
	Secret      string            `json:"secret"`
	MinSeverity Severity          `json:"min_severity"`
	Approvals   bool              `json:"approvals"`
	Approvers   []Approver        `json:"approvers"`
	AppToken    string            `json:"app_token"`
	BotToken    string            `json:"bot_token"`
}

// NotifyPutNotifyChannelsType implements PUT /notify/channels/{type} (admin).
func (h *NotifyHandlers) NotifyPutNotifyChannelsType(ctx context.Context, req *oas.NotifyPutNotifyChannelsTypeReq, params oas.NotifyPutNotifyChannelsTypeParams) (*oas.NotifyPutNotifyChannelsTypeOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	b, err := convert[channelBody](req)
	if err != nil {
		return nil, err
	}
	c, err := h.svc.SaveChannel(ctx, who, channel.Type(params.Type), ChannelInput{Enabled: b.Enabled, Fields: b.Fields, Secret: b.Secret, MinSeverity: b.MinSeverity,
		Approvals: b.Approvals, Approvers: b.Approvers, AppToken: b.AppToken, BotToken: b.BotToken})
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPutNotifyChannelsTypeOK](c)
}

// NotifyDeleteNotifyChannelsType implements DELETE /notify/channels/{type} (admin).
func (h *NotifyHandlers) NotifyDeleteNotifyChannelsType(ctx context.Context, params oas.NotifyDeleteNotifyChannelsTypeParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteChannel(ctx, who, channel.Type(params.Type))
}

// NotifyPostNotifyChannelsTypeTest implements POST /notify/channels/{type}/test (admin).
func (h *NotifyHandlers) NotifyPostNotifyChannelsTypeTest(ctx context.Context, params oas.NotifyPostNotifyChannelsTypeTestParams) (*oas.NotifyPostNotifyChannelsTypeTestOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.TestChannel(ctx, who, channel.Type(params.Type))
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyChannelsTypeTestOK](r)
}

// NotifyPutNotifyRules implements PUT /notify/rules (admin).
func (h *NotifyHandlers) NotifyPutNotifyRules(ctx context.Context, req *oas.NotifyPutNotifyRulesReq) (*oas.NotifyPutNotifyRulesOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := convert[Rules](req)
	if err != nil {
		return nil, err
	}
	out, err := h.svc.SaveRules(ctx, who, *r)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPutNotifyRulesOK](out)
}
