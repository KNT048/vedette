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

// NotifyHandlers implements the 19 operations of the notify module. Embed it in the composite handler of
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
	Signin      string            `json:"signin"`
	ZaloLogin   bool              `json:"zalo_login"`
	SecretKey   string            `json:"secret_key"`
	Refresh     string            `json:"refresh_token"`
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
		Approvals: b.Approvals, Approvers: b.Approvers, AppToken: b.AppToken, BotToken: b.BotToken, Signin: b.Signin, ZaloLogin: b.ZaloLogin,
		SecretKey: b.SecretKey, RefreshToken: b.Refresh})
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPutNotifyChannelsTypeOK](c)
}

// NotifyPostNotifyEmailSignin implements POST /notify/email-signin (admin).
func (h *NotifyHandlers) NotifyPostNotifyEmailSignin(ctx context.Context, req *oas.NotifyPostNotifyEmailSigninReq) (*oas.NotifyPostNotifyEmailSigninOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[EmailSigninStart](req)
	if err != nil {
		return nil, err
	}
	out, err := h.svc.StartEmailSignin(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyEmailSigninOK](out)
}

// NotifyPostNotifyEmailSigninID implements POST /notify/email-signin/{id} (admin).
func (h *NotifyHandlers) NotifyPostNotifyEmailSigninID(ctx context.Context, req *oas.NotifyPostNotifyEmailSigninIDReq, params oas.NotifyPostNotifyEmailSigninIDParams) (*oas.NotifyPostNotifyEmailSigninIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	pasted := ""
	if req != nil {
		pasted = req.URL.Or("")
	}
	out, err := h.svc.CheckEmailSignin(ctx, who, params.ID, pasted)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyEmailSigninIDOK](out)
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

// NotifyPostNotifyZaloLogin implements POST /notify/zalo/login (admin).
func (h *NotifyHandlers) NotifyPostNotifyZaloLogin(ctx context.Context) (*oas.NotifyPostNotifyZaloLoginOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.StartZaloLogin(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyZaloLoginOK](v)
}

// NotifyGetNotifyZaloLogin implements GET /notify/zalo/login (admin).
func (h *NotifyHandlers) NotifyGetNotifyZaloLogin(ctx context.Context) (*oas.NotifyGetNotifyZaloLoginOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyZaloLoginOK](h.svc.ZaloLoginState(who))
}

// NotifyDeleteNotifyZaloLogin implements DELETE /notify/zalo/login (admin).
func (h *NotifyHandlers) NotifyDeleteNotifyZaloLogin(ctx context.Context) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	h.svc.CancelZaloLogin(who)
	return nil
}

// NotifyGetNotifyZaloContacts implements GET /notify/zalo/contacts (admin).
func (h *NotifyHandlers) NotifyGetNotifyZaloContacts(ctx context.Context) (*oas.NotifyGetNotifyZaloContactsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.ListZaloContacts(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyZaloContactsOK](v)
}

// NotifyPostNotifyZaloResolve implements POST /notify/zalo/resolve (admin).
func (h *NotifyHandlers) NotifyPostNotifyZaloResolve(ctx context.Context, req *oas.NotifyPostNotifyZaloResolveReq) (*oas.NotifyPostNotifyZaloResolveOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.ResolveZalo(ctx, who, req.Query)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyZaloResolveOK](v)
}

// NotifyGetNotifyZaloApprovers implements GET /notify/zalo/approvers (admin).
func (h *NotifyHandlers) NotifyGetNotifyZaloApprovers(ctx context.Context) (*oas.NotifyGetNotifyZaloApproversOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	l, err := h.svc.ZaloApprovers(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyZaloApproversOK](struct {
		Items []ZaloApprover `json:"items"`
	}{l})
}

// NotifyPostNotifyZaloApproversUserIDCode implements POST /notify/zalo/approvers/{user_id}/code (admin).
func (h *NotifyHandlers) NotifyPostNotifyZaloApproversUserIDCode(ctx context.Context, params oas.NotifyPostNotifyZaloApproversUserIDCodeParams) (*oas.NotifyPostNotifyZaloApproversUserIDCodeOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SendZaloCode(ctx, who, params.UserID)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyZaloApproversUserIDCodeOK](v)
}

// NotifyGetNotifyTelegramApprovers implements GET /notify/telegram/approvers (admin, D-414).
func (h *NotifyHandlers) NotifyGetNotifyTelegramApprovers(ctx context.Context) (*oas.NotifyGetNotifyTelegramApproversOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	l, err := h.svc.TelegramApprovers(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyGetNotifyTelegramApproversOK](struct {
		Items []ZaloApprover `json:"items"`
	}{l})
}

// NotifyPostNotifyTelegramApproversUserIDCode implements POST /notify/telegram/approvers/{user_id}/code (admin, D-414).
func (h *NotifyHandlers) NotifyPostNotifyTelegramApproversUserIDCode(ctx context.Context, params oas.NotifyPostNotifyTelegramApproversUserIDCodeParams) (*oas.NotifyPostNotifyTelegramApproversUserIDCodeOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SendTelegramLink(ctx, who, params.UserID)
	if err != nil {
		return nil, err
	}
	return convert[oas.NotifyPostNotifyTelegramApproversUserIDCodeOK](v)
}

// NotifyPostNotifyTelegramChats implements POST /notify/telegram/chats (admin, D-491).
func (h *NotifyHandlers) NotifyPostNotifyTelegramChats(ctx context.Context, req *oas.NotifyPostNotifyTelegramChatsReq) (*oas.NotifyPostNotifyTelegramChatsOK, error) {
	if _, err := actor(ctx); err != nil {
		return nil, err
	}
	chats, fresh, err := h.svc.TelegramChats(ctx, req.Token.Or(""))
	if err != nil {
		return nil, err
	}
	if chats == nil {
		chats = []channel.TelegramChat{}
	}
	return convert[oas.NotifyPostNotifyTelegramChatsOK](struct {
		Items []channel.TelegramChat `json:"items"`
		Fresh bool                   `json:"fresh"`
	}{chats, fresh})
}
