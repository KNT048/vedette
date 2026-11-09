package response

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// ResponseHandlers implements the operations of the response module that part 1 (WP-13a) builds. Embed it in the
// composite handler of cmd/vedette. The role of each route comes from the route table, so nothing here checks roles.
//
// Not implemented here, and so answered 501 not_implemented by server.Fallback (part 13b): GET and POST
// /response/approve/{token}, GET /response/ai, POST /response/ai/proposals, POST /response/ai/resume.
//
// The two preview-only operations, POST /response/rules/run and POST /response/actions/{id}/chat-decision, are implemented
// only to answer 404 like an unknown route: they must not exist in the real build (FORBID-5).
//
// ogen generates a separate struct per operation for the same schema, so answers are built from the domain types (their
// JSON names are the wire names) and decoded into the generated ones; request bodies go the other way.
//
//nolint:revive // the name is distinct on purpose: cmd/vedette embeds every module's handler struct and two fields named Handlers would not compile
type ResponseHandlers struct{ svc *Service }

// NewResponseHandlers returns the handlers of the module.
func NewResponseHandlers(svc *Service) *ResponseHandlers { return &ResponseHandlers{svc: svc} }

// convert re-reads v, through its JSON form, as T.
func convert[T any](v any) (*T, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("response: encode: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("response: decode: %w", err)
	}
	return out, nil
}

// body reads a generated request body as a domain type.
func body[T any](req any) (T, error) {
	p, err := convert[T](req)
	if err != nil {
		var zero T
		return zero, apierr.Invalid("The request body is not valid.")
	}
	return *p, nil
}

// actor is the signed-in user; the route table guarantees a principal on these routes.
func (h *ResponseHandlers) actor(ctx context.Context) (Actor, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return Actor{}, apierr.Unauthenticated()
	}
	a := Actor{ID: p.ID, Email: p.Email, Name: p.Email, Via: ViaApp}
	if u, ok, err := h.svc.cfg.Users.Lookup(ctx, p.ID); err == nil && ok && u.Name != "" {
		a.Name = u.Name
	}
	return a, nil
}

var errPreviewOnly = apierr.NotFound // answers like an unknown route

// ResponseGetResponsePlans implements GET /response/plans (viewer).
func (h *ResponseHandlers) ResponseGetResponsePlans(ctx context.Context, params oas.ResponseGetResponsePlansParams) (*oas.ResponseGetResponsePlansOK, error) {
	v, err := h.svc.Plans(ctx, params.Finding.Or(""))
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponsePlansOK](v)
}

// ResponseGetResponseActions implements GET /response/actions (viewer).
func (h *ResponseHandlers) ResponseGetResponseActions(ctx context.Context) (*oas.ResponseGetResponseActionsOK, error) {
	l, err := h.svc.Actions(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseActionsOK](struct {
		Items []ActionRequest `json:"items"`
	}{l})
}

// ResponsePostResponseProposalsIDRequest implements POST /response/proposals/{id}/request (operator).
func (h *ResponseHandlers) ResponsePostResponseProposalsIDRequest(ctx context.Context, params oas.ResponsePostResponseProposalsIDRequestParams) (*oas.ResponsePostResponseProposalsIDRequestCreated, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.RequestProposal(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseProposalsIDRequestCreated](r)
}

// ResponsePostResponseActionsIDApprove implements POST /response/actions/{id}/approve (operator).
func (h *ResponseHandlers) ResponsePostResponseActionsIDApprove(ctx context.Context, req *oas.ResponsePostResponseActionsIDApproveReq, params oas.ResponsePostResponseActionsIDApproveParams) (*oas.ResponsePostResponseActionsIDApproveOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Approve(ctx, who, params.ID, req.Items, req.Code.Or(""))
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseActionsIDApproveOK](r)
}

// ResponsePostResponseActionsIDReject implements POST /response/actions/{id}/reject (operator).
func (h *ResponseHandlers) ResponsePostResponseActionsIDReject(ctx context.Context, req *oas.ResponsePostResponseActionsIDRejectReq, params oas.ResponsePostResponseActionsIDRejectParams) (*oas.ResponsePostResponseActionsIDRejectOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Reject(ctx, who, params.ID, req.Reason.Or(""))
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseActionsIDRejectOK](r)
}

// ResponsePostResponseActionsIDRollback implements POST /response/actions/{id}/rollback (operator).
func (h *ResponseHandlers) ResponsePostResponseActionsIDRollback(ctx context.Context, params oas.ResponsePostResponseActionsIDRollbackParams) (*oas.ResponsePostResponseActionsIDRollbackOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Rollback(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseActionsIDRollbackOK](r)
}

// ResponsePostResponseActionsIDChatDecision answers 404: the operation exists only in the preview build (FORBID-5).
func (h *ResponseHandlers) ResponsePostResponseActionsIDChatDecision(context.Context, *oas.ResponsePostResponseActionsIDChatDecisionReq, oas.ResponsePostResponseActionsIDChatDecisionParams) (*oas.ResponsePostResponseActionsIDChatDecisionOK, error) {
	return nil, errPreviewOnly()
}

// ResponsePostResponseRulesRun answers 404: the operation exists only in the preview build (FORBID-5).
func (h *ResponseHandlers) ResponsePostResponseRulesRun(context.Context) (*oas.ResponsePostResponseRulesRunOK, error) {
	return nil, errPreviewOnly()
}

// ResponseGetResponseSettings implements GET /response/settings (admin).
func (h *ResponseHandlers) ResponseGetResponseSettings(ctx context.Context) (*oas.ResponseGetResponseSettingsOK, error) {
	v, err := h.svc.Settings(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseSettingsOK](v)
}

// ResponsePutResponseSettings implements PUT /response/settings (admin).
func (h *ResponseHandlers) ResponsePutResponseSettings(ctx context.Context, req *oas.ResponsePutResponseSettingsReq) (*oas.ResponsePutResponseSettingsOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[SettingsInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SaveSettings(ctx, who, in)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePutResponseSettingsOK](v)
}

// ResponsePostResponseExecution implements POST /response/execution (admin).
func (h *ResponseHandlers) ResponsePostResponseExecution(ctx context.Context, req *oas.ResponsePostResponseExecutionReq) (*oas.ResponsePostResponseExecutionOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetExecution(ctx, who, req.Enabled, req.Phrase.Or(""))
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseExecutionOK](v)
}

// ResponsePostResponseEmergencyStop implements POST /response/emergency-stop (operator).
func (h *ResponseHandlers) ResponsePostResponseEmergencyStop(ctx context.Context) (*oas.ResponsePostResponseEmergencyStopOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	n, err := h.svc.EmergencyStop(ctx, who)
	if err != nil {
		return nil, err
	}
	return &oas.ResponsePostResponseEmergencyStopOK{Cancelled: n}, nil
}

// ResponsePostResponseBreakerReset implements POST /response/breaker/reset (admin).
func (h *ResponseHandlers) ResponsePostResponseBreakerReset(ctx context.Context) (*oas.ResponsePostResponseBreakerResetOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.ResetBreaker(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseBreakerResetOK](v)
}

// ResponseGetResponseTriggers implements GET /response/triggers (viewer).
func (h *ResponseHandlers) ResponseGetResponseTriggers(ctx context.Context) (*oas.ResponseGetResponseTriggersOK, error) {
	l, err := h.svc.Triggers(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseTriggersOK](struct {
		Items []TriggerInfo `json:"items"`
	}{l})
}

// ResponseGetResponseRules implements GET /response/rules (viewer).
func (h *ResponseHandlers) ResponseGetResponseRules(ctx context.Context) (*oas.ResponseGetResponseRulesOK, error) {
	l, err := h.svc.Rules(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseRulesOK](struct {
		Items []Rule `json:"items"`
	}{l})
}

// ResponsePostResponseRules implements POST /response/rules (admin).
func (h *ResponseHandlers) ResponsePostResponseRules(ctx context.Context, req *oas.ResponsePostResponseRulesReq) (*oas.ResponsePostResponseRulesCreated, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[RuleInput](req)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.AddRule(ctx, who, in)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseRulesCreated](r)
}

// ResponsePutResponseRulesID implements PUT /response/rules/{id} (admin).
func (h *ResponseHandlers) ResponsePutResponseRulesID(ctx context.Context, req *oas.ResponsePutResponseRulesIDReq, params oas.ResponsePutResponseRulesIDParams) (*oas.ResponsePutResponseRulesIDOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[RuleInput](req)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.ChangeRule(ctx, who, params.ID, in)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePutResponseRulesIDOK](r)
}

// ResponseDeleteResponseRulesID implements DELETE /response/rules/{id} (admin).
func (h *ResponseHandlers) ResponseDeleteResponseRulesID(ctx context.Context, params oas.ResponseDeleteResponseRulesIDParams) error {
	who, err := h.actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteRule(ctx, who, params.ID)
}

// ResponsePostResponseRulesSimulate implements POST /response/rules/simulate (operator).
func (h *ResponseHandlers) ResponsePostResponseRulesSimulate(ctx context.Context, req *oas.ResponsePostResponseRulesSimulateReq) (*oas.ResponsePostResponseRulesSimulateOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[struct {
		Rule    RuleInput `json:"rule"`
		EventID string    `json:"event_id"`
	}](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Simulate(ctx, who, in.Rule, in.EventID)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseRulesSimulateOK](v)
}

// ResponsePostResponseRulesIDManual implements POST /response/rules/{id}/manual (operator).
func (h *ResponseHandlers) ResponsePostResponseRulesIDManual(ctx context.Context, req *oas.ResponsePostResponseRulesIDManualReq, params oas.ResponsePostResponseRulesIDManualParams) (*oas.ResponsePostResponseRulesIDManualOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	sum, err := h.svc.RunManual(ctx, who, params.ID, req.AssetID)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseRulesIDManualOK](sum)
}

// ResponseGetResponseEvents implements GET /response/events (viewer).
func (h *ResponseHandlers) ResponseGetResponseEvents(ctx context.Context) (*oas.ResponseGetResponseEventsOK, error) {
	l, err := h.svc.Events(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseEventsOK](struct {
		Items []EventView `json:"items"`
	}{l})
}

// ResponseGetResponseTemplates implements GET /response/templates (viewer).
func (h *ResponseHandlers) ResponseGetResponseTemplates(ctx context.Context) (*oas.ResponseGetResponseTemplatesOK, error) {
	l, err := h.svc.Templates(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseTemplatesOK](struct {
		Items []Template `json:"items"`
	}{l})
}

// ResponsePostResponseTemplatesIDClone implements POST /response/templates/{id}/clone (admin).
func (h *ResponseHandlers) ResponsePostResponseTemplatesIDClone(ctx context.Context, params oas.ResponsePostResponseTemplatesIDCloneParams) (*oas.ResponsePostResponseTemplatesIDCloneCreated, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Clone(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseTemplatesIDCloneCreated](r)
}

// ResponseGetResponseAllowlist implements GET /response/allowlist (viewer).
func (h *ResponseHandlers) ResponseGetResponseAllowlist(ctx context.Context) (*oas.ResponseGetResponseAllowlistOK, error) {
	l, err := h.svc.Allowlist(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseAllowlistOK](struct {
		Items []AllowEntry `json:"items"`
	}{l})
}

// ResponsePutResponseAllowlist implements PUT /response/allowlist (admin).
func (h *ResponseHandlers) ResponsePutResponseAllowlist(ctx context.Context, req *oas.ResponsePutResponseAllowlistReq) (*oas.ResponsePutResponseAllowlistOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[struct {
		Items []AllowEntry `json:"items"`
	}](req)
	if err != nil {
		return nil, err
	}
	l, err := h.svc.SetAllowlist(ctx, who, in.Items)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePutResponseAllowlistOK](struct {
		Items []AllowEntry `json:"items"`
	}{l})
}

// ResponseGetResponseBlocklist implements GET /response/blocklist (admin).
func (h *ResponseHandlers) ResponseGetResponseBlocklist(ctx context.Context) (*oas.ResponseGetResponseBlocklistOK, error) {
	v, err := h.svc.Blocklist(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseBlocklistOK](v)
}

// ResponsePostResponseBlocklistToken implements POST /response/blocklist/token (admin).
func (h *ResponseHandlers) ResponsePostResponseBlocklistToken(ctx context.Context) (*oas.ResponsePostResponseBlocklistTokenOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.RegenerateToken(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseBlocklistTokenOK](v)
}

// ResponseGetResponseBlocklistTokenTxt implements GET /response/blocklist/{token}.txt (public: the token is the credential).
// ogen fixes the content type of a file answer to application/octet-stream; the text is plain, one address per line.
func (h *ResponseHandlers) ResponseGetResponseBlocklistTokenTxt(ctx context.Context, params oas.ResponseGetResponseBlocklistTokenTxtParams) (oas.ResponseGetResponseBlocklistTokenTxtOK, error) {
	from := ""
	if x, ok := server.ExchangeFrom(ctx); ok {
		from = x.ClientAddr().String()
		x.W.Header().Set("Cache-Control", "no-store")
		x.W.Header().Set("X-Content-Type-Options", "nosniff")
	}
	b, err := h.svc.FetchBlocklist(ctx, params.Token, from)
	if err != nil {
		return oas.ResponseGetResponseBlocklistTokenTxtOK{}, err
	}
	return oas.ResponseGetResponseBlocklistTokenTxtOK{Data: io.NopCloser(bytes.NewReader(b))}, nil
}

// ResponseGetResponseCatalog implements GET /response/catalog (viewer).
func (h *ResponseHandlers) ResponseGetResponseCatalog(ctx context.Context) (*oas.ResponseGetResponseCatalogOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	v, err := h.svc.Catalog(ctx, p.Role == routes.Admin)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseCatalogOK](v)
}

// ResponsePostResponseCatalog implements POST /response/catalog (admin).
func (h *ResponseHandlers) ResponsePostResponseCatalog(ctx context.Context, req *oas.ResponsePostResponseCatalogReq) (*oas.ResponsePostResponseCatalogCreated, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := body[CatalogInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddAction(ctx, who, in)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePostResponseCatalogCreated](v)
}

// ResponsePutResponseCatalogID implements PUT /response/catalog/{id} (admin).
func (h *ResponseHandlers) ResponsePutResponseCatalogID(ctx context.Context, req *oas.ResponsePutResponseCatalogIDReq, params oas.ResponsePutResponseCatalogIDParams) (*oas.ResponsePutResponseCatalogIDOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, apierr.Invalid("The request body is not valid.")
	}
	var u CatalogUpdate
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, apierr.Invalid("The request body is not valid.")
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	u.Present = map[string]bool{}
	for k := range keys {
		u.Present[k] = true
	}
	v, err := h.svc.ChangeAction(ctx, who, params.ID, u)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponsePutResponseCatalogIDOK](v)
}

// ResponseDeleteResponseCatalogID implements DELETE /response/catalog/{id} (admin).
func (h *ResponseHandlers) ResponseDeleteResponseCatalogID(ctx context.Context, params oas.ResponseDeleteResponseCatalogIDParams) error {
	who, err := h.actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteAction(ctx, who, params.ID)
}

// ResponseGetResponseMetrics implements GET /response/metrics (viewer).
func (h *ResponseHandlers) ResponseGetResponseMetrics(ctx context.Context) (*oas.ResponseGetResponseMetricsOK, error) {
	m, err := h.svc.Metrics(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseMetricsOK](m)
}

// ResponseGetResponseLog implements GET /response/log (operator).
func (h *ResponseHandlers) ResponseGetResponseLog(ctx context.Context) (*oas.ResponseGetResponseLogOK, error) {
	l, err := h.svc.Log(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.ResponseGetResponseLogOK](struct {
		Items []LogEntry `json:"items"`
	}{l})
}
