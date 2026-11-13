package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// AIHandlers implements the operations of the ai module built so far: profiles, keys, assignments, the shared token
// settings (S-AI-1), explaining a CVE, usage and runs (S-AI-2, S-AI-4, S-AI-6). Embed it in the composite handler of cmd/vedette. The role of each route comes from the route table, so
// nothing here checks roles.
//
// ogen generates a separate struct per operation for the same schema, so answers are built from the domain types (their JSON
// names are the wire names) and decoded into the generated ones; request bodies go the other way.
//
//nolint:revive // the name is distinct on purpose: cmd/vedette embeds every module's handler struct and two fields named Handlers would not compile
type AIHandlers struct{ svc *Service }

// NewAIHandlers returns the handlers of the module.
func NewAIHandlers(svc *Service) *AIHandlers { return &AIHandlers{svc: svc} }

// convert re-reads v, through its JSON form, as T.
func convert[T any](v any) (*T, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("ai: encode: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("ai: decode: %w", err)
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

// AiGetAiConfig implements GET /ai/config (viewer).
func (h *AIHandlers) AiGetAiConfig(context.Context) (*oas.AiGetAiConfigOK, error) {
	// When the saved settings could not be loaded, the default tier and cap are not the saved ones: say so instead of showing them.
	if h.svc.Degraded() != "" {
		return nil, h.svc.errDegraded()
	}
	return convert[oas.AiGetAiConfigOK](h.svc.Config())
}

// AiPutAiConfig implements PUT /ai/config (admin).
func (h *AIHandlers) AiPutAiConfig(ctx context.Context, req *oas.AiPutAiConfigReq) (*oas.AiPutAiConfigOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetConfig(ctx, who, Settings{Tier: Tier(req.Tier), MonthlyBudget: req.MonthlyBudget, RedactPII: req.RedactPii})
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiConfigOK](v)
}

// AiGetAiProfiles implements GET /ai/profiles (viewer).
func (h *AIHandlers) AiGetAiProfiles(context.Context) (*oas.AiGetAiProfilesOK, error) {
	return convert[oas.AiGetAiProfilesOK](struct {
		Items []ProfileView `json:"items"`
	}{h.svc.Profiles()})
}

// AiPostAiProfiles implements POST /ai/profiles (admin).
func (h *AIHandlers) AiPostAiProfiles(ctx context.Context, req *oas.AiPostAiProfilesReq) (*oas.AiPostAiProfilesOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[ProfileInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddProfile(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiProfilesOK](v)
}

// AiPutAiProfilesID implements PUT /ai/profiles/{id} (admin).
func (h *AIHandlers) AiPutAiProfilesID(ctx context.Context, req *oas.AiPutAiProfilesIDReq, params oas.AiPutAiProfilesIDParams) (*oas.AiPutAiProfilesIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[ProfileInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.EditProfile(ctx, who, params.ID, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiProfilesIDOK](v)
}

// AiDeleteAiProfilesID implements DELETE /ai/profiles/{id} (admin).
func (h *AIHandlers) AiDeleteAiProfilesID(ctx context.Context, params oas.AiDeleteAiProfilesIDParams) (*oas.AiDeleteAiProfilesIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	cleared, err := h.svc.DeleteProfile(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiDeleteAiProfilesIDOK](struct {
		ClearedJobs []Job `json:"cleared_jobs"`
	}{cleared})
}

// AiPostAiProfilesTest implements POST /ai/profiles/test (admin).
func (h *AIHandlers) AiPostAiProfilesTest(ctx context.Context, req *oas.AiPostAiProfilesTestReq) (*oas.AiPostAiProfilesTestOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[ProfileInput](req)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.TestProfile(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiProfilesTestOK](res)
}

// AiPostAiProfilesModels implements POST /ai/profiles/models (admin).
func (h *AIHandlers) AiPostAiProfilesModels(ctx context.Context, req *oas.AiPostAiProfilesModelsReq) (*oas.AiPostAiProfilesModelsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[ProfileInput](req)
	if err != nil {
		return nil, err
	}
	ids, err := h.svc.ListModels(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiProfilesModelsOK](struct {
		Models []string `json:"models"`
	}{ids})
}

// AiGetAiAssignments implements GET /ai/assignments (viewer).
func (h *AIHandlers) AiGetAiAssignments(context.Context) (*oas.AiGetAiAssignmentsOK, error) {
	return convert[oas.AiGetAiAssignmentsOK](h.svc.Assignments())
}

// AiPutAiAssignments implements PUT /ai/assignments (admin).
func (h *AIHandlers) AiPutAiAssignments(ctx context.Context, req *oas.AiPutAiAssignmentsReq) (*oas.AiPutAiAssignmentsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[AssignmentsView](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetAssignments(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiAssignmentsOK](v)
}

// AiGetAiAssignmentsSuggestion implements GET /ai/assignments/suggestion (viewer).
func (h *AIHandlers) AiGetAiAssignmentsSuggestion(_ context.Context, params oas.AiGetAiAssignmentsSuggestionParams) (*oas.AiGetAiAssignmentsSuggestionOK, error) {
	return convert[oas.AiGetAiAssignmentsSuggestionOK](h.svc.Suggestion(params.InternalOnly == oas.AiGetAiAssignmentsSuggestionInternalOnlyTrue))
}

// AiPostAiCveIDExplain implements POST /ai/cve/{id}/explain (operator).
func (h *AIHandlers) AiPostAiCveIDExplain(ctx context.Context, params oas.AiPostAiCveIDExplainParams) (*oas.AiPostAiCveIDExplainOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.ExplainCVE(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiCveIDExplainOK](v)
}

// AiGetAiCveIDCached implements GET /ai/cve/{id}/cached (viewer): what was generated before, with no AI call.
func (h *AIHandlers) AiGetAiCveIDCached(ctx context.Context, params oas.AiGetAiCveIDCachedParams) (*oas.AiGetAiCveIDCachedOK, error) {
	ex, err := h.svc.CachedCVE(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	nw, err := h.svc.CachedNews(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiCveIDCachedOK](struct {
		Explain *ExplainResult `json:"explain"`
		News    *NewsResult    `json:"news"`
	}{ex, nw})
}

// AiPostAiCveIDNews implements POST /ai/cve/{id}/news (operator): the box fetches the public sources, the AI summarises them.
func (h *AIHandlers) AiPostAiCveIDNews(ctx context.Context, params oas.AiPostAiCveIDNewsParams) (*oas.AiPostAiCveIDNewsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.NewsCVE(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiCveIDNewsOK](v)
}

// AiGetAiUsage implements GET /ai/usage (viewer).
func (h *AIHandlers) AiGetAiUsage(ctx context.Context) (*oas.AiGetAiUsageOK, error) {
	v, err := h.svc.Usage(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiUsageOK](v)
}

// AiGetAiRuns implements GET /ai/runs (viewer).
func (h *AIHandlers) AiGetAiRuns(ctx context.Context) (*oas.AiGetAiRunsOK, error) {
	runs, err := h.svc.Runs(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiRunsOK](struct {
		Items []RunView `json:"items"`
	}{runs})
}

// AiGetAiActivity implements GET /ai/activity (operator).
func (h *AIHandlers) AiGetAiActivity(ctx context.Context, params oas.AiGetAiActivityParams) (*oas.AiGetAiActivityOK, error) {
	f := ActivityFilter{Job: params.Job.Or("")}
	if r, ok := params.Result.Get(); ok {
		f.Result = ActivityResult(r)
	}
	f.From, f.To = params.From.Or(time.Time{}), params.To.Or(time.Time{})
	page, err := h.svc.ListActivity(ctx, f)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiActivityOK](page)
}

// AiGetAiActivityVerify implements GET /ai/activity/verify (operator).
func (h *AIHandlers) AiGetAiActivityVerify(ctx context.Context) (*oas.AiGetAiActivityVerifyOK, error) {
	res, err := h.svc.VerifyActivity(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": res.OK, "count": res.Count, "broken_at": nil, "entry_id": nil}
	if !res.OK {
		out["broken_at"] = res.BrokenAt
		if res.EntryID != "" {
			out["entry_id"] = res.EntryID
		}
	}
	return convert[oas.AiGetAiActivityVerifyOK](out)
}

// AiGetAiActivitySettings implements GET /ai/activity/settings (admin).
func (h *AIHandlers) AiGetAiActivitySettings(ctx context.Context) (*oas.AiGetAiActivitySettingsOK, error) {
	days, err := h.svc.RetentionDays(ctx)
	if err != nil {
		return nil, err
	}
	return &oas.AiGetAiActivitySettingsOK{RetentionDays: days}, nil
}

// AiPutAiActivitySettings implements PUT /ai/activity/settings (admin).
func (h *AIHandlers) AiPutAiActivitySettings(ctx context.Context, req *oas.AiPutAiActivitySettingsReq) (*oas.AiPutAiActivitySettingsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	days, err := h.svc.SetRetention(ctx, who, req.RetentionDays)
	if err != nil {
		return nil, mapErr(err)
	}
	return &oas.AiPutAiActivitySettingsOK{RetentionDays: days}, nil
}

// AiGetAiRules implements GET /ai/rules (admin).
func (h *AIHandlers) AiGetAiRules(context.Context) (*oas.AiGetAiRulesOK, error) {
	return convert[oas.AiGetAiRulesOK](h.svc.RulesView())
}

// AiPostAiRules implements POST /ai/rules (admin).
func (h *AIHandlers) AiPostAiRules(ctx context.Context, req *oas.AiPostAiRulesReq) (*oas.AiPostAiRulesOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[RuleInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddRule(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiRulesOK](v)
}

// AiPutAiRulesID implements PUT /ai/rules/{id} (admin).
func (h *AIHandlers) AiPutAiRulesID(ctx context.Context, req *oas.AiPutAiRulesIDReq, params oas.AiPutAiRulesIDParams) (*oas.AiPutAiRulesIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[RuleInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.EditRule(ctx, who, params.ID, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiRulesIDOK](v)
}

// AiDeleteAiRulesID implements DELETE /ai/rules/{id} (admin).
func (h *AIHandlers) AiDeleteAiRulesID(ctx context.Context, params oas.AiDeleteAiRulesIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteRule(ctx, who, params.ID)
}

// AiGetAiHooks implements GET /ai/hooks (admin).
func (h *AIHandlers) AiGetAiHooks(context.Context) (*oas.AiGetAiHooksOK, error) {
	return convert[oas.AiGetAiHooksOK](h.svc.HooksView())
}

// AiPostAiHooks implements POST /ai/hooks (admin).
func (h *AIHandlers) AiPostAiHooks(ctx context.Context, req *oas.AiPostAiHooksReq) (*oas.AiPostAiHooksOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[HookJSON](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.AddHook(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiHooksOK](v)
}

// AiPutAiHooksID implements PUT /ai/hooks/{id} (admin).
func (h *AIHandlers) AiPutAiHooksID(ctx context.Context, req *oas.AiPutAiHooksIDReq, params oas.AiPutAiHooksIDParams) (*oas.AiPutAiHooksIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[HookJSON](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.EditHook(ctx, who, params.ID, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiHooksIDOK](v)
}

// AiDeleteAiHooksID implements DELETE /ai/hooks/{id} (admin).
func (h *AIHandlers) AiDeleteAiHooksID(ctx context.Context, params oas.AiDeleteAiHooksIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteHook(ctx, who, params.ID)
}

// AiPutAiHooksBuiltinID implements PUT /ai/hooks/builtin/{id} (admin).
func (h *AIHandlers) AiPutAiHooksBuiltinID(ctx context.Context, req *oas.AiPutAiHooksBuiltinIDReq, params oas.AiPutAiHooksBuiltinIDParams) (*oas.AiPutAiHooksBuiltinIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetBuiltinHook(ctx, who, params.ID, req.Enabled)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiHooksBuiltinIDOK](v)
}

// AiPostAiHooksTest implements POST /ai/hooks/test (admin).
func (h *AIHandlers) AiPostAiHooksTest(ctx context.Context, req *oas.AiPostAiHooksTestReq) (*oas.AiPostAiHooksTestOK, error) {
	in, err := convert[HookTestInput](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.TestHook(ctx, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiHooksTestOK](v)
}

// AiPostAiAsk implements POST /ai/ask (operator): the AI answers from the box's data with read-only tools (S-AI-5, S-AI-6).
func (h *AIHandlers) AiPostAiAsk(ctx context.Context, req *oas.AiPostAiAskReq) (*oas.AiPostAiAskOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Ask(ctx, who, req.Question)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiAskOK](v)
}

// AiGetAiAsks implements GET /ai/asks (viewer): the recent questions, newest first.
func (h *AIHandlers) AiGetAiAsks(ctx context.Context) (*oas.AiGetAiAsksOK, error) {
	items, err := h.svc.Asks(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiAsksOK](struct {
		Items []AskResult `json:"items"`
	}{items})
}

// AiGetAiLogsDigest implements GET /ai/logs/digest (viewer): the stored digest of the level in force, with no AI call; null when none.
func (h *AIHandlers) AiGetAiLogsDigest(ctx context.Context) (*oas.AiGetAiLogsDigestOK, error) {
	v, err := h.svc.CachedLogDigest(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiLogsDigestOK](struct {
		Digest *LogDigestResult `json:"digest"`
	}{v})
}

// AiPostAiLogsDigest implements POST /ai/logs/digest (operator): the AI summarises the digest of the logs now.
func (h *AIHandlers) AiPostAiLogsDigest(ctx context.Context) (*oas.AiPostAiLogsDigestOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.LogDigest(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiLogsDigestOK](struct {
		Digest LogDigestResult `json:"digest"`
	}{v})
}
