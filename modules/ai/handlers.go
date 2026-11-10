package ai

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// AIHandlers implements the operations of the ai module that this slice builds: profiles, keys, assignments and the shared token
// settings (S-AI-1). Embed it in the composite handler of cmd/vedette. The role of each route comes from the route table, so
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
	v, err := h.svc.SetConfig(ctx, who, Settings{Tier: Tier(req.Tier), DailyCap: req.DailyCap, RedactPII: req.RedactPii})
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
