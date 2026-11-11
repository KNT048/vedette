package ai

import (
	"context"

	"github.com/knt048/vedette/core/api/oas"
)

// The routes of slice 4b: memory and skills. All need an administrator (the route table says so).

// AiGetAiMemory implements GET /ai/memory (admin).
func (h *AIHandlers) AiGetAiMemory(ctx context.Context) (*oas.AiGetAiMemoryOK, error) {
	v, err := h.svc.MemoryView(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiMemoryOK](v)
}

// AiPostAiMemory implements POST /ai/memory (admin).
func (h *AIHandlers) AiPostAiMemory(ctx context.Context, req *oas.AiPostAiMemoryReq) (*oas.AiPostAiMemoryOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.AddMemory(ctx, who, req.Text)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiMemoryOK](m)
}

// AiPutAiMemorySettings implements PUT /ai/memory/settings (admin).
func (h *AIHandlers) AiPutAiMemorySettings(ctx context.Context, req *oas.AiPutAiMemorySettingsReq) (*oas.AiPutAiMemorySettingsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetSuggest(ctx, who, req.SuggestEnabled)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiMemorySettingsOK](v)
}

// AiPutAiMemoryID implements PUT /ai/memory/{id} (admin).
func (h *AIHandlers) AiPutAiMemoryID(ctx context.Context, req *oas.AiPutAiMemoryIDReq, params oas.AiPutAiMemoryIDParams) (*oas.AiPutAiMemoryIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var p MemoryPatch
	if v, ok := req.Text.Get(); ok {
		p.Text = &v
	}
	if v, ok := req.Enabled.Get(); ok {
		p.Enabled = &v
	}
	m, err := h.svc.EditMemory(ctx, who, params.ID, p)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiMemoryIDOK](m)
}

// AiDeleteAiMemoryID implements DELETE /ai/memory/{id} (admin).
func (h *AIHandlers) AiDeleteAiMemoryID(ctx context.Context, params oas.AiDeleteAiMemoryIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteMemory(ctx, who, params.ID)
}

// AiPostAiMemorySuggestionsIDAccept implements POST /ai/memory/suggestions/{id}/accept (admin).
func (h *AIHandlers) AiPostAiMemorySuggestionsIDAccept(ctx context.Context, params oas.AiPostAiMemorySuggestionsIDAcceptParams) (*oas.AiPostAiMemorySuggestionsIDAcceptOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.AcceptSuggestion(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiMemorySuggestionsIDAcceptOK](m)
}

// AiPostAiMemorySuggestionsIDReject implements POST /ai/memory/suggestions/{id}/reject (admin).
func (h *AIHandlers) AiPostAiMemorySuggestionsIDReject(ctx context.Context, params oas.AiPostAiMemorySuggestionsIDRejectParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.RejectSuggestion(ctx, who, params.ID)
}

// AiGetAiSkills implements GET /ai/skills (admin).
func (h *AIHandlers) AiGetAiSkills(context.Context) (*oas.AiGetAiSkillsOK, error) {
	return convert[oas.AiGetAiSkillsOK](struct {
		Items []SkillView `json:"items"`
	}{h.svc.Skills()})
}

// AiPutAiSkillsID implements PUT /ai/skills/{id} (admin).
func (h *AIHandlers) AiPutAiSkillsID(ctx context.Context, req *oas.AiPutAiSkillsIDReq, params oas.AiPutAiSkillsIDParams) (*oas.AiPutAiSkillsIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.SetSkill(ctx, who, params.ID, req.Enabled)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiSkillsIDOK](v)
}
