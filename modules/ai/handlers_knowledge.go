package ai

import (
	"context"

	"github.com/knt048/vedette/core/api/oas"
)

// The routes of slice 4c: the knowledge base (S-AI-7, INV-10). All need an administrator (the route table says so).

// AiGetAiKnowledge implements GET /ai/knowledge (admin).
func (h *AIHandlers) AiGetAiKnowledge(ctx context.Context) (*oas.AiGetAiKnowledgeOK, error) {
	v, err := h.svc.KnowledgeView(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiGetAiKnowledgeOK](v)
}

// AiPutAiKnowledgeSettings implements PUT /ai/knowledge/settings (admin).
func (h *AIHandlers) AiPutAiKnowledgeSettings(ctx context.Context, req *oas.AiPutAiKnowledgeSettingsReq) (*oas.AiPutAiKnowledgeSettingsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var id *string
	if v, ok := req.IndexProfile.Get(); ok {
		id = &v
	}
	v, err := h.svc.SetIndexProfile(ctx, who, id)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiKnowledgeSettingsOK](v)
}

// AiPostAiKnowledge implements POST /ai/knowledge (admin).
func (h *AIHandlers) AiPostAiKnowledge(ctx context.Context, req *oas.AiPostAiKnowledgeReq) (*oas.AiPostAiKnowledgeOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in := KnowledgeUpload{Name: req.Name, Size: req.Size, Content: req.Content}
	if req.Jobs != nil {
		in.Jobs = make([]string, 0, len(req.Jobs))
		for _, j := range req.Jobs {
			in.Jobs = append(in.Jobs, string(j))
		}
	}
	d, err := h.svc.AddDoc(ctx, who, in)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPostAiKnowledgeOK](d)
}

// AiPutAiKnowledgeID implements PUT /ai/knowledge/{id} (admin).
func (h *AIHandlers) AiPutAiKnowledgeID(ctx context.Context, req *oas.AiPutAiKnowledgeIDReq, params oas.AiPutAiKnowledgeIDParams) (*oas.AiPutAiKnowledgeIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	jobs := make([]string, 0, len(req.Jobs))
	for _, j := range req.Jobs {
		jobs = append(jobs, string(j))
	}
	d, err := h.svc.SetDocJobs(ctx, who, params.ID, jobs)
	if err != nil {
		return nil, err
	}
	return convert[oas.AiPutAiKnowledgeIDOK](d)
}

// AiDeleteAiKnowledgeID implements DELETE /ai/knowledge/{id} (admin).
func (h *AIHandlers) AiDeleteAiKnowledgeID(ctx context.Context, params oas.AiDeleteAiKnowledgeIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteDoc(ctx, who, params.ID)
}
