package honeypot

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// HoneypotHandlers implements the 15 operations of the module. Embed it in the composite handler of cmd/vedette. The
// role of each route comes from the route table, so nothing here checks roles. Answers are built from the domain types
// (their JSON names are the wire names) and decoded into the generated ones, as notify does.
//
//nolint:revive // the name is distinct on purpose: cmd/vedette embeds every module's handler struct and two fields named Handlers would not compile
type HoneypotHandlers struct{ svc *Service }

// NewHoneypotHandlers returns the handlers of the module.
func NewHoneypotHandlers(svc *Service) *HoneypotHandlers { return &HoneypotHandlers{svc: svc} }

func convert[T any](v any) (*T, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("honeypot: encode: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("honeypot: decode: %w", err)
	}
	return out, nil
}

func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// HoneypotGetHoneypot implements GET /honeypot (viewer).
func (h *HoneypotHandlers) HoneypotGetHoneypot(ctx context.Context) (*oas.HoneypotGetHoneypotOK, error) {
	o, err := h.svc.Overview(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotGetHoneypotOK](o)
}

// HoneypotPutHoneypotConfig implements PUT /honeypot/config (admin).
func (h *HoneypotHandlers) HoneypotPutHoneypotConfig(ctx context.Context, req *oas.HoneypotPutHoneypotConfigReq) (*oas.HoneypotPutHoneypotConfigOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	o, err := h.svc.SetConfig(ctx, who, req.SecondaryIP, req.Hostname)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPutHoneypotConfigOK](o)
}

// HoneypotPatchHoneypotTrapsService implements PATCH /honeypot/traps/{service} (admin).
func (h *HoneypotHandlers) HoneypotPatchHoneypotTrapsService(ctx context.Context, req *oas.HoneypotPatchHoneypotTrapsServiceReq, params oas.HoneypotPatchHoneypotTrapsServiceParams) (*oas.HoneypotPatchHoneypotTrapsServiceOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	o, err := h.svc.SetTrap(ctx, who, ServiceName(params.Service), req.Enabled)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPatchHoneypotTrapsServiceOK](o)
}

// HoneypotGetHoneypotHits implements GET /honeypot/hits (viewer).
func (h *HoneypotHandlers) HoneypotGetHoneypotHits(ctx context.Context, params oas.HoneypotGetHoneypotHitsParams) (*oas.HoneypotGetHoneypotHitsOK, error) {
	l, err := h.svc.Hits(ctx, HitFilter{Asset: params.Asset.Or("")})
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotGetHoneypotHitsOK](struct {
		Items []Hit `json:"items"`
	}{l})
}

// HoneypotGetHoneypotHitsID implements GET /honeypot/hits/{id} (viewer).
func (h *HoneypotHandlers) HoneypotGetHoneypotHitsID(ctx context.Context, params oas.HoneypotGetHoneypotHitsIDParams) (*oas.HoneypotGetHoneypotHitsIDOK, error) {
	d, err := h.svc.HitDetail(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotGetHoneypotHitsIDOK](d)
}

// HoneypotPostHoneypotTestHit implements POST /honeypot/test-hit (operator).
func (h *HoneypotHandlers) HoneypotPostHoneypotTestHit(ctx context.Context, req *oas.HoneypotPostHoneypotTestHitReq) (*oas.HoneypotPostHoneypotTestHitOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	hit, err := h.svc.TestHit(ctx, who, ServiceName(req.Service))
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPostHoneypotTestHitOK](hit)
}

// HoneypotGetHoneypotDecoys implements GET /honeypot/decoys (viewer).
func (h *HoneypotHandlers) HoneypotGetHoneypotDecoys(ctx context.Context) (*oas.HoneypotGetHoneypotDecoysOK, error) {
	d, err := h.svc.Decoys(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotGetHoneypotDecoysOK](d)
}

// HoneypotPostHoneypotDecoys implements POST /honeypot/decoys (admin).
func (h *HoneypotHandlers) HoneypotPostHoneypotDecoys(ctx context.Context, req *oas.HoneypotPostHoneypotDecoysReq) (*oas.HoneypotPostHoneypotDecoysCreated, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.AddDecoy(ctx, who, DecoyInput{Personality: Personality(req.Personality), Name: req.Name, IP: req.IP})
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPostHoneypotDecoysCreated](d)
}

// HoneypotPatchHoneypotDecoysID implements PATCH /honeypot/decoys/{id} (admin).
func (h *HoneypotHandlers) HoneypotPatchHoneypotDecoysID(ctx context.Context, req *oas.HoneypotPatchHoneypotDecoysIDReq, params oas.HoneypotPatchHoneypotDecoysIDParams) (*oas.HoneypotPatchHoneypotDecoysIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.SetDecoyEnabled(ctx, who, params.ID, req.Enabled)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPatchHoneypotDecoysIDOK](d)
}

// HoneypotDeleteHoneypotDecoysID implements DELETE /honeypot/decoys/{id} (admin).
func (h *HoneypotHandlers) HoneypotDeleteHoneypotDecoysID(ctx context.Context, params oas.HoneypotDeleteHoneypotDecoysIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteDecoy(ctx, who, params.ID)
}

// HoneypotPostHoneypotTestScan implements POST /honeypot/test-scan (operator).
func (h *HoneypotHandlers) HoneypotPostHoneypotTestScan(ctx context.Context) (*oas.HoneypotPostHoneypotTestScanOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	hit, err := h.svc.TestScan(ctx, who)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPostHoneypotTestScanOK](hit)
}

// HoneypotGetHoneypotTokens implements GET /honeypot/tokens (viewer).
func (h *HoneypotHandlers) HoneypotGetHoneypotTokens(ctx context.Context) (*oas.HoneypotGetHoneypotTokensOK, error) {
	l, err := h.svc.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotGetHoneypotTokensOK](struct {
		Items []Token `json:"items"`
	}{l})
}

// HoneypotPostHoneypotTokens implements POST /honeypot/tokens (admin).
func (h *HoneypotHandlers) HoneypotPostHoneypotTokens(ctx context.Context, req *oas.HoneypotPostHoneypotTokensReq) (*oas.HoneypotPostHoneypotTokensCreated, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	t, err := h.svc.AddToken(ctx, who, TokenInput{Type: TokenType(req.Type), Name: req.Name, PlantAt: req.PlantAt, Ext: string(req.Ext.Or(""))})
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPostHoneypotTokensCreated](t)
}

// HoneypotDeleteHoneypotTokensID implements DELETE /honeypot/tokens/{id} (admin).
func (h *HoneypotHandlers) HoneypotDeleteHoneypotTokensID(ctx context.Context, params oas.HoneypotDeleteHoneypotTokensIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteToken(ctx, who, params.ID)
}

// HoneypotPostHoneypotTokensIDTest implements POST /honeypot/tokens/{id}/test (operator).
func (h *HoneypotHandlers) HoneypotPostHoneypotTokensIDTest(ctx context.Context, params oas.HoneypotPostHoneypotTokensIDTestParams) (*oas.HoneypotPostHoneypotTokensIDTestOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	hit, err := h.svc.TestToken(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPostHoneypotTokensIDTestOK](hit)
}
