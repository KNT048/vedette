package honeypot

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// HoneypotHandlers implements the 14 operations of the module. Embed it in the composite handler of cmd/vedette. The
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

// HoneypotGetHoneypotTrapIps implements GET /honeypot/trap-ips (viewer).
func (h *HoneypotHandlers) HoneypotGetHoneypotTrapIps(ctx context.Context) (*oas.HoneypotGetHoneypotTrapIpsOK, error) {
	d, err := h.svc.TrapIPs(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotGetHoneypotTrapIpsOK](d)
}

// HoneypotPostHoneypotTrapIps implements POST /honeypot/trap-ips (admin). The body passed the schema (SYS-2); the service
// checks the values.
func (h *HoneypotHandlers) HoneypotPostHoneypotTrapIps(ctx context.Context, req *oas.HoneypotPostHoneypotTrapIpsReq) (*oas.HoneypotPostHoneypotTrapIpsCreated, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[TrapIPInput](req)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.AddTrapIP(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPostHoneypotTrapIpsCreated](d)
}

// HoneypotPutHoneypotTrapIpsID implements PUT /honeypot/trap-ips/{id} (admin).
func (h *HoneypotHandlers) HoneypotPutHoneypotTrapIpsID(ctx context.Context, req *oas.HoneypotPutHoneypotTrapIpsIDReq, params oas.HoneypotPutHoneypotTrapIpsIDParams) (*oas.HoneypotPutHoneypotTrapIpsIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[TrapIPInput](req)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.EditTrapIP(ctx, who, params.ID, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPutHoneypotTrapIpsIDOK](d)
}

// HoneypotPatchHoneypotTrapIpsID implements PATCH /honeypot/trap-ips/{id} (admin).
func (h *HoneypotHandlers) HoneypotPatchHoneypotTrapIpsID(ctx context.Context, req *oas.HoneypotPatchHoneypotTrapIpsIDReq, params oas.HoneypotPatchHoneypotTrapIpsIDParams) (*oas.HoneypotPatchHoneypotTrapIpsIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.SetTrapIPEnabled(ctx, who, params.ID, req.Enabled)
	if err != nil {
		return nil, err
	}
	return convert[oas.HoneypotPatchHoneypotTrapIpsIDOK](d)
}

// HoneypotDeleteHoneypotTrapIpsID implements DELETE /honeypot/trap-ips/{id} (admin).
func (h *HoneypotHandlers) HoneypotDeleteHoneypotTrapIpsID(ctx context.Context, params oas.HoneypotDeleteHoneypotTrapIpsIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteTrapIP(ctx, who, params.ID)
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

// HoneypotGetHoneypotTokens implements GET /honeypot/tokens (viewer). The bait passwords are in full for an operator and an
// administrator only; a viewer gets the last 4 characters, so an insider with a read-only account cannot learn the canary
// set (INV-10, D-189).
func (h *HoneypotHandlers) HoneypotGetHoneypotTokens(ctx context.Context) (*oas.HoneypotGetHoneypotTokensOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	l, err := h.svc.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	if p.Role != routes.Operator && p.Role != routes.Admin { // fail closed: viewer and any unknown role see the mask
		l = MaskTokens(l)
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
