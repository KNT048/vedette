package agentintake

import (
	"context"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
)

// WazuhHandlers implement the admin operations of the Wazuh card (CONTRACT "Endpoints owned"): test, save, delete, and the mock-only
// sample data, which answers 404 in the real build (INV-10). The route table requires the admin role; the server answers 404 for all
// of them while the module is off (SYS-5).
type WazuhHandlers struct{ s *Service }

// NewWazuhHandlers wraps the service; nil gives 501 for every operation, like a module that is not wired.
func NewWazuhHandlers(s *Service) *WazuhHandlers { return &WazuhHandlers{s: s} }

func adminActor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

func wazuhInput(url, user string, pw oas.OptString, interval int) WazuhInput {
	in := WazuhInput{URL: url, Username: user, IntervalMinutes: interval}
	if v, ok := pw.Get(); ok && v != "" {
		in.Password = secrets.NewValue(v)
	}
	return in
}

// InventoryPostInventoryAgentsWazuhTest implements POST /inventory/agents/wazuh/test.
func (h *WazuhHandlers) InventoryPostInventoryAgentsWazuhTest(ctx context.Context, req *oas.InventoryPostInventoryAgentsWazuhTestReq) (*oas.InventoryPostInventoryAgentsWazuhTestOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	if _, err := adminActor(ctx); err != nil {
		return nil, err
	}
	r, err := h.s.TestWazuh(ctx, wazuhInput(req.URL, req.Username, req.Password, req.IntervalMinutes))
	if err != nil {
		return nil, err
	}
	return &oas.InventoryPostInventoryAgentsWazuhTestOK{Ok: true, Version: r.Version, Agents: r.Agents}, nil
}

// InventoryPutInventoryAgentsWazuh implements PUT /inventory/agents/wazuh.
func (h *WazuhHandlers) InventoryPutInventoryAgentsWazuh(ctx context.Context, req *oas.InventoryPutInventoryAgentsWazuhReq) (*oas.InventoryPutInventoryAgentsWazuhOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return nil, err
	}
	w, err := h.s.SaveWazuh(ctx, who, wazuhInput(req.URL, req.Username, req.Password, req.IntervalMinutes))
	if err != nil {
		return nil, err
	}
	out := &oas.InventoryPutInventoryAgentsWazuhOK{
		URL: w.URL, Username: w.Username, PasswordLast4: w.PasswordLast4, IntervalMinutes: w.IntervalMinutes,
		Status: oas.InventoryPutInventoryAgentsWazuhOKStatus(w.Status), Agents: w.Agents, Packages: w.Packages,
		LastSync: oas.NilDateTime{Null: true}, Error: oas.NilString{Null: true},
	}
	if !w.LastSync.IsZero() {
		out.LastSync = oas.NewNilDateTime(w.LastSync)
	}
	if w.Error != "" {
		out.Error = oas.NewNilString(w.Error)
	}
	return out, nil
}

// InventoryDeleteInventoryAgentsWazuh implements DELETE /inventory/agents/wazuh: the connection and its password go together.
func (h *WazuhHandlers) InventoryDeleteInventoryAgentsWazuh(ctx context.Context) error {
	if h.s == nil {
		return apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return err
	}
	return h.s.DeleteWazuh(ctx, who)
}

// InventoryPostInventoryAgentsWazuhSampleData is the preview-only sample data (INV-10): the real build has none, like an unknown route.
func (h *WazuhHandlers) InventoryPostInventoryAgentsWazuhSampleData(context.Context) (*oas.InventoryPostInventoryAgentsWazuhSampleDataOK, error) {
	return nil, apierr.NotFound()
}
