package agentintake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
)

// AdminHandlers implement the token operations and the page of the Agents section (CONTRACT "Endpoints owned"). The route table requires the
// admin role for all of them; the server answers 404 while the module is off (SYS-5).
type AdminHandlers struct{ s *Service }

// NewAdminHandlers wraps the service; nil gives 501 for every operation, like a module that is not wired.
func NewAdminHandlers(s *Service) *AdminHandlers { return &AdminHandlers{s: s} }

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// nilTime is a time of the service as the contract has it: the zero time is null.
func nilTime(t time.Time) oas.NilDateTime {
	if t.IsZero() {
		return oas.NilDateTime{Null: true}
	}
	return oas.NewNilDateTime(t)
}

// InventoryGetInventoryAgents implements GET /inventory/agents: the tokens (last four characters only), the Wazuh card, and what the install
// box needs: the scripts as the box serves them to the very address this request came in at, and their SHA-256.
func (h *AdminHandlers) InventoryGetInventoryAgents(ctx context.Context) (*oas.InventoryGetInventoryAgentsOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	if _, err := adminActor(ctx); err != nil {
		return nil, err
	}
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	list, err := h.s.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	sh, ps1, err := h.s.installFor(x.R.Host, true)
	if err != nil {
		return nil, fmt.Errorf("agentintake: the box certificate: %w", err)
	}
	box := h.s.boxURL(x.R.Host)
	out := &oas.InventoryGetInventoryAgentsOK{
		ServerURL: box,
		Tokens:    make([]oas.InventoryGetInventoryAgentsOKTokensItem, 0, len(list)),
		Wazuh:     oas.NilInventoryGetInventoryAgentsOKWazuh{Null: true},
	}
	out.Install.OsqueryVersion = OsqueryVersion
	out.Install.Linux = oas.InventoryGetInventoryAgentsOKInstallLinux{URL: box + "/api/v1/install/osquery.sh", SHA256: sha256Hex(sh), Script: sh}
	out.Install.Windows = oas.InventoryGetInventoryAgentsOKInstallWindows{URL: box + "/api/v1/install/osquery.ps1", SHA256: sha256Hex(ps1), Script: ps1}
	for _, t := range list {
		out.Tokens = append(out.Tokens, oas.InventoryGetInventoryAgentsOKTokensItem{
			ID: t.ID, Name: t.Name, Kind: oas.InventoryGetInventoryAgentsOKTokensItemKindOsquery, Last4: t.Last4, CreatedAt: t.CreatedAt, Hosts: t.Hosts,
			ExpiresAt:    nilTime(t.ExpiresAt),
			LastReceived: nilTime(t.LastReceived),
		})
	}
	w, err := h.s.Wazuh(ctx)
	if err != nil {
		return nil, err
	}
	if w != nil {
		c := oas.InventoryGetInventoryAgentsOKWazuh{
			URL: w.URL, Username: w.Username, PasswordLast4: w.PasswordLast4, IntervalMinutes: w.IntervalMinutes,
			Status: oas.InventoryGetInventoryAgentsOKWazuhStatus(w.Status), Agents: w.Agents, Packages: w.Packages,
			LastSync: nilTime(w.LastSync), Error: oas.NilString{Null: true},
		}
		if w.Error != "" {
			c.Error = oas.NewNilString(w.Error)
		}
		out.Wazuh = oas.NewNilInventoryGetInventoryAgentsOKWazuh(c)
	}
	return out, nil
}

// InventoryPostInventoryAgentsTokens implements POST /inventory/agents/tokens: the secret is in this answer and nowhere else, and never in the
// audit line or the log (INV-3, INV-4). The default expiry is 7 days (D-34).
func (h *AdminHandlers) InventoryPostInventoryAgentsTokens(ctx context.Context, req *oas.InventoryPostInventoryAgentsTokensReq) (*oas.InventoryPostInventoryAgentsTokensCreated, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return nil, err
	}
	t, secret, err := h.s.IssueToken(ctx, who, req.Name, req.ExpiresInDays.Or(7))
	if err != nil {
		return nil, err
	}
	tok := oas.InventoryPostInventoryAgentsTokensCreatedToken{
		ID: t.ID, Name: t.Name, Kind: oas.InventoryPostInventoryAgentsTokensCreatedTokenKindOsquery, Last4: t.Last4, CreatedAt: t.CreatedAt,
		ExpiresAt: oas.NilDateTime{Null: true}, LastReceived: oas.NilDateTime{Null: true},
	}
	if !t.ExpiresAt.IsZero() {
		tok.ExpiresAt = oas.NewNilDateTime(t.ExpiresAt)
	}
	return &oas.InventoryPostInventoryAgentsTokensCreated{Token: tok, Secret: secret}, nil
}

// InventoryDeleteInventoryAgentsTokensID implements DELETE /inventory/agents/tokens/{id}: the token goes with its nodes (POST-3); what they
// already delivered stays in the inventory.
func (h *AdminHandlers) InventoryDeleteInventoryAgentsTokensID(ctx context.Context, params oas.InventoryDeleteInventoryAgentsTokensIDParams) error {
	if h.s == nil {
		return apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return err
	}
	return h.s.RevokeToken(ctx, who, params.ID)
}
