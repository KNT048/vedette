package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// McpHandlers implements the three /core/mcp operations (CONTRACT, Endpoints owned). The server pipeline answers 404 for them
// while the module is off and enforces the admin role before a handler runs.
type McpHandlers struct{ svc *Service }

// NewMcpHandlers returns the handlers of svc.
func NewMcpHandlers(svc *Service) *McpHandlers { return &McpHandlers{svc: svc} }

func into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("mcpserver: encoding response: %w", err)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("mcpserver: response does not fit the API schema: %w", err)
	}
	return &out, nil
}

func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

type tokenView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Last4     string   `json:"last4"`
	CreatedAt string   `json:"created_at"`
	LastUsed  *string  `json:"last_used"`
}

func view(t Token) tokenView {
	v := tokenView{ID: t.ID, Name: t.Name, Scopes: t.Scopes, Last4: t.Last4, CreatedAt: t.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z")}
	if t.LastUsed != nil {
		u := t.LastUsed.UTC().Format("2006-01-02T15:04:05.000Z")
		v.LastUsed = &u
	}
	return v
}

// CoreGetCoreMcp implements GET /core/mcp (POST-3): the endpoint, the tokens without their secret and the tool list.
func (h *McpHandlers) CoreGetCoreMcp(ctx context.Context) (*oas.CoreGetCoreMcpOK, error) {
	toks, err := h.svc.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]tokenView, 0, len(toks))
	for _, t := range toks {
		views = append(views, view(t))
	}
	tools := make([]map[string]string, 0, len(Tools))
	for _, t := range Tools {
		tools = append(tools, map[string]string{"name": t.Name, "scope": t.Scope})
	}
	bind, endpoint := h.svc.Endpoint()
	return into[oas.CoreGetCoreMcpOK](map[string]any{
		"enabled": true, "bind": bind.Addr().String(), "port": bind.Port(), "endpoint": endpoint,
		"tokens": views, "tools": tools, "scopes": AllScopes,
	})
}

// CorePostCoreMcpTokens implements POST /core/mcp/tokens (POST-2): the full token, this once.
func (h *McpHandlers) CorePostCoreMcpTokens(ctx context.Context, req *oas.CorePostCoreMcpTokensReq) (*oas.CorePostCoreMcpTokensCreated, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	secret, t, err := h.svc.Create(ctx, who, req.Name, req.Scopes)
	if err != nil {
		return nil, err
	}
	return into[oas.CorePostCoreMcpTokensCreated](map[string]any{"token": secret, "item": view(t)})
}

// CoreDeleteCoreMcpTokensID implements DELETE /core/mcp/tokens/{id} (INV-4).
func (h *McpHandlers) CoreDeleteCoreMcpTokensID(ctx context.Context, params oas.CoreDeleteCoreMcpTokensIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.Revoke(ctx, who, params.ID)
}
