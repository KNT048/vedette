package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
)

// Connections (D-93, D-94; S-AI-7, S-RESP-4): the endpoints of Settings → Connections, admin only. The rules, the credential
// store and the audit rows live in core/conn; the handlers only move values between the generated types and conn. A secret
// never appears in an answer: conn.Connection has no field for it.

// wireSecret reads the secret of a request into a value that prints, formats and marshals as a placeholder, so no log line or
// error that shows the request can show the secret.
type wireSecret struct{ secrets.Value }

func (w *wireSecret) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	w.Value = secrets.NewValue(s)
	return nil
}

// wireInput is the body of POST and PUT /core/connections. The generated request types differ only in the names of their
// enums, so both are read through their JSON form.
type wireInput struct {
	Name     string     `json:"name"`
	Kind     string     `json:"kind"`
	Target   string     `json:"target"`
	AssetID  *string    `json:"asset_id"`
	AuthType string     `json:"auth_type"`
	Secret   wireSecret `json:"secret"`
	Username *string    `json:"username"`
	ClearPin *bool      `json:"clear_pin"`
	Allow    []string   `json:"allow"`
	Enabled  bool       `json:"enabled"`
	Tools    []struct {
		Name    string  `json:"name"`
		Enabled bool    `json:"enabled"`
		Access  *string `json:"access"`
	} `json:"tools"`
}

func connInput(req json.Marshaler) (conn.Input, error) {
	raw, err := req.MarshalJSON()
	if err != nil {
		return conn.Input{}, fmt.Errorf("core: encode connection request: %w", err)
	}
	var w wireInput
	if err := json.Unmarshal(raw, &w); err != nil {
		return conn.Input{}, fmt.Errorf("core: read connection request: %w", err)
	}
	in := conn.Input{Name: w.Name, Kind: w.Kind, Target: w.Target, AssetID: w.AssetID, AuthType: w.AuthType, Secret: w.Secret.Value,
		Username: w.Username, ClearPin: w.ClearPin != nil && *w.ClearPin, Allow: w.Allow, Enabled: w.Enabled}
	for _, t := range w.Tools {
		in.Tools = append(in.Tools, conn.ToolInput{Name: t.Name, Enabled: t.Enabled, Access: t.Access})
	}
	return in, nil
}

// connView converts a connection to the generated answer type through its JSON form (the three answer types are the same
// shape under three names).
func connView[T any, P interface {
	*T
	json.Unmarshaler
}](c conn.Connection) (*T, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("core: encode connection: %w", err)
	}
	out := new(T)
	if err := P(out).UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("core: decode connection: %w", err)
	}
	return out, nil
}

// connsOrNotImplemented is the store, or 501 in a build that did not wire it (never a made-up answer).
func (h *APIHandlers) connsOrNotImplemented() (*conn.Service, error) {
	if h.conns == nil {
		return nil, apierr.NotImplemented()
	}
	return h.conns, nil
}

// CoreGetCoreConnections implements GET /core/connections (admin).
func (h *APIHandlers) CoreGetCoreConnections(ctx context.Context) (*oas.CoreGetCoreConnectionsOK, error) {
	svc, err := h.connsOrNotImplemented()
	if err != nil {
		return nil, err
	}
	list, err := svc.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &oas.CoreGetCoreConnectionsOK{Items: make([]oas.CoreGetCoreConnectionsOKItemsItem, 0, len(list))}
	for _, c := range list {
		v, err := connView[oas.CoreGetCoreConnectionsOKItemsItem](c)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, *v)
	}
	return out, nil
}

// CorePostCoreConnections implements POST /core/connections (admin, 201).
func (h *APIHandlers) CorePostCoreConnections(ctx context.Context, req *oas.CorePostCoreConnectionsReq) (*oas.CorePostCoreConnectionsCreated, error) {
	svc, err := h.connsOrNotImplemented()
	if err != nil {
		return nil, err
	}
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	in, err := connInput(req)
	if err != nil {
		return nil, err
	}
	var made conn.Connection
	err = h.db.Write(ctx, func(tx *sql.Tx) (err error) {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		made, err = svc.Create(ctx, tx, c.Email, in)
		return err
	})
	if err != nil {
		return nil, err
	}
	return connView[oas.CorePostCoreConnectionsCreated](made)
}

// CorePutCoreConnectionsID implements PUT /core/connections/{id} (admin).
func (h *APIHandlers) CorePutCoreConnectionsID(ctx context.Context, req *oas.CorePutCoreConnectionsIDReq, params oas.CorePutCoreConnectionsIDParams) (*oas.CorePutCoreConnectionsIDOK, error) {
	svc, err := h.connsOrNotImplemented()
	if err != nil {
		return nil, err
	}
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	in, err := connInput(req)
	if err != nil {
		return nil, err
	}
	var made conn.Connection
	err = h.db.Write(ctx, func(tx *sql.Tx) (err error) {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		made, err = svc.Update(ctx, tx, c.Email, params.ID, in)
		return err
	})
	if err != nil {
		return nil, err
	}
	return connView[oas.CorePutCoreConnectionsIDOK](made)
}

// CoreDeleteCoreConnectionsID implements DELETE /core/connections/{id} (admin): 409 in_use while a change made through it
// is still in force.
func (h *APIHandlers) CoreDeleteCoreConnectionsID(ctx context.Context, params oas.CoreDeleteCoreConnectionsIDParams) error {
	svc, err := h.connsOrNotImplemented()
	if err != nil {
		return err
	}
	c, err := h.caller(ctx)
	if err != nil {
		return err
	}
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		return svc.Delete(ctx, tx, c.Email, params.ID)
	})
}

// CorePostCoreConnectionsIDTest implements POST /core/connections/{id}/test (admin). The transports and the pin come with
// slice 13b-5, so a connection that is on answers 501 and nothing is sent; one that is off is 409 connection_off first
// (PRIVACY flow 12: nothing goes to a connection that is turned off).
func (h *APIHandlers) CorePostCoreConnectionsIDTest(ctx context.Context, params oas.CorePostCoreConnectionsIDTestParams) (*oas.CorePostCoreConnectionsIDTestOK, error) {
	svc, err := h.connsOrNotImplemented()
	if err != nil {
		return nil, err
	}
	cur, err := svc.Get(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	if !cur.Enabled {
		return nil, apierr.New(409, "connection_off", "This connection is turned off, so nothing is sent to it. Turn it on, then test it.")
	}
	return nil, apierr.NotImplemented()
}
