package sensoractive

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
)

// SNMPHandlers implement the SNMP credential operations (CONTRACT "Endpoints owned", D-512): list, add, edit, delete, test. The
// route table requires the admin role; the server answers 404 for all of them while the module is off (SYS-5).
type SNMPHandlers struct{ s *Service }

// NewSNMPHandlers wraps the service; nil gives 501 for every operation, like a module that is not wired.
func NewSNMPHandlers(s *Service) *SNMPHandlers { return &SNMPHandlers{s: s} }

func (h *SNMPHandlers) actor(ctx context.Context) (string, error) {
	if h.s == nil {
		return "", apierr.NotImplemented()
	}
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// credentialItem is a credential in the shape of the API.
func credentialItem(c SNMPCredential) oas.InventoryGetInventorySnmpOKCredentialsItem {
	out := oas.InventoryGetInventorySnmpOKCredentialsItem{
		ID: c.ID, Name: c.Name, Version: oas.InventoryGetInventorySnmpOKCredentialsItemVersion(c.Version), SecretLast4: c.SecretLast4, PrivLast4: c.PrivLast4,
		Scope: c.Scope, CreatedAt: c.CreatedAt, Answered: c.Answered, Username: oas.NilString{Null: true}, LastAnswerAt: oas.NilDateTime{Null: true},
		Auth: oas.NilInventoryGetInventorySnmpOKCredentialsItemAuth{Null: true}, Priv: oas.NilInventoryGetInventorySnmpOKCredentialsItemPriv{Null: true},
	}
	if c.Version == "v3" {
		out.Username = oas.NewNilString(c.Username)
		out.Auth = oas.NewNilInventoryGetInventorySnmpOKCredentialsItemAuth(oas.InventoryGetInventorySnmpOKCredentialsItemAuth(c.Auth))
		out.Priv = oas.NewNilInventoryGetInventorySnmpOKCredentialsItemPriv(oas.InventoryGetInventorySnmpOKCredentialsItemPriv(c.Priv))
	}
	if !c.LastAnswerAt.IsZero() {
		out.LastAnswerAt = oas.NewNilDateTime(c.LastAnswerAt)
	}
	return out
}

// as converts a credential to one of the other generated types of the same JSON shape (created, edited).
func as[T any](c SNMPCredential) (*T, error) {
	b, err := json.Marshal(credentialItem(c))
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("sensoractive: credential shape: %w", err)
	}
	return &out, nil
}

func formOf(name, version string, community, user oas.OptString, auth, priv string, authPass, privPass oas.OptString, scope []string) SNMPCredentialInput {
	in := SNMPCredentialInput{Name: name, Version: version, Username: user.Or(""), Auth: auth, Priv: priv, Scope: scope}
	in.Community, in.AuthPassword, in.PrivPassword = secrets.NewValue(community.Or("")), secrets.NewValue(authPass.Or("")), secrets.NewValue(privPass.Or(""))
	return in
}

// InventoryGetInventorySnmp implements GET /inventory/snmp.
func (h *SNMPHandlers) InventoryGetInventorySnmp(ctx context.Context) (*oas.InventoryGetInventorySnmpOK, error) {
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	list, err := h.s.SNMPCredentials(ctx)
	if err != nil {
		return nil, err
	}
	out := &oas.InventoryGetInventorySnmpOK{Credentials: make([]oas.InventoryGetInventorySnmpOKCredentialsItem, len(list)), Message: oas.NilString{Null: true}}
	for i, c := range list {
		out.Credentials[i] = credentialItem(c)
	}
	ready, msg := h.s.SNMPStatus()
	out.Ready = ready
	if !ready {
		out.Message = oas.NewNilString(msg)
	}
	return out, nil
}

// InventoryPostInventorySnmp implements POST /inventory/snmp.
func (h *SNMPHandlers) InventoryPostInventorySnmp(ctx context.Context, req *oas.InventoryPostInventorySnmpReq) (*oas.InventoryPostInventorySnmpCreated, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in := formOf(req.Name, string(req.Version), req.Community, req.Username, string(req.Auth.Or("")), string(req.Priv.Or("")), req.AuthPassword, req.PrivPassword, req.Scope)
	c, err := h.s.AddSNMP(ctx, who, in)
	if err != nil {
		return nil, err
	}
	return as[oas.InventoryPostInventorySnmpCreated](c)
}

// InventoryPutInventorySnmpID implements PUT /inventory/snmp/{id}.
func (h *SNMPHandlers) InventoryPutInventorySnmpID(ctx context.Context, req *oas.InventoryPutInventorySnmpIDReq, params oas.InventoryPutInventorySnmpIDParams) (*oas.InventoryPutInventorySnmpIDOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in := formOf(req.Name, string(req.Version), req.Community, req.Username, string(req.Auth.Or("")), string(req.Priv.Or("")), req.AuthPassword, req.PrivPassword, req.Scope)
	c, err := h.s.EditSNMP(ctx, who, params.ID, in)
	if err != nil {
		return nil, err
	}
	return as[oas.InventoryPutInventorySnmpIDOK](c)
}

// InventoryDeleteInventorySnmpID implements DELETE /inventory/snmp/{id}.
func (h *SNMPHandlers) InventoryDeleteInventorySnmpID(ctx context.Context, params oas.InventoryDeleteInventorySnmpIDParams) error {
	who, err := h.actor(ctx)
	if err != nil {
		return err
	}
	return h.s.DeleteSNMP(ctx, who, params.ID)
}

// InventoryPostInventorySnmpIDTest implements POST /inventory/snmp/{id}/test.
func (h *SNMPHandlers) InventoryPostInventorySnmpIDTest(ctx context.Context, req *oas.InventoryPostInventorySnmpIDTestReq, params oas.InventoryPostInventorySnmpIDTestParams) (*oas.InventoryPostInventorySnmpIDTestOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.s.TestSNMP(ctx, who, params.ID, req.IP)
	if err != nil {
		return nil, err
	}
	out := &oas.InventoryPostInventorySnmpIDTestOK{Ok: r.OK, Reason: oas.InventoryPostInventorySnmpIDTestOKReason(r.Reason), Message: r.Message,
		DeviceID: oas.NilString{Null: true}, Answer: oas.NilInventoryPostInventorySnmpIDTestOKAnswer{Null: true}}
	if r.DeviceID != "" {
		out.DeviceID = oas.NewNilString(r.DeviceID)
	}
	if a := r.Answer; a != nil {
		out.Answer = oas.NewNilInventoryPostInventorySnmpIDTestOKAnswer(oas.InventoryPostInventorySnmpIDTestOKAnswer{
			SysDescr: a.SysDescr, SysObjectID: a.SysObjectID, SysName: a.SysName, Vendor: a.Vendor, Product: a.Product, Model: a.Model,
			Os: a.OS, Kind: a.Kind, Serial: a.Serial, Firmware: a.Firmware,
		})
	}
	return out, nil
}
