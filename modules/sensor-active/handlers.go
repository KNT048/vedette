package sensoractive

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
)

// SNMPHandlers implement the SNMP credential operations (CONTRACT "Endpoints owned", D-512): list, add, edit, delete, test, and Read
// now (#849). The
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

// readWire is a Read now in the JSON shape of the API (SnmpRead in contract.ts).
type readWire struct {
	ID           string     `json:"id"`
	CredentialID string     `json:"credential_id"`
	By           string     `json:"by"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	Status       string     `json:"status"`
	Message      *string    `json:"message"`
	Total        int        `json:"total"`
	Done         int        `json:"done"`
	Answered     int        `json:"answered"`
	Skipped      int        `json:"skipped"`
	Results      []readRow  `json:"results"`
}

type readRow struct {
	IP       string     `json:"ip"`
	OK       bool       `json:"ok"`
	Reason   string     `json:"reason"`
	Message  string     `json:"message"`
	DeviceID *string    `json:"device_id"`
	Answer   *answerRow `json:"answer"`
}

type answerRow struct {
	SysDescr    string `json:"sys_descr"`
	SysObjectID string `json:"sys_object_id"`
	SysName     string `json:"sys_name"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Model       string `json:"model"`
	OS          string `json:"os"`
	Kind        string `json:"kind"`
	Serial      string `json:"serial"`
	Firmware    string `json:"firmware"`
}

// readAs converts a read to the generated type T of the same JSON shape.
func readAs[T any](r SNMPRead) (*T, error) {
	w := readWire{ID: r.ID, CredentialID: r.CredentialID, By: r.By, StartedAt: r.StartedAt, Status: r.Status, Total: r.Total, Done: r.Done,
		Answered: r.Answered, Skipped: r.Skipped, Results: []readRow{}}
	if !r.FinishedAt.IsZero() {
		w.FinishedAt = &r.FinishedAt
	}
	if r.Message != "" {
		w.Message = &r.Message
	}
	for _, x := range r.Results {
		row := readRow{IP: x.IP, OK: x.OK, Reason: x.Reason, Message: x.Message}
		if x.DeviceID != "" {
			row.DeviceID = &x.DeviceID
		}
		if a := x.Answer; a != nil {
			row.Answer = &answerRow{SysDescr: a.SysDescr, SysObjectID: a.SysObjectID, SysName: a.SysName, Vendor: a.Vendor, Product: a.Product,
				Model: a.Model, OS: a.OS, Kind: a.Kind, Serial: a.Serial, Firmware: a.Firmware}
		}
		w.Results = append(w.Results, row)
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("sensoractive: read shape: %w", err)
	}
	return &out, nil
}

// InventoryPostInventorySnmpIDRead implements POST /inventory/snmp/{id}/read (#849): Read now, 202 with the run.
func (h *SNMPHandlers) InventoryPostInventorySnmpIDRead(ctx context.Context, params oas.InventoryPostInventorySnmpIDReadParams) (*oas.InventoryPostInventorySnmpIDReadAccepted, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.s.ReadSNMP(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return readAs[oas.InventoryPostInventorySnmpIDReadAccepted](r)
}

// InventoryGetInventorySnmpIDRead implements GET /inventory/snmp/{id}/read (#849): the read that runs, or the last one; null when none.
func (h *SNMPHandlers) InventoryGetInventorySnmpIDRead(ctx context.Context, params oas.InventoryGetInventorySnmpIDReadParams) (oas.NilInventoryGetInventorySnmpIDReadOK, error) {
	if _, err := h.actor(ctx); err != nil {
		return oas.NilInventoryGetInventorySnmpIDReadOK{}, err
	}
	r, err := h.s.SNMPReadOf(ctx, params.ID)
	if err != nil || r == nil {
		return oas.NilInventoryGetInventorySnmpIDReadOK{Null: true}, err
	}
	out, err := readAs[oas.InventoryGetInventorySnmpIDReadOK](*r)
	if err != nil {
		return oas.NilInventoryGetInventorySnmpIDReadOK{}, err
	}
	return oas.NewNilInventoryGetInventorySnmpIDReadOK(*out), nil
}
