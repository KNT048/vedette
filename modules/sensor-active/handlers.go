package sensoractive

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/api/apijson"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
)

// SNMPHandlers implement the SNMP operations (CONTRACT "Endpoints owned"): the list and notices, and one device's SNMP:
// read, set up or edit, remove, Check now. The route table requires the admin role; the server answers 404 for all of them while the module is off (SYS-5).
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

// The responses are built in the JSON shape of contract.ts and converted to the generated types (one shape, several generated names).

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

func answerOf(a *SNMPFacts) *answerRow {
	if a == nil {
		return nil
	}
	return &answerRow{SysDescr: a.SysDescr, SysObjectID: a.SysObjectID, SysName: a.SysName, Vendor: a.Vendor, Product: a.Product,
		Model: a.Model, OS: a.OS, Kind: a.Kind, Serial: a.Serial, Firmware: a.Firmware}
}

type blockedRow struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func blockedOf(b *SNMPBlocked) *blockedRow {
	if b == nil {
		return nil
	}
	return &blockedRow{Reason: b.Reason, Message: b.Message}
}

// deviceRow is DeviceSnmp of contract.ts.
type deviceRow struct {
	DeviceID        string      `json:"device_id"`
	IP              *string     `json:"ip"`
	State           string      `json:"state"`
	ReadFrom        *string     `json:"read_from"`
	ReadFromDefault bool        `json:"read_from_default"`
	Version         *string     `json:"version"`
	Username        *string     `json:"username"`
	Auth            *string     `json:"auth"`
	Priv            *string     `json:"priv"`
	Port            *int        `json:"port"`
	SecretLast4     string      `json:"secret_last4"`
	PrivLast4       string      `json:"priv_last4"`
	SecretLost      bool        `json:"secret_lost"`
	LastCheckedAt   *time.Time  `json:"last_checked_at"`
	LastAnswerAt    *time.Time  `json:"last_answer_at"`
	LastReason      *string     `json:"last_reason"`
	Error           *string     `json:"error"`
	Answer          *answerRow  `json:"answer"`
	Blocked         *blockedRow `json:"blocked"`
	UpdatedAt       *time.Time  `json:"updated_at"`
}

func ptr[T any](v T) *T { return &v }

func strOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func addrOrNil(a netip.Addr) *string {
	if !a.IsValid() {
		return nil
	}
	return ptr(a.String())
}

func deviceWire(d SNMPDevice) deviceRow {
	out := deviceRow{DeviceID: d.DeviceID, IP: addrOrNil(d.IP), State: d.State, ReadFrom: addrOrNil(d.ReadFrom), ReadFromDefault: d.ReadFromDefault,
		Version: strOrNil(d.Version), SecretLast4: d.SecretLast4, PrivLast4: d.PrivLast4, SecretLost: d.SecretLost,
		LastCheckedAt: timeOrNil(d.LastCheckedAt), LastAnswerAt: timeOrNil(d.LastAnswerAt), LastReason: strOrNil(d.LastReason), Error: strOrNil(d.Error),
		Answer: answerOf(d.Answer), Blocked: blockedOf(d.Blocked), UpdatedAt: timeOrNil(d.UpdatedAt)}
	if d.Version == "v3" {
		out.Username, out.Auth, out.Priv = ptr(d.Username), ptr(d.Auth), ptr(d.Priv)
	}
	if d.Port != 0 {
		out.Port = ptr(d.Port)
	}
	return out
}

// shapeAs converts v to the generated type T of the same JSON shape.
func shapeAs[T any](v any) (*T, error) {
	out, err := apijson.Into[T](v)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: %w", err)
	}
	return out, nil
}

// InventoryGetInventorySnmp implements GET /inventory/snmp.
func (h *SNMPHandlers) InventoryGetInventorySnmp(ctx context.Context) (*oas.InventoryGetInventorySnmpOK, error) {
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	list, err := h.s.SNMPDevices(ctx)
	if err != nil {
		return nil, err
	}
	notices, err := h.s.SNMPNotices(ctx)
	if err != nil {
		return nil, err
	}
	type row struct {
		DeviceID     string      `json:"device_id"`
		Name         string      `json:"name"`
		IP           *string     `json:"ip"`
		ReadFrom     string      `json:"read_from"`
		Version      string      `json:"version"`
		Username     *string     `json:"username"`
		Port         int         `json:"port"`
		State        string      `json:"state"`
		LastAnswerAt *time.Time  `json:"last_answer_at"`
		Blocked      *blockedRow `json:"blocked"`
	}
	type notice struct {
		ID   int64     `json:"id"`
		At   time.Time `json:"at"`
		Text string    `json:"text"`
	}
	ready, msg := h.s.SNMPStatus()
	out := struct {
		Ready   bool     `json:"ready"`
		Message *string  `json:"message"`
		Devices []row    `json:"devices"`
		Notices []notice `json:"notices"`
	}{Ready: ready, Message: strOrNil(msg), Devices: []row{}, Notices: []notice{}}
	for _, d := range list {
		r := row{DeviceID: d.DeviceID, Name: d.Name, IP: addrOrNil(d.IP), ReadFrom: d.ReadFrom.String(), Version: d.Version, Port: d.Port, State: d.State,
			LastAnswerAt: timeOrNil(d.LastAnswerAt), Blocked: blockedOf(d.Blocked)}
		if d.Version == "v3" {
			r.Username = ptr(d.Username)
		}
		out.Devices = append(out.Devices, r)
	}
	for _, n := range notices {
		out.Notices = append(out.Notices, notice(n))
	}
	return shapeAs[oas.InventoryGetInventorySnmpOK](out)
}

// InventoryPostInventorySnmpNoticesDismiss implements POST /inventory/snmp/notices/dismiss.
func (h *SNMPHandlers) InventoryPostInventorySnmpNoticesDismiss(ctx context.Context) (*oas.InventoryPostInventorySnmpNoticesDismissOK, error) {
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.s.DismissSNMPNotices(ctx); err != nil {
		return nil, err
	}
	return &oas.InventoryPostInventorySnmpNoticesDismissOK{Ok: true}, nil
}

// InventoryGetInventorySnmpDevicesID implements GET /inventory/snmp/devices/{id}.
func (h *SNMPHandlers) InventoryGetInventorySnmpDevicesID(ctx context.Context, params oas.InventoryGetInventorySnmpDevicesIDParams) (*oas.InventoryGetInventorySnmpDevicesIDOK, error) {
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	d, err := h.s.SNMPDeviceOf(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	return shapeAs[oas.InventoryGetInventorySnmpDevicesIDOK](deviceWire(d))
}

// InventoryPutInventorySnmpDevicesID implements PUT /inventory/snmp/devices/{id}.
func (h *SNMPHandlers) InventoryPutInventorySnmpDevicesID(ctx context.Context, req *oas.InventoryPutInventorySnmpDevicesIDReq, params oas.InventoryPutInventorySnmpDevicesIDParams) (*oas.InventoryPutInventorySnmpDevicesIDOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	in := SNMPInput{CopyFrom: req.CopyFrom.Or(""), ReadFrom: req.ReadFrom.Or(""), Version: string(req.Version.Or("")), Username: req.Username.Or(""),
		Auth: string(req.Auth.Or("")), Priv: string(req.Priv.Or("")), Port: req.Port.Or(0)}
	in.Community, in.AuthPassword, in.PrivPassword = secrets.NewValue(req.Community.Or("")), secrets.NewValue(req.AuthPassword.Or("")), secrets.NewValue(req.PrivPassword.Or(""))
	d, err := h.s.SetSNMP(ctx, who, params.ID, in)
	if err != nil {
		return nil, err
	}
	return shapeAs[oas.InventoryPutInventorySnmpDevicesIDOK](deviceWire(d))
}

// InventoryDeleteInventorySnmpDevicesID implements DELETE /inventory/snmp/devices/{id}.
func (h *SNMPHandlers) InventoryDeleteInventorySnmpDevicesID(ctx context.Context, params oas.InventoryDeleteInventorySnmpDevicesIDParams) error {
	who, err := h.actor(ctx)
	if err != nil {
		return err
	}
	return h.s.DeleteSNMP(ctx, who, params.ID)
}

// InventoryPostInventorySnmpDevicesIDCheck implements POST /inventory/snmp/devices/{id}/check (Check now).
func (h *SNMPHandlers) InventoryPostInventorySnmpDevicesIDCheck(ctx context.Context, params oas.InventoryPostInventorySnmpDevicesIDCheckParams) (*oas.InventoryPostInventorySnmpDevicesIDCheckOK, error) {
	who, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.s.CheckSNMP(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	return shapeAs[oas.InventoryPostInventorySnmpDevicesIDCheckOK](struct {
		OK      bool       `json:"ok"`
		Reason  string     `json:"reason"`
		Message string     `json:"message"`
		Answer  *answerRow `json:"answer"`
		SNMP    deviceRow  `json:"snmp"`
	}{r.OK, r.Reason, r.Message, answerOf(r.Answer), deviceWire(r.Device)})
}
