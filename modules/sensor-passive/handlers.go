package sensorpassive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// SensorHandlers implements the operations of the module: GET and PATCH /inventory/sensors (admin). Embed it in the
// composite handler of cmd/vedette. The role comes from the route table.
//
// PATCH /inventory/sensors/{id} (CONTRACT INV-9) serves only a container-only install (D-387): on an appliance the SPA sets
// the card and SPAN in Settings → Box network (PUT /core/network/span, host module), which calls Service.SetInterface.
type SensorHandlers struct{ svc *Service }

// NewSensorHandlers returns the handlers of the module.
func NewSensorHandlers(svc *Service) *SensorHandlers { return &SensorHandlers{svc: svc} }

// InventoryGetInventorySensors implements GET /inventory/sensors (admin).
func (h *SensorHandlers) InventoryGetInventorySensors(ctx context.Context) (*oas.InventoryGetInventorySensorsOK, error) {
	list, err := h.svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryGetInventorySensorsOK](struct {
		Sensors []Sensor `json:"sensors"`
	}{list})
}

// InventoryPatchInventorySensorsID implements PATCH /inventory/sensors/{id} (admin): the card the sensor reads and whether it is
// the SPAN card, on a container-only install only (D-387). The answer is the sensor as GET /inventory/sensors lists it.
func (h *SensorHandlers) InventoryPatchInventorySensorsID(ctx context.Context, req *oas.InventoryPatchInventorySensorsIDReq, params oas.InventoryPatchInventorySensorsIDParams) (*oas.InventoryPatchInventorySensorsIDOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	iface := ""
	if v, ok := req.Interface.Get(); ok {
		iface = v
	}
	if err := h.svc.ChooseCard(ctx, p.Email, params.ID, iface, req.Span); err != nil {
		return nil, apiErr(err)
	}
	list, err := h.svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryPatchInventorySensorsIDOK](list[0])
}

// apiErr turns the errors of Service into API answers. The reason of a bad_interface is a plain sentence after the prefix
// (SetInterface writes it for the person; it names no path or internal detail).
func apiErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return apierr.New(404, apierr.CodeNotFound, "No such sensor. This box has one sensor, "+SensorID+".")
	case errors.Is(err, ErrUseBoxNetwork):
		return apierr.New(409, CodeSetInBoxNetwork, "On this box the card the sensor listens on is chosen in Settings → Box network.")
	case errors.Is(err, ErrBadInterface):
		return apierr.New(400, CodeBadInterface, sentence(strings.TrimPrefix(err.Error(), ErrBadInterface.Error()+": ")))
	}
	return err
}

// API codes of the module (API_CONVENTIONS 3.3).
const (
	CodeBadInterface    = "bad_interface"
	CodeSetInBoxNetwork = "set_in_box_network"
)

// sentence starts msg with a capital letter and ends it with a full stop.
func sentence(msg string) string {
	r, n := utf8.DecodeRuneInString(msg)
	msg = string(unicode.ToUpper(r)) + msg[n:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}

// convert re-reads v, through its JSON form, as the generated type T.
func convert[T any](v any) (*T, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("sensorpassive: encode response: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("sensorpassive: build response: %w", err)
	}
	return out, nil
}
