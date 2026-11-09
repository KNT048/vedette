package sensorpassive

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
)

// SensorHandlers implements the operations of the module: GET /inventory/sensors (admin). Embed it in the
// composite handler of cmd/vedette. The role comes from the route table.
//
// PATCH /inventory/sensors/{id} (CONTRACT INV-9) has no operation in the API yet: the SPA sets the interface
// and SPAN mode in Settings → Box network (PUT /core/network/span, host module), and contract.ts has no such
// route. Service.SetInterface implements the rule and the audit; the route follows when the host module
// calls it (see .ai/deferred/feat-sensor-passive.md).
type SensorHandlers struct{ svc *Service }

// NewSensorHandlers returns the handlers of the module.
func NewSensorHandlers(svc *Service) *SensorHandlers { return &SensorHandlers{svc: svc} }

// InventoryGetInventorySensors implements GET /inventory/sensors (admin).
func (h *SensorHandlers) InventoryGetInventorySensors(ctx context.Context) (*oas.InventoryGetInventorySensorsOK, error) {
	list, err := h.svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(struct {
		Sensors []Sensor `json:"sensors"`
	}{list})
	if err != nil {
		return nil, fmt.Errorf("sensorpassive: encode response: %w", err)
	}
	out := new(oas.InventoryGetInventorySensorsOK)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("sensorpassive: build response: %w", err)
	}
	return out, nil
}
