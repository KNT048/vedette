package ids

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/knt048/vedette/core/api/apijson"
	"github.com/knt048/vedette/core/api/oas"
)

// IDSHandlers implements the alert operations of intrusion detection (GET /detection/alerts, /detection/alerts/{id}). The overview
// (GET /detection/overview) is core's: it answers while this module is off. Embed it in the composite handler.
//
//nolint:revive // distinct on purpose: it is embedded in cmd/vedette next to the other modules' handlers
type IDSHandlers struct{ svc *Service }

// NewIDSHandlers returns the handlers of svc.
func NewIDSHandlers(svc *Service) *IDSHandlers { return &IDSHandlers{svc: svc} }

// into turns a value of this package into the generated response type; the generated decoder rejects anything that does not fit the
// OpenAPI schema, so a drift between this code and the contract fails loudly.
func into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	out, err := apijson.Into[T](v)
	if err != nil {
		return nil, fmt.Errorf("ids: %w", err)
	}
	return out, nil
}

// DetectionGetDetectionAlerts implements detection_get_detection_alerts (viewer).
func (h *IDSHandlers) DetectionGetDetectionAlerts(ctx context.Context, p oas.DetectionGetDetectionAlertsParams) (*oas.DetectionGetDetectionAlertsOK, error) {
	q := Query{Window: string(p.Window), Q: p.Q.Or(""), Device: p.Device.Or(""), CVE: p.Cve.Or(""), Sort: string(p.Sort.Or(oas.DetectionGetDetectionAlertsSortLast))}
	q.Offset, _ = strconv.Atoi(p.Offset.Or("0")) // the schema allows digits only
	q.Limit, _ = strconv.Atoi(p.Limit.Or(""))
	v, err := h.svc.List(ctx, q)
	if err != nil {
		return nil, err
	}
	return into[oas.DetectionGetDetectionAlertsOK](v)
}

// DetectionGetDetectionAlertsID implements detection_get_detection_alerts_id (viewer).
func (h *IDSHandlers) DetectionGetDetectionAlertsID(ctx context.Context, p oas.DetectionGetDetectionAlertsIDParams) (*oas.DetectionGetDetectionAlertsIDOK, error) {
	a, err := h.svc.Get(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	return into[oas.DetectionGetDetectionAlertsIDOK](a)
}
