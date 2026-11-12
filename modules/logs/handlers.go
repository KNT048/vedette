package logs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// LogsHandlers implements the operations of the logs module: the sources, the events, the retention, the digest and the SIEM
// forwarding. Embed it in the composite handler.
// Roles are enforced by the server pipeline before a handler runs, never here.
//
//nolint:revive // distinct on purpose: it is embedded in cmd/vedette next to inventory.Handlers
type LogsHandlers struct{ svc *Service }

// NewLogsHandlers returns the handlers of svc.
func NewLogsHandlers(svc *Service) *LogsHandlers { return &LogsHandlers{svc: svc} }

// into turns a value of this package into the generated response type of an operation; the generated decoder rejects
// anything that does not fit the OpenAPI schema, so a drift between this code and the contract fails loudly.
func into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("logs: encoding response: %w", err)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("logs: response does not fit the API schema: %w", err)
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

// LogsGetLogsSources implements logs_get_logs_sources (viewer).
func (h *LogsHandlers) LogsGetLogsSources(ctx context.Context) (*oas.LogsGetLogsSourcesOK, error) {
	v, err := h.svc.Sources(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.LogsGetLogsSourcesOK](v)
}

// LogsGetLogsUnknownSenders implements logs_get_logs_unknown_senders (operator).
func (h *LogsHandlers) LogsGetLogsUnknownSenders(ctx context.Context) (*oas.LogsGetLogsUnknownSendersOK, error) {
	v, err := h.svc.UnknownSenders(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.LogsGetLogsUnknownSendersOK](v)
}

// LogsPostLogsSources implements logs_post_logs_sources (admin).
func (h *LogsHandlers) LogsPostLogsSources(ctx context.Context, req *oas.LogsPostLogsSourcesReq) (*oas.LogsPostLogsSourcesCreated, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.svc.AddSource(ctx, user, Input{Kind: string(req.Kind), Name: req.Name, SenderIP: req.SenderIP, Proto: string(req.Proto), Port: req.Port})
	if err != nil {
		return nil, err
	}
	return into[oas.LogsPostLogsSourcesCreated](s)
}

// LogsPutLogsSourcesID implements logs_put_logs_sources_id (admin).
func (h *LogsHandlers) LogsPutLogsSourcesID(ctx context.Context, req *oas.LogsPutLogsSourcesIDReq, params oas.LogsPutLogsSourcesIDParams) (*oas.LogsPutLogsSourcesIDOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.svc.UpdateSource(ctx, user, params.ID, Input{Kind: string(req.Kind), Name: req.Name, SenderIP: req.SenderIP, Proto: string(req.Proto), Port: req.Port})
	if err != nil {
		return nil, err
	}
	return into[oas.LogsPutLogsSourcesIDOK](s)
}

// LogsDeleteLogsSourcesID implements logs_delete_logs_sources_id (admin).
func (h *LogsHandlers) LogsDeleteLogsSourcesID(ctx context.Context, params oas.LogsDeleteLogsSourcesIDParams) error {
	user, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.svc.DeleteSource(ctx, user, params.ID)
}

// LogsGetLogsEvents implements logs_get_logs_events (viewer).
func (h *LogsHandlers) LogsGetLogsEvents(ctx context.Context, params oas.LogsGetLogsEventsParams) (*oas.LogsGetLogsEventsOK, error) {
	v, err := h.svc.Events(ctx, EventQuery{Window: string(params.Window), Source: params.Source.Or(""), Q: params.Q.Or("")})
	if err != nil {
		return nil, err
	}
	return into[oas.LogsGetLogsEventsOK](v)
}

// LogsPutLogsRetention implements logs_put_logs_retention (admin).
func (h *LogsHandlers) LogsPutLogsRetention(ctx context.Context, req *oas.LogsPutLogsRetentionReq) (*oas.LogsPutLogsRetentionOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	days, err := h.svc.SetRetention(ctx, user, int(req.Days))
	if err != nil {
		return nil, err
	}
	return into[oas.LogsPutLogsRetentionOK](struct {
		RetentionDays int `json:"retention_days"`
	}{days})
}

// LogsGetLogsDigest implements logs_get_logs_digest (viewer).
func (h *LogsHandlers) LogsGetLogsDigest(ctx context.Context) (*oas.LogsGetLogsDigestOK, error) {
	v, err := h.svc.Digest(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.LogsGetLogsDigestOK](v)
}

// LogsGetLogsSiem implements logs_get_logs_siem (admin).
func (h *LogsHandlers) LogsGetLogsSiem(ctx context.Context) (*oas.LogsGetLogsSiemOK, error) {
	v, err := h.svc.Siem(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.LogsGetLogsSiemOK](v)
}

// LogsPutLogsSiem implements logs_put_logs_siem (admin).
func (h *LogsHandlers) LogsPutLogsSiem(ctx context.Context, req *oas.LogsPutLogsSiemReq) (*oas.LogsPutLogsSiemOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in := SiemInput{Enabled: req.Enabled, Format: string(req.Format), Host: req.Host, Port: req.Port, Proto: string(req.Proto), URL: req.URL, Secret: req.Secret.Or("")}
	for _, e := range req.Events {
		in.Events = append(in.Events, string(e))
	}
	v, err := h.svc.SetSiem(ctx, user, in)
	if err != nil {
		return nil, err
	}
	return into[oas.LogsPutLogsSiemOK](v)
}

// LogsPostLogsSiemTest implements logs_post_logs_siem_test (admin).
func (h *LogsHandlers) LogsPostLogsSiemTest(ctx context.Context) (*oas.LogsPostLogsSiemTestOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.TestSiem(ctx, user)
	if err != nil {
		return nil, err
	}
	return into[oas.LogsPostLogsSiemTestOK](v)
}
