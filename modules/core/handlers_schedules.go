package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/server"
)

// ScheduleHandlers serve the schedules a person can set (core/schedule): GET and PUT /schedules/{owner_key}, POST
// /schedules/{owner_key}/run and POST /schedules/preview. Core serves them so the one editor works the same for every owner.
type ScheduleHandlers struct{ svc *schedule.Service }

// NewScheduleHandlers returns the handlers over the box's schedule service.
func NewScheduleHandlers(s *schedule.Service) *ScheduleHandlers { return &ScheduleHandlers{svc: s} }

// CoreGetSchedulesOwnerKey implements GET /schedules/{owner_key} (viewer).
func (h *ScheduleHandlers) CoreGetSchedulesOwnerKey(ctx context.Context, params oas.CoreGetSchedulesOwnerKeyParams) (*oas.CoreGetSchedulesOwnerKeyOK, error) {
	v, err := h.svc.Get(ctx, params.OwnerKey)
	if err != nil {
		return nil, scheduleErr(err)
	}
	return encode[oas.CoreGetSchedulesOwnerKeyOK](v)
}

// scheduleSave is the body of PUT /schedules/{owner_key}.
type scheduleSave struct {
	Enabled     bool          `json:"enabled"`
	PausedUntil *time.Time    `json:"paused_until"`
	Rule        schedule.Rule `json:"rule"`
}

// CorePutSchedulesOwnerKey implements PUT /schedules/{owner_key} (operator; admin for an owner that says so): audited
// schedule.save by core/schedule in the same transaction.
func (h *ScheduleHandlers) CorePutSchedulesOwnerKey(ctx context.Context, req *oas.CorePutSchedulesOwnerKeyReq, params oas.CorePutSchedulesOwnerKeyParams) (*oas.CorePutSchedulesOwnerKeyOK, error) {
	p, err := h.editor(ctx, params.OwnerKey)
	if err != nil {
		return nil, err
	}
	in, err := decode[scheduleSave](req)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Save(ctx, params.OwnerKey, schedule.Setting{Enabled: in.Enabled, PausedUntil: in.PausedUntil, Rule: in.Rule}, p.Email)
	if err != nil {
		return nil, scheduleErr(err)
	}
	return encode[oas.CorePutSchedulesOwnerKeyOK](v)
}

// CorePostSchedulesOwnerKeyRun implements POST /schedules/{owner_key}/run (operator; admin for an owner that says so): run once
// now, audited schedule.run_now.
func (h *ScheduleHandlers) CorePostSchedulesOwnerKeyRun(ctx context.Context, params oas.CorePostSchedulesOwnerKeyRunParams) (*oas.CorePostSchedulesOwnerKeyRunOK, error) {
	p, err := h.editor(ctx, params.OwnerKey)
	if err != nil {
		return nil, err
	}
	id, err := h.svc.RunNow(ctx, params.OwnerKey, p.Email)
	if err != nil {
		return nil, scheduleErr(err)
	}
	var runID *string
	if id != "" {
		runID = &id
	}
	return encode[oas.CorePostSchedulesOwnerKeyRunOK](struct {
		RunID *string `json:"run_id"`
	}{runID})
}

// schedulePreview is the body of POST /schedules/preview.
type schedulePreview struct {
	OwnerKey    string        `json:"owner_key"`
	Rule        schedule.Rule `json:"rule"`
	PausedUntil *time.Time    `json:"paused_until"`
}

// CorePostSchedulesPreview implements POST /schedules/preview (viewer): the next start times of a rule not saved yet.
func (h *ScheduleHandlers) CorePostSchedulesPreview(ctx context.Context, req *oas.CorePostSchedulesPreviewReq) (*oas.CorePostSchedulesPreviewOK, error) {
	in, err := decode[schedulePreview](req)
	if err != nil {
		return nil, err
	}
	up, zone, err := h.svc.Preview(ctx, in.OwnerKey, in.Rule, in.PausedUntil)
	if err != nil {
		return nil, scheduleErr(err)
	}
	return encode[oas.CorePostSchedulesPreviewOK](struct {
		Zone     string      `json:"zone"`
		Upcoming []time.Time `json:"upcoming"`
	}{zone, up})
}

// editor returns the caller when it may change the schedule: an operator, or an administrator for an owner that asks for one.
func (h *ScheduleHandlers) editor(ctx context.Context, key string) (server.Principal, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return server.Principal{}, apierr.Unauthenticated()
	}
	v, err := h.svc.Get(ctx, key)
	if err != nil {
		return server.Principal{}, scheduleErr(err)
	}
	if v.EditRole == "admin" && p.Role != routes.Admin {
		return server.Principal{}, apierr.Forbidden()
	}
	return p, nil
}

// decode turns a generated request into the service's input (the field names are the contract's).
func decode[T any](req any) (T, error) {
	var out T
	raw, err := json.Marshal(req)
	if err != nil {
		return out, fmt.Errorf("core: schedules: read the request: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, apierr.Invalid("The schedule could not be read: " + err.Error())
	}
	return out, nil
}

// scheduleErr maps the errors of core/schedule to answers.
func scheduleErr(err error) error {
	var re *schedule.RuleError
	var sk *schedule.SkipError
	switch {
	case errors.Is(err, schedule.ErrUnknownOwner):
		return apierr.NotFound()
	case errors.As(err, &re):
		return apierr.Invalid(re.Message).With("field", re.Field)
	case errors.Is(err, schedule.ErrBusy):
		return apierr.New(http.StatusConflict, "busy", "The run this schedule last started has not ended. Open it to follow it or stop it, then try again.")
	case errors.As(err, &sk):
		return apierr.New(http.StatusConflict, "not_started", sk.Reason)
	}
	return err
}
