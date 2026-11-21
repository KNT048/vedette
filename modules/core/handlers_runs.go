package core

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/server"
)

// RunHandlers serve the runs of every engine (core/run): GET /runs, GET /runs/{id}, POST /runs/{id}/stop and /resume. Core
// serves them so the Runs tab and every "Open the run" link answer while any engine's module is off.
type RunHandlers struct{ runs *run.Manager }

// NewRunHandlers returns the handlers over the box's run manager.
func NewRunHandlers(m *run.Manager) *RunHandlers { return &RunHandlers{runs: m} }

// ScanningGetRuns implements GET /runs (viewer): one page of runs, newest first.
func (h *RunHandlers) ScanningGetRuns(ctx context.Context, params oas.ScanningGetRunsParams) (*oas.ScanningGetRunsOK, error) {
	f := run.Filter{
		Module: params.Module.Or(""), Kind: params.Kind.Or(""), SubjectKind: params.SubjectKind.Or(""), SubjectID: params.SubjectID.Or(""),
		Q: params.Q.Or(""), Status: run.Status(params.Status.Or("")),
	}
	f.Offset, _ = strconv.Atoi(params.Offset.Or("0")) // the contract allows digits only
	f.Limit, _ = strconv.Atoi(params.Limit.Or("0"))
	items, total, err := h.runs.List(ctx, f)
	if err != nil {
		return nil, err
	}
	for i := range items {
		h.forViewer(ctx, &items[i])
	}
	return encode[oas.ScanningGetRunsOK](struct {
		Items []run.Run `json:"items"`
		Total int       `json:"total"`
	}{items, total})
}

// ScanningGetRunsID implements GET /runs/{id} (viewer): the run page.
func (h *RunHandlers) ScanningGetRunsID(ctx context.Context, params oas.ScanningGetRunsIDParams) (*oas.ScanningGetRunsIDOK, error) {
	d, err := h.runs.Get(ctx, params.ID)
	if err != nil {
		return nil, runErr(err)
	}
	h.forViewer(ctx, &d.Run)
	for i := range d.Children {
		h.forViewer(ctx, &d.Children[i])
	}
	return encode[oas.ScanningGetRunsIDOK](d)
}

// ScanningPostRunsIDStop implements POST /runs/{id}/stop (operator): audited scanning.run_stop by core/run in the same transaction.
func (h *RunHandlers) ScanningPostRunsIDStop(ctx context.Context, params oas.ScanningPostRunsIDStopParams) (*oas.ScanningPostRunsIDStopOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := h.runs.Stop(ctx, params.ID, p.Email, ""); err != nil {
		return nil, runErr(err)
	}
	r, err := h.runs.Read(ctx, params.ID)
	if err != nil {
		return nil, runErr(err)
	}
	h.forViewer(ctx, &r)
	return encode[oas.ScanningPostRunsIDStopOK](r)
}

// ScanningPostRunsIDResume implements POST /runs/{id}/resume (operator; admin for a kind with AdminResume): audited
// scanning.run_resume by core/run.
func (h *RunHandlers) ScanningPostRunsIDResume(ctx context.Context, params oas.ScanningPostRunsIDResumeParams) (*oas.ScanningPostRunsIDResumeOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	cur, err := h.runs.Read(ctx, params.ID)
	if err != nil {
		return nil, runErr(err)
	}
	if h.runs.AdminResume(cur) && p.Role != routes.Admin { // its kind's start is an administrator's, so is going on with it
		return nil, apierr.Forbidden()
	}
	if err := h.runs.Resume(ctx, params.ID, p.Email); err != nil {
		return nil, runErr(err)
	}
	r, err := h.runs.Read(ctx, params.ID)
	if err != nil {
		return nil, runErr(err)
	}
	h.forViewer(ctx, &r)
	return encode[oas.ScanningPostRunsIDResumeOK](r)
}

// forViewer makes can_stop and can_resume the asking person's: Stop needs an operator, and Resume an operator, or an administrator for
// a kind whose start is an administrator's (a LAN sweep). The page shows the buttons these say, so it never guesses a role per kind.
func (h *RunHandlers) forViewer(ctx context.Context, r *run.Run) {
	p, ok := server.PrincipalFrom(ctx)
	operator := ok && (p.Role == routes.Operator || p.Role == routes.Admin)
	r.CanStop = r.CanStop && operator
	r.CanResume = r.CanResume && operator && (!h.runs.AdminResume(*r) || p.Role == routes.Admin)
}

// runErr maps the errors of core/run to answers.
func runErr(err error) error {
	switch {
	case errors.Is(err, run.ErrNotFound):
		return apierr.NotFound()
	case errors.Is(err, run.ErrEnded):
		return apierr.New(http.StatusConflict, "not_running", "This run has already ended, so there is nothing to stop.")
	case errors.Is(err, run.ErrNotResumable):
		return apierr.New(http.StatusConflict, "not_resumable", "This run cannot be resumed: it has no work left, or its engine cannot go on from where it stopped.")
	}
	return err
}
