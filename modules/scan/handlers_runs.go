package scan

import (
	"context"

	"github.com/knt048/vedette/core/api/oas"
)

// ScanGetScansTargets implements scan_get_scans_targets (viewer).
func (h *ScanHandlers) ScanGetScansTargets(ctx context.Context) (*oas.ScanGetScansTargetsOK, error) {
	items, err := h.svc.Targets(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ScanGetScansTargetsOK](struct {
		Items []TargetView `json:"items"`
	}{items})
}

// ScanGetScansRuns implements scan_get_scans_runs (viewer).
func (h *ScanHandlers) ScanGetScansRuns(ctx context.Context) (*oas.ScanGetScansRunsOK, error) {
	items, err := h.svc.Runs(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ScanGetScansRunsOK](struct {
		Items []RunView `json:"items"`
	}{items})
}

// ScanPostScansRuns implements scan_post_scans_runs (operator): Scan now.
func (h *ScanHandlers) ScanPostScansRuns(ctx context.Context, req *oas.ScanPostScansRunsReq) (*oas.ScanPostScansRunsCreated, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.StartRun(ctx, user, req.Targets)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ScanPostScansRunsCreated](v)
}

// ScanPostScansRunsIDStop implements scan_post_scans_runs_id_stop (operator): Stop now.
func (h *ScanHandlers) ScanPostScansRunsIDStop(ctx context.Context, params oas.ScanPostScansRunsIDStopParams) (*oas.ScanPostScansRunsIDStopOK, error) {
	user, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.StopRun(ctx, user, params.ID)
	if err != nil {
		return nil, ToAPIError(err)
	}
	return into[oas.ScanPostScansRunsIDStopOK](v)
}

// ScanGetScansProbes implements scan_get_scans_probes (viewer).
func (h *ScanHandlers) ScanGetScansProbes(ctx context.Context) (*oas.ScanGetScansProbesOK, error) {
	items, err := h.svc.Probes(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ScanGetScansProbesOK](struct {
		Items         []ProbeView `json:"items"`
		RetentionDays int         `json:"retention_days"`
	}{items, RetentionDays})
}

// ScanGetScansProbesCsv implements scan_get_scans_probes_csv (viewer).
func (h *ScanHandlers) ScanGetScansProbesCsv(ctx context.Context) (oas.ScanGetScansProbesCsvOK, error) {
	r, err := h.svc.ProbesCSV(ctx)
	if err != nil {
		return oas.ScanGetScansProbesCsvOK{}, err
	}
	return oas.ScanGetScansProbesCsvOK{Data: r}, nil
}

// ScanGetScansEvents implements scan_get_scans_events (viewer): the log of automatic rescans (S-SCAN-2).
func (h *ScanHandlers) ScanGetScansEvents(ctx context.Context) (*oas.ScanGetScansEventsOK, error) {
	items, auto, err := h.svc.Events(ctx)
	if err != nil {
		return nil, err
	}
	return into[oas.ScanGetScansEventsOK](struct {
		Items      []EventView `json:"items"`
		AutoRescan bool        `json:"auto_rescan"`
	}{items, auto})
}
