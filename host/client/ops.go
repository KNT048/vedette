package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/knt048/vedette/host/api"
)

// Typed helpers for the system commands (docs/specs/host-api.md section 6) and the state reads
// (section 5). Each command helper is Run with the command's name and args type: requestID is the
// idempotency key (retry with the same one), actor is the label core sets for the audit line.

// OSCheck runs os.check.
func (c *Client) OSCheck(ctx context.Context, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdOSCheck, nil, requestID, actor)
}

// OSInstall runs os.install with scope "security" or "all"; snapshot is the id of the snapshot
// core wrote for the pre_os_update backup.
func (c *Client) OSInstall(ctx context.Context, scope, snapshot, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdOSInstall, api.OSInstallArgs{Scope: scope, Snapshot: snapshot}, requestID, actor)
}

// OSAutoSecuritySet runs os.auto_security.set.
func (c *Client) OSAutoSecuritySet(ctx context.Context, enabled bool, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdOSAutoSecuritySet, api.OSAutoSecurityArgs{Enabled: enabled}, requestID, actor)
}

// OSReboot runs os.reboot.
func (c *Client) OSReboot(ctx context.Context, args api.OSRebootArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdOSReboot, args, requestID, actor)
}

// OSRebootCancel runs os.reboot.cancel.
func (c *Client) OSRebootCancel(ctx context.Context, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdOSRebootCancel, nil, requestID, actor)
}

// BackupCreate runs backup.create.
func (c *Client) BackupCreate(ctx context.Context, args api.BackupCreateArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdBackupCreate, args, requestID, actor)
}

// BackupRestore runs backup.restore; snapshot is the id of a snapshot of core's current state
// (kept as the pre_restore backup).
func (c *Client) BackupRestore(ctx context.Context, backupID, snapshot, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: backupID, Snapshot: snapshot}, requestID, actor)
}

// LogsExport runs logs.export.
func (c *Client) LogsExport(ctx context.Context, args api.LogsExportArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdLogsExport, args, requestID, actor)
}

// NetApply runs net.apply: the whole desired state of the network part Vedette manages. A change
// of the management part leaves the run in awaiting_confirm until NetConfirm or NetRevert.
func (c *Client) NetApply(ctx context.Context, args api.NetApplyArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdNetApply, args, requestID, actor)
}

// NetConfirm runs net.confirm for the awaiting net.apply run runID.
func (c *Client) NetConfirm(ctx context.Context, runID, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdNetConfirm, api.NetRunArgs{RunID: runID}, requestID, actor)
}

// NetRevert runs net.revert for the awaiting net.apply run runID.
func (c *Client) NetRevert(ctx context.Context, runID, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdNetRevert, api.NetRunArgs{RunID: runID}, requestID, actor)
}

// ContainerStart runs container.start for the current image of a service (slice 3-6: no version).
func (c *Client) ContainerStart(ctx context.Context, args api.ContainerStartArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdContainerStart, args, requestID, actor)
}

// ContainerStop runs container.stop; persist keeps the service down after a reboot.
func (c *Client) ContainerStop(ctx context.Context, service string, persist bool, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdContainerStop, api.ContainerStopArgs{Service: service, Persist: persist}, requestID, actor)
}

// ContainerPull runs container.pull (slice 3-7): the host verifies the signed documents itself.
func (c *Client) ContainerPull(ctx context.Context, args api.ContainerPullArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdContainerPull, args, requestID, actor)
}

// ContainerRollback runs container.rollback (slice 3-8a): back to the stored previous version.
func (c *Client) ContainerRollback(ctx context.Context, args api.ContainerRollbackArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdContainerRollback, args, requestID, actor)
}

// SelfUpdate runs host.self_update (D-316): the host upgrades its own package to the release's. The run is
// parked while the applier works and the host restarts; reconnect and ask GET /v1/runs/{id} until it ends
// (at most until its deadline plus 5 minutes).
func (c *Client) SelfUpdate(ctx context.Context, args api.HostSelfUpdateArgs, requestID, actor string) (api.Run, error) {
	return c.Run(ctx, api.CmdHostSelfUpdate, args, requestID, actor)
}

// StateHost returns GET /v1/state/host. A host older than host.self_update answers 404 unknown_command.
func (c *Client) StateHost(ctx context.Context) (api.HostState, error) {
	var out api.HostState
	err := c.getJSON(ctx, "/v1/state/host", &out)
	return out, err
}

// StatePackages returns GET /v1/state/packages: the Debian packages installed on the box (D-470). A host older than
// D-470 answers 404 unknown_command.
func (c *Client) StatePackages(ctx context.Context) (api.PackagesState, error) {
	var out api.PackagesState
	err := c.getJSON(ctx, "/v1/state/packages", &out)
	return out, err
}

// StateHPTouches returns GET /v1/state/hp-touches: the sources that tried a new TCP or UDP connection to a decoy address in the
// last two minutes (D-466, B2 review M2). A host older than it answers 404 unknown_command.
func (c *Client) StateHPTouches(ctx context.Context) (api.HPTouchesState, error) {
	var out api.HPTouchesState
	err := c.getJSON(ctx, "/v1/state/hp-touches", &out)
	return out, err
}

// StateContainers returns GET /v1/state/containers.
func (c *Client) StateContainers(ctx context.Context) (api.ContainersState, error) {
	var out api.ContainersState
	err := c.getJSON(ctx, "/v1/state/containers", &out)
	return out, err
}

// StateOS returns GET /v1/state/os. A host that has never checked answers 404 no_check_yet.
func (c *Client) StateOS(ctx context.Context) (api.OSState, error) {
	var out api.OSState
	err := c.getJSON(ctx, "/v1/state/os", &out)
	return out, err
}

// StateBackups returns GET /v1/state/backups.
func (c *Client) StateBackups(ctx context.Context) (api.BackupList, error) {
	var out api.BackupList
	err := c.getJSON(ctx, "/v1/state/backups", &out)
	return out, err
}

// StateNet returns GET /v1/state/net: the cards with their counters and addresses, the default
// route and the configuration the host wrote. A host older than the network commands answers 404
// unknown_command.
func (c *Client) StateNet(ctx context.Context) (api.NetState, error) {
	var out api.NetState
	err := c.getJSON(ctx, "/v1/state/net", &out)
	return out, err
}

// DownloadBackup opens GET /v1/backups/{id}/content. The caller closes the body. Backups that
// hold secrets answer 403 contains_secrets.
func (c *Client) DownloadBackup(ctx context.Context, backupID string) (io.ReadCloser, int64, error) {
	return c.download(ctx, "/v1/backups/"+url.PathEscape(backupID)+"/content")
}

// DownloadExport opens GET /v1/exports/{id}/content. The caller closes the body.
func (c *Client) DownloadExport(ctx context.Context, exportID string) (io.ReadCloser, int64, error) {
	return c.download(ctx, "/v1/exports/"+url.PathEscape(exportID)+"/content")
}

func (c *Client) download(ctx context.Context, path string) (io.ReadCloser, int64, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.do(c.stream, req)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// ResultOf decodes the result of a finished run into T (for example api.OSRunResult). A run
// without a result is an error.
func ResultOf[T any](run api.Run) (T, error) {
	var out T
	if len(run.Result) == 0 {
		return out, errors.New("host: the run has no result")
	}
	if err := json.Unmarshal(run.Result, &out); err != nil {
		return out, fmt.Errorf("host: decode result: %w", err)
	}
	return out, nil
}

// BackupPurge runs backup.purge (D-156): the host deletes every backup archive and its index, and
// answers how many archives went. requestID is the idempotency key (a UUID v4; retry with the
// same one). It waits for the run (a few files: a moment) and returns the run id as soon as the
// host has accepted it, also when ctx ends or an error follows, so the caller can ask
// GetRun(runID) later. A running write is a *Error with code busy; a failed run is an error
// with the run's code.
func (c *Client) BackupPurge(ctx context.Context, requestID, actor string) (deleted int, runID string, err error) {
	run, err := c.Run(ctx, api.CmdBackupPurge, nil, requestID, actor)
	runID = run.RunID
	for err == nil && !run.Status.Terminal() {
		select {
		case <-ctx.Done():
			return 0, runID, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		run, err = c.GetRun(ctx, runID)
	}
	if err != nil {
		return 0, runID, err
	}
	if run.Status != api.StatusSucceeded {
		code := "command_failed"
		if run.Error != nil {
			code = run.Error.Code
		}
		return 0, runID, fmt.Errorf("host: backup.purge %s: %s", run.Status, code)
	}
	res, err := ResultOf[api.BackupPurgeResult](run)
	return res.Deleted, runID, err
}

// ZapBaseline runs zap.baseline (D-521) and follows the run until it ends (a scan takes minutes: the run is read again every two
// seconds), then returns it as it ended: succeeded with an api.ZapBaselineResult, or refused or failed with its code. ctx bounds the
// wait; the run itself stops at the host's own limit.
func (c *Client) ZapBaseline(ctx context.Context, args api.ZapBaselineArgs, requestID, actor string) (api.Run, error) {
	run, err := c.Run(ctx, api.CmdZapBaseline, args, requestID, actor)
	for err == nil && !run.Status.Terminal() {
		select {
		case <-ctx.Done():
			return run, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		run, err = c.GetRun(ctx, run.RunID)
	}
	return run, err
}

// Greenbone runs one of the OpenVAS commands (api.CmdGreenboneUp with api.GreenboneUpArgs, api.CmdGreenboneDown or
// api.CmdGreenboneSyncFeed with nil; D-529) and follows the run until it ends, read again every two seconds like ZapBaseline. ctx bounds
// the wait only: the run goes on at the host until its own limit, or until greenbone.down stops it.
func (c *Client) Greenbone(ctx context.Context, command string, args any, requestID, actor string) (api.Run, error) {
	switch command {
	case api.CmdGreenboneUp, api.CmdGreenboneDown, api.CmdGreenboneSyncFeed:
	default:
		return api.Run{}, fmt.Errorf("host: %q is not an OpenVAS command", command)
	}
	run, err := c.Run(ctx, command, args, requestID, actor)
	for err == nil && !run.Status.Terminal() {
		select {
		case <-ctx.Done():
			return run, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		run, err = c.GetRun(ctx, run.RunID)
	}
	return run, err
}

// DownloadZapReport opens GET /v1/zap/{id}/content, the report of the last zap.baseline (at most api.MaxZapReport bytes, as the host
// says; the caller bounds its read too). The caller closes the body.
func (c *Client) DownloadZapReport(ctx context.Context, reportID string) (io.ReadCloser, int64, error) {
	return c.download(ctx, "/v1/zap/"+url.PathEscape(reportID)+"/content")
}
