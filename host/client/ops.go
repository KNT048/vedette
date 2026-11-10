package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
// answers how many archives went. It waits for the run (a few files: a moment). A running write
// is a *Error with code busy; a failed run is returned as an error with the run's code.
func (c *Client) BackupPurge(ctx context.Context, actor string) (int, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return 0, err
	}
	id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80
	h := hex.EncodeToString(id[:])
	run, err := c.Run(ctx, api.CmdBackupPurge, nil, h[0:8]+"-"+h[8:12]+"-"+h[12:16]+"-"+h[16:20]+"-"+h[20:], actor)
	for err == nil && !run.Status.Terminal() {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		run, err = c.GetRun(ctx, run.RunID)
	}
	if err != nil {
		return 0, err
	}
	if run.Status != api.StatusSucceeded {
		code := "command_failed"
		if run.Error != nil {
			code = run.Error.Code
		}
		return 0, fmt.Errorf("host: backup.purge %s: %s", run.Status, code)
	}
	res, err := ResultOf[api.BackupPurgeResult](run)
	return res.Deleted, err
}
