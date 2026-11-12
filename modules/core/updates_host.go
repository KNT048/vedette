package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// The system helper step of a software run (S-CORE-2 criterion D-316, host-api 6.14, plan slice 5): when the release
// brings a vedette-host newer than the running one, the run's first call is host.self_update. Core downloads the
// package named in the signed manifest from the same release files as the manifest (PRIVACY.md flow 6, no new
// destination), checks its size and SHA-256 before the call, and the host verifies everything again. A step that does
// not succeed ends the run before any image is touched; a helper too old to have the command ends it before any call.

const (
	hostComponent   = "host"          // the component and the service name of the system helper on the page
	stepHost        = "host"          // the step of host.self_update
	hostPackagesDir = "host-packages" // in core_data: <hex32>.deb, read by the host by descriptor (host-api 6.14 Check 6)
	// hostPackageMaxAge: a package older than this at start-up is left over (the host copies it within its 10-minute
	// pre-park limit; a resend downloads it again).
	hostPackageMaxAge = time.Hour
	hostPackageFetch  = 15 * time.Minute // one package download, at most 256 MiB
	maxHostPackage    = 256 << 20        // the host's limit on host.files[].size

	// The host's clocks (host-api 6.14 "Thời hạn"): Run parks within 10 minutes, the run's deadline is 130 minutes after
	// the journal starts, and the host settles a parked run at the latest 15 minutes past it (its safety net); core
	// waits 20 minutes past the deadline (host/ops coreWaitPastDeadline) before it calls the run stopped half way.
	selfUpdatePrePark = 10 * time.Minute
	selfUpdateWindow  = 130 * time.Minute
	selfUpdateGrace   = 20 * time.Minute

	// End codes of the host step that core decides itself.
	codeHostTooOld   = "host_too_old"         // the helper has no host.self_update (criterion (h))
	codeHostDownload = "host_download_failed" // the package could not be downloaded
	// codeSelfUpdateRollbackFailed is the host's audit and phase name of rollback_failed (host-api 6.14 "Kiểm toán").
	codeSelfUpdateRollbackFailed = "self_update_rollback_failed"
)

var hostPackageRE = regexp.MustCompile(`^[0-9a-f]{32}\.deb$`)

// runHost is the system helper part of a stored run: the running helper, the release's, and the package for the
// host's architecture (nil when the release has none).
type runHost struct {
	From string            `json:"from"`
	To   string            `json:"to"`
	File *release.HostFile `json:"file,omitempty"`
}

// hostNewer: the release brings a helper above running. A running version that is not a release version (a dev
// build) counts as older: the step is planned and the host decides (host_version_unknown).
func hostNewer(m *release.Manifest, running string) bool {
	if m.Host == nil {
		return false
	}
	c, err := release.CompareVersions(m.Host.Version, running)
	return err != nil || c > 0
}

// hostFileOf is the release's package of the helper for arch, nil when there is none.
func hostFileOf(m *release.Manifest, arch string) *release.HostFile {
	if m.Host == nil || (arch != "amd64" && arch != "arm64") {
		return nil
	}
	name := release.HostPackageName(m.Host.Version, arch)
	for i := range m.Host.Files {
		if m.Host.Files[i].Name == name {
			f := m.Host.Files[i]
			return &f
		}
	}
	return nil
}

// hostComponentOf is the System helper row of the page: never rolled back by hand (previous null). installed_at is
// the history entry that brought this version, or this process's start (core has no better record).
func hostComponentOf(info api.Info, hist []updateHistoryView, started time.Time) updateComponentView {
	c := updateComponentView{ID: hostComponent, Kind: "software", Version: info.HostVersion, InstalledAt: started, Signature: "unsigned"}
	if _, err := release.CompareVersions(info.HostVersion, info.HostVersion); err == nil {
		c.Signature = "valid" // install.sh and host.self_update install only a package whose hash a signed document names
	}
	for _, e := range hist {
		if e.Component == hostComponent && e.To == info.HostVersion {
			c.InstalledAt = e.TS
			break
		}
	}
	return c
}

// planHost puts the host step first when the release brings a newer helper. A helper without host.self_update
// ends the run before any host call (rec.Outcome): the step is never skipped, the new images may need the new host.
// detail is what the audit row of the intent adds.
func (h *OSHandlers) planHost(ctx context.Context, rec *updateRunRec, m *release.Manifest) (string, error) {
	if m.Host == nil {
		return "", nil
	}
	info, err := h.host.Info(ctx)
	if err != nil {
		return "", hostErr(ctx, h.log, err)
	}
	if !hostNewer(m, info.HostVersion) {
		return "", nil
	}
	rec.Host = &runHost{From: info.HostVersion, To: m.Host.Version, File: hostFileOf(m, info.Arch)}
	step := stepHost
	rec.Steps, rec.Step = append([]string{stepHost}, rec.Steps...), &step
	if !slices.Contains(info.Commands, api.CmdHostSelfUpdate) {
		rec.Outcome, rec.Why = runFailed, hostWhy(ctx, rec, codeHostTooOld)
		return fmt.Sprintf("; system helper %s is too old to update itself (%s)", info.HostVersion, codeHostTooOld), nil
	}
	return fmt.Sprintf("; system helper %s to %s first", info.HostVersion, m.Host.Version), rec.add(stepHost, api.CmdHostSelfUpdate, hostComponent, false)
}

// sendHost downloads the package (once per process and package id) and sends host.self_update; the package id
// is stored with the call, so a resend after a restart carries the same arguments.
func (f *updFollower) sendHost(ctx context.Context, rec *updateRunRec, i int) (api.Run, error) {
	h := f.h
	c := &rec.Calls[i]
	if rec.Release == nil || rec.Host == nil {
		return api.Run{Status: api.StatusRefused, Error: &api.RunError{Code: codeNotOffered}}, nil
	}
	if rec.Host.File == nil { // the release has no package for this machine: nothing to send
		return api.Run{Status: api.StatusRefused, Error: &api.RunError{Code: api.CodePlatformMismatch}}, nil
	}
	if c.Package == "" { // stored before the file exists, so a file a cut run leaves is always one the run names
		id, err := newPackageID()
		if err != nil {
			return api.Run{}, err
		}
		c.Package = id
		if err := h.saveUpdateRun(ctx, rec); err != nil {
			return api.Run{}, err
		}
	}
	if !f.fetched[c.Package] {
		code, err := h.downloadHostPackage(ctx, rec.To, *rec.Host.File, c.Package)
		if err != nil {
			return api.Run{}, err
		}
		if code != "" {
			return api.Run{Status: api.StatusRefused, Error: &api.RunError{Code: code}}, nil
		}
		f.fetched[c.Package] = true
	}
	enc := base64.StdEncoding.EncodeToString
	args := api.HostSelfUpdateArgs{Version: rec.To, Index: enc(rec.Release.Index), IndexSig: enc(rec.Release.IndexSig),
		Manifest: enc(rec.Release.Manifest), ManifestSig: enc(rec.Release.ManifestSig), Package: c.Package}
	c.Sent = true
	f.sent[c.RequestID] = true
	if err := h.saveUpdateRun(ctx, rec); err != nil { // the key and the package id are stored before the call
		return api.Run{}, err
	}
	run, err := h.host.SelfUpdate(ctx, args, c.RequestID, rec.Actor)
	if err != nil {
		return refusalOf(err)
	}
	c.RunID, rec.Progress = run.RunID, h.now()
	if err := h.saveUpdateRun(ctx, rec); err != nil {
		return api.Run{}, err
	}
	return f.wait(ctx, c, run)
}

// downloadHostPackage writes <core_data>/host-packages/<id>.deb (O_EXCL, 0600) from <base>/v<version>/<file name>,
// at most file.Size bytes, hashed as it is written. code is the end of the step when it is not usable
// (checksum_mismatch, package_invalid, host_download_failed); err only when core is stopping.
func (h *OSHandlers) downloadHostPackage(ctx context.Context, version string, file release.HostFile, id string) (code string, err error) {
	if file.Size < 1 || file.Size > maxHostPackage {
		return api.CodePackageInvalid, nil
	}
	if _, _, ok := release.ParseHostPackageName(file.Name); !ok {
		return api.CodePackageInvalid, nil
	}
	fail := func(what string, err error) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		h.log.WarnContext(ctx, "core: the system helper package could not be downloaded", "step", what, "error", err)
		return codeHostDownload, nil
	}
	dctx, cancel := context.WithTimeout(ctx, hostPackageFetch)
	defer cancel()
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, h.upd.base+"/v"+version+"/"+file.Name, nil)
	if err != nil {
		return fail("request", err)
	}
	req.Header.Set("User-Agent", h.upd.userAgent())
	cl := *h.upd.client // the same redirect rule (releaseHosts) and transport; a package may take longer than a document
	cl.Timeout = hostPackageFetch
	resp, err := cl.Do(req)
	if err != nil {
		return fail("get", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fail("get", fmt.Errorf("HTTP %d", resp.StatusCode))
	}
	if err := os.MkdirAll(h.pkgDir, 0o700); err != nil {
		return fail("folder", err)
	}
	p := filepath.Join(h.pkgDir, id+".deb")
	// A resend after a restart writes it again: the host did not take the earlier one.
	_ = os.Remove(p)

	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // p is pkgDir + a 32-hex id
	if err != nil {
		return fail("create", err)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(resp.Body, file.Size+1))
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(p)
		return fail("write", err)
	}
	if n != file.Size || hex.EncodeToString(sum.Sum(nil)) != file.SHA256 {
		_ = os.Remove(p)
		h.log.ErrorContext(ctx, "core: the downloaded system helper package does not match the signed release", "bytes", n, "want_bytes", file.Size)
		return api.CodeChecksumMismatch, nil
	}
	return "", nil
}

func newPackageID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("core: package id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// sweepHostPackages removes packages an earlier process left in host-packages/ (older than an hour), at start-up.
func (h *OSHandlers) sweepHostPackages() {
	entries, err := os.ReadDir(h.pkgDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			h.log.Warn("core: sweeping old system helper packages failed", "error", err)
		}
		return
	}
	for _, e := range entries {
		if !hostPackageRE.MatchString(e.Name()) {
			continue // not ours: leave it
		}
		if info, err := e.Info(); err == nil && h.now().Sub(info.ModTime()) >= hostPackageMaxAge {
			_ = os.Remove(filepath.Join(h.pkgDir, e.Name()))
		}
	}
}

// removeHostPackages removes the packages of a run that ended.
func (h *OSHandlers) removeHostPackages(rec *updateRunRec) {
	for _, c := range rec.Calls {
		if c.Package != "" && h.pkgDir != "" {
			_ = os.Remove(filepath.Join(h.pkgDir, c.Package+".deb"))
		}
	}
}

// selfUpdateEnd is when core stops waiting for a host.self_update run: its deadline (known once it parked, else the
// latest it can be) plus 20 minutes. The host never lets a run outlive its deadline by more than its 15-minute safety net.
func selfUpdateEnd(run api.Run) time.Time {
	if run.ParkedDeadline != nil {
		return run.ParkedDeadline.Add(selfUpdateGrace)
	}
	return run.StartedAt.Add(selfUpdatePrePark + selfUpdateWindow + selfUpdateGrace)
}

// hostUpdated writes down the succeeded host step with its history entry (component host, criterion (b)) in one
// transaction, so the entry is written once; the page then reads the helper's version again.
func (h *OSHandlers) hostUpdated(ctx context.Context, rec *updateRunRec, run api.Run) error {
	from, to, changed := rec.Host.From, rec.Host.To, true
	var res api.HostSelfUpdateResult
	if json.Unmarshal(run.Result, &res) == nil && res.To != "" {
		from, to, changed = res.From, res.To, res.Changed
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var hist []updateHistoryView
	if err := h.loadJSON(wctx, keyUpdateHistory, &hist); err != nil {
		return err
	}
	err := h.db.Write(wctx, func(tx *sql.Tx) error {
		if changed {
			hist = append([]updateHistoryView{{ID: "h_" + rec.ID + "_host", TS: h.now(), Component: hostComponent, From: &from, To: to, Action: actionUpdate, User: rec.User}}, hist...)
			if len(hist) > updateHistoryMax {
				hist = hist[:updateHistoryMax]
			}
			if err := h.putSetting(wctx, tx, keyUpdateHistory, hist, rec.User); err != nil {
				return err
			}
		}
		return h.putSetting(wctx, tx, keyUpdateRun, rec, rec.User)
	})
	if err != nil {
		return err
	}
	h.upd.dropHostCopy()
	return nil
}

// hostWhy is the sentence of S-CORE-2 criterion D-316 for the end code of the host step; the GUI mock's hostError
// (web/src/features/core/mocks.ts) holds the same words.
func hostWhy(ctx context.Context, rec *updateRunRec, code string) string {
	v, running := rec.To, ""
	if rec.Host != nil {
		v, running = rec.Host.To, rec.Host.From
	}
	switch code {
	case api.CodeSelfUpdateUnhealthy, api.CodeInstallFailed:
		return "The new system helper " + v + " did not start correctly, so the box went back to " + running + " by itself. Nothing else was changed."
	case api.CodeSignatureInvalid, api.CodeKeyRevoked, api.CodeManifestMismatch:
		return "The system helper in this update is not signed by the Vedette release key. Nothing was installed."
	case api.CodeChecksumMismatch, api.CodePackageInvalid, api.CodePackageMismatch:
		return "The downloaded system helper does not match the signed release. Nothing was installed."
	case api.CodeDowngradeNotAllowed:
		return "System helper " + v + " is older than the one running (" + running + "). The helper is never taken back by an update."
	case api.CodeTestVersionRefused:
		return v + " is a test build. It is never installed on a real box."
	case api.CodeDependenciesUnavailable:
		return "The new system helper needs operating system packages that the box's package sources do not offer. Nothing was installed."
	case api.CodeDpkgLocked:
		return "The box is installing operating system packages. Try again in a few minutes."
	case api.CodeRollbackFailed, codeSelfUpdateRollbackFailed, api.CodeSelfUpdateInterrupted:
		return "The system helper update stopped half way and could not be undone. Vedette keeps running; follow the runbook section \"vedette-host self-update stopped half way\"."
	case codeHostTooOld:
		return "This box's system helper (" + running + ") is too old to update itself. Run install.sh of release " + rec.To + " on the box (it upgrades the helper and keeps your data), then apply again."
	case api.CodeCurrentPackageMissing:
		return "Updating the system helper to " + v + " failed: the box has no copy of the running helper to go back to, so it was not updated. Run install.sh of release " + rec.To + " on the box (it keeps your data), then apply again."
	case codeHostDownload:
		return "Updating the system helper to " + v + " failed: its package could not be downloaded. Check that the box can reach github.com over HTTPS, then apply again."
	}
	return "Updating the system helper to " + v + " failed: " + updateReason(ctx, code)
}
