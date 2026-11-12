package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/modules/mitigation"
)

// Signed confirmed mitigation packs (D-345..D-349). The packs ship inside the signed core image (D-36) at defaultPackDir with
// packs.minisig, the release minisign signature of mitigation.Statement (version, SHA-256 and name of every file). The job
// load-packs reads the directory and hands it to mitigation.Loader, whose first step is this Verifier: nothing is read into the
// database unless the signature holds.

// defaultPackDir is where the core Containerfile copies content/mitigation/packs.
const defaultPackDir = "/opt/vedette/content/mitigation"

// packEvery is how often the job looks again. The directory only changes with a new image, which restarts core, and a job runs
// once at start and when the module is turned on; the daily run only retries a failure.
const packEvery = 24 * time.Hour

// packVerifier is mitigation.Verifier over the release minisign keys compiled into the binary (D-346).
type packVerifier struct{ trust func() (release.Trust, error) }

func (v packVerifier) Verify(_ context.Context, u mitigation.Update) error {
	get := v.trust
	if get == nil {
		get = release.Embedded
	}
	t, err := get()
	if err != nil {
		return err
	}
	stmt, err := mitigation.Statement(u.Version, u.Docs)
	if err != nil {
		return err
	}
	return release.VerifyContent(stmt, u.Signature, t)
}

// loadPacks is one run of load-packs. No directory (a build without packs) and the same version again are not failures.
func loadPacks(ctx context.Context, l *mitigation.Loader, dir string, log *slog.Logger) error {
	u, err := mitigation.ReadPackDir(dir)
	if errors.Is(err, mitigation.ErrNoPackDir) {
		log.DebugContext(ctx, "mitigation: this build ships no confirmed packs", "dir", dir)
		return nil
	}
	if err != nil {
		return err
	}
	res, err := l.Install(ctx, u)
	if errors.Is(err, mitigation.ErrReplay) {
		// the packs of this version (or a newer one) are installed already: after an image rollback the newer packs stay
		log.DebugContext(ctx, "mitigation: the shipped packs are not newer than the installed ones", "version", u.Version)
		return nil
	}
	if err != nil {
		return fmt.Errorf("load the confirmed packs %q: %w", u.Version, err) // %q: VERSION is not trusted before the signature
	}
	log.InfoContext(ctx, "mitigation: confirmed packs loaded", "version", u.Version, "loaded", res.Loaded, "rejected", len(res.Rejected))
	return nil
}

// mitigationJobs is the Jobs func of the mitigation entry in wiredModules.
func mitigationJobs(d deps) []jobs.Job {
	if d.PackLoader == nil {
		return nil
	}
	dir := d.PackDir
	if dir == "" {
		dir = defaultPackDir
	}
	l, log := d.PackLoader, d.Log
	return []jobs.Job{{Module: "mitigation", Name: "load-packs", Every: packEvery, Run: func(ctx context.Context) error { return loadPacks(ctx, l, dir, log) }}}
}
