package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureGreenbone is exposure's GreenboneHost (S-EXP-2, exposure INV-25, D-563, D-529, FULL-2): OpenVAS (Greenbone Community
// Edition) as vedette-host runs it, Greenbone's official compose project under its own name. Up, Down and SyncFeed are the host's
// greenbone.up, greenbone.down and greenbone.sync_feed; Dial opens gvmd's unix socket, which the host hands to core through
// /run/vedette-greenbone (core's unit mounts that directory and nothing else of Greenbone), and returns the GMP login.
//
// The GMP password is the box's own: 24 random bytes in core/secrets (purpose gbSecretPurpose, AES-256-GCM), written as 48 hex
// characters. Up gives it to the host, which sets it on gvmd at every start, so a wiped volume gets it back (W4-1); Dial hands it to
// exposure. It is never logged, audited or put in an error (the host's audit line redacts it by its key).
type exposureGreenbone struct {
	host   greenboneHostClient
	login  func(ctx context.Context) (string, error)
	socket string
}

// greenboneHostClient is what OpenVAS needs of the host client (*hostclient.Client).
type greenboneHostClient interface {
	Greenbone(ctx context.Context, command string, args any, requestID, actor string) (api.Run, error)
}

const (
	// gbSecretPurpose is the core/secrets purpose of the GMP password; gbSecretSize its random bytes (48 hex characters).
	gbSecretPurpose = "exposure_greenbone.gmp_password"
	gbSecretSize    = 24
	gbActor         = "exposure:openvas"
	gbDownAfterStop = 5 * time.Minute // the stop a cancelled feed update sends, on its own context
)

// The sentences exposure shows of the host side (after "Greenbone could not be started: " and the like).
const (
	gbStarting = "OpenVAS is still starting: its manager (gvmd) has not opened its socket yet."
	gbOldHost  = "the box's host helper (vedette-host) is older than this version of Vedette and cannot run OpenVAS. Update the box."
)

// exposureGreenboneFor is cfg.Greenbone: the host op when this install has vedette-host, else nil (the page says OpenVAS is not
// available). privacyFacts.GreenboneEnabled answers flow 16 from the same exposure service, so the two are wired together (review r2).
func exposureGreenboneFor(d deps) exposure.GreenboneHost {
	if d.HostSocket == "" || d.Secrets == nil || d.DB == nil {
		return nil
	}
	return exposureGreenbone{host: hostclient.New(d.HostSocket), socket: api.GreenboneSocket, login: func(ctx context.Context) (string, error) {
		b, err := d.Secrets.OpenOrCreate(ctx, d.DB, gbSecretPurpose, gbSecretSize)
		if err != nil {
			return "", fmt.Errorf("openvas: the GMP password: %w", err)
		}
		return hex.EncodeToString(b), nil
	}}
}

func (g exposureGreenbone) run(ctx context.Context, command string, args any) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	run, err := g.host.Greenbone(ctx, command, args, id, gbActor)
	var he *hostclient.Error
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.As(err, &he) && he.Code == api.CodeUnknownCommand:
		return &exposure.Unavailable{Reason: gbOldHost}
	default:
		return fmt.Errorf("openvas: %s: %w", command, err)
	}
	if run.Status == api.StatusSucceeded {
		return nil
	}
	if run.Error == nil {
		return fmt.Errorf("openvas: %s ended %s", command, run.Status)
	}
	if run.Error.Code == api.CodeGreenboneCancelled {
		return context.Canceled // turned off meanwhile: exposure reads it so
	}
	// The host's sentences are plain English written for the page (no argv, no password): failed steps, the provider, apt's lock.
	return &exposure.Unavailable{Reason: run.Error.Message}
}

// Up starts OpenVAS with the box's GMP password (made the first time).
func (g exposureGreenbone) Up(ctx context.Context) error {
	pw, err := g.login(ctx)
	if err != nil {
		return err
	}
	return g.run(ctx, api.CmdGreenboneUp, api.GreenboneUpArgs{Password: pw})
}

// Down stops OpenVAS and keeps its volumes; the host first ends an up or a feed update that runs.
func (g exposureGreenbone) Down(ctx context.Context) error {
	return g.run(ctx, api.CmdGreenboneDown, nil)
}

// SyncFeed is Greenbone's feed update. When ctx ends first (OpenVAS turned off, the box or the module stopping), it returns at once
// and asks the host to stop OpenVAS, which ends the pull that runs there (exposure INV-25, D-564 G6: no pull after a stop).
func (g exposureGreenbone) SyncFeed(ctx context.Context) error {
	err := g.run(ctx, api.CmdGreenboneSyncFeed, nil)
	if ctx.Err() != nil {
		go func() { //nolint:gosec,contextcheck // the stop outlives the cancelled update on purpose, bounded by gbDownAfterStop
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gbDownAfterStop)
			defer cancel()
			_ = g.Down(dctx)
		}()
		return ctx.Err()
	}
	return err
}

// Dial opens gvmd's socket. While it is not there (OpenVAS starting, or never started on this box) the answer is "starting".
func (g exposureGreenbone) Dial(ctx context.Context) (net.Conn, exposure.GMPLogin, error) {
	if _, err := os.Stat(g.socket); errors.Is(err, fs.ErrNotExist) {
		return nil, exposure.GMPLogin{}, &exposure.Unavailable{Reason: gbStarting}
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", g.socket)
	if err != nil {
		return nil, exposure.GMPLogin{}, fmt.Errorf("openvas: dialling gvmd: %w", err)
	}
	pw, err := g.login(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, exposure.GMPLogin{}, err
	}
	return conn, exposure.GMPLogin{User: api.GreenboneUser, Password: pw}, nil
}
