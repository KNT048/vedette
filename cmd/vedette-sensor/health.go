package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// The container health check of `sensor` and `scan` (`HealthCmd=/vedette-sensor healthcheck`, host/ops/quadlet.go, D-137). The
// process says it is alive and talking to core by touching a file after every heartbeat core accepted; the check reads the file's
// age. The file lives on /tmp, a tmpfs in both units, so a restart starts without it (and unhealthy until the first heartbeat, inside
// the unit's start period). The check needs no credentials and no network: a heartbeat that core refuses or that never arrives
// leaves the file to age.
const (
	// heartbeatEvery is the pace of both roles: capture.Runner and worker.Worker send one every 30 s (their defaults;
	// health_test.go checks the worker's). heartbeatMaxAge is two beats: one lost heartbeat is not unhealthy.
	heartbeatEvery  = 30 * time.Second
	heartbeatMaxAge = 2 * heartbeatEvery
)

// heartbeatPath is where the process touches the file. A variable only so a test can point it elsewhere.
var heartbeatPath = "/tmp/vedette-sensor.heartbeat"

// beatLink is the link to core that notes every heartbeat core accepted. It embeds the client, so every other call is the
// client's own.
type beatLink struct {
	*sensorlink.Client
	path string
	log  *slog.Logger
}

func withBeat(c *sensorlink.Client, path string, log *slog.Logger) beatLink {
	return beatLink{Client: c, path: path, log: log}
}

func (b beatLink) PassiveHeartbeat(ctx context.Context, hb *sensorlink.PassiveHeartbeat) (string, error) {
	inst, err := b.Client.PassiveHeartbeat(ctx, hb)
	if err == nil {
		b.note(ctx)
	}
	return inst, err
}

func (b beatLink) ActiveHeartbeat(ctx context.Context, hb *sensorlink.ActiveHeartbeat) (string, error) {
	inst, err := b.Client.ActiveHeartbeat(ctx, hb)
	if err == nil {
		b.note(ctx)
	}
	return inst, err
}

func (b beatLink) note(ctx context.Context) {
	if err := touchHeartbeat(b.path, time.Now()); err != nil {
		b.log.WarnContext(ctx, "heartbeat file not written: the health check will report unhealthy", "error", err)
	}
}

// touchHeartbeat creates the file when missing and sets its modification time to now.
func touchHeartbeat(path string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // path is the package constant (a variable only for tests), never input
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chtimes(path, now, now)
}

// checkHeartbeat is `vedette-sensor healthcheck`: nil when the file exists, is a regular file and is younger than heartbeatMaxAge.
func checkHeartbeat(path string, now time.Time) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("no heartbeat yet")
	}
	if err != nil {
		return fmt.Errorf("heartbeat file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return errors.New("heartbeat file is not a regular file")
	}
	if age := now.Sub(fi.ModTime()); age > heartbeatMaxAge { // a time in the future (clock step) counts as fresh
		return fmt.Errorf("last heartbeat %s ago, more than %s", age.Round(time.Second), heartbeatMaxAge)
	}
	return nil
}
