package main

import (
	"bytes"
	"context"
	"errors"
	"go/build"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
)

// heartbeatCore is a Backend that only listens for the heartbeat of the active role.
type heartbeatCore struct {
	beats chan sensorlink.ActiveHeartbeat
}

func (heartbeatCore) Config(context.Context, time.Duration, string) (sensorlink.ConfigReply, error) {
	return sensorlink.ConfigReply{}, sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (heartbeatCore) Observations(context.Context, *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (heartbeatCore) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	return "", sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (c heartbeatCore) ActiveHeartbeat(_ context.Context, hb *sensorlink.ActiveHeartbeat) (string, error) {
	select {
	case c.beats <- *hb:
	default:
	}
	return strings.Repeat("c", 32), nil
}

func (heartbeatCore) Jobs(ctx context.Context, wait time.Duration, _ string) (sensorlink.JobsReply, error) {
	select {
	case <-time.After(wait):
	case <-ctx.Done():
	}
	return sensorlink.JobsReply{Instance: strings.Repeat("c", 32)}, nil
}

func (heartbeatCore) JobRunning(string) bool { return false }

func (heartbeatCore) JobResult(context.Context, string, *sensorlink.JobResult) error {
	return sensorlink.NewError(sensorlink.CodeUnknownJob)
}

// `vedette-sensor active` connects with the bundle core wrote and reports nmap in its heartbeat.
func TestActiveSubcommandTalksToCore(t *testing.T) {
	t.Parallel()
	core := heartbeatCore{beats: make(chan sensorlink.ActiveHeartbeat, 4)}
	link := linktest.New(t, core)
	nmap := filepath.Join(t.TempDir(), "nmap")
	exectest.WriteScript(t, nmap, "#!/bin/sh\necho 'Nmap version 7.94SVN ( https://nmap.org )'\n")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"active", "--core", link.URL, "--creds", link.CredsPath(sensorlink.Active), "--nmap", nmap}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	}()
	select {
	case hb := <-core.beats:
		if hb.Version != version || !hb.Nmap.Present || hb.Nmap.Version != "7.94SVN" {
			t.Fatalf("heartbeat = %+v", hb)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no heartbeat")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the worker did not stop")
	}
}

// The scan container holds no database, no secrets and no consent (D-113, D-114): its binary must not link database/sql, SQLite,
// the generated API or any module but the leaf packages below, and no third-party code at all. The test walks the imports of
// the packages of this module from the binary down (go/build, once for the build host and once for Linux, where the binary
// runs): every import of every one of them is either standard library outside database/sql, or on the allowed list.
func TestBinaryDependencies(t *testing.T) {
	t.Parallel()
	const mod = "github.com/knt048/vedette/"
	allowed := []string{
		"cmd/vedette-sensor",
		"core/exec",
		"core/sensorlink",
		"internal/jsonstrict",
		"modules/sensor-active/nmapargv",
		"modules/sensor-active/worker",
	}
	for _, goos := range []string{runtime.GOOS, "linux"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			ctx := build.Default
			ctx.GOOS, ctx.CgoEnabled = goos, false
			seen := map[string]bool{}
			var walk func(pkg string)
			walk = func(pkg string) {
				if seen[pkg] {
					return
				}
				seen[pkg] = true
				p, err := ctx.ImportDir(filepath.Join("..", "..", filepath.FromSlash(pkg)), 0)
				if err != nil {
					t.Errorf("%s: %v", pkg, err)
					return
				}
				for _, imp := range p.Imports {
					switch {
					case imp == "database/sql" || strings.HasPrefix(imp, "database/sql/"):
						t.Errorf("%s links %s", pkg, imp)
					case strings.HasPrefix(imp, mod):
						rel := strings.TrimPrefix(imp, mod)
						if !slices.Contains(allowed, rel) {
							t.Errorf("%s links %s, which the sensor binary must not", pkg, imp)
							continue
						}
						walk(rel)
					case strings.Contains(strings.SplitN(imp, "/", 2)[0], "."):
						t.Errorf("%s links the third-party package %s", pkg, imp)
					}
				}
			}
			walk("cmd/vedette-sensor")
			for _, must := range allowed {
				if !seen[must] {
					t.Errorf("expected %s in the binary", must)
				}
			}
		})
	}
}

func TestUsageAndUnknownCommand(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	for _, args := range [][]string{nil, {"passive"}, {"healthcheck"}, {"active", "stray"}, {"active", "--creds", "/nonexistent/sensor.pem"}} {
		if err := run(t.Context(), args, &bytes.Buffer{}, log); err == nil {
			t.Errorf("run(%q) succeeded", args)
		}
	}
	var out bytes.Buffer
	if err := run(t.Context(), []string{"--version"}, &out, log); err != nil || strings.TrimSpace(out.String()) != version {
		t.Errorf("--version = %q, %v", out.String(), err)
	}
}
