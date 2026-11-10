package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

func TestCheckHeartbeat(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := t.TempDir()
	path := filepath.Join(dir, "hb")
	if err := checkHeartbeat(path, now); err == nil {
		t.Fatal("a missing file is unhealthy")
	}
	if err := touchHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	if err := checkHeartbeat(path, now.Add(heartbeatMaxAge)); err != nil {
		t.Fatalf("exactly two beats old is still healthy: %v", err)
	}
	if err := checkHeartbeat(path, now.Add(heartbeatMaxAge+time.Second)); err == nil {
		t.Fatal("a stale file is unhealthy")
	}
	if err := checkHeartbeat(path, now.Add(-time.Hour)); err != nil {
		t.Fatalf("a clock step back must not make a fresh file unhealthy: %v", err)
	}
	// touching again moves the time forward without truncating or failing on an existing file
	if err := touchHeartbeat(path, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := checkHeartbeat(path, now.Add(time.Minute+heartbeatEvery)); err != nil {
		t.Fatalf("a touched file is fresh: %v", err)
	}
	// a directory or a link is not what the process wrote
	if err := checkHeartbeat(dir, now); err == nil {
		t.Fatal("a directory is unhealthy")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := checkHeartbeat(link, now); err == nil {
		t.Fatal("a symlink is unhealthy")
	}
}

// Both roles beat every 30 s, and the check allows two beats.
func TestHeartbeatPaceMatchesTheRoles(t *testing.T) {
	t.Parallel()
	if heartbeatEvery != worker.HeartbeatEvery {
		t.Fatalf("heartbeatEvery %s != worker.HeartbeatEvery %s", heartbeatEvery, worker.HeartbeatEvery)
	}
	if heartbeatMaxAge != 2*heartbeatEvery {
		t.Fatalf("heartbeatMaxAge = %s", heartbeatMaxAge)
	}
}

// The writer: a heartbeat core accepted touches the file; one core refused does not.
func TestBeatLinkTouchesTheFileOnlyAfterAnAcceptedHeartbeat(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	t.Run("active accepted", func(t *testing.T) {
		t.Parallel()
		link := linktest.New(t, heartbeatCore{beats: make(chan sensorlink.ActiveHeartbeat, 4)})
		path := filepath.Join(t.TempDir(), "hb")
		b := withBeat(link.Client(t, sensorlink.Active), path, log)
		if _, err := b.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: version}); err != nil {
			t.Fatal(err)
		}
		if err := checkHeartbeat(path, time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("passive accepted", func(t *testing.T) {
		t.Parallel()
		link := linktest.New(t, linktest.Passive(passiveCore{beats: make(chan sensorlink.PassiveHeartbeat, 4)}))
		path := filepath.Join(t.TempDir(), "hb")
		b := withBeat(link.Client(t, sensorlink.Passive), path, log)
		if _, err := b.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: version, Interfaces: []sensorlink.HeartbeatIface{}, Drops: map[string]int64{}}); err != nil {
			t.Fatal(err)
		}
		if err := checkHeartbeat(path, time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		// heartbeatCore refuses the passive heartbeat with forbidden_route.
		link := linktest.New(t, heartbeatCore{beats: make(chan sensorlink.ActiveHeartbeat, 4)})
		path := filepath.Join(t.TempDir(), "hb")
		b := withBeat(link.Client(t, sensorlink.Passive), path, log)
		if _, err := b.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: version, Interfaces: []sensorlink.HeartbeatIface{}, Drops: map[string]int64{}}); err == nil {
			t.Fatal("core refuses this heartbeat")
		}
		if _, err := os.Lstat(path); err == nil {
			t.Fatal("a refused heartbeat must not touch the file")
		}
	})
}

// Not parallel: it points the package's heartbeat path at a temporary file. The real run of each role must write it.
func TestRunWritesTheHeartbeatFile(t *testing.T) {
	old := heartbeatPath
	t.Cleanup(func() { heartbeatPath = old })
	for _, role := range []string{"passive", "active"} {
		heartbeatPath = filepath.Join(t.TempDir(), role+".hb")
		var link *linktest.Link
		if role == "passive" {
			link = linktest.New(t, linktest.Passive(passiveCore{beats: make(chan sensorlink.PassiveHeartbeat, 4)}))
		} else {
			link = linktest.New(t, heartbeatCore{beats: make(chan sensorlink.ActiveHeartbeat, 4)})
		}
		role2 := sensorlink.Role(role)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, []string{role, "--core", link.URL, "--creds", link.CredsPath(role2)}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
		}()
		deadline := time.Now().Add(15 * time.Second)
		for checkHeartbeat(heartbeatPath, time.Now()) != nil {
			if time.Now().After(deadline) {
				t.Fatalf("%s: no heartbeat file", role)
			}
			<-time.After(20 * time.Millisecond)
		}
		// and the subcommand answers 0 while it is fresh
		if err := run(t.Context(), []string{"healthcheck"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("%s: healthcheck: %v", role, err)
		}
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: run: %v", role, err)
		}
	}
	// stale or missing: exit 1 (an error from run)
	heartbeatPath = filepath.Join(t.TempDir(), "missing")
	if err := run(t.Context(), []string{"healthcheck"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("no file must be unhealthy")
	}
	if err := run(t.Context(), []string{"healthcheck", "extra"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("healthcheck takes no arguments")
	}
}

// The gate for HealthCmd= of the sensor and scan units: argv[0] is this binary's path in the image, the arguments are a subcommand
// this binary has and need nothing the unit does not pass, and the interval and retries give the check room: the start period
// covers the first heartbeat, one heartbeat every 30 s against a window of 60 s.
func TestSensorAndScanUnitsHealthCmdRunsWithTheRealSubcommand(t *testing.T) {
	old := heartbeatPath
	t.Cleanup(func() { heartbeatPath = old })
	for _, svc := range []string{"sensor", "scan"} {
		text, err := ops.RenderUnit(svc, "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
		if err != nil {
			t.Fatal(err)
		}
		var cmd string
		for _, l := range strings.Split(string(text), "\n") {
			if v, ok := strings.CutPrefix(l, "HealthCmd="); ok {
				cmd = v
			}
		}
		argv := strings.Fields(cmd)
		if len(argv) < 2 || argv[0] != "/vedette-sensor" {
			t.Fatalf("%s: HealthCmd=%q must run /vedette-sensor with a subcommand", svc, cmd)
		}
		heartbeatPath = filepath.Join(t.TempDir(), "hb")
		if err := touchHeartbeat(heartbeatPath, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := run(t.Context(), argv[1:], &bytes.Buffer{}, slog.New(slog.DiscardHandler)); err != nil {
			t.Errorf("%s: HealthCmd=%q does not run with the real binary: %v", svc, cmd, err)
		}
	}
}
