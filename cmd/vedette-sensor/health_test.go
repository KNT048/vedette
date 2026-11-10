package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/modules/sensor-active/worker"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
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
	if err := checkHeartbeat(path, now.Add(-heartbeatEvery)); err != nil {
		t.Fatalf("a small clock step back must not make a fresh file unhealthy: %v", err)
	}
	if err := checkHeartbeat(path, now.Add(-heartbeatMaxAge-time.Second)); err == nil {
		t.Fatal("a modification time far in the future is not a heartbeat")
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
	if heartbeatEvery != capture.DefaultHeartbeatEvery {
		t.Fatalf("heartbeatEvery %s != capture.DefaultHeartbeatEvery %s", heartbeatEvery, capture.DefaultHeartbeatEvery)
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

// The gate for the health lines of the sensor and scan units: HealthCmd= is a JSON array (the exec form: the string form runs through
// /bin/sh -c, D-137), argv[0] is this binary's path in the image, the arguments are a subcommand this binary has and need nothing
// the unit does not pass; the interval, retries and start period give the check room (the start period covers the first
// heartbeat, one beat every 30 s against a window of 60 s); /tmp, where the file goes, is a tmpfs because the root is read-only.
func TestSensorAndScanUnitsHealthCmdRunsWithTheRealSubcommand(t *testing.T) {
	old := heartbeatPath
	t.Cleanup(func() { heartbeatPath = old })
	for _, svc := range []string{"sensor", "scan"} {
		text, err := ops.RenderUnit(svc, "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
		if err != nil {
			t.Fatal(err)
		}
		kv := map[string]string{}
		for _, l := range strings.Split(string(text), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = v
			}
		}
		var argv []string
		if err := json.Unmarshal([]byte(kv["HealthCmd"]), &argv); err != nil {
			t.Fatalf("%s: HealthCmd=%q must be a JSON array (exec form): %v", svc, kv["HealthCmd"], err)
		}
		if len(argv) < 2 || argv[0] != "/vedette-sensor" {
			t.Fatalf("%s: HealthCmd=%q must run /vedette-sensor with a subcommand", svc, kv["HealthCmd"])
		}
		if d, err := time.ParseDuration(kv["HealthInterval"]); err != nil || d != heartbeatEvery {
			t.Errorf("%s: HealthInterval=%q, want %s", svc, kv["HealthInterval"], heartbeatEvery)
		}
		if d, err := time.ParseDuration(kv["HealthStartPeriod"]); err != nil || d < heartbeatEvery {
			t.Errorf("%s: HealthStartPeriod=%q must cover the first heartbeat (%s)", svc, kv["HealthStartPeriod"], heartbeatEvery)
		}
		if kv["HealthRetries"] != "3" {
			t.Errorf("%s: HealthRetries=%q, want 3", svc, kv["HealthRetries"])
		}
		if kv["ReadOnly"] != "true" || kv["Tmpfs"] != "/tmp" || path.Dir(heartbeatPath) != "/tmp" {
			t.Errorf("%s: the heartbeat file %s needs ReadOnly=true with Tmpfs=/tmp (got %q, %q)", svc, heartbeatPath, kv["ReadOnly"], kv["Tmpfs"])
		}
		heartbeatPath = filepath.Join(t.TempDir(), "hb")
		if err := touchHeartbeat(heartbeatPath, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := run(t.Context(), argv[1:], &bytes.Buffer{}, slog.New(slog.DiscardHandler)); err != nil {
			t.Errorf("%s: HealthCmd=%q does not run with the real binary: %v", svc, kv["HealthCmd"], err)
		}
		heartbeatPath = old
	}
}

// The writer does not follow a symbolic link: nothing is written through it.
func TestTouchHeartbeatRefusesASymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(target, old, old); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hb")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := touchHeartbeat(link, time.Now()); err == nil {
		t.Fatal("a symlink must be refused")
	}
	fi, err := os.Stat(target)
	if err != nil || !fi.ModTime().Equal(old) {
		t.Fatalf("the link target was touched: %v %v", fi, err)
	}
	// and a dangling link is not created through
	dangling := filepath.Join(dir, "hb2")
	if err := os.Symlink(filepath.Join(dir, "new"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := touchHeartbeat(dangling, time.Now()); err == nil {
		t.Fatal("a dangling symlink must be refused")
	}
	if _, err := os.Lstat(filepath.Join(dir, "new")); err == nil {
		t.Fatal("the file behind a dangling link was created")
	}
}

// A failed write is logged once, again only after it worked and failed again.
func TestBeatLinkWarnsOnceOnWriteFailure(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	dir := t.TempDir()
	b := withBeat(nil, filepath.Join(dir, "sub", "hb"), log) // the directory is missing: the write fails
	warns := func() int { return strings.Count(buf.String(), "level=WARN") }
	b.note(t.Context())
	b.note(t.Context())
	if warns() != 1 {
		t.Fatalf("want one warning for two failures, got %d:\n%s", warns(), buf.String())
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	b.note(t.Context())
	if !strings.Contains(buf.String(), "written again") || warns() != 1 {
		t.Fatalf("want a recovery line and no new warning:\n%s", buf.String())
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Remove(filepath.Join(sub, "hb")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o500); err != nil { //nolint:gosec // a directory must be searchable // a read-only directory: creating the file fails
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })                                                      //nolint:gosec // a directory must be searchable
	if f, err := os.OpenFile(filepath.Join(sub, "probe"), os.O_CREATE|os.O_WRONLY, 0o600); err == nil { //nolint:gosec // a test path
		_ = f.Close()
		t.Skip("read-only directory not enforced (root)")
	}
	b.note(t.Context())
	b.note(t.Context())
	if warns() != 2 {
		t.Fatalf("a failure after a recovery warns again, once: got %d:\n%s", warns(), buf.String())
	}
}
