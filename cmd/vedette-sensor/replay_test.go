package main

import (
	"bytes"
	"context"
	"errors"
	"go/build"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	coreexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
)

// replayCore is core's passive half for the replay test: it never names a card (the compose dev stack has no vedette-host to pick
// one) and keeps what the sensor delivers.
type replayCore struct {
	mu    sync.Mutex
	items []sensorlink.ObservationItem
	got   chan struct{}
}

func (*replayCore) Config(ctx context.Context, wait time.Duration, etag string) (sensorlink.ConfigReply, error) {
	if etag == "" {
		return sensorlink.ConfigReply{ETag: `"e1"`, Config: sensorlink.Config{Filters: []sensorlink.Filter{}}}, nil
	}
	select {
	case <-time.After(wait):
	case <-ctx.Done():
	}
	return sensorlink.ConfigReply{NotModified: true, ETag: etag}, nil
}

func (c *replayCore) Observations(_ context.Context, req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	c.mu.Lock()
	c.items = append(c.items, req.Items...)
	c.mu.Unlock()
	select {
	case c.got <- struct{}{}:
	default:
	}
	return sensorlink.ObservationsReply{AckSeq: req.Seq}, nil
}

func (*replayCore) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	return strings.Repeat("c", 32), nil
}

// `passive --replay FILE` captures from the recording although core names no card, and delivers what the recording holds. This is
// the sensor of the compose dev stack (D-146): no card, no vedette-host, and a device still appears in the inventory.
func TestPassiveReplayDeliversTheRecordingWithoutACard(t *testing.T) {
	// not parallel: the running sensor touches the real heartbeat file, which TestUsageAndUnknownCommand expects to be absent
	t.Cleanup(func() { _ = os.Remove(heartbeatPath) })
	core := &replayCore{got: make(chan struct{}, 1)}
	link := linktest.New(t, linktest.Passive(core))
	pcap := filepath.Join("..", "..", "modules", "sensor-passive", "testdata", "lan-discovery.pcap")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"passive", "--core", link.URL, "--creds", link.CredsPath(sensorlink.Passive), "--replay", pcap}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	}()
	select {
	case <-core.got:
	case <-time.After(30 * time.Second):
		t.Fatal("the replayed recording delivered nothing")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("run: %v", err)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if len(core.items) == 0 || core.items[0].MAC == "" {
		t.Fatalf("items = %+v", core.items)
	}
	// core refuses observations outside its time window, and the recording is old: the replay stamps the time it reads a packet
	for _, it := range core.items {
		if d := time.Since(it.SeenAt); d < -time.Minute || d > time.Minute {
			t.Fatalf("%s seen_at %s is not about now", it.Field, it.SeenAt)
		}
	}
}

// Without --replay the sensor still waits for core to name a card, as before: the flag is the only thing that changes that.
func TestPassiveWithoutReplayStaysIdleWhenCoreNamesNoCard(t *testing.T) {
	// not parallel: the running sensor touches the real heartbeat file, which TestUsageAndUnknownCommand expects to be absent
	t.Cleanup(func() { _ = os.Remove(heartbeatPath) })
	core := &replayCore{got: make(chan struct{}, 1)}
	link := linktest.New(t, linktest.Passive(core))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"passive", "--core", link.URL, "--creds", link.CredsPath(sensorlink.Passive)}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	}()
	select {
	case <-core.got:
		t.Fatal("a sensor with no card delivered observations")
	case <-time.After(3 * time.Second):
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("run: %v", err)
	}
}

func TestPassiveReplayRefusesAMissingRecording(t *testing.T) {
	t.Parallel()
	err := run(t.Context(), []string{"passive", "--replay", filepath.Join(t.TempDir(), "nope.pcap")}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("a recording that cannot be opened must stop the start, not be retried for ever")
	}
}

// D-114 (2), D-146: the sensor and scan binary is built with CGO_ENABLED=0 into an image that holds no shell and no libpcap, so
// the dependency graph, listed by the go tool itself, must hold none of core's storage, secrets or server, no module but the leaf
// packages the binary shares with core, no database driver and no cgo of its own. A failure names the import path that crossed the line.
func TestGoListDepsOfTheSensorBinary(t *testing.T) {
	t.Parallel()
	const mod = "github.com/knt048/vedette/"
	allowed := []string{
		"cmd/vedette-sensor", "content/oui", "core/egressip", "core/exec", "core/localnet", "core/observe", "core/sensorlink", "internal/jsonstrict",
		"modules/scan/commonports", "modules/scan/nucleiargv", "modules/scan/nucleiout", "modules/scan/pack", "modules/sensor-active/nmapargv", "modules/sensor-active/worker",
		"modules/sensor-passive/capture",
	}
	never := []string{"core/store", "core/secrets", "core/audit", "core/pki", "core/server", "core/api", "cmd/vedette", "cmd/vedette-host", "host"}
	// Through core/exec (SYS-1): the environment is the runner's own (PATH, LANG, HOME), so this lists for the host's GOOS; the go/build walk
	// of TestBinaryDependencies covers linux and the build host's other OS.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory for the go tool")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-C", root, "list", "-deps", "-f", "{{.ImportPath}}\t{{len .CgoFiles}}", "./cmd/vedette-sensor"}
	r, err := coreexec.NewRunner(slog.New(slog.DiscardHandler), coreexec.Binary{
		Name: "go", Path: filepath.Join(build.Default.GOROOT, "bin", "go"), Env: []string{"HOME=" + home}, MaxOutput: 8 << 20,
		Validate: func(a []string) error {
			if !slices.Equal(a, args) {
				return errors.New("only the one go list of this test")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	res, err := r.Run(ctx, "go", args, nil)
	if err != nil {
		t.Fatalf("go list -deps: %v %s", err, res.Stderr)
	}
	var listed []string
	for _, line := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
		p, cgo, _ := strings.Cut(line, "\t")
		listed = append(listed, p)
		own := strings.HasPrefix(p, mod) || strings.Contains(strings.SplitN(p, "/", 2)[0], ".")
		switch {
		case own && cgo != "0":
			t.Errorf("%s has cgo files: the image is built with CGO_ENABLED=0 and has no libpcap", p)
		case strings.HasPrefix(p, mod):
			rel := strings.TrimPrefix(p, mod)
			if slices.Contains(never, rel) || slices.ContainsFunc(never, func(n string) bool { return strings.HasPrefix(rel, n+"/") }) {
				t.Errorf("the sensor binary links %s, which holds state or serves the API", p)
			} else if !slices.Contains(allowed, rel) {
				t.Errorf("the sensor binary links %s, which is not a leaf it may share with core", p)
			}
		case p == "database/sql" || strings.HasPrefix(p, "database/sql/") || strings.HasPrefix(p, "modernc.org/") || strings.HasPrefix(p, "github.com/ogen-go/"):
			t.Errorf("the sensor binary links %s", p)
		}
	}
	for _, must := range allowed {
		if !slices.Contains(listed, mod+must) {
			t.Errorf("expected %s in the binary", must)
		}
	}
}
