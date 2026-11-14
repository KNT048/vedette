package main

import (
	"bytes"
	"context"
	"errors"
	"go/build"
	"log/slog"
	"net"
	"os"
	"os/exec" //nolint:depguard // the test re-runs its own binary to send main() a real signal; SYS-1 is about the product
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
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

func (heartbeatCore) Jobs(ctx context.Context, wait time.Duration, _ []string) (sensorlink.JobsReply, error) {
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

// The scan unit's stop (podman sends SIGTERM to the container's process 1, podman-init, which passes it on) must end the worker at once
// with exit 0, so podman never reaches its 10 s SIGKILL and the unit ends inactive. main() runs in a child copy of this test binary,
// connected and polling, and gets a real SIGTERM.
func TestActiveExitsZeroAtOnceOnSIGTERM(t *testing.T) {
	if os.Getenv("VEDETTE_SENSOR_MAIN") == "1" { // the child: main() with the arguments the parent passed
		heartbeatPath = os.Getenv("VEDETTE_SENSOR_HB")
		os.Args = append([]string{"vedette-sensor"}, strings.Split(os.Getenv("VEDETTE_SENSOR_ARGS"), "\n")...)
		main()
		return
	}
	t.Parallel()
	core := heartbeatCore{beats: make(chan sensorlink.ActiveHeartbeat, 4)}
	link := linktest.New(t, core)
	dir := t.TempDir()
	nmap := filepath.Join(dir, "nmap")
	exectest.WriteScript(t, nmap, "#!/bin/sh\necho 'Nmap version 7.94SVN ( https://nmap.org )'\n")
	args := []string{"active", "--core", link.URL, "--creds", link.CredsPath(sensorlink.Active), "--nmap", nmap, "--nuclei-home", filepath.Join(dir, "nuclei")}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActiveExitsZeroAtOnceOnSIGTERM$") //nolint:gosec // test: re-runs its own binary
	cmd.Env = append(os.Environ(), "VEDETTE_SENSOR_MAIN=1", "VEDETTE_SENSOR_HB="+filepath.Join(dir, "hb"), "VEDETTE_SENSOR_ARGS="+strings.Join(args, "\n"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-core.beats: // running and connected: the signal handler is in place since main's first line
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("no heartbeat\n%s", out.String())
	}
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("SIGTERM took %s to end the worker", took)
	}
	if err != nil {
		t.Errorf("exit on SIGTERM: %v, want 0\n%s", err, out.String())
	}
}

// passiveCore is core's passive half for the subcommand test: an empty configuration (do not capture) and a record of the heartbeats.
type passiveCore struct {
	beats chan sensorlink.PassiveHeartbeat
}

func (passiveCore) Config(ctx context.Context, wait time.Duration, etag string) (sensorlink.ConfigReply, error) {
	if etag == "" {
		return sensorlink.ConfigReply{ETag: `"e1"`, Config: sensorlink.Config{Filters: []sensorlink.Filter{}}}, nil
	}
	select {
	case <-time.After(wait):
	case <-ctx.Done():
	}
	return sensorlink.ConfigReply{NotModified: true, ETag: etag}, nil
}

func (passiveCore) Observations(_ context.Context, req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	return sensorlink.ObservationsReply{AckSeq: req.Seq}, nil
}

func (c passiveCore) PassiveHeartbeat(_ context.Context, hb *sensorlink.PassiveHeartbeat) (string, error) {
	select {
	case c.beats <- *hb:
	default:
	}
	return strings.Repeat("c", 32), nil
}

// `vedette-sensor passive` connects with the bundle core wrote, says hello with its version and the cards of this machine, and stops
// when it is told to.
func TestPassiveSubcommandTalksToCore(t *testing.T) {
	t.Parallel()
	core := passiveCore{beats: make(chan sensorlink.PassiveHeartbeat, 4)}
	link := linktest.New(t, linktest.Passive(core))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"passive", "--core", link.URL, "--creds", link.CredsPath(sensorlink.Passive)}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	}()
	select {
	case hb := <-core.beats:
		if hb.Version != version || hb.Interfaces == nil || hb.Drops == nil {
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
		t.Fatal("the capture did not stop")
	}
}

// The sensor and scan containers hold no database, no secrets and no consent (D-113, D-114): the binary must not link database/sql, SQLite,
// the generated API, core's store, audit, secrets or PKI, or any module but the leaf packages below, and no third-party code
// but x/sys/unix. The test walks the imports of
// the packages of this module from the binary down (go/build, once for the build host and once for Linux, where the binary
// runs): every import of every one of them is either standard library outside database/sql, or on the allowed list.
func TestBinaryDependencies(t *testing.T) {
	t.Parallel()
	const mod = "github.com/knt048/vedette/"
	allowed := []string{
		"cmd/vedette-sensor",
		"content/oui",
		"core/domainfence", // the worker's domain fence of domain_ip jobs (D-591); standard library and core/localnet only, its own leaf test
		"core/egressip",    // the worker's own-IP fence of the external shape and its public-address rule (D-514); standard library only, its own leaf test
		"core/exec",
		"core/localnet", // the local networks of nmapargv and nucleiargv (D-461); net/netip and slices only, its own leaf test
		"core/observe",
		"core/sensorlink",
		"internal/jsonstrict",
		"modules/scan/commonports", // the ports of nmapargv's external shape, the surface scan's list (D-514); it imports nothing
		"modules/scan/nucleiargv",  // the leaves of scan the worker shares with core (D-125 (2), D-136 (3))
		"modules/scan/nucleiout",   // the worker counts host errors from nuclei's error log with it (D-165); its own deps_test keeps it a leaf
		"modules/scan/pack",
		"modules/sensor-active/nmapargv",
		"modules/sensor-active/worker",
		"modules/sensor-passive/capture",
	}
	// The only code from outside the standard library and this module: the raw socket of the capture (afpacket_linux.go) uses
	// one receive-side option that package syscall lacks; the worker reads SNMP agents with gosnmp (BSD-2, D-512: SNMPv3 USM is
	// key localization, HMAC and AES-CFB, not worth writing again). Both are pinned in go.mod and import the standard library only.
	thirdParty := []string{"golang.org/x/sys/unix", "github.com/gosnmp/gosnmp"}
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
					case slices.Contains(thirdParty, imp):
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
	for _, args := range [][]string{nil, {"passive"}, {"healthcheck"}, {"active", "stray"}, {"active", "--creds", "/nonexistent/sensor.pem"},
		{"passive", "stray"}, {"passive", "--bogus"}, {"passive", "--creds", "/nonexistent/sensor.pem"}, {"passive", "--nmap", "/usr/bin/nmap"}} {
		if err := run(t.Context(), args, &bytes.Buffer{}, log); err == nil {
			t.Errorf("run(%q) succeeded", args)
		}
	}
	var out bytes.Buffer
	if err := run(t.Context(), []string{"--version"}, &out, log); err != nil || strings.TrimSpace(out.String()) != version {
		t.Errorf("--version = %q, %v", out.String(), err)
	}
}

// L8: the sensor does not offer virtual links (bridges, veths, bonds, VLANs) as cards, by the same rule as the Box network page.
func TestVirtualLinksAreNotCards(t *testing.T) {
	t.Parallel()
	for name, virtual := range map[string]bool{
		"eth0": false, "enp2s0": false, "eno1": false, "wlan0": false, "ens18": false,
		"veth1a2b": true, "br0": true, "virbr0": true, "docker0": true, "podman1": true, "bond0": true, "tun0": true, "wg0": true,
		"eth0.20": true, "enp2s0@if3": true, "lo": true, "vnet3": true, "dummy0": true, "vedette0": true, // #471: the box's own bridge
	} {
		if got := sensorlink.VirtualIfaceName(name); got != virtual {
			t.Errorf("%s: virtual = %v, want %v", name, got, virtual)
		}
	}
}

// The worker empties -nuclei-home before every run: "/" and paths that are not clean are refused when the flags are parsed.
func TestNucleiHomeFlagIsRefusedWhenDangerous(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"/", "", "relative", "/tmp/../", "/tmp/a/..", "/tmp//x", "/tmp/x/", "/tmp/./x"} {
		err := run(t.Context(), []string{"active", "--nuclei-home", h, "--creds", "/nonexistent/sensor.pem"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
		if err == nil || !strings.Contains(err.Error(), "-nuclei-home") {
			t.Errorf("-nuclei-home %q: %v", h, err)
		}
	}
	if err := validNucleiHome("/tmp/vedette-nuclei"); err != nil {
		t.Errorf("the default is refused: %v", err)
	}
}

// #723 review M2: the own-IP fence connects over IPv4 only, so a dual-stack host's services answer with its IPv4 address.
func TestEgressTransportDialsIPv4Only(t *testing.T) {
	t.Parallel()
	tr := egressTransport()
	v4, err := new(net.ListenConfig).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v4.Close() }()
	c, err := tr.DialContext(t.Context(), "tcp", v4.Addr().String())
	if err != nil {
		t.Fatalf("IPv4: %v", err)
	}
	_ = c.Close()
	v6, err := new(net.ListenConfig).Listen(t.Context(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine")
	}
	defer func() { _ = v6.Close() }()
	if c, err := tr.DialContext(t.Context(), "tcp", v6.Addr().String()); err == nil {
		_ = c.Close()
		t.Fatal("the fence's transport dialed an IPv6 address")
	}
}
