package main

import (
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// The gate between the unit text vedette-host writes for scan and sensor (host/ops/quadlet.go, D-123 L3) and
// this binary: the subcommand is one the binary has, its flags parse with the real flag set, and the creds path
// it names is the container side of the unit's own read-only keys volume.
func unitLines(t *testing.T, svc string) (execLine string, volumes []string) {
	t.Helper()
	text, err := ops.RenderUnit(svc, "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(text), "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "Exec":
			execLine = v
		case "Volume":
			volumes = append(volumes, v)
		}
	}
	return execLine, volumes
}

func TestScanUnitExecParsesWithTheRealFlagsAndAgreesWithItsMount(t *testing.T) {
	t.Parallel()
	execLine, volumes := unitLines(t, "scan")
	args := strings.Fields(execLine)
	if len(args) == 0 || args[0] != "active" {
		t.Fatalf("Exec=%q: the scan unit runs the active subcommand", execLine)
	}
	fs, f := newActiveFlags(io.Discard)
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		t.Fatalf("Exec=%q does not parse with the real flags: %v %v", execLine, err, fs.Args())
	}
	if !strings.HasPrefix(*f.core, "https://127.0.0.1:8444") {
		t.Errorf("-core %q: core's sensor listener is published on 127.0.0.1:8444 only", *f.core)
	}
	if len(volumes) != 1 || !strings.HasSuffix(volumes[0], ":ro") || !strings.HasPrefix(*f.creds, strings.Split(volumes[0], ":")[1]+"/") {
		t.Errorf("-creds %q is not under the read-only keys volume %v", *f.creds, volumes)
	}
	if *f.nmap != "/usr/bin/nmap" {
		t.Errorf("-nmap %q: the unit leaves the OS package's path alone", *f.nmap)
	}
}

// The sensor unit runs `passive`: its Exec= parses with the real flags, -creds is under the unit's read-only keys volume, and
// -core is the address core's own unit publishes (127.0.0.1:8444 only).
func TestSensorUnitExecParsesWithTheRealFlagsAndAgreesWithItsMountAndCore(t *testing.T) {
	t.Parallel()
	execLine, volumes := unitLines(t, "sensor")
	args := strings.Fields(execLine)
	if len(args) == 0 || args[0] != "passive" {
		t.Fatalf("Exec=%q: the sensor unit runs the passive subcommand", execLine)
	}
	fs, f := newPassiveFlags(io.Discard)
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		t.Fatalf("Exec=%q does not parse with the real flags: %v %v", execLine, err, fs.Args())
	}
	if len(volumes) != 1 || !strings.HasSuffix(volumes[0], ":ro") || !strings.HasPrefix(*f.creds, strings.Split(volumes[0], ":")[1]+"/") {
		t.Errorf("-creds %q is not under the read-only keys volume %v", *f.creds, volumes)
	}
	u, err := url.Parse(*f.core)
	if err != nil || u.Scheme != "https" {
		t.Fatalf("-core %q is not an https address: %v", *f.core, err)
	}
	coreText, err := ops.RenderUnit("core", "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
	if err != nil {
		t.Fatal(err)
	}
	published := false
	for _, l := range strings.Split(string(coreText), "\n") {
		if v, ok := strings.CutPrefix(l, "PublishPort="); ok && v == u.Host+":"+u.Port() { // host:hostport:containerport on the same address and port
			published = true
		}
	}
	if !published {
		t.Errorf("-core %q is not a port the core unit publishes", *f.core)
	}
}
