package main

import (
	"io"
	"net"
	"path"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// The gate between the unit text vedette-host writes for core (host/ops/quadlet.go, D-123 L3) and the real
// binary: the Exec= line must parse with the flag set of this very package, and the ports, key and
// honeypot paths it names must agree with the unit's own PublishPort= and Volume= lines.
func TestCoreUnitExecParsesWithTheRealFlagsAndAgreesWithItsMounts(t *testing.T) {
	t.Parallel()
	text, err := ops.RenderUnit("core", "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
	if err != nil {
		t.Fatal(err)
	}
	var execLine string
	var publish, volumes []string
	for _, l := range strings.Split(string(text), "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "Exec":
			execLine = v
		case "PublishPort":
			publish = append(publish, v)
		case "Volume":
			volumes = append(volumes, v)
		}
	}
	var o options
	flags, _ := newFlags(&o, io.Discard)
	if err := flags.Parse(strings.Fields(execLine)); err != nil || flags.NArg() != 0 {
		t.Fatalf("Exec=%q does not parse with the real flags: %v (extra args %v)", execLine, err, flags.Args())
	}
	if _, err := parseHosts(o.hosts); err != nil {
		t.Fatal(err)
	}
	if (o.tlsCert == "") != (o.tlsKey == "") {
		t.Fatal("-tls-cert and -tls-key go together")
	}
	// The listen address is TLS (not loopback) and its port is the container side of the first published port.
	loop, err := isLoopback(o.listen)
	if err != nil || loop {
		t.Fatalf("-listen %q must be a non-loopback address (TLS): %v", o.listen, err)
	}
	_, port, err := net.SplitHostPort(o.listen)
	if err != nil || len(publish) == 0 || !strings.HasSuffix(publish[0], ":"+port) {
		t.Fatalf("-listen port %q does not match PublishPort=%v", port, publish)
	}
	targets := map[string]string{} // container path -> option field of the Volume line
	for _, v := range volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 {
			targets[parts[1]] = v
		}
	}
	has := func(p string) bool { _, ok := targets[p]; return ok }
	if !has(o.key) {
		t.Errorf("-key %q is not a mount target of the unit: %v", o.key, volumes)
	}
	for _, sub := range []string{"config", "log"} {
		if !has(path.Join(o.honeypotDir, sub)) {
			t.Errorf("-honeypot-dir %q/%s is not a mount target of the unit: %v", o.honeypotDir, sub, volumes)
		}
	}
	if !has(path.Dir(o.hostSocket)) {
		t.Errorf("-host-socket %q has no mounted directory: %v", o.hostSocket, volumes)
	}
	if !has(path.Dir(o.db)) {
		t.Errorf("-db %q has no mounted directory: %v", o.db, volumes)
	}
	// The key may be mounted read-only; the database directory and the honeypot config may not.
	if !strings.HasSuffix(targets[o.key], ":ro") || strings.HasSuffix(targets[path.Dir(o.db)], ":ro") || strings.HasSuffix(targets[path.Join(o.honeypotDir, "config")], ":ro") {
		t.Errorf("mount modes: %v", targets)
	}
}
