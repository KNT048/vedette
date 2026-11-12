package main

import (
	"io"
	"net"
	"path"
	"slices"
	"strconv"
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
	// D-142 (H1): core reads the key it always read by default, in the directory vedette-host backs up and
	// restores: no -key flag in the unit, no separate key mount, and the key sits beside the database.
	if strings.Contains(execLine, "-key") || strings.Contains(string(text), "master.key") {
		t.Errorf("the unit names a key file: Exec=%q", execLine)
	}
	if path.Dir(o.key) != path.Dir(o.db) || path.Base(o.key) != "vedette.key" || path.Base(o.db) != "vedette.db" {
		t.Errorf("the key %q and the database %q must be <core_data>/vedette.key and vedette.db", o.key, o.db)
	}
	if !has(path.Dir(o.key)) {
		t.Errorf("-key %q is not under a mount target of the unit: %v", o.key, volumes)
	}
	// D-147: the sensor link. The unit gives core both sensor flags (without them core would not listen on 8444), the port is the container
	// side of the one published port that is bound to loopback only, and each role's credential folder is mounted at <creds>/<role> (never the
	// whole directory in one volume, so a sensor container sees only its own role's bundle).
	if o.sensorListen == "" || o.sensorCreds == "" || !path.IsAbs(o.sensorCreds) {
		t.Fatalf("Exec=%q must carry -sensor-listen and an absolute -sensor-creds", execLine)
	}
	_, sport, err := net.SplitHostPort(o.sensorListen)
	if err != nil {
		t.Fatalf("-sensor-listen %q: %v", o.sensorListen, err)
	}
	if !slices.Contains(publish, "127.0.0.1:"+sport+":"+sport) {
		t.Errorf("-sensor-listen port %q has no loopback-only PublishPort in %v", sport, publish)
	}
	for _, p := range publish {
		if strings.HasSuffix(p, ":"+sport) && !strings.HasPrefix(p, "127.0.0.1:") {
			t.Errorf("the sensor port is published beyond loopback: %q", p)
		}
	}
	// #266: the syslog listener. The box publishes 514 (udp and tcp) onto the unprivileged port the process binds (-syslog-port), so the
	// container needs no capability; both protocols are published for that same container port, on every address like 8443.
	if o.syslogPort < 1024 || o.syslogPort > 65535 {
		t.Errorf("-syslog-port %d must be an unprivileged port: the unit drops every capability", o.syslogPort)
	}
	for _, proto := range []string{"udp", "tcp"} {
		want := "514:" + strconv.Itoa(o.syslogPort) + "/" + proto
		if !slices.Contains(publish, want) {
			t.Errorf("-syslog-port %d has no PublishPort %q in %v", o.syslogPort, want, publish)
		}
	}
	// D-214: syslog over TLS listens on -syslog-port + 1, TCP only, published as 6514 (RFC 5425).
	if want := "6514:" + strconv.Itoa(o.syslogPort+1) + "/tcp"; !slices.Contains(publish, want) || slices.Contains(publish, "6514:"+strconv.Itoa(o.syslogPort+1)+"/udp") {
		t.Errorf("syslog over TLS must be published as exactly %q (tcp only), got %v", want, publish)
	}
	if strings.Contains(string(text), "AddCapability") || strings.Contains(string(text), "ip_unprivileged_port_start") {
		t.Errorf("core's unit needs no capability or sysctl for the syslog port:\n%s", text)
	}
	for _, role := range []string{"passive", "active"} {
		if v, ok := targets[path.Join(o.sensorCreds, role)]; !ok || !strings.HasPrefix(v, "vedette-creds-"+role+".volume:") || strings.HasSuffix(v, ":ro") {
			t.Errorf("the %s credential folder is not a read-write volume at %s/%s: %v", role, o.sensorCreds, role, volumes)
		}
	}
	if has(o.sensorCreds) {
		t.Errorf("the whole credential directory %q is one mount: %v", o.sensorCreds, volumes)
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
	// The data directory (database and key) and the honeypot config are not read-only.
	if strings.HasSuffix(targets[path.Dir(o.db)], ":ro") || strings.HasSuffix(targets[path.Join(o.honeypotDir, "config")], ":ro") {
		t.Errorf("mount modes: %v", targets)
	}
}
