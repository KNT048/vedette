package host_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

// A unit change that adds a host port another program listens on (D-455): an update in place does not run install.sh, so the host
// refuses the change (412 port_in_use) before it touches the running release, and the unit migration at start keeps the earlier
// unit. The fake /proc of the machine has a socket table and the process that holds the socket.

const (
	pinTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	// 127.0.0.1:8765 in LISTEN, inode 41, as a little-endian kernel prints it.
	pinRow8765 = "   0: 0100007F:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41 1 0000000000000000 100 0 0 10 0\n"
	pinUserCg  = "0::/user.slice/user-1000.slice/session-3.scope\n"
	pinCoreCg  = "0::/system.slice/vedette-core.service/libpod-payload-0123abcd\n"
)

// holdPort8765 makes pid 4242 (python3, in cgroup cg) listen on 127.0.0.1:8765.
func holdPort8765(t *testing.T, m *opstest.Machine, cg string) {
	t.Helper()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the /proc/net fixture is little-endian")
	}
	m.WriteRoot("proc/net/tcp", pinTCPHeader+pinRow8765)
	m.WriteRoot("proc/4242/comm", "python3\n")
	m.WriteRoot("proc/4242/cgroup", cg)
	fd := filepath.Join(m.Root, "proc", "4242", "fd")
	if err := os.MkdirAll(fd, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(fd, "3")
	_ = os.Remove(link)
	if err := os.Symlink("socket:[41]", link); err != nil {
		t.Fatal(err)
	}
}

// legacyCore3 is core's unit as host releases before D-395 wrote it (core-3: no 127.0.0.1:8765).
func legacyCore3(t *testing.T, m *opstest.Machine, digest string) string {
	t.Helper()
	cfg := m.Config()
	l, err := ops.RenderLegacyUnits(api.ServiceCore, digest, true, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil || len(l) < 3 || strings.Contains(string(l[2]), ":8765") {
		t.Fatalf("no core-3 template without 8765: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.UnitsDir(), "vedette-core.container"), l[2], 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	return string(l[2])
}

func TestContract_PortInUse_AStartThatAddsABusyPortIsRefusedBeforeAnythingChanges(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	old := legacyCore3(t, e.m, digA)
	e.m.SetRunning(api.ServiceCore, true)
	holdPort8765(t, e.m, pinUserCg)
	for _, restart := range []bool{true, false} { // a restart, and the start that only writes the current template
		ce := e.refusedWith(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceCore, Restart: restart}, 412, api.CodePortInUse)
		if !strings.Contains(ce.Message, "8765/tcp (python3, pid 4242)") || !strings.Contains(ce.Message, "Nothing was changed.") {
			t.Errorf("the refusal does not name the port and the program: %s", ce.Message)
		}
	}
	if e.unit(t, api.ServiceCore) != old || len(e.ctl()) != 0 || !e.m.IsRunning(api.ServiceCore) || e.journalExists(api.ServiceCore) {
		t.Fatalf("the refused start changed something: %v", e.ctl())
	}
	// The port held by core's own container (a container of the unit runs in a sub-cgroup of it) is not a conflict.
	holdPort8765(t, e.m, pinCoreCg)
	if r := e.start(t, api.ServiceCore, true); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if e.unit(t, api.ServiceCore) != e.render(t, api.ServiceCore, digA, true) {
		t.Fatal("the start did not write the current template")
	}
	// The unit publishes 8765 now: a program on it no longer blocks a restart (the port is not new; the running container holds it).
	holdPort8765(t, e.m, pinUserCg)
	if r := e.start(t, api.ServiceCore, true); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
}

// The update in place of the finding: core runs 1.0.0 on a unit of an earlier host release, a program holds 8765, the switch to
// 2.0.0 is refused at Check: no backup, no unit write, no restart, 1.0.0 stays. Once the port is free the same switch goes through.
func TestContract_PortInUse_ACoreSwitchIsRefusedAndTheRunningReleaseStays(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	old := legacyCore3(t, e.m, d1)
	e.pullRel(t, "core", rel2(d2, d2))
	holdPort8765(t, e.m, pinUserCg)
	e.forget()
	ce := e.refusedWith(t, api.CmdContainerStart, e.startArgs("core", v2), 412, api.CodePortInUse)
	if !strings.Contains(ce.Message, "8765/tcp (python3, pid 4242)") {
		t.Errorf("%s", ce.Message)
	}
	if e.unit(t, "core") != old || len(e.ctl()) != 0 || e.journal("core") {
		t.Fatalf("the refused switch changed the unit or called systemd: %v", e.ctl())
	}
	if bk, err := e.h.Client.StateBackups(context.Background()); err != nil || len(bk.Backups) != 0 {
		t.Fatalf("a backup was made: %+v %v", bk, err)
	}
	if v, _ := e.versions(t, "core"); v != v1 {
		t.Fatalf("version %q", v)
	}
	e.m.RemoveRoot("proc/net/tcp")
	if r := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("core", v2))); r.Digest != d2 || !r.Healthy {
		t.Fatalf("%+v", r)
	}
	if e.unit(t, "core") != e.render(t, "core", d2) {
		t.Fatal("the switch did not write the current template")
	}
	// container.rollback writes the current template too: from a unit of an earlier release it is refused the same way.
	legacyCore3(t, e.m, d2)
	holdPort8765(t, e.m, pinUserCg)
	e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodePortInUse)
	if v, _ := e.versions(t, "core"); v != v2 {
		t.Fatalf("version %q after a refused rollback", v)
	}
}

// The unit migration at start (D-316 (10)) does not write a unit whose new port is busy: the earlier unit stays, one
// unit_migration_deferred line names the port, and the next start, with the port free, migrates.
func TestContract_PortInUse_TheMigrationAtStartWaitsForTheNewPort(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	old := legacyCore3(t, e.m, digA)
	e.m.SetRunning(api.ServiceCore, true)
	holdPort8765(t, e.m, pinUserCg)
	rec := e.startHost(t)
	if e.unit(t, api.ServiceCore) != old || slices.Contains(e.ctl(), "daemon-reload") {
		t.Fatalf("the unit was migrated onto a busy port: %v", e.ctl())
	}
	txt := rec.text()
	if !strings.Contains(txt, "container.start unit_migration_deferred") || !strings.Contains(txt, `"ports":["8765/tcp (python3, pid 4242)"]`) ||
		strings.Contains(txt, "unit_migrated") || strings.Contains(txt, "unit_migration_failed") {
		t.Fatalf("audit: %s", txt)
	}
	if !e.state(t)[api.ServiceCore].Installed {
		t.Error("the kept unit is not the host's")
	}
	e.m.RemoveRoot("proc/net/tcp")
	rec = e.startHost(t)
	if e.unit(t, api.ServiceCore) != e.render(t, api.ServiceCore, digA, true) || !strings.Contains(rec.text(), "unit_migrated") {
		t.Fatalf("the next start did not migrate: %s", rec.text())
	}
}
