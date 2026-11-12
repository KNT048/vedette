package host_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

// A unit change that adds a host port (D-455). An update in place does not run install.sh, so before it restarts a service on a
// unit that publishes a port the earlier unit did not, the host looks at who listens there and refuses (412 port_in_use) with the
// running release untouched. A change that would only take effect at a later restart (the migration at start, a start without
// restart of a running service) never adds a port. The fake /proc of the machine has a socket table and the process that holds
// the socket.

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
func legacyCore3(t *testing.T, m *opstest.Machine, digest string, install bool) string {
	t.Helper()
	cfg := m.Config()
	l, err := ops.RenderLegacyUnits(api.ServiceCore, digest, install, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil || len(l) < 3 || strings.Contains(string(l[2]), ":8765") {
		t.Fatalf("no core-3 template without 8765: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.UnitsDir(), "vedette-core.container"), l[2], 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	return string(l[2])
}

func TestContract_PortInUse_ARestartThatAddsABusyPortIsRefusedAndAStartWithoutRestartKeepsTheUnit(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	old := legacyCore3(t, e.m, digA, true)
	e.m.SetRunning(api.ServiceCore, true)
	holdPort8765(t, e.m, pinUserCg)
	rec := e.startHost(t)
	ce := e.refusedWith(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceCore, Restart: true}, 412, api.CodePortInUse)
	if !strings.Contains(ce.Message, "8765/tcp (python3, pid 4242)") || !strings.Contains(ce.Message, "Nothing was changed.") {
		t.Errorf("the refusal does not name the port and the program: %s", ce.Message)
	}
	if e.unit(t, api.ServiceCore) != old || len(e.ctl()) != 0 || !e.m.IsRunning(api.ServiceCore) || e.journalExists(api.ServiceCore) {
		t.Fatalf("the refused start changed something: %v", e.ctl())
	}
	// Without restart a running, healthy core is left alone and so is its unit: the change waits for a restart (audited), no 412.
	r := e.start(t, api.ServiceCore, false)
	if res := result[api.ContainerStartResult](t, r); r.Status != api.StatusSucceeded || res.Restarted {
		t.Fatalf("%+v %+v", r, res)
	}
	if e.unit(t, api.ServiceCore) != old || len(e.ctl()) != 0 {
		t.Fatalf("a start without restart moved the unit: %v", e.ctl())
	}
	if n := strings.Count(rec.text(), `container.start unit_migration_deferred {"digest":"`+digA+`","ports":["8765/tcp"],"run_id":"`); n != 1 {
		t.Fatalf("%d deferral lines of the start, want 1: %s", n, rec.text())
	}
	// The port held by core's own container (a container of the unit runs in a sub-cgroup of it) is not a conflict.
	holdPort8765(t, e.m, pinCoreCg)
	if r := e.start(t, api.ServiceCore, true); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if e.unit(t, api.ServiceCore) != e.render(t, api.ServiceCore, digA, true) {
		t.Fatal("the restart did not write the current template")
	}
	// The unit publishes 8765 now and core runs: the port is no longer new, a program on it does not block a restart.
	holdPort8765(t, e.m, pinUserCg)
	if r := e.start(t, api.ServiceCore, true); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
}

// A start without restart that puts [Install] back on a unit of an earlier template keeps that template.
func TestContract_PortInUse_PuttingInstallBackKeepsTheEarlierTemplate(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	legacyCore3(t, e.m, digA, false)
	e.m.SetRunning(api.ServiceCore, true)
	if r := e.start(t, api.ServiceCore, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	cfg := e.m.Config()
	l, err := ops.RenderLegacyUnits(api.ServiceCore, digA, true, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil || e.unit(t, api.ServiceCore) != string(l[2]) {
		t.Fatalf("the unit is not core-3 with [Install]:\n%s", e.unit(t, api.ServiceCore))
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("%v", got)
	}
}

// container.stop persist drops [Install] from the unit's own template; it never moves the unit to the current one.
func TestContract_PortInUse_AStopWithPersistKeepsTheEarlierTemplate(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.writeLegacy(t, api.ServiceHoneypot, digA, 0, true)
	e.m.SetRunning(api.ServiceHoneypot, true)
	if r := e.stop(t, api.ServiceHoneypot, true); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	cfg := e.m.Config()
	l, err := ops.RenderLegacyUnits(api.ServiceHoneypot, digA, false, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil || e.unit(t, api.ServiceHoneypot) != string(l[0]) {
		t.Fatalf("the unit is not honeypot-1 without [Install]:\n%s", e.unit(t, api.ServiceHoneypot))
	}
}

// A stopped service holds no port: a start looks at every port of its unit, not only the new ones, and refuses before the restart.
func TestContract_PortInUse_AStoppedServiceIsCheckedOnEveryPort(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceCore, digA, true) // the current template: 8765 is not new
	holdPort8765(t, e.m, pinUserCg)
	for _, restart := range []bool{false, true} {
		r := e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceCore, Restart: restart}, api.StatusRefused, api.CodePortInUse)
		if !strings.Contains(r.Error.Message, "8765/tcp (python3, pid 4242)") {
			t.Errorf("%s", r.Error.Message)
		}
	}
	if len(e.ctl()) != 0 || e.journalExists(api.ServiceCore) {
		t.Fatalf("the refused start changed something: %v", e.ctl())
	}
	e.m.RemoveRoot("proc/net/tcp")
	if r := e.start(t, api.ServiceCore, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
}

// The update in place of the finding: core runs 1.0.0 on a unit of an earlier host release, a program holds 8765, the switch to
// 2.0.0 is refused at Check: no backup, no unit write, no restart, 1.0.0 stays. Once the port is free the same switch goes through.
func TestContract_PortInUse_ACoreSwitchIsRefusedAndTheRunningReleaseStays(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	old := legacyCore3(t, e.m, d1, true)
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
	legacyCore3(t, e.m, d2, true)
	holdPort8765(t, e.m, pinUserCg)
	e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodePortInUse)
	if v, _ := e.versions(t, "core"); v != v2 {
		t.Fatalf("version %q after a refused rollback", v)
	}
}

// The port is taken while the pre_update backup runs (it can take minutes): the switch checks once more right before the unit write
// and is refused there. The hook is the existing journal seam: the journal write that records the backup id is the one step between
// the backup and the unit write, and it makes 8765 busy (a table written aside beforehand is moved in place, so the hook, which runs
// on the run's goroutine, needs no testing.T). The journal is dropped, the backup kept, the unit and the version unchanged.
func TestContract_PortInUse_APortTakenDuringTheBackupRefusesTheSwitchBeforeTheUnitWrite(t *testing.T) {
	t.Parallel()
	var (
		armed   atomic.Bool
		pending atomic.Int32
		busy    atomic.Bool
		from    atomic.Pointer[string] // the prepared table, and where it goes
		to      atomic.Pointer[string]
	)
	e := startUpd(t, func(_ *ops.Config, d *ops.Deps) {
		d.JournalFault = func(svc, phase string) error {
			if armed.Load() && svc == api.ServiceCore && phase == "pending" && pending.Add(1) == 2 { // 1: before the backup, 2: after it
				busy.Store(os.Rename(*from.Load(), *to.Load()) == nil)
			}
			return nil
		}
	})
	e.adopt(t, "core", rel1(d1, d1))
	old := legacyCore3(t, e.m, d1, true)
	e.pullRel(t, "core", rel2(d2, d2))
	holdPort8765(t, e.m, pinUserCg) // the process and its socket; the table is moved aside until the hook puts it back
	table := filepath.Join(e.m.Root, "proc", "net", "tcp")
	aside := filepath.Join(e.m.Root, "proc", "tcp.aside")
	if err := os.Rename(table, aside); err != nil {
		t.Fatal(err)
	}
	from.Store(&aside)
	to.Store(&table)
	e.forget()
	armed.Store(true)
	r := e.final(t, api.CmdContainerStart, e.startArgs("core", v2), api.StatusRefused, api.CodePortInUse)
	armed.Store(false)
	if !busy.Load() || !strings.Contains(r.Error.Message, "8765/tcp (python3, pid 4242)") {
		t.Fatalf("the hook did not run between the backup and the unit write (%t): %+v", busy.Load(), r.Error)
	}
	if e.journal("core") {
		t.Error("the journal stayed")
	}
	if bk, err := e.h.Client.StateBackups(context.Background()); err != nil || len(bk.Backups) != 1 || bk.Backups[0].Kind != "pre_update" {
		t.Errorf("the pre_update backup is not kept: %+v %v", bk, err)
	}
	if e.unit(t, "core") != old || e.restarts("core") != 0 || slices.Contains(e.ctl(), "daemon-reload") {
		t.Fatalf("the unit changed or core was restarted: %v", e.ctl())
	}
	if v, _ := e.versions(t, "core"); v != v1 {
		t.Fatalf("version %q", v)
	}
}

// The unit migration at start (D-316 (10)) never adds a host port (it runs at boot, before other programs bind theirs): core's
// earlier unit stays, busy port or not, with one unit_migration_deferred line per start; the restart of a container.start moves it.
func TestContract_PortInUse_TheMigrationAtStartNeverAddsAPort(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	old := legacyCore3(t, e.m, digA, true)
	e.m.SetRunning(api.ServiceCore, true)
	for range 2 {
		rec := e.startHost(t)
		if e.unit(t, api.ServiceCore) != old || slices.Contains(e.ctl(), "daemon-reload") {
			t.Fatalf("the migration added a port: %v", e.ctl())
		}
		txt := rec.text()
		if strings.Count(txt, "unit_migration_deferred") != 1 || !strings.Contains(txt, `"ports":["8765/tcp"]`) || strings.Contains(txt, "unit_migrated") {
			t.Fatalf("audit: %s", txt)
		}
	}
	if !e.state(t)[api.ServiceCore].Installed {
		t.Error("the kept unit is not the host's")
	}
	if r := e.start(t, api.ServiceCore, true); r.Status != api.StatusSucceeded || e.unit(t, api.ServiceCore) != e.render(t, api.ServiceCore, digA, true) {
		t.Fatalf("the restart did not move the unit: %+v", r)
	}
}
