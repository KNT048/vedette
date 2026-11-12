package host_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

// Units between host releases (UNIT-4, D-316 (9)): a unit that an earlier release of the host wrote from an earlier template is still
// the host's own, and is rewritten to the current template before READY without restarting anything; a unit a person edited stays
// refused; nothing moves while a self-update is not committed. Credential volumes made for other ids are refused, never re-owned.

// writeLegacy puts the unit an earlier release wrote for svc (the n-th earlier template, from 0) in place, as that host left it.
func (e *ctrEnv) writeLegacy(t *testing.T, svc, digest string, n int, install bool) string {
	t.Helper()
	cfg := e.m.Config()
	l, err := ops.RenderLegacyUnits(svc, digest, install, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil || len(l) <= n {
		t.Fatalf("no legacy template %d of %s: %v", n, svc, err)
	}
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-"+svc+".container"), l[n], 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	return string(l[n])
}

func TestContract_UnitMigration_StartRewritesAnEarlierTemplateBeforeReadyWithoutARestart(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldCore := e.writeLegacy(t, api.ServiceCore, digA, 0, true)    // D-318: no 6514, no HostName
	oldHp := e.writeLegacy(t, api.ServiceHoneypot, digB, 0, false) // before ContainersConfModule, stopped with persist
	e.m.InstallUnit(api.ServiceSensor, digA, true)                 // already current
	e.m.SetRunning(api.ServiceCore, true)
	e.m.Mark("host-starting", true)
	// Before the start the host already reads them as its own (state, retention, every command).
	st := e.state(t)
	if !st[api.ServiceCore].Installed || !st[api.ServiceHoneypot].Installed || st[api.ServiceHoneypot].Enabled {
		t.Fatalf("legacy units are not read as the host's: %+v", st)
	}
	rec := e.startHost(t)

	if got, want := e.unit(t, api.ServiceCore), e.render(t, api.ServiceCore, digA, true); got != want || !strings.Contains(got, "\nPublishPort=6514:5515/tcp\n") {
		t.Fatalf("core was not moved to the current template:\n%s", got)
	}
	if got := e.unit(t, api.ServiceHoneypot); got != e.render(t, api.ServiceHoneypot, digB, false) {
		t.Fatalf("honeypot was not moved to the current template, [Install] state kept:\n%s", got)
	}
	if p, err := e.m.Prev(api.ServiceCore); err != nil || p != oldCore {
		t.Errorf("core's old bytes are not kept in .prev: %v", err)
	}
	if p, err := e.m.Prev(api.ServiceHoneypot); err != nil || p != oldHp {
		t.Errorf("honeypot's old bytes are not kept in .prev: %v", err)
	}
	if _, err := e.m.Prev(api.ServiceSensor); err == nil {
		t.Error("a current unit was rewritten")
	}
	// The volume units core mounts are written with it (a unit that names a missing .volume would not be generated).
	for _, name := range []string{"vedette-creds-passive.volume", "vedette-creds-active.volume", "vedette-hp-log.volume"} {
		if _, err := os.Stat(filepath.Join(e.m.UnitsDir(), name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// One reload, before READY; no restart, no stop, no look at a container: the new text takes effect at the next restart.
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("systemctl calls %v, want one daemon-reload", got)
	}
	for _, c := range e.m.Calls("podman") {
		if c[0] != "container" || c[1] != "inspect" { // checkCoreAtStart looks at core; nothing else may run
			t.Errorf("the host ran podman %v", c)
		}
	}
	if !e.m.IsRunning(api.ServiceCore) {
		t.Error("core was stopped")
	}
	txt := rec.text()
	for _, svc := range []string{api.ServiceCore, api.ServiceHoneypot} {
		if !strings.Contains(txt, `container.start unit_migrated {"digest":`) || !strings.Contains(txt, `"service":"`+svc+`"`) {
			t.Errorf("no unit_migrated line for %s: %s", svc, txt)
		}
	}
	if strings.Contains(txt, `"service":"sensor"`) {
		t.Errorf("a current unit was audited as migrated: %s", txt)
	}
	// A second start finds nothing to do.
	e.startHost(t)
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("a second start reloaded again: %v", got)
	}
}

func TestContract_UnitMigration_AHandEditedUnitIsNeitherMigratedNorObeyed(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	old := e.writeLegacy(t, api.ServiceCore, digA, 1, true)
	edited := strings.Replace(old, "--cpus=2", "--cpus=4", 1)
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-core.container"), []byte(edited), 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	e.startHost(t)
	if e.unit(t, api.ServiceCore) != edited || len(e.ctl()) != 0 {
		t.Fatalf("an edited unit was touched: %v", e.ctl())
	}
	if e.state(t)[api.ServiceCore].Installed {
		t.Error("an edited unit is reported as installed")
	}
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceCore, Restart: true}, 412, api.CodeUnitUnsafe)
}

// D-316 (6b): the new host is not committed while the self-update journal is there, and the previous host, if it is put back,
// must find the units it wrote. The migration waits for a start without the journal (or the next command that writes the unit).
func TestContract_UnitMigration_NothingMovesWhileASelfUpdateIsNotCommitted(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	old := e.writeLegacy(t, api.ServiceHoneypot, digA, 0, true)
	if err := os.WriteFile(filepath.Join(e.m.State, "selfupdate", "journal.json"), []byte(`{"phase":"installing"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := e.startHost(t)
	if e.unit(t, api.ServiceHoneypot) != old || slices.Contains(e.ctl(), "daemon-reload") || strings.Contains(rec.text(), "unit_migrated") {
		t.Fatalf("a unit moved during a self-update: %v %s", e.ctl(), rec.text())
	}
	if !e.state(t)[api.ServiceHoneypot].Installed {
		t.Error("the legacy unit is not the host's while it waits")
	}
}

// The next container.start of a running, healthy service writes the current template and reloads, and leaves the container alone
// (as for a missing [Install]); a restart asked for applies it.
func TestContract_UnitMigration_AStartOfARunningServiceWritesTheCurrentTemplateWithoutARestart(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.writeLegacy(t, api.ServiceHoneypot, digA, 0, true)
	e.m.SetRunning(api.ServiceHoneypot, true)
	r := e.start(t, api.ServiceHoneypot, false)
	if res := result[api.ContainerStartResult](t, r); r.Status != api.StatusSucceeded || res.Restarted {
		t.Fatalf("%+v %+v", r, res)
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("%v", got)
	}
	if e.unit(t, api.ServiceHoneypot) != e.render(t, api.ServiceHoneypot, digA, true) {
		t.Fatal("the start did not write the current template")
	}
}

// L5 of SP-6: Quadlet sets the owner of a volume only when it makes it, so a credential volume unit the host wrote for other ids
// than host.conf gives now is refused at Check (no run, nothing written), and is not rewritten even by -bootstrap -force-units.
func TestContract_Container_ACredentialVolumeMadeForOtherIdsIsRefusedNotReowned(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	cfg := e.m.Config()
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	vol, err := ops.RenderVolume("passive", cfg.CoreUID+1, cfg.SensorGID)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.m.UnitsDir(), "vedette-creds-passive.volume")
	if err := os.WriteFile(p, vol, 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	ce := e.refusedWith(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceSensor, Restart: true}, 412, api.CodeUnitUnsafe)
	if !strings.Contains(ce.Message, "RUNBOOK") {
		t.Errorf("the refusal does not say what to do: %s", ce.Message)
	}
	if b, _ := os.ReadFile(p); string(b) != string(vol) || len(e.ctl()) != 0 { //nolint:gosec // test: a path under the fake root
		t.Fatalf("the volume unit was rewritten or systemd called: %v", e.ctl())
	}
	// The honeypot mounts no credential volume: it is not held up.
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	if r := e.start(t, api.ServiceHoneypot, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	// A hand-edited volume unit is not this refusal: the start writes the host's text over it, as before.
	if err := os.WriteFile(p, []byte("[Volume]\nVolumeName=vedette-creds-passive\n"), 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	if r := e.start(t, api.ServiceSensor, true); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if want, _ := ops.RenderVolume("passive", cfg.CoreUID, cfg.SensorGID); func() string { b, _ := os.ReadFile(p); return string(b) }() != string(want) { //nolint:gosec // test path
		t.Error("the edited volume unit was not rewritten")
	}
}

func TestContract_Bootstrap_ACredentialVolumeMadeForOtherIdsIsRefusedEvenWithForceUnits(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	cfg := e.m.Config()
	vol, err := ops.RenderVolume("active", cfg.CoreUID, cfg.SensorGID+1)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.m.UnitsDir(), "vedette-creds-active.volume")
	if err := os.WriteFile(p, vol, 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	a := e.bsDocs(t, 5, v1, bsDigest)
	a.Services = []string{api.ServiceHoneypot, api.ServiceCore}
	a.ForceUnits = true
	_, err = e.bootstrap(a)
	if code, msg := ops.BootstrapCode(err); code != api.CodeUnitUnsafe || !strings.Contains(msg, "vedette-creds-active.volume") {
		t.Fatalf("%v", err)
	}
	e.bsNothingButScan(t, "volume for other ids")
	if w := e.writes(); len(w) != 0 {
		t.Errorf("podman wrote before the refusal: %v", w)
	}
	if b, _ := os.ReadFile(p); string(b) != string(vol) { //nolint:gosec // test: a path under the fake root
		t.Error("the volume unit was rewritten")
	}
}

// L4 of SP-6: a scan image built on the box that has no name any more (its tag moved to a newer build of the same version, or a
// failed build could not be removed) is removed by its ID once no unit, record or container keeps it; one a record keeps stays,
// and one a container uses stays.
func TestContract_Retention_RemovesANamelessScanBuildNothingKeeps(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.pull(t, e.scanArgs(t, v1))
	id1, id2 := "sha256:"+opstest.BuiltID(1), "sha256:"+opstest.BuiltID(2)
	orphan, used := opstest.BuiltID(90), opstest.BuiltID(91)
	e.m.InstallUnit(api.ServiceScan, id1, true)
	e.m.SetRunning(api.ServiceScan, true)
	e.ok(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v1))
	e.m.PresentBuilt(orphan, "") // no name: what a rebuild of the same version leaves
	e.m.PresentBuilt(used, "")
	e.m.MarkImageUsed("sha256:" + used)
	e.pull(t, e.scanArgs(t, v2))
	if r := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v2))); r.Digest != id2 {
		t.Fatalf("%+v", r)
	}
	removed := e.m.ImageRemoved()
	if !slices.Contains(removed, "sha256:"+orphan) {
		t.Errorf("the nameless build nothing keeps was not removed: %v", removed)
	}
	for _, d := range []string{id1, id2, "sha256:" + used, scanBase} {
		if slices.Contains(removed, d) {
			t.Errorf("retention removed %s: %v", d, removed)
		}
	}
	if !e.m.ImagePresent(id1) { // versions.previous keeps it
		t.Fatal("the previous build is gone")
	}
}
