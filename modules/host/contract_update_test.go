package host_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/internal/release"
)

// container.start with a version, container.rollback and image retention (WP-07b part 3, slice 3-8a; spec
// 6.8, 6.10, D-104, D-105, D-138; host CONTRACT INV-20, INV-21). The machine is the fake of opstest with a
// stateful systemctl and one stateful podman that holds both containers and images (StatefulPodman), and
// signing keys made for the test. A release is pulled with container.pull (the real path), then started.

const (
	v1 = "1.0.0"
	v2 = "2.0.0"
	v3 = "3.0.0"
)

var (
	d0 = opstest.Digest('0')
	d1 = opstest.Digest('1')
	d2 = opstest.Digest('2')
	d3 = opstest.Digest('3')
	d4 = opstest.Digest('4')
)

// relSpec is one release: its version, the digest of its core and sensor images, and the rules of its manifest.
type relSpec struct {
	version      string
	core, sensor string
	unsafe       bool   // rollback.safe=false
	minRollback  string // rollback.min_version
	minUpgrade   string // min_upgrade_from
}

type updEnv struct {
	*pullEnv
	sleeps *sleepLog
	seq    uint64
	muts   []mut
}

func startUpd(t *testing.T, muts ...mut) *updEnv {
	t.Helper()
	rel := opstest.NewRelease(t)
	pe := &pullEnv{rel: rel}
	pe.keys.Store(&rel.Trust)
	sl := &sleepLog{}
	base := func(_ *ops.Config, d *ops.Deps) {
		d.Keys = func() (release.Trust, error) { return *pe.keys.Load(), nil }
		d.Sleep = sl.sleep
	}
	all := append([]mut{base}, muts...)
	e := startSys(t, all...)
	e.m.StatefulContainers()
	e.m.StatefulPodman()
	e.m.MakeUnitsDir()
	pe.sysEnv = e
	pe.startAudit(t) // the audit notes of the host's own doings need the notifier Start installs
	return &updEnv{pullEnv: pe, sleeps: sl, seq: 4, muts: all}
}

func (e *updEnv) docsFor(seq uint64, r relSpec) (idx, man opstest.Doc) {
	man = e.rel.ManifestDoc(r.version, opstest.Img{Service: api.ServiceCore, Digest: r.core, Size: 1000}, opstest.Img{Service: api.ServiceSensor, Digest: r.sensor, Size: 2000})
	man["rollback"] = opstest.Doc{"safe": !r.unsafe, "min_version": r.minRollback}
	man["min_upgrade_from"] = r.minUpgrade
	return e.rel.IndexDoc(seq), man
}

// pullRel pulls the release for a service with the next index sequence.
func (e *updEnv) pullRel(t *testing.T, svc string, r relSpec) {
	t.Helper()
	e.seq++
	idx, man := e.docsFor(e.seq, r)
	e.pull(t, e.argsFor(t, svc, r.version, idx, man))
}

// pullWith pulls with an index the test shaped (revocations).
func (e *updEnv) pullWith(t *testing.T, svc string, r relSpec, shape func(idx opstest.Doc)) {
	t.Helper()
	e.seq++
	idx, man := e.docsFor(e.seq, r)
	shape(idx)
	e.pull(t, e.argsFor(t, svc, r.version, idx, man))
}

func (e *updEnv) digestOf(r relSpec, svc string) string {
	if svc == api.ServiceCore {
		return r.core
	}
	return r.sensor
}

// adopt makes svc run release r: the unit and the container exist (as the bootstrap leaves them), the
// release is pulled, and a start with its version tells the host which version runs.
func (e *updEnv) adopt(t *testing.T, svc string, r relSpec) {
	t.Helper()
	dg := e.digestOf(r, svc)
	e.m.InstallUnit(svc, dg, true)
	e.m.SetRunning(svc, true)
	e.m.PresentImage(svc, dg, r.version)
	e.pullRel(t, svc, r)
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs(svc, r.version)))
	if res.Restarted || res.Version == nil || *res.Version != r.version {
		t.Fatalf("adopt: %+v", res)
	}
}

func (e *updEnv) startArgs(svc, version string) api.ContainerStartArgs {
	a := api.ContainerStartArgs{Service: svc, Version: version}
	if svc == api.ServiceCore {
		a.Snapshot = e.snap()
	}
	return a
}

func (e *updEnv) unit(t *testing.T, svc string) string {
	t.Helper()
	u, err := e.m.Unit(svc)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *updEnv) render(t *testing.T, svc, digest string) string {
	t.Helper()
	cfg := e.m.Config()
	b, err := ops.RenderUnitIn(svc, digest, true, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ctl lists the systemctl calls that are not is-active looks, as "verb unit".
func (e *updEnv) ctl() []string {
	var out []string
	for _, c := range e.m.Calls("systemctl") {
		if c[0] != "is-active" {
			out = append(out, strings.TrimSpace(strings.Join(c, " ")))
		}
	}
	return out
}

func (e *updEnv) restarts(svc string) int {
	n := 0
	for _, c := range e.ctl() {
		if c == "restart vedette-"+svc+".service" {
			n++
		}
	}
	return n
}

// writes lists the podman calls that change something (pull, tag, rmi).
func (e *updEnv) writes() []string {
	var out []string
	for _, c := range e.podman() {
		if slices.Contains([]string{"pull", "tag", "rmi"}, c[0]) {
			out = append(out, strings.Join(c, " "))
		}
	}
	return out
}

func (e *updEnv) journal(svc string) bool {
	_, err := os.Lstat(e.m.TransitionPath(svc))
	return err == nil
}

func (e *updEnv) versions(t *testing.T, svc string) (version string, prev string) {
	t.Helper()
	st := e.state(t)[svc]
	if st.Version != nil {
		version = *st.Version
	}
	if st.Previous != nil && st.Previous.Version != nil {
		prev = *st.Previous.Version
	}
	return version, prev
}

// forget drops the calls recorded so far, so that what a test asserts is only what the command under test did.
func (e *updEnv) forget() {
	for _, b := range []string{"podman", "systemctl"} {
		_ = os.Remove(filepath.Join(e.m.Rec, b+".calls"))
	}
}

// untouched asserts that nothing was written: no systemctl change, no podman pull/tag/rmi, the unit as it was, no journal.
func (e *updEnv) untouched(t *testing.T, what, svc, unitBefore string) {
	t.Helper()
	if c := e.ctl(); len(c) != 0 {
		t.Fatalf("%s: systemctl changed something: %v", what, c)
	}
	if w := e.writes(); len(w) != 0 {
		t.Fatalf("%s: podman wrote: %v", what, w)
	}
	if e.unit(t, svc) != unitBefore || e.journal(svc) {
		t.Fatalf("%s: the unit or its journal changed", what)
	}
}

func (e *updEnv) rollback(t *testing.T, svc string) api.Run {
	t.Helper()
	return e.ok(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: svc})
}

// idOf is the image ID the fake podman shows for an image of that digest (the hex of the digest); retention
// removes by this ID, not by the digest (D-138 M3).
func idOf(digest string) string { return strings.TrimPrefix(digest, "sha256:") }

func rel1(core, sensor string) relSpec { return relSpec{version: v1, core: core, sensor: sensor} }
func rel2(core, sensor string) relSpec { return relSpec{version: v2, core: core, sensor: sensor} }

// --- container.start with a version: every refusal is decided in Check, with no write ---------------

func TestContract_Update_StartRefusalsAreAllDecidedInCheckWithNoWrite(t *testing.T) {
	t.Parallel()
	type tc struct {
		name   string
		svc    string
		status int
		code   string
		setup  func(t *testing.T, e *updEnv) api.ContainerStartArgs
		muts   []mut
	}
	// revoking is how a refusal after the pull comes about: a later pull of another service stores a newer index.
	cases := []tc{
		{name: "never pulled", svc: "sensor", status: 412, code: api.CodeNotPulled, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			return e.startArgs("sensor", v2)
		}},
		{name: "the record is of another version", svc: "sensor", status: 412, code: api.CodeNotPulled, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			e.pullRel(t, "sensor", relSpec{version: v3, core: d3, sensor: d3}) // a newer pull replaces the record of 2.0.0
			return e.startArgs("sensor", v2)
		}},
		{name: "the image is gone", svc: "sensor", status: 412, code: api.CodeNotPulled, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			e.m.RemoveImage(d2)
			return e.startArgs("sensor", v2)
		}},
		{name: "no stored index", svc: "sensor", status: 412, code: api.CodeNotPulled, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			if err := os.Remove(e.indexFile()); err != nil {
				t.Fatal(err)
			}
			return e.startArgs("sensor", v2)
		}},
		{name: "damaged index", svc: "sensor", status: 412, code: api.CodeReleaseStateInvalid, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			if err := os.WriteFile(e.indexFile(), []byte(`{"index":"x"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return e.startArgs("sensor", v2)
		}},
		{name: "release revoked", svc: "sensor", status: 412, code: api.CodeReleaseRevoked, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			e.pullWith(t, "core", relSpec{version: v3, core: d3, sensor: d3}, func(i opstest.Doc) { i["revoked"] = []any{opstest.Revocation("release", v2)} })
			return e.startArgs("sensor", v2)
		}},
		{name: "image digest revoked", svc: "sensor", status: 412, code: api.CodeReleaseRevoked, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			e.pullWith(t, "core", relSpec{version: v3, core: d3, sensor: d3}, func(i opstest.Doc) { i["revoked"] = []any{opstest.Revocation("image_digest", d2)} })
			return e.startArgs("sensor", v2)
		}},
		{name: "signing key revoked", svc: "sensor", status: 412, code: api.CodeKeyRevoked, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			// An index signed by the offline backup key revokes the active key (update-manifest.md section 8).
			e.seq++
			idx, man := e.docsFor(e.seq, relSpec{version: v3, core: d3, sensor: d3})
			idx["revoked"] = []any{opstest.Revocation("key", e.rel.ActiveKeyID())}
			raw, mraw := opstest.JSON(t, idx), opstest.JSON(t, man)
			e.pull(t, e.rel.ArgsSig("core", v3, raw, e.rel.SignBackup(raw), mraw, e.rel.SignBackup(mraw)))
			return e.startArgs("sensor", v2)
		}},
		{name: "downgrade", svc: "sensor", status: 412, code: api.CodeDowngradeNotAllowed, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel2(d2, d2))
			e.m.PresentImage("sensor", d1, v1)
			e.pullRel(t, "sensor", rel1(d1, d1)) // the older release is pulled again: allowed; starting it is not
			return e.startArgs("sensor", v1)
		}},
		{name: "a prerelease is lower than its release", svc: "sensor", status: 412, code: api.CodeDowngradeNotAllowed, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.m.PresentImage("sensor", d2, "1.0.0-rc.1")
			e.pullRel(t, "sensor", relSpec{version: "1.0.0-rc.1", core: d2, sensor: d2})
			return e.startArgs("sensor", "1.0.0-rc.1")
		}},
		{name: "upgrade path", svc: "sensor", status: 412, code: api.CodeUpgradePathRequired, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", relSpec{version: v2, core: d2, sensor: d2, minUpgrade: "1.5.0"})
			return e.startArgs("sensor", v2)
		}},
		{name: "core: no snapshot", svc: "core", status: 412, code: api.CodeSnapshotRequired, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "core", rel1(d1, d1))
			e.pullRel(t, "core", rel2(d2, d2))
			return api.ContainerStartArgs{Service: "core", Version: v2, Snapshot: strings.Repeat("a", 32)}
		}},
		{name: "core: a snapshot older than 10 minutes", svc: "core", status: 412, code: api.CodeSnapshotRequired, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "core", rel1(d1, d1))
			e.pullRel(t, "core", rel2(d2, d2))
			old := e.m.Snapshot(e.clock.Now().Add(-11*time.Minute), func(*opstest.SnapOpts) {})
			return api.ContainerStartArgs{Service: "core", Version: v2, Snapshot: old}
		}},
		{name: "core: a snapshot that breaks the contract", svc: "core", status: 412, code: api.CodeSnapshotInvalid, setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
			e.adopt(t, "core", rel1(d1, d1))
			e.pullRel(t, "core", rel2(d2, d2))
			id := e.snap()
			if err := os.WriteFile(e.m.SnapshotPath(id, "snapshot.json"), []byte(`{"created_at":"x"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return api.ContainerStartArgs{Service: "core", Version: v2, Snapshot: id}
		}},
		{name: "core: low disk", svc: "core", status: 412, code: api.CodeLowDisk, muts: []mut{func(_ *ops.Config, d *ops.Deps) { d.FreeBytes = func(string) (uint64, error) { return 1, nil } }},
			setup: func(t *testing.T, e *updEnv) api.ContainerStartArgs {
				e.adopt(t, "core", rel1(d1, d1))
				e.m.PresentImage("core", d2, v2) // a pull of an image that is here needs no space
				e.pullRel(t, "core", rel2(d2, d2))
				return e.startArgs("core", v2)
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t, c.muts...)
			args := c.setup(t, e)
			before := e.unit(t, c.svc)
			e.forget() // the calls of the setup (the pulls) are not the refused start's
			e.refused(t, api.CmdContainerStart, args, c.status, c.code)
			e.untouched(t, c.name, c.svc, before)
			if v, _ := e.versions(t, c.svc); v != v1 && v != v2 {
				t.Fatalf("the recorded version changed: %q", v)
			}
		})
	}
}

func TestContract_Update_StartArgsAreValidatedBeforeAnything(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.adopt(t, "core", rel1(d1, d1))
	snap := e.snap()
	e.forget()
	for name, a := range map[string]api.ContainerStartArgs{
		"core without a snapshot":      {Service: "core", Version: v2},
		"sensor with a snapshot":       {Service: "sensor", Version: v2, Snapshot: snap},
		"a snapshot that is not hex32": {Service: "core", Version: v2, Snapshot: "../../x"},
		"a version that is not semver": {Service: "sensor", Version: "latest"},
		"a version with a shell":       {Service: "sensor", Version: "2.0.0;id"},
		"an unknown service":           {Service: "nope", Version: v2},
	} {
		e.refused(t, api.CmdContainerStart, a, 400, api.CodeInvalidArgs)
		_ = name
	}
	if len(e.writes()) != 0 {
		t.Fatalf("%v", e.writes())
	}
}

// --- the happy paths -------------------------------------------------------------------------------

func TestContract_Update_SensorSwitchWritesTheUnitReloadsRestartsAndRecordsTheOldVersionAsPrevious(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	if v, p := e.versions(t, "sensor"); v != v1 || p != "" {
		t.Fatalf("after adopt: %q %q", v, p)
	}
	e.pullRel(t, "sensor", rel2(d2, d2))
	oldUnit := e.unit(t, "sensor")
	e.m.PresentImage("sensor", d0, "0.9.0") // an image nothing keeps: retention removes it
	e.forget()

	r := e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	res := result[api.ContainerStartResult](t, r)
	if res.Version == nil || *res.Version != v2 || res.Digest != d2 || res.PreviousDigest == nil || *res.PreviousDigest != d1 || !res.Healthy || !res.Restarted || res.BackupID != nil || res.IndexExpired {
		t.Fatalf("%+v", res)
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload", "restart vedette-sensor.service"}) {
		t.Fatalf("systemctl: %v", got)
	}
	if e.unit(t, "sensor") != e.render(t, "sensor", d2) {
		t.Fatalf("unit:\n%s", e.unit(t, "sensor"))
	}
	if prev, err := e.m.Prev("sensor"); err != nil || prev != oldUnit {
		t.Fatalf("the old bytes are kept in .prev: %q %v", prev, err)
	}
	if e.journal("sensor") {
		t.Fatal("the journal stayed")
	}
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("versions %q %q", v, p)
	}
	st := e.state(t)["sensor"]
	if st.Previous == nil || st.Previous.Digest != d1 || st.Digest == nil || *st.Digest != d2 {
		t.Fatalf("%+v", st)
	}
	// Retention: only the image nothing keeps went, by digest, and not the current, the previous or the pulled one.
	if got := e.m.ImageRemoved(); !slices.Equal(got, []string{d0}) {
		t.Fatalf("removed %v", got)
	}
	for _, d := range []string{d1, d2} {
		if !e.m.ImagePresent(d) {
			t.Errorf("%s was removed", d)
		}
	}
	if w := e.writes(); !slices.Equal(w, []string{"rmi " + idOf(d0)}) {
		t.Fatalf("podman wrote %v", w)
	}
	if n := e.notes(t, "version_switch"); len(n) != 1 || n[0]["to_digest"] != d2 {
		t.Fatalf("notes %v", n)
	}
	if n := e.notes(t, "image_removed"); len(n) != 1 || n[0]["image_id"] != idOf(d0) {
		t.Fatalf("notes %v", n)
	}
}

func TestContract_Update_CoreSwitchMakesThePreUpdateBackupBeforeTheUnitChanges(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", rel2(d2, d2))
	e.m.MigratesDatabaseOn(d2) // the new release migrates the database when it starts
	r := e.ok(t, api.CmdContainerStart, e.startArgs("core", v2))
	res := result[api.ContainerStartResult](t, r)
	if res.BackupID == nil || len(*res.BackupID) != 32 || *res.Version != v2 || res.Digest != d2 || !res.Healthy {
		t.Fatalf("%+v", res)
	}
	bk, err := e.h.Client.StateBackups(context.Background())
	if err != nil || len(bk.Backups) != 1 || bk.Backups[0].BackupID != *res.BackupID || bk.Backups[0].Kind != "pre_update" || bk.Backups[0].Downloadable || !bk.Backups[0].IncludesSecrets {
		t.Fatalf("%+v %v", bk, err)
	}
	// The order: at the restart the backup already existed and the database was still as core had it.
	at := e.m.AtRestart()
	if len(at) != 1 || at[0] != "core backups=1 db=db: first digest="+d2 {
		t.Fatalf("at restart: %v", at)
	}
	if e.m.DB() != "db: migrated" {
		t.Fatalf("db %q", e.m.DB())
	}
	if v, p := e.versions(t, "core"); v != v2 || p != v1 {
		t.Fatalf("versions %q %q", v, p)
	}
	if n := e.notes(t, "pre_update_backup_made"); len(n) != 1 || n[0]["backup_id"] != *res.BackupID {
		t.Fatalf("notes %v", n)
	}
}

func TestContract_Update_AStartOfTheRunningDigestIsIdempotentAndMakesNoBackupAndNoRestart(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("core", v2))
	nctl, nbk := len(e.ctl()), func() int {
		b, _ := e.h.Client.StateBackups(context.Background())
		return len(b.Backups)
	}
	before := nbk()
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("core", v2)))
	if res.Restarted || !res.Healthy || res.BackupID != nil || *res.Version != v2 {
		t.Fatalf("%+v", res)
	}
	if len(e.ctl()) != nctl || nbk() != before {
		t.Fatalf("a repeated start restarted or made a backup: %v %d", e.ctl()[nctl:], nbk())
	}
	// restart:true restarts the same digest (the honeypot reloading its configuration) and still makes no backup.
	a := e.startArgs("core", v2)
	a.Restart = true
	res = result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, a))
	if !res.Restarted || res.BackupID != nil || nbk() != before {
		t.Fatalf("%+v", res)
	}
}

func TestContract_Update_TheFirstStartWithAVersionOfAServiceThatSetsUpWithoutOneOnlyRecordsIt(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit("sensor", d1, true)
	e.m.SetRunning("sensor", true)
	e.m.PresentImage("sensor", d1, v1)
	if v, _ := e.versions(t, "sensor"); v != "" {
		t.Fatal(v)
	}
	e.pullRel(t, "sensor", rel1(d1, d1))
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v1)))
	if res.Restarted || e.restarts("sensor") != 0 {
		t.Fatalf("%+v %v", res, e.ctl())
	}
	if v, p := e.versions(t, "sensor"); v != v1 || p != "" {
		t.Fatalf("%q %q", v, p)
	}
	// Until a version is recorded nothing can be rolled back.
	e2 := startUpd(t)
	e2.m.InstallUnit("sensor", d1, true)
	e2.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "sensor"}, 412, api.CodeNoPrevious)
}

func TestContract_Update_IndexExpiredIsInTheResultTheLogAndTheAudit(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.clock.Advance(40 * 24 * time.Hour) // the test clock starts on 2026-11-09; the test index expires 14 days after 2026-12-02
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2)))
	if !res.IndexExpired || res.Digest != d2 {
		t.Fatalf("%+v", res)
	}
	if n := e.notes(t, "index_expired"); len(n) != 1 {
		t.Fatalf("notes %v", n)
	}
}

// --- an unhealthy new version ---------------------------------------------------------------------

func TestContract_Update_AnUnhealthyNewVersionPutsTheOldUnitBackByteForByte(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	old := e.unit(t, "sensor")
	e.m.BadImage(d2)
	e.forget()
	r := e.final(t, api.CmdContainerStart, e.startArgs("sensor", v2), api.StatusReverted, api.CodeUnitFailed)
	if res := result[api.ContainerStartResult](t, r); res.Healthy || res.Digest != d2 {
		t.Fatalf("%+v", res)
	}
	if e.unit(t, "sensor") != old {
		t.Fatalf("the old unit is not back:\n%s", e.unit(t, "sensor"))
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload", "restart vedette-sensor.service", "daemon-reload", "restart vedette-sensor.service"}) {
		t.Fatalf("systemctl: %v", got)
	}
	if e.journal("sensor") {
		t.Fatal("the journal stayed")
	}
	if v, p := e.versions(t, "sensor"); v != v1 || p != "" {
		t.Fatalf("versions %q %q", v, p)
	}
	if len(e.writes()) != 0 {
		t.Fatalf("retention ran after a failure: %v", e.writes())
	}
	if !e.m.IsRunning("sensor") || e.state(t)["sensor"].Digest == nil || *e.state(t)["sensor"].Digest != d1 {
		t.Fatalf("%+v", e.state(t)["sensor"])
	}
}

func TestContract_Update_AnUnhealthyCoreThatSaysRollbackIsUnsafeGetsTheBackupBackBeforeTheOldReleaseStarts(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	old := e.unit(t, "core")
	e.m.MigratesDatabaseOn(d2)
	e.m.BadImage(d2)
	r := e.final(t, api.CmdContainerStart, e.startArgs("core", v2), api.StatusReverted, api.CodeUnitFailed)
	res := result[api.ContainerStartResult](t, r)
	if res.Healthy || res.BackupID == nil {
		t.Fatalf("%+v", res)
	}
	if e.m.DB() != "db: first" {
		t.Fatalf("the new release's migration was not undone: %q", e.m.DB())
	}
	// The order: the new release started on the first database, and the old one only after the backup was restored.
	if at := e.m.AtRestart(); !slices.Equal(at, []string{"core backups=1 db=db: first digest=" + d2, "core backups=1 db=db: first digest=" + d1}) {
		t.Fatalf("at restart: %v", at)
	}
	if e.unit(t, "core") != old || e.journal("core") {
		t.Fatal("the unit or the journal")
	}
	if n := e.notes(t, "backup_restored"); len(n) != 1 || n[0]["backup_id"] != *res.BackupID {
		t.Fatalf("notes %v", n)
	}
	if v, _ := e.versions(t, "core"); v != v1 {
		t.Fatalf("version %q", v)
	}
	// stop before the swap of the database, then the restart.
	ctl := e.ctl()
	if i, j := slices.Index(ctl, "stop vedette-core.service"), slices.Index(ctl, "restart vedette-core.service"); i < 0 || j < 0 {
		t.Fatalf("%v", ctl)
	}
}

func TestContract_Update_AnUnhealthyCoreThatIsSafeToRollBackKeepsItsDatabaseAndOnlyTheUnitGoesBack(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", rel2(d2, d2)) // rollback.safe=true
	e.m.MigratesDatabaseOn(d2)
	e.m.BadImage(d2)
	e.final(t, api.CmdContainerStart, e.startArgs("core", v2), api.StatusReverted, api.CodeUnitFailed)
	if e.m.DB() != "db: migrated" {
		t.Fatalf("a restore ran for a release that is safe to roll back: %q", e.m.DB())
	}
	if slices.Contains(e.ctl(), "stop vedette-core.service") {
		t.Fatalf("core was stopped: %v", e.ctl())
	}
}

func TestContract_Update_AFailedPutBackLeavesTheJournalAndTheRunFailed(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	// The first restart (the new unit) does nothing: the container stays the old one, never healthy with the new digest.
	// Every later restart fails: the old unit cannot be restarted either.
	e.m.Rule("systemctl", "restart", "", 0, "!r1", "r1")
	e.m.Rule("systemctl", "restart", "", 1, "r1", "")
	e.final(t, api.CmdContainerStart, e.startArgs("sensor", v2), api.StatusFailed, api.CodeUnitFailed)
	b, err := os.ReadFile(e.m.TransitionPath("sensor"))
	if err != nil || !strings.Contains(string(b), `"phase":"pending"`) || !strings.Contains(string(b), `"version":"2.0.0"`) || strings.Contains(string(b), `"applied"`) {
		t.Fatalf("%s %v", b, err)
	}
	if e.restarts("sensor") != 2 {
		t.Fatalf("restarts: %d", e.restarts("sensor"))
	}
	if v, _ := e.versions(t, "sensor"); v != v1 {
		t.Fatalf("a change that did not work was recorded: %q", v)
	}
}

// --- container.rollback ---------------------------------------------------------------------------

func TestContract_Update_RollbackGoesBackToPreviousAndTwiceReturnsToTheStart(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	afterUpgrade := e.unit(t, "sensor")
	e.m.PresentImage("sensor", d0, "0.9.0")

	res := result[api.ContainerRollbackResult](t, e.rollback(t, "sensor"))
	if res.Digest != d1 || res.FromDigest != d2 || res.RestoredBackupID != nil {
		t.Fatalf("%+v", res)
	}
	if e.unit(t, "sensor") != e.render(t, "sensor", d1) || e.journal("sensor") {
		t.Fatal("the unit or the journal")
	}
	if v, p := e.versions(t, "sensor"); v != v1 || p != v2 {
		t.Fatalf("after one rollback: %q %q", v, p)
	}
	if st := e.state(t)["sensor"]; st.Digest == nil || *st.Digest != d1 || st.Previous.Digest != d2 {
		t.Fatalf("%+v", st)
	}
	// Retention ran, and neither the running nor the previous image went (nor the other one that is pulled).
	if got := e.m.ImageRemoved(); !slices.Equal(got, []string{d0}) {
		t.Fatalf("removed %v", got)
	}

	res = result[api.ContainerRollbackResult](t, e.rollback(t, "sensor"))
	if res.Digest != d2 || res.FromDigest != d1 {
		t.Fatalf("%+v", res)
	}
	if e.unit(t, "sensor") != afterUpgrade {
		t.Fatal("two rollbacks did not return to where it started")
	}
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("after two rollbacks: %q %q", v, p)
	}
	for _, d := range []string{d1, d2} {
		if !e.m.ImagePresent(d) {
			t.Errorf("%s was removed", d)
		}
	}
	if n := e.notes(t, "rollback_start"); len(n) != 2 {
		t.Fatalf("notes %v", n)
	}
}

func TestContract_Update_RollbackRefusalsAreAllDecidedInCheckWithNoWrite(t *testing.T) {
	t.Parallel()
	type tc struct {
		name  string
		code  string
		setup func(t *testing.T, e *updEnv)
	}
	upgraded := func(t *testing.T, e *updEnv, v2spec relSpec) {
		e.adopt(t, "sensor", rel1(d1, d1))
		e.pullRel(t, "sensor", v2spec)
		e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2spec.version))
	}
	revoke := func(t *testing.T, e *updEnv, kind, id string) {
		e.pullWith(t, "core", relSpec{version: v3, core: d3, sensor: d3}, func(i opstest.Doc) { i["revoked"] = []any{opstest.Revocation(kind, id)} })
	}
	cases := []tc{
		{"no previous", api.CodeNoPrevious, func(t *testing.T, e *updEnv) { e.adopt(t, "sensor", rel1(d1, d1)) }},
		{"the previous image is gone", api.CodeNoPrevious, func(t *testing.T, e *updEnv) {
			upgraded(t, e, rel2(d2, d2))
			e.m.RemoveImage(d1)
		}},
		{"the previous version is revoked", api.CodePreviousRevoked, func(t *testing.T, e *updEnv) {
			upgraded(t, e, rel2(d2, d2))
			revoke(t, e, "release", v1)
		}},
		{"the previous image digest is revoked", api.CodePreviousRevoked, func(t *testing.T, e *updEnv) {
			upgraded(t, e, rel2(d2, d2))
			revoke(t, e, "image_digest", d1)
		}},
		{"the previous signing key is revoked", api.CodePreviousRevoked, func(t *testing.T, e *updEnv) {
			upgraded(t, e, rel2(d2, d2))
			e.seq++
			idx, man := e.docsFor(e.seq, relSpec{version: v3, core: d3, sensor: d3})
			idx["revoked"] = []any{opstest.Revocation("key", e.rel.ActiveKeyID())}
			raw, mraw := opstest.JSON(t, idx), opstest.JSON(t, man)
			e.pull(t, e.rel.ArgsSig("core", v3, raw, e.rel.SignBackup(raw), mraw, e.rel.SignBackup(mraw)))
		}},
		{"below the running release's rollback.min_version", api.CodeRollbackNotAllowed, func(t *testing.T, e *updEnv) {
			upgraded(t, e, relSpec{version: v2, core: d2, sensor: d2, minRollback: "1.5.0"})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			c.setup(t, e)
			before := e.unit(t, "sensor")
			e.forget()
			e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "sensor"}, 412, c.code)
			e.untouched(t, c.name, "sensor", before)
		})
	}
	// A revoked RUNNING release is no reason to refuse going back: that is the way out of it.
	t.Run("a revoked running release can still be left", func(t *testing.T) {
		t.Parallel()
		e := startUpd(t)
		upgraded(t, e, rel2(d2, d2))
		revoke(t, e, "release", v2)
		e.rollback(t, "sensor")
		if e.unit(t, "sensor") != e.render(t, "sensor", d1) {
			t.Fatal("not rolled back")
		}
	})
	t.Run("the same refusals for bad args", func(t *testing.T) {
		t.Parallel()
		e := startUpd(t)
		e.refused(t, api.CmdContainerRollback, map[string]any{"service": "nope"}, 400, api.CodeInvalidArgs)
		e.refused(t, api.CmdContainerRollback, map[string]any{"service": "sensor", "version": v1}, 400, api.CodeInvalidArgs)
		e.refused(t, api.CmdContainerRollback, map[string]any{"service": "greenbone"}, 412, api.CodeUnitUnknown)
	})
}

func TestContract_Update_AFailedRollbackPutsTheRunningReleaseBack(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	running := e.unit(t, "sensor")
	e.m.BadImage(d1)
	r := e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "sensor"}, api.StatusReverted, api.CodeUnitFailed)
	if res := result[api.ContainerRollbackResult](t, r); res.Digest != d1 || res.FromDigest != d2 {
		t.Fatalf("%+v", res)
	}
	if e.unit(t, "sensor") != running || e.journal("sensor") {
		t.Fatal("the running unit is not back")
	}
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("a rollback that did not work changed the versions: %q %q", v, p)
	}
	if st := e.state(t)["sensor"]; st.Digest == nil || *st.Digest != d2 {
		t.Fatalf("%+v", st)
	}
}

func TestContract_Update_AFailedRevertEndsFailedAndTheHostDoesNotLoop(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	e.m.Rule("systemctl", "restart", "", 0, "!r1", "r1") // the rollback's restart does nothing: the container stays the old one
	e.m.Rule("systemctl", "restart", "", 1, "r1", "")    // and the restart that would put the running release back fails
	n0 := e.restarts("sensor")
	r := e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "sensor"}, api.StatusFailed, api.CodeRollbackRevertFailed)
	if r.Error == nil || !strings.Contains(r.Error.Message, "stopped") {
		t.Fatalf("%+v", r.Error)
	}
	if got := e.restarts("sensor") - n0; got != 2 {
		t.Fatalf("restarts: %d, want the rollback's and one try to put back", got)
	}
	// The journal stays pending for the next start, and says what it was.
	b, err := os.ReadFile(e.m.TransitionPath("sensor"))
	if err != nil || !strings.Contains(string(b), `"op":"rollback"`) || !strings.Contains(string(b), `"phase":"pending"`) {
		t.Fatalf("%s %v", b, err)
	}
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("%q %q", v, p)
	}
}

// core, going down from a release that says rollback.safe=false.
type coreUnsafe struct {
	e        *updEnv
	upgraded string
	backup   string
}

func setupCoreUnsafe(t *testing.T) *coreUnsafe {
	t.Helper()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	e.m.MigratesDatabaseOn(d2)
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("core", v2)))
	e.m.Mark("migrate-db", false) // the fake migrates on every restart of that digest; the data written since is what the tests look for
	e.m.WriteDB("db: migrated, plus data written since the update")
	return &coreUnsafe{e: e, upgraded: e.unit(t, "core"), backup: *res.BackupID}
}

func asides(t *testing.T, e *updEnv) []string {
	t.Helper()
	var out []string
	ents, err := os.ReadDir(e.m.CoreData)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ents {
		if strings.HasSuffix(x.Name(), ".rollback") {
			out = append(out, x.Name())
		}
	}
	return out
}

func TestContract_Update_CoreRollbackOfAnUnsafeReleaseRestoresTheBackupThenSwapsTheUnit(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	n := len(e.ctl())
	res := result[api.ContainerRollbackResult](t, e.rollback(t, "core"))
	if res.Digest != d1 || res.FromDigest != d2 || res.RestoredBackupID == nil || *res.RestoredBackupID != c.backup {
		t.Fatalf("%+v", res)
	}
	if e.m.DB() != "db: first" {
		t.Fatalf("db %q", e.m.DB())
	}
	if key, _ := os.ReadFile(filepath.Join(e.m.CoreData, "vedette.key")); string(key) != opstest.Key {
		t.Fatalf("key %q", key)
	}
	// The order: core stopped, the backup restored, and only then the old release started, on the restored database.
	ctl := e.ctl()[n:]
	if !slices.Equal(ctl, []string{"stop vedette-core.service", "daemon-reload", "restart vedette-core.service"}) {
		t.Fatalf("systemctl: %v", ctl)
	}
	at := e.m.AtRestart()
	if last := at[len(at)-1]; last != "core backups=1 db=db: first digest="+d1 {
		t.Fatalf("at restart: %v", at)
	}
	if e.unit(t, "core") != e.render(t, "core", d1) || e.journal("core") {
		t.Fatal("unit or journal")
	}
	if a := asides(t, e); len(a) != 0 {
		t.Fatalf("files moved aside were left: %v", a)
	}
	if v, p := e.versions(t, "core"); v != v1 || p != v2 {
		t.Fatalf("versions %q %q", v, p)
	}
	if n := e.notes(t, "backup_restored"); len(n) != 1 || n[0]["backup_id"] != c.backup {
		t.Fatalf("notes %v", n)
	}
	// H1: core never rolls forward. The previous version is now the newer one; going up is container.start with
	// a version and a snapshot (a fresh pre_update backup), not a rollback with a backup of another time.
	e.m.WriteDB("db: after the rollback")
	before := e.unit(t, "core")
	e.forget()
	e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeRollbackIsUpgrade)
	e.untouched(t, "core roll-forward", "core", before)
	if e.m.DB() != "db: after the rollback" {
		t.Fatal("the database was touched")
	}
	// The versions swapped without carrying a backup id onto the record it does not belong to.
	vs, err := os.ReadFile(filepath.Join(e.m.State, "containers", "versions-core.json"))
	if err != nil {
		t.Fatal(err)
	}
	type rec struct {
		Version  string `json:"version"`
		BackupID string `json:"backup_id"`
	}
	var st struct {
		Current  rec `json:"current"`
		Previous rec `json:"previous"`
	}
	if err := json.Unmarshal(vs, &st); err != nil || st.Current.Version != v1 || st.Current.BackupID != "" || st.Previous.Version != v2 || st.Previous.BackupID != c.backup {
		t.Fatalf("%s %v", vs, err)
	}
	// Going up with container.start makes a fresh backup, and the next rollback uses that one.
	res2 := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("core", v2)))
	if res2.BackupID == nil || *res2.BackupID == c.backup {
		t.Fatalf("%+v", res2)
	}
	res = result[api.ContainerRollbackResult](t, e.rollback(t, "core"))
	if res.RestoredBackupID == nil || *res.RestoredBackupID != *res2.BackupID {
		t.Fatalf("the third rollback used the backup %v, want the fresh %s", res.RestoredBackupID, *res2.BackupID)
	}
}

func TestContract_Update_ASensorRollbackTwiceStillReturnsToTheStart(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	up := e.unit(t, "sensor")
	e.rollback(t, "sensor")
	e.rollback(t, "sensor")
	if e.unit(t, "sensor") != up {
		t.Fatal("not back where it started")
	}
}

func TestContract_Update_AFailedCoreRollbackPutsTheDatabaseAndTheUnitBack(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.m.BadImage(d1)
	r := e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusReverted, api.CodeUnitFailed)
	if res := result[api.ContainerRollbackResult](t, r); res.RestoredBackupID == nil {
		t.Fatalf("%+v", res)
	}
	if e.m.DB() != "db: migrated, plus data written since the update" {
		t.Fatalf("the data written since the update is lost: %q", e.m.DB())
	}
	if e.unit(t, "core") != c.upgraded || e.journal("core") {
		t.Fatal("unit or journal")
	}
	if a := asides(t, e); len(a) != 0 {
		t.Fatalf("aside: %v", a)
	}
	at := e.m.AtRestart()
	if len(at) < 3 || at[len(at)-1] != "core backups=1 db=db: migrated, plus data written since the update digest="+d2 {
		t.Fatalf("at restart: %v", at)
	}
	if v, p := e.versions(t, "core"); v != v2 || p != v1 {
		t.Fatalf("versions %q %q", v, p)
	}
}

func TestContract_Update_AFailedRevertOfACoreRollbackEndsFailedWithoutALoop(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.m.Rule("systemctl", "restart", "", 0, "!r1", "r1")
	e.m.Rule("systemctl", "restart", "", 1, "r1", "")
	n0 := e.restarts("core")
	e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusFailed, api.CodeRollbackRevertFailed)
	if got := e.restarts("core") - n0; got != 2 {
		t.Fatalf("restarts %d", got)
	}
	// The database was put back before the unit was tried; the journal stays for the next start.
	if e.m.DB() != "db: migrated, plus data written since the update" {
		t.Fatalf("db %q", e.m.DB())
	}
	b, err := os.ReadFile(e.m.TransitionPath("core"))
	if err != nil || !strings.Contains(string(b), `"db_revert":"aside"`) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestContract_Update_RollbackNeedsThePreUpdateBackupOfAnUnsafeCoreRelease(t *testing.T) {
	t.Parallel()
	t.Run("the archive is gone", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		if err := os.Remove(filepath.Join(e.m.State, "backups", c.backup+".tar.gz")); err != nil {
			t.Fatal(err)
		}
		before := e.unit(t, "core")
		e.forget()
		e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeRollbackBackupMissing)
		e.untouched(t, "gone", "core", before)
		if e.m.DB() != "db: migrated, plus data written since the update" {
			t.Fatal("the database was touched")
		}
	})
	t.Run("it is not in the index", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		if err := os.WriteFile(filepath.Join(e.m.State, "backups", "index.json"), []byte(`{"backups":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeRollbackBackupMissing)
	})
	t.Run("retention keeps it (D-157): the versions point at it", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		for range 3 { // the host keeps the three newest pre_* backups, and B1 on top of them
			e.clock.Advance(time.Minute)
			e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true})
		}
		res := result[api.ContainerRollbackResult](t, e.rollback(t, "core"))
		if res.RestoredBackupID == nil || *res.RestoredBackupID != c.backup {
			t.Fatalf("%+v", res)
		}
	})
}

// --- retention -----------------------------------------------------------------------------------

func TestContract_Update_RetentionRemovesOnlyWhatNothingKeepsByDigestAndFailureIsNotFatal(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.m.PresentImage("sensor", d0, "0.8.0")
	e.m.PresentImage("sensor", d3, "")      // the leftover of a failed pull: a digest name only
	e.m.PresentImage("sensor", d4, "0.9.0") // in use by a container
	e.m.MarkImageUsed(d4)
	e.m.PresentImage("core", opstest.Digest('5'), "5.0.0") // another service's image is never touched
	e.m.SetImagePresent(opstest.Digest('6'))               // an image the fake cannot name: left alone
	e.m.Mark("rmi-fails", true)
	r := e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2)) // a failing rmi does not fail the run
	if res := result[api.ContainerStartResult](t, r); !res.Healthy {
		t.Fatalf("%+v", res)
	}
	var rmis []string
	for _, c := range e.podman() {
		if c[0] == "rmi" {
			rmis = append(rmis, strings.Join(c[1:], " "))
		}
		if c[0] == "rmi" && (len(c) != 2 || strings.HasPrefix(c[1], "-")) {
			t.Fatalf("an rmi with more than a digest: %v", c)
		}
	}
	slices.Sort(rmis)
	if want := []string{idOf(d0), idOf(d3)}; !slices.Equal(rmis, want) {
		t.Fatalf("rmi %v, want %v", rmis, want)
	}
	if n := e.notes(t, "image_removal_failed"); len(n) != 2 {
		t.Fatalf("notes %v", n)
	}
	for _, c := range e.podman() {
		if (c[0] == "image" && c[1] == "prune") || slices.Contains(c, "prune") || slices.Contains(c, "-a") || slices.Contains(c, "-f") {
			t.Fatalf("a prune or a force: %v", c)
		}
	}
	// Without the failure marker the two go.
	e.m.Mark("rmi-fails", false)
	e.rollback(t, "sensor")
	got := e.m.ImageRemoved()
	slices.Sort(got)
	if !slices.Equal(got, []string{d0, d3}) {
		t.Fatalf("removed %v", got)
	}
	for _, d := range []string{d1, d2, d4, opstest.Digest('5'), opstest.Digest('6')} {
		if !e.m.ImagePresent(d) {
			t.Errorf("%s was removed", d)
		}
	}
}

func TestContract_Update_RetentionNeverRemovesTheCurrentOrThePreviousEvenWhenTheySharedADigestOrAfterARollback(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	// Versions 1.0.0 and 2.0.0 are the same image (a re-tagged release): current and previous share a digest.
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d1, d1))
	e.m.PresentImage("sensor", d0, "0.9.0")
	state := map[string]any{"service": "sensor"}
	rec := func(version, digest string) map[string]any {
		return map[string]any{"service": "sensor", "version": version, "digest": digest, "key_id": e.rel.ActiveKeyID(), "size": 1, "pulled_at": "2026-11-10T08:00:00Z", "manifest": "eA==", "manifest_sig": "eA=="}
	}
	state["current"], state["previous"] = rec(v2, d1), rec(v1, d1)
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(e.m.State, "containers", "versions-sensor.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2)) // the unit already pins d1: retention only
	if got := e.m.ImageRemoved(); !slices.Equal(got, []string{d0}) || !e.m.ImagePresent(d1) {
		t.Fatalf("removed %v", got)
	}
}

// --- a host that died in the middle of a swap ----------------------------------------------------

// crashSeed leaves what a host that died in the middle of a change leaves, for a service that runs old and
// switches to new: the journal, the unit text of the step in place and .prev holding the old one.
type crashSeed struct {
	op, svc, phase       string
	oldText, newText     string
	onDisk               string // the unit text on disk at the step
	version              string
	fromDigest, toDigest string
	backupID, dbRevert   string
	aside                []string
	applied              bool
}

func (e *updEnv) seedCrash(t *testing.T, s crashSeed) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-"+s.svc+".container"), []byte(s.onDisk), 0o644); err != nil { //nolint:gosec // test: a unit file of the fake root
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.m.State, "containers", "units", s.svc+".prev"), []byte(s.oldText), 0o600); err != nil {
		t.Fatal(err)
	}
	j := map[string]any{
		"service": s.svc, "op": s.op, "phase": s.phase, "digest": s.toDigest, "prev_sha256": shaOf(s.oldText), "new_sha256": shaOf(s.newText),
		"was_active": true, "at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef", "version": s.version, "from_digest": s.fromDigest,
	}
	if s.backupID != "" {
		j["backup_id"] = s.backupID
	}
	if s.dbRevert != "" {
		j["db_revert"] = s.dbRevert
	}
	if s.applied {
		j["applied"] = true
	}
	if len(s.aside) > 0 {
		j["aside"] = s.aside
	}
	b, _ := json.Marshal(j)
	if err := os.WriteFile(e.m.TransitionPath(s.svc), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// reboot builds a new Ops on the same state directory, as a restarted host has, and runs Start and AfterReady.
func (e *updEnv) reboot(t *testing.T) *noteRecorder {
	t.Helper()
	o2 := e.m.Ops(e.clock.Now, e.muts...)
	rec := &noteRecorder{}
	o2.Start(context.Background(), rec)
	t.Cleanup(o2.Close)
	e.m.Mark("host-starting", false)
	o2.AfterReady(context.Background(), e.h.Server)
	return rec
}

func TestContract_Update_AHostThatDiedAtEachStepOfASensorSwitchPutsTheOldUnitBack(t *testing.T) {
	t.Parallel()
	steps := map[string]string{ // what is on disk at the step: the old text (nothing written yet) or the new one
		"after the journal, before the unit": "old",
		"after the unit, before the reload":  "new",
		"after the restart, before the look": "new",
		"unhealthy and being put back":       "new",
	}
	for name, which := range steps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			e.adopt(t, "sensor", rel1(d1, d1))
			e.pullRel(t, "sensor", rel2(d2, d2))
			oldText, newText := e.unit(t, "sensor"), e.render(t, "sensor", d2)
			on := oldText
			if which == "new" {
				on = newText
			}
			e.seedCrash(t, crashSeed{op: "start", svc: "sensor", phase: "pending", oldText: oldText, newText: newText, onDisk: on, version: v2, fromDigest: d1, toDigest: d2})
			e.m.Mark("host-starting", true)
			o2 := e.m.Ops(e.clock.Now, e.muts...)
			rec := &noteRecorder{}
			o2.Start(context.Background(), rec)
			t.Cleanup(o2.Close)
			if e.unit(t, "sensor") != oldText {
				t.Fatalf("the old unit was not put back at Start:\n%s", e.unit(t, "sensor"))
			}
			if d := e.m.Deadlocked(); len(d) != 0 {
				t.Fatalf("a restart before READY: %v", d)
			}
			e.m.Mark("host-starting", false)
			o2.AfterReady(context.Background(), e.h.Server)
			if e.journal("sensor") || e.unit(t, "sensor") != oldText {
				t.Fatal("the journal stayed or the unit changed")
			}
			if v, p := e.versions(t, "sensor"); v != v1 || p != "" {
				t.Fatalf("a change that never took effect was recorded: %q %q", v, p)
			}
			if st := e.state(t)["sensor"]; st.Digest == nil || *st.Digest != d1 {
				t.Fatalf("the old release does not run: %+v", st)
			}
			if !strings.Contains(rec.text(), "container.start transition_interrupted") {
				t.Fatalf("notes %s", rec.text())
			}
		})
	}
}

func TestContract_Update_AVerifiedJournalOfAChangeThatTookEffectRecordsTheVersionsOnceAtStart(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	oldText, newText := e.unit(t, "sensor"), e.render(t, "sensor", d2)
	e.seedCrash(t, crashSeed{op: "start", svc: "sensor", phase: "verified", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, applied: true})
	e.reboot(t)
	if e.journal("sensor") || e.unit(t, "sensor") != newText {
		t.Fatal("the journal stayed or the unit changed")
	}
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("%q %q", v, p)
	}
	// A second boot with the same journal again (a crash before the removal) records nothing twice.
	e.seedCrash(t, crashSeed{op: "start", svc: "sensor", phase: "verified", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, applied: true})
	e.reboot(t)
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("%q %q", v, p)
	}
	// A verified journal of a change that was undone (not applied) records nothing.
	e2 := startUpd(t)
	e2.adopt(t, "sensor", rel1(d1, d1))
	e2.pullRel(t, "sensor", rel2(d2, d2))
	o, n := e2.unit(t, "sensor"), e2.render(t, "sensor", d2)
	e2.seedCrash(t, crashSeed{op: "start", svc: "sensor", phase: "verified", oldText: o, newText: n, onDisk: o, version: v2, fromDigest: d1, toDigest: d2})
	e2.reboot(t)
	if v, p := e2.versions(t, "sensor"); v != v1 || p != "" {
		t.Fatalf("%q %q", v, p)
	}
}

func TestContract_Update_AHostThatDiedAfterANewCoreReleaseMayHaveMigratedItsDatabaseRestoresTheBackupAfterReady(t *testing.T) {
	t.Parallel()
	for _, step := range []string{"unit written", "unit not written"} {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			e.adopt(t, "core", rel1(d1, d1))
			e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
			bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
			oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
			on := oldText
			if step == "unit written" {
				on = newText
			}
			e.m.WriteDB("db: migrated")
			e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: on, version: v2, fromDigest: d1, toDigest: d2, backupID: bk.BackupID, dbRevert: "backup"})
			e.reboot(t)
			want := "db: first"
			if step == "unit not written" {
				want = "db: migrated" // the new release never started: nothing to undo
			}
			if e.m.DB() != want {
				t.Fatalf("db %q, want %q", e.m.DB(), want)
			}
			if e.journal("core") || e.unit(t, "core") != oldText {
				t.Fatal("journal or unit")
			}
			if st := e.state(t)["core"]; st.Digest == nil || *st.Digest != d1 {
				t.Fatalf("%+v", st)
			}
		})
	}
}

func TestContract_Update_AHostThatDiedInTheMiddleOfACoreRollbackBringsTheFilesMovedAsideBack(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
	// The host moved the database aside, restored the backup and wrote the unit of the previous release, then died.
	live := filepath.Join(e.m.CoreData, "vedette.db")
	if err := os.Rename(live, live+".rollback"); err != nil {
		t.Fatal(err)
	}
	e.m.WriteDB("db: first") // the restored backup
	e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1, backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}})
	e.reboot(t)
	if e.m.DB() != "db: migrated, plus data written since the update" {
		t.Fatalf("db %q", e.m.DB())
	}
	if a := asides(t, e); len(a) != 0 || e.journal("core") || e.unit(t, "core") != oldText {
		t.Fatalf("aside %v journal %t", a, e.journal("core"))
	}
	if v, p := e.versions(t, "core"); v != v2 || p != v1 {
		t.Fatalf("%q %q", v, p)
	}
}

func TestContract_Update_AVerifiedRollbackJournalDropsTheAsideAndSwapsTheVersionsAtStart(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
	live := filepath.Join(e.m.CoreData, "vedette.db")
	if err := os.Rename(live, live+".rollback"); err != nil {
		t.Fatal(err)
	}
	e.m.WriteDB("db: first")
	e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "verified", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1, backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}, applied: true})
	e.reboot(t)
	if e.m.DB() != "db: first" || len(asides(t, e)) != 0 || e.journal("core") {
		t.Fatalf("db %q aside %v", e.m.DB(), asides(t, e))
	}
	if v, p := e.versions(t, "core"); v != v1 || p != v2 {
		t.Fatalf("%q %q", v, p)
	}
}

func TestContract_Update_ABadJournalFieldIsMovedAsideNotBelieved(t *testing.T) {
	t.Parallel()
	for name, patch := range map[string]map[string]any{
		"a version that is not a release": {"version": "latest; id"},
		"a backup id that is a path":      {"backup_id": "../../etc/passwd"},
		"a database mode that is unknown": {"db_revert": "rm -rf"},
		"a from digest that is a name":    {"from_digest": "ghcr.io/x/y:latest"},
		"an unknown field":                {"command": "podman rmi -a"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			e.adopt(t, "sensor", rel1(d1, d1))
			j := map[string]any{
				"service": "sensor", "op": "rollback", "phase": "pending", "digest": d1, "prev_sha256": shaOf("a"), "new_sha256": shaOf("b"),
				"was_active": true, "at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef",
			}
			for k, v := range patch {
				j[k] = v
			}
			b, _ := json.Marshal(j)
			if err := os.WriteFile(e.m.TransitionPath("sensor"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			rec := e.reboot(t)
			if e.journal("sensor") || !strings.Contains(rec.text(), "transition_invalid") {
				t.Fatalf("journal %t notes %s", e.journal("sensor"), rec.text())
			}
		})
	}
}

// --- the state endpoint and the unit of a service that was switched ---------------------------------

func TestContract_Update_TheSwitchedServiceStillRendersExactlyTheHostsOwnUnit(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	e.rollback(t, "sensor")
	// Every container command still accepts the unit (it is byte for byte the host's own, D-123 L2).
	e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Restart: true})
	if e.unit(t, "sensor") != e.render(t, "sensor", d1) {
		t.Fatal("the unit is not the host's own")
	}
}
