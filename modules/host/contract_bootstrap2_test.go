package host_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/internal/release"
)

// Review of slice 3-8b (D-142): the key core reads is the key the host backs up, the version records agree
// with the unit after a recovery, core_data is vetted when it exists and made without following links, one
// lock for the daemon and the bootstrap, audit lines, and a partial install is not mixed with another release.

// bsOps is a second Ops on the machine of e with the keys of e and a changed host.conf.
func (e *updEnv) bsOps(t *testing.T, mutate func(*ops.Config)) *ops.Ops {
	t.Helper()
	return e.m.Ops(e.clock.Now, func(c *ops.Config, d *ops.Deps) {
		if mutate != nil {
			mutate(c)
		}
		d.Keys = func() (release.Trust, error) { return e.rel.Trust, nil }
	})
}

func (e *updEnv) bootstrapWith(o *ops.Ops, a ops.BootstrapArgs) error {
	return o.Bootstrap(context.Background(), a, func(string) {})
}

func codeIs(t *testing.T, name string, err error, want string) {
	t.Helper()
	if got, _ := ops.BootstrapCode(err); err == nil || got != want {
		t.Fatalf("%s: want %s, got %v", name, want, err)
	}
}

// H1: the unit binds core_data and names no key; a backup and a restore keep the key that core reads, which
// is <core_data>/vedette.key (core's default -key under /var/lib/vedette).
func TestContract_Bootstrap_TheKeyCoreReadsIsTheKeyTheHostBacksUp(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	u := e.unit(t, api.ServiceCore)
	if strings.Contains(u, "master.key") || strings.Contains(u, "-key") || strings.Contains(u, "vedette-data.volume") {
		t.Errorf("the unit still names a key file or the old volume:\n%s", u)
	}
	if !strings.Contains(u, "\nVolume="+e.m.CoreData+":/var/lib/vedette\n") {
		t.Errorf("the unit does not bind core_data:\n%s", u)
	}
	e.m.SetRunning(api.ServiceCore, true)
	keyPath := filepath.Join(e.m.CoreData, "vedette.key")
	b := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual", IncludeSecrets: true}))
	if err := os.WriteFile(keyPath, []byte("a different key, as after a reinstall"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.ok(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: b.BackupID, Snapshot: e.snap()})
	if got, err := os.ReadFile(keyPath); err != nil || string(got) != opstest.Key { //nolint:gosec // test: a path under the fake core_data
		t.Fatalf("after the restore core would read %q (%v), want the backed-up key", got, err)
	}
}

// M1: a recovery whose unit pins another release than versions.current records what the unit pins, or keeps the journal.
func TestContract_Restore_RecoveryReconcilesTheVersionsWithTheUnit(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*updEnv, string) {
		e := startUpd(t)
		a := e.bsDocs(t, 5, v1, bsDigest)
		a.Services = []string{api.ServiceCore}
		e.bootstrapOK(t, a)
		e.seq = 5
		e.m.SetRunning(api.ServiceCore, true)
		b := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual", IncludeSecrets: true}))
		return e, b.BackupID
	}
	t.Run("the unit pins a release the host pulled", func(t *testing.T) {
		t.Parallel()
		e, id := setup(t)
		d5 := opstest.Digest('5')
		e.pullRel(t, api.ServiceCore, relSpec{version: v2, core: d5, sensor: opstest.Digest('6')})
		e.m.InstallUnit(api.ServiceCore, d5, true) // the switch that was interrupted had written the new unit
		e.m.SetRunning(api.ServiceCore, true)
		e.unrecoverable(t, true)
		e.ok(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: id, Snapshot: e.snap()})
		if e.journal(api.ServiceCore) {
			t.Error("the journal stayed although the versions could be reconciled")
		}
		if v := e.versionsFile(t, api.ServiceCore); v.Current == nil || v.Current.Version != v2 || v.Current.Digest != d5 {
			t.Errorf("versions %+v", v)
		}
	})
	t.Run("the unit pins a release the host knows nothing of", func(t *testing.T) {
		t.Parallel()
		e, id := setup(t)
		e.m.InstallUnit(api.ServiceCore, opstest.Digest('7'), true)
		e.m.SetRunning(api.ServiceCore, true)
		e.unrecoverable(t, true)
		e.ok(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: id, Snapshot: e.snap()})
		if !e.journal(api.ServiceCore) {
			t.Error("the journal was removed although versions and unit disagree")
		}
		if v := e.versionsFile(t, api.ServiceCore); v.Current.Version != v1 {
			t.Errorf("versions %+v", v)
		}
		if n := e.notes(t, "core_data_recovered"); len(n) != 0 {
			t.Errorf("recovery audited: %v", n)
		}
	})
}

// M2: an existing core_data is vetted, not trusted.
func TestContract_Bootstrap_AnExistingCoreDataIsVetted(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	if err := os.Chmod(e.m.CoreData, 0o750); err != nil { //nolint:gosec // test: a mode core would not have
		t.Fatal(err)
	}
	e.bsRefused(t, "core_data open to the group", e.bsDocs(t, 5, v1, bsDigest), api.CodeCoreDataInvalid)

	// Owned by someone who is not core and not empty: refused, untouched.
	o := startUpd(t, func(c *ops.Config, _ *ops.Deps) { c.CoreUID = os.Getuid() + 1 })
	before, _ := os.ReadFile(o.m.CoreDBPath())
	o.bsRefused(t, "core_data of another owner with files in it", o.bsDocs(t, 5, v1, bsDigest), api.CodeCoreDataInvalid)
	if after, _ := os.ReadFile(o.m.CoreDBPath()); string(after) != string(before) {
		t.Error("the database changed")
	}

	// The exact owner and mode: fine.
	g := startUpd(t)
	g.bootstrapOK(t, g.bsDocs(t, 5, v1, bsDigest))
}

func TestContract_Bootstrap_AnEmptyDirectoryOfAnotherOwnerIsGivenToCore(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("giving a directory to another uid needs root")
	}
	e := startUpd(t, func(c *ops.Config, _ *ops.Deps) { c.CoreUID, c.CoreGID = 10001, 10002 })
	_ = os.RemoveAll(e.m.CoreData)
	if err := os.Mkdir(e.m.CoreData, 0o755); err != nil { //nolint:gosec // test: root's empty directory
		t.Fatal(err)
	}
	e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	st, _ := os.Stat(e.m.CoreData)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", st.Mode())
	}
}

// L1: core_data is made relative to its vetted parent; a parent that is a link, or missing, is refused.
func TestContract_Bootstrap_CoreDataIsNotMadeThroughALinkedOrMissingParent(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	base := filepath.Dir(e.m.CoreData)
	realDir := filepath.Join(base, "realDir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	o := e.bsOps(t, func(c *ops.Config) { c.CoreData = filepath.Join(link, "vedette") })
	codeIs(t, "linked parent", e.bootstrapWith(o, e.bsDocs(t, 5, v1, bsDigest)), api.CodeCoreDataInvalid)
	if _, err := os.Lstat(filepath.Join(realDir, "vedette")); err == nil {
		t.Error("core_data was made through the link")
	}
	m := e.bsOps(t, func(c *ops.Config) { c.CoreData = filepath.Join(base, "nothere", "vedette") })
	codeIs(t, "missing parent", e.bootstrapWith(m, e.bsDocs(t, 5, v1, bsDigest)), api.CodeCoreDataInvalid)
	if _, err := os.Lstat(filepath.Join(base, "nothere")); err == nil {
		t.Error("a missing parent was made")
	}
	e.bsUntouched(t, "refused core_data")
}

// L2: one lock for the daemon and the bootstrap; two bootstraps never run together.
func TestContract_Bootstrap_OneHolderOfTheStateLockAtATime(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	holder := e.bsOps(t, nil)
	unlock, err := holder.LockState()
	if err != nil {
		t.Fatal(err)
	}
	a := e.bsDocs(t, 5, v1, bsDigest)
	other := e.bsOps(t, nil)
	codeIs(t, "a second bootstrap", e.bootstrapWith(other, a), ops.BootstrapDaemonRunning)
	if _, err := other.LockState(); !errors.Is(err, ops.ErrStateLocked) {
		t.Errorf("a second lock: %v", err)
	}
	e.bsUntouched(t, "locked")
	unlock()
	if err := e.bootstrapWith(other, a); err != nil {
		t.Fatalf("after the lock was released: %v", err)
	}
	// The bootstrap let go of it: a daemon can take it now.
	if u, err := holder.LockState(); err != nil {
		t.Errorf("the bootstrap kept the lock: %v", err)
	} else {
		u()
	}
}

// L3: the bootstrap writes to the audit chain the daemon uses: the index it stored, and one line per service.
func TestContract_Bootstrap_WritesTheAuditChain(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	path := filepath.Join(t.TempDir(), "log", "audit.jsonl")
	w, err := server.OpenNoteWriter(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	o := e.bsOps(t, nil)
	o.AuditTo(w)
	if err := e.bootstrapWith(o, e.bsDocs(t, 5, v1, bsDigest)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	f, err := os.Open(path) //nolint:gosec // test: a temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var stored, installed int
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r struct {
			Command string
			Code    string
			Actor   string
			Args    map[string]any `json:"args_redacted"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.Actor != "system" {
			t.Errorf("actor %q", r.Actor)
		}
		switch r.Code {
		case "release_index_stored":
			stored++
		case "installed":
			installed++
			s, _ := r.Args["service"].(string)
			seen[s] = r.Args["version"] == v1 && r.Args["digest"] == bsDigest[s]
		}
	}
	if stored != 1 || installed != 4 || len(seen) != 4 {
		t.Errorf("stored %d installed %d %v", stored, installed, seen)
	}
	for s, ok := range seen {
		if !ok {
			t.Errorf("%s: wrong version or digest in the line", s)
		}
	}
	// A rerun that changes nothing writes no new "installed" line (checked by size).
	w2, err := server.OpenNoteWriter(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w2.Close() }()
	before, _ := os.Stat(path)
	o2 := e.bsOps(t, nil)
	o2.AuditTo(w2)
	if err := e.bootstrapWith(o2, e.bsDocs(t, 5, v1, bsDigest)); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); after.Size() != before.Size() {
		t.Error("a no-op bootstrap wrote audit lines")
	}
}

// L4: a subset run does not put a release beside services that run another one.
func TestContract_Bootstrap_ASubsetDoesNotMixReleases(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	a := e.bsDocs(t, 5, v1, bsDigest)
	a.Services = []string{api.ServiceSensor}
	e.bootstrapOK(t, a)
	v2d := map[string]string{api.ServiceCore: opstest.Digest('5'), api.ServiceSensor: opstest.Digest('6'), api.ServiceHoneypot: opstest.Digest('7'), api.ServiceScan: opstest.Digest('8')}
	b := e.bsDocs(t, 6, v2, v2d)
	b.Services = []string{api.ServiceCore}
	e.forget()
	_, err := e.bootstrap(b)
	codeIs(t, "another release beside sensor", err, ops.BootstrapMixedVersions)
	if _, err := e.m.Unit(api.ServiceCore); err == nil {
		t.Error("core got a unit")
	}
	if w := e.writes(); len(w) != 0 {
		t.Errorf("pulled: %v", w)
	}
	// The same release in another subset is fine.
	c := e.bsDocs(t, 7, v1, bsDigest)
	c.Services = []string{api.ServiceCore, api.ServiceHoneypot}
	e.bootstrapOK(t, c)
}
