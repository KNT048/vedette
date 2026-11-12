package ops_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
	"github.com/knt048/vedette/internal/release"
)

// host.self_update, slice 2a (spec 6.14, D-316; host CONTRACT INV-26, INV-27, INV-29): Check decides every
// refusal and writes nothing; Run copies core's file into staged/ while it hashes it, and parks with a
// staged journal before anything is dispatched. The command is not in the registry yet (slice 2b, with the
// settle goroutine), so these tests add it to the harness themselves.

const (
	suFrom    = "1.3.0"
	suTo      = "1.4.0"
	suRelease = "1.4.0"
)

type suEnv struct {
	m       *opstest.Machine
	rel     *opstest.Release
	o       *ops.Ops
	h       *servertest.Harness
	pkg     []byte
	id      string // core's file
	free    atomic.Uint64
	locked  atomic.Bool
	applier []byte
	n       atomic.Int64
}

func startSU(t *testing.T, version string, muts ...func(*ops.Config, *ops.Deps)) *suEnv {
	t.Helper()
	m := opstest.NewMachine(t)
	e := &suEnv{m: m, rel: opstest.NewRelease(t), pkg: opstest.HostPackage(suTo), applier: []byte("the running vedette-host binary")}
	e.free.Store(100 << 30)
	exe := filepath.Join(m.Rec, "self-exe")
	if err := os.WriteFile(exe, e.applier, 0o700); err != nil { //nolint:gosec // test: a fake binary
		t.Fatal(err)
	}
	m.KeepPackage(suFrom, opstest.HostPackage(suFrom))
	m.KeptDebFields(suFrom)
	m.HostInstalled(suFrom, "installed")
	m.ApplierUnit("inactive")
	m.DebFields("vedette-host", suTo, "amd64")
	m.SimInstall(opstest.SimInstallOK(suFrom, suTo), 0)
	m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	e.id = m.CorePackage(e.pkg)
	all := append([]func(*ops.Config, *ops.Deps){func(c *ops.Config, d *ops.Deps) {
		c.Version = version
		d.Keys = e.rel.Keys
		d.SelfExe = exe
		d.FreeBytes = func(string) (uint64, error) { return e.free.Load(), nil }
		d.LockHeld = func(string) (bool, error) { return e.locked.Load(), nil }
	}}, muts...)
	clock := servertest.NewClock(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)) // one clock for the host and its commands
	e.o = m.Ops(clock.Now, all...)
	e.h = servertest.Prepare(t, append(e.o.Commands(), e.o.SelfUpdateCommand()), func(o *server.Options) {
		o.StateDir, o.Readers, o.Resume, o.Now = m.State, e.o.Readers(), e.o.Resume, clock.Now
	})
	e.o.Start(context.Background(), e.h.Server) // adopts the kept package of the running version
	t.Cleanup(e.o.Close)
	e.h.Serve(t)
	return e
}

// args are the args of a release whose host part is hostVersion with this env's package.
func (e *suEnv) args(t *testing.T, hostVersion string, mutMan ...func(opstest.Doc)) api.HostSelfUpdateArgs {
	t.Helper()
	man := e.rel.HostManifestDoc(suRelease, hostVersion, opstest.HostFileOf(hostVersion, e.pkg))
	for _, f := range mutMan {
		f(man)
	}
	return e.rel.SelfUpdateArgs(suRelease, opstest.JSON(t, e.rel.IndexDoc(5)), opstest.JSON(t, man), e.id)
}

func (e *suEnv) send(t *testing.T, a api.HostSelfUpdateArgs) (api.Run, error) {
	t.Helper()
	rid := strconv.FormatInt(e.n.Add(1), 16)
	return e.h.Client.SelfUpdate(context.Background(), a, strings.Repeat("0", 8-len(rid))+rid+"-5555-4555-8555-555555555555", "admin@example.com")
}

// waitRun waits (on state: the run's record) until the run has ended or is parked.
func (e *suEnv) waitRun(t *testing.T, id string) api.Run {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := e.h.Client.GetRun(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status.Terminal() || r.ParkedDeadline != nil {
			return r
		}
		select {
		case <-deadline.C:
			t.Fatalf("run %s never ended nor parked: %+v", id, r)
		case <-tick.C:
		}
	}
}

func (e *suEnv) suFile(rel string) string { return filepath.Join(e.m.State, "selfupdate", rel) }

func (e *suEnv) stagedFiles() []string {
	es, _ := os.ReadDir(e.suFile("staged"))
	var out []string
	for _, x := range es {
		out = append(out, x.Name())
	}
	return out
}

// stagedDebCalls are the dpkg-deb calls on a staged file (Start also asks it about the kept package it adopts).
func (e *suEnv) stagedDebCalls() [][]string {
	var out [][]string
	for _, c := range e.m.Calls("dpkg-deb") {
		if len(c) > 1 && strings.Contains(c[1], "/selfupdate/staged/") {
			out = append(out, c)
		}
	}
	return out
}

// assertUntouched: no dpkg-deb on a staged file, no simulated install, no systemd-run, nothing staged, no applier, no journal.
func (e *suEnv) assertUntouched(t *testing.T, what string) {
	t.Helper()
	if c := e.stagedDebCalls(); len(c) != 0 {
		t.Errorf("%s: dpkg-deb ran %v", what, c)
	}
	if c := e.m.Calls("systemd-run"); len(c) != 0 {
		t.Errorf("%s: systemd-run ran %v", what, c)
	}
	for _, c := range e.m.Calls("apt-get") {
		if slices.Contains(c, "install") {
			t.Errorf("%s: apt-get ran %v", what, c)
		}
	}
	if s := e.stagedFiles(); len(s) != 0 {
		t.Errorf("%s: staged %v", what, s)
	}
	for _, f := range []string{"applier", "journal.json"} {
		if _, err := os.Lstat(e.suFile(f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %s is there (%v)", what, f, err)
		}
	}
}

func refusedWith(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != status || ce.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

// INV-26 and INV-29: every refusal of Check, in one world that each case changes and puts back; none
// leaves a write behind. Downgrades are refused here (there is no command that goes down).
func TestSelfUpdate_RefusalsAreAllDecidedInCheckWithNoWrite(t *testing.T) {
	t.Parallel()
	e := startSU(t, suFrom)
	journal := e.suFile("journal.json")
	kept := e.suFile("packages/vedette-host_" + suFrom + "_amd64.deb")
	for _, c := range []struct {
		name   string
		status int
		code   string
		set    func(a *api.HostSelfUpdateArgs) (undo func())
	}{
		{"not an appliance", 412, api.CodeNotAppliance, func(*api.HostSelfUpdateArgs) func() {
			e.m.OSRelease("fedora", "40", "Fedora 40")
			return func() { e.m.OSRelease("ubuntu", "24.04", "Ubuntu 24.04.3 LTS") }
		}},
		{"an open self-update", 412, api.CodeTransitionPending, func(*api.HostSelfUpdateArgs) func() {
			_ = os.WriteFile(journal, []byte("{}"), 0o600)
			return func() { _ = os.Remove(journal) }
		}},
		// A unit change still being put right: AfterReady's recovery can then never wait behind a parked
		// self-update (parked-run deferred line 4, decided in the plan, slice 2).
		{"an open unit change", 412, api.CodeTransitionPending, func(*api.HostSelfUpdateArgs) func() {
			p := filepath.Join(e.m.State, "containers", "transition-sensor.json")
			_ = os.WriteFile(p, []byte("{}"), 0o600)
			return func() { _ = os.Remove(p) }
		}},
		{"an open restore", 412, api.CodeTransitionPending, func(*api.HostSelfUpdateArgs) func() {
			p := filepath.Join(e.m.State, "restore.json")
			_ = os.WriteFile(p, []byte("{}"), 0o600)
			return func() { _ = os.Remove(p) }
		}},
		{"an applier alive", 409, api.CodeBusy, func(*api.HostSelfUpdateArgs) func() {
			e.m.ClearRules("systemctl")
			e.m.ApplierUnit("activating")
			return func() { e.m.ClearRules("systemctl"); e.m.ApplierUnit("inactive") }
		}},
		{"a bad signature", 412, api.CodeSignatureInvalid, func(a *api.HostSelfUpdateArgs) func() {
			a.ManifestSig = a.IndexSig
			return func() {}
		}},
		{"another release", 412, api.CodeManifestMismatch, func(a *api.HostSelfUpdateArgs) func() {
			a.Version = "1.4.1"
			return func() {}
		}},
		{"no host part", 412, api.CodeNoHostPackage, func(a *api.HostSelfUpdateArgs) func() {
			*a = e.args(t, suTo, func(d opstest.Doc) { delete(d, "host") })
			return func() {}
		}},
		{"no file for amd64", 412, api.CodePlatformMismatch, func(a *api.HostSelfUpdateArgs) func() {
			*a = e.args(t, suTo, func(d opstest.Doc) {
				f := opstest.HostFileOf(suTo, e.pkg)
				d["host"] = opstest.Doc{"version": suTo, "files": []any{opstest.Doc{"name": strings.Replace(f.Name, "amd64", "arm64", 1), "sha256": f.SHA256, "size": f.Size}}}
			})
			return func() {}
		}},
		{"a test build", 412, api.CodeTestVersionRefused, func(a *api.HostSelfUpdateArgs) func() {
			*a = e.args(t, "1.4.0-test.1")
			return func() {}
		}},
		{"a downgrade", 412, api.CodeDowngradeNotAllowed, func(a *api.HostSelfUpdateArgs) func() {
			*a = e.args(t, "1.2.9")
			return func() {}
		}},
		{"dpkg shows another version", 412, api.CodeCurrentPackageMissing, func(*api.HostSelfUpdateArgs) func() {
			e.m.ClearRules("dpkg-query")
			e.m.HostInstalled("1.2.0", "installed")
			return func() { e.m.ClearRules("dpkg-query"); e.m.HostInstalled(suFrom, "installed") }
		}},
		{"dpkg shows it half installed", 412, api.CodeCurrentPackageMissing, func(*api.HostSelfUpdateArgs) func() {
			e.m.ClearRules("dpkg-query")
			e.m.HostInstalled(suFrom, "half-installed")
			return func() { e.m.ClearRules("dpkg-query"); e.m.HostInstalled(suFrom, "installed") }
		}},
		{"the kept package changed", 412, api.CodeCurrentPackageMissing, func(*api.HostSelfUpdateArgs) func() {
			_ = os.WriteFile(kept, []byte("other bytes"), 0o600)
			return func() { e.m.KeepPackage(suFrom, opstest.HostPackage(suFrom)) }
		}},
		{"core's file is missing", 412, api.CodePackageMissing, func(a *api.HostSelfUpdateArgs) func() {
			a.Package = strings.Repeat("0", 32)
			return func() {}
		}},
		{"core's file has another size", 412, api.CodePackageInvalid, func(*api.HostSelfUpdateArgs) func() {
			_ = os.WriteFile(e.m.CorePackagePath(e.id), append(slices.Clone(e.pkg), 'x'), 0o600)
			return func() { _ = os.WriteFile(e.m.CorePackagePath(e.id), e.pkg, 0o600) }
		}},
		{"core's file is a link", 412, api.CodePackageInvalid, func(*api.HostSelfUpdateArgs) func() {
			p := e.m.CorePackagePath(e.id)
			_ = os.Rename(p, p+".real")
			_ = os.Symlink(p+".real", p)
			return func() { _ = os.Remove(p); _ = os.Rename(p+".real", p) }
		}},
		{"low disk", 412, api.CodeLowDisk, func(*api.HostSelfUpdateArgs) func() {
			e.free.Store(uint64(len(e.pkg)))
			return func() { e.free.Store(100 << 30) }
		}},
		{"dpkg locked", 409, api.CodeDpkgLocked, func(*api.HostSelfUpdateArgs) func() {
			e.locked.Store(true)
			return func() { e.locked.Store(false) }
		}},
		{"dpkg inconsistent", 412, api.CodeDpkgInconsistent, func(*api.HostSelfUpdateArgs) func() {
			e.m.RuleText("dpkg", "--audit", "The following packages are only half configured\n", 0, "", "")
			return func() { e.m.ClearRules("dpkg") }
		}},
	} {
		a := e.args(t, suTo)
		undo := c.set(&a)
		_, err := e.send(t, a)
		undo()
		refusedWith(t, err, c.status, c.code)
		e.assertUntouched(t, c.name)
	}
}

// A dev build (no SemVer version) has no way back and refuses.
func TestSelfUpdate_ADevBuildRefuses(t *testing.T) {
	t.Parallel()
	e := startSU(t, "dev")
	_, err := e.send(t, e.args(t, suTo))
	refusedWith(t, err, 412, api.CodeHostVersionUnknown)
	e.assertUntouched(t, "dev build")
}

// INV-26: the same version is a no-op that touches nothing.
func TestSelfUpdate_SameVersionIsANoOp(t *testing.T) {
	t.Parallel()
	e := startSU(t, suTo)
	run, err := e.send(t, e.args(t, suTo))
	if err != nil {
		t.Fatal(err)
	}
	r := e.waitRun(t, run.RunID)
	res, err := client.ResultOf[api.HostSelfUpdateResult](r)
	if r.Status != api.StatusSucceeded || err != nil || res.Changed || res.From != suTo || res.To != suTo {
		t.Fatalf("%+v %+v %v", r, res, err)
	}
	e.assertUntouched(t, "same version")
	if c := e.m.Calls("dpkg-query"); len(c) != 0 {
		t.Errorf("dpkg-query ran %v", c)
	}
}

// INV-26: a flipped bit in core's file is checksum_mismatch; dpkg never sees anything.
func TestSelfUpdate_ABitFlipInThePackageIsChecksumMismatchAndDpkgNeverRuns(t *testing.T) {
	t.Parallel()
	e := startSU(t, suFrom)
	a := e.args(t, suTo) // hashes the good bytes
	bad := slices.Clone(e.pkg)
	bad[3] ^= 1
	if err := os.WriteFile(e.m.CorePackagePath(e.id), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := e.send(t, a)
	if err != nil {
		t.Fatal(err)
	}
	r := e.waitRun(t, run.RunID)
	if r.Status != api.StatusFailed || r.Error == nil || r.Error.Code != api.CodeChecksumMismatch {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	e.assertUntouched(t, "bit flip")
}

// INV-26 and INV-28 (park first, dispatch after): the run copies core's file into staged/ while it hashes it,
// gives dpkg-deb and apt only that copy, copies the running binary to the applier, writes a staged journal
// (attempt 0, deadline 130 min from the start) and parks with the write lock; nothing is dispatched yet.
// Core's file changed after the copy does not change what was staged.
func TestSelfUpdate_TheStagedCopyIsWhatDpkgGetsAndTheRunParksBeforeAnyDispatch(t *testing.T) {
	t.Parallel()
	e := startSU(t, suFrom)
	run, err := e.send(t, e.args(t, suTo))
	if err != nil {
		t.Fatal(err)
	}
	r := e.waitRun(t, run.RunID)
	if r.Status != api.StatusRunning || r.ParkedDeadline == nil {
		t.Fatalf("not parked: %+v %+v", r, r.Error)
	}
	if err := os.WriteFile(e.m.CorePackagePath(e.id), []byte("swapped by core after the copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha := opstest.SHA(e.pkg)
	staged := e.suFile("staged/" + sha + ".deb")
	if b, err := os.ReadFile(staged); err != nil || string(b) != string(e.pkg) { //nolint:gosec // test path
		t.Fatalf("staged copy %q %v", b, err)
	}
	if got := e.stagedDebCalls(); len(got) != 1 || !slices.Equal(got[0], []string{"--field", staged, "Package", "Version", "Architecture"}) {
		t.Fatalf("dpkg-deb %v", got)
	}
	sim := []string{"-s", "-q", "-o", "Debug::NoLocking=1", "--no-remove", "--no-install-recommends", "install", staged}
	if got := e.m.Calls("apt-get"); !slices.ContainsFunc(got, func(c []string) bool { return slices.Equal(c, sim) }) {
		t.Fatalf("apt-get %v", got)
	}
	for _, bin := range opstest.Bins {
		for _, c := range e.m.Calls(bin) {
			if slices.ContainsFunc(c, func(s string) bool { return strings.Contains(s, e.m.CoreData) }) {
				t.Errorf("%s was given core's path: %v", bin, c)
			}
		}
	}
	if c := e.m.Calls("systemd-run"); len(c) != 0 {
		t.Fatalf("dispatched before the settle goroutine: %v", c)
	}
	st, err := os.Stat(e.suFile("applier"))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("applier %v %v", st, err)
	}
	var j map[string]any
	b, err := os.ReadFile(e.suFile("journal.json"))
	if err != nil || json.Unmarshal(b, &j) != nil {
		t.Fatalf("journal %s %v", b, err)
	}
	started, _ := time.Parse(time.RFC3339Nano, j["started_at"].(string))
	deadline, _ := time.Parse(time.RFC3339Nano, j["deadline"].(string))
	if j["phase"] != "staged" || j["attempt"] != 0.0 || j["run_id"] != run.RunID || j["applier_sha256"] != opstest.SHA(e.applier) ||
		deadline.Sub(started) != 130*time.Minute || !r.ParkedDeadline.Equal(deadline) || j["from"].(map[string]any)["version"] != suFrom {
		t.Fatalf("journal %s, parked until %v", b, r.ParkedDeadline)
	}
	// The run holds the write lock while parked.
	_, err = e.h.Client.Run(context.Background(), api.CmdOSCheck, struct{}{}, "0000ffff-5555-4555-8555-555555555555", "admin@example.com")
	refusedWith(t, err, 409, api.CodeBusy)
}

// INV-26: the self-update path opens no network connection (it imports nothing that could).
func TestSelfUpdate_NoNetworkInTheSelfUpdatePath(t *testing.T) {
	t.Parallel()
	files, _ := filepath.Glob("selfupdate*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == "net" || strings.HasPrefix(p, "net/") || p == "crypto/tls" {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if n < 3 {
		t.Fatalf("found %d files", n)
	}
}

// Adoption at Start (spec 6.14 "Nhận bản đầu") keeps two packages; GET /v1/state/host shows them.
func TestSelfUpdate_StartAdoptsTheKeptPackageAndKeepsTwo(t *testing.T) {
	t.Parallel()
	e := startSU(t, suFrom) // adopts 1.3.0 (no versions.json yet)
	e.m.KeepPackage("1.4.0", opstest.HostPackage("1.4.0"))
	e.m.KeepPackage("1.1.0", opstest.HostPackage("1.1.0"))
	e.m.KeptDebFields("1.4.0")
	// A newer host starts on the same state (install.sh upgraded it): 1.4.0 becomes current, 1.3.0 previous, 1.1.0 goes.
	o2 := e.m.Ops(nil, func(c *ops.Config, d *ops.Deps) { c.Version = "1.4.0"; d.Keys = e.rel.Keys })
	h2 := servertest.Start(t, o2.Commands(), func(o *server.Options) { o.StateDir, o.Readers = e.m.State, o2.Readers() })
	o2.Start(context.Background(), h2.Server)
	t.Cleanup(o2.Close)
	st, err := h2.Client.StateHost(context.Background())
	if err != nil || st.Version != "1.4.0" || st.Previous == nil || st.Previous.Version != suFrom || !slices.Equal(st.PackagesKept, []string{suFrom, "1.4.0"}) || st.Update != nil {
		t.Fatalf("%+v %v", st, err)
	}
	var v struct {
		Current  struct{ Version, SHA256 string }
		Previous *struct{ Version, SHA256 string }
	}
	b, _ := os.ReadFile(e.suFile("versions.json"))
	if json.Unmarshal(b, &v) != nil || v.Current.SHA256 != opstest.SHA(opstest.HostPackage("1.4.0")) || v.Previous.SHA256 != opstest.SHA(opstest.HostPackage(suFrom)) {
		t.Fatalf("versions.json %s", b)
	}
	audit, _ := os.ReadFile(h2.AuditPath)
	if !strings.Contains(string(audit), "host_package_adopted") || !strings.Contains(string(audit), "host_package_removed") {
		t.Fatalf("audit %s", audit)
	}
	// A kept file whose fields dpkg-deb does not confirm is not adopted (review L2); a dev build adopts nothing.
	e.m.KeepPackage("1.5.0", opstest.HostPackage("1.5.0"))
	o4 := e.m.Ops(nil, func(c *ops.Config, _ *ops.Deps) { c.Version = "1.5.0" })
	o4.Start(context.Background(), h2.Server)
	o4.Close()
	o3 := e.m.Ops(nil, func(c *ops.Config, _ *ops.Deps) { c.Version = "dev" })
	o3.Start(context.Background(), h2.Server)
	o3.Close()
	if b2, _ := os.ReadFile(e.suFile("versions.json")); string(b2) != string(b) {
		t.Fatal("a dev build changed versions.json")
	}
}

// The committed vectors of internal/release (signed by the throwaway test keys, with a host part of 1.4.0
// whose sha256 is all zeros): a build without keys refuses with no_trusted_keys, a production build with
// signature_invalid, and a build with -tags releasetestkeys accepts the documents, so the run reaches the copy
// and ends checksum_mismatch (no file hashes to zeros). Nothing is installed in any case.
func TestSelfUpdate_TheEmbeddedKeysOfThisBuild(t *testing.T) {
	t.Parallel()
	tr, kerr := release.Embedded()
	e := startSU(t, suFrom, func(_ *ops.Config, d *ops.Deps) { d.Keys = nil })
	rd := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "release", "testdata", "release", name)) //nolint:gosec // test: fixed vector names
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := base64.StdEncoding.EncodeToString
	id := e.m.CorePackage(make([]byte, 1234))
	a := api.HostSelfUpdateArgs{
		Version: "1.4.0", Index: b(rd("index.json")), IndexSig: b(rd("index.json.minisig")),
		Manifest: b(rd("release-manifest.json")), ManifestSig: b(rd("release-manifest.json.minisig")), Package: id,
	}
	switch run, err := e.send(t, a); {
	case kerr != nil:
		refusedWith(t, err, 412, api.CodeNoTrustedKeys)
	case !tr.TestOnly:
		refusedWith(t, err, 412, api.CodeSignatureInvalid)
	default:
		if err != nil {
			t.Fatal(err)
		}
		if r := e.waitRun(t, run.RunID); r.Status != api.StatusFailed || r.Error == nil || r.Error.Code != api.CodeChecksumMismatch {
			t.Fatalf("%+v %+v", r, r.Error)
		}
	}
	e.assertUntouched(t, "vectors")
}
