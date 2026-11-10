package host_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/internal/release"
)

// vedette-host -bootstrap, the first install (WP-07b part 3, slice 3-8b; spec "Khởi động lần đầu", D-138 M4,
// D-142). Ops.Bootstrap is what the command line calls; the daemon check and the exit codes are tested in
// cmd/vedette-host. The machine is the stateful fake of opstest and a signing environment made for the test.

var bsDigest = map[string]string{
	api.ServiceCore: d1, api.ServiceSensor: d2, api.ServiceHoneypot: d3, api.ServiceScan: d4,
}

var bsOrder = []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan}

// bsDocs builds the four documents of a release holding an image for each of the four services. shape may
// change the unsigned documents before they are signed (and return the signing to use for the index).
func (e *updEnv) bsDocs(t *testing.T, seq uint64, version string, digests map[string]string, shape ...func(idx, man opstest.Doc)) ops.BootstrapArgs {
	t.Helper()
	var imgs []opstest.Img
	for _, s := range bsOrder {
		imgs = append(imgs, opstest.Img{Service: s, Digest: digests[s], Size: 1000})
	}
	idx, man := e.rel.IndexDoc(seq), e.rel.ManifestDoc(version, imgs...)
	for _, f := range shape {
		f(idx, man)
	}
	ir, mr := opstest.JSON(t, idx), opstest.JSON(t, man)
	return ops.BootstrapArgs{Index: ir, IndexSig: e.rel.Sign(ir), Manifest: mr, ManifestSig: e.rel.Sign(mr)}
}

func (e *updEnv) bootstrap(a ops.BootstrapArgs) (lines []string, err error) {
	err = e.o.Bootstrap(context.Background(), a, func(s string) { lines = append(lines, s) })
	return lines, err
}

func (e *updEnv) bootstrapOK(t *testing.T, a ops.BootstrapArgs) []string {
	t.Helper()
	lines, err := e.bootstrap(a)
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, strings.Join(lines, "\n"))
	}
	return lines
}

func (e *updEnv) bsRefused(t *testing.T, name string, a ops.BootstrapArgs, code string) {
	t.Helper()
	_, err := e.bootstrap(a)
	if got, _ := ops.BootstrapCode(err); err == nil || got != code {
		t.Fatalf("%s: want %s, got %v", name, code, err)
	}
	e.bsUntouched(t, name)
}

// bsUntouched: no unit, no record of a version, no podman call that writes.
func (e *updEnv) bsUntouched(t *testing.T, name string) {
	t.Helper()
	for _, s := range bsOrder {
		if _, err := e.m.Unit(s); err == nil {
			t.Errorf("%s: a unit for %s was written", name, s)
		}
		for _, f := range []string{"versions-" + s + ".json"} {
			if _, err := os.Lstat(filepath.Join(e.m.State, "containers", f)); err == nil {
				t.Errorf("%s: %s was written", name, f)
			}
		}
	}
	if w := e.writes(); len(w) != 0 {
		t.Errorf("%s: podman wrote: %v", name, w)
	}
}

type versionsFile struct {
	Current  *struct{ Version, Digest string } `json:"current"`
	Previous *struct{ Version, Digest string } `json:"previous"`
}

func (e *updEnv) versionsFile(t *testing.T, svc string) versionsFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.m.State, "containers", "versions-"+svc+".json")) //nolint:gosec // test: a path under the fake state
	if err != nil {
		t.Fatal(err)
	}
	var v versionsFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestContract_Bootstrap_HappyPathWritesUnitsPulledAndVersions(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	lines := e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	for _, s := range bsOrder {
		got, err := e.m.Unit(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		// Golden: byte for byte what container.start would write (the D-105 writer, install=true).
		if want := e.render(t, s, bsDigest[s]); got != want {
			t.Errorf("%s: unit differs from the template:\n%s", s, got)
		}
		if v := e.versionsFile(t, s); v.Current == nil || v.Current.Version != v1 || v.Current.Digest != bsDigest[s] || v.Previous != nil {
			t.Errorf("%s: versions %+v", s, v)
		}
		if st := e.state(t)[s]; st.LatestPulled == nil || st.LatestPulled.Version == nil || *st.LatestPulled.Version != v1 {
			t.Errorf("%s: no pulled record: %+v", s, st)
		}
	}
	// Podman: one pull per service, by digest, then the tag; and nothing was started.
	for _, s := range bsOrder {
		pull := "pull -q ghcr.io/knt048/vedette-" + s + "@" + bsDigest[s]
		if !slices.Contains(e.writes(), pull) {
			t.Errorf("no %q in %v", pull, e.writes())
		}
	}
	for _, c := range e.ctl() {
		t.Errorf("systemctl was called: %s (the installer reloads and starts)", c)
	}
	if !strings.Contains(lines[len(lines)-1], "daemon-reload") {
		t.Errorf("last line: %q", lines[len(lines)-1])
	}
	// The line of a step never holds a secret or a document.
	for _, l := range lines {
		if strings.Contains(l, "minisign") || strings.Contains(l, "BEGIN") {
			t.Errorf("leaky line %q", l)
		}
	}
}

func TestContract_Bootstrap_SecondRunIsANoOp(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	a := e.bsDocs(t, 5, v1, bsDigest)
	e.bootstrapOK(t, a)
	before := map[string]string{}
	for _, s := range bsOrder {
		before[s] = e.unit(t, s)
	}
	pulled, _ := os.ReadFile(filepath.Join(e.m.State, "containers", "pulled-core.json"))
	e.forget()
	lines := e.bootstrapOK(t, a)
	if w := e.writes(); len(w) != 0 {
		t.Errorf("a second run wrote: %v", w)
	}
	for _, s := range bsOrder {
		if e.unit(t, s) != before[s] {
			t.Errorf("%s: unit changed", s)
		}
	}
	if again, _ := os.ReadFile(filepath.Join(e.m.State, "containers", "pulled-core.json")); string(again) != string(pulled) {
		t.Error("the pulled record was rewritten by a no-op")
	}
	if !strings.Contains(strings.Join(lines, "\n"), "nothing to do") {
		t.Errorf("lines: %v", lines)
	}
}

func TestContract_Bootstrap_ServicesListAndItsLimits(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	for name, svcs := range map[string][]string{"greenbone": {"greenbone"}, "unknown": {"nope"}, "twice": {"core", "core"}, "empty name": {""}} {
		a := e.bsDocs(t, 5, v1, bsDigest)
		a.Services = svcs
		e.bsRefused(t, name, a, ops.BootstrapBadArgs)
	}
	a := e.bsDocs(t, 5, v1, bsDigest)
	a.Services = []string{api.ServiceSensor, api.ServiceCore} // any order
	e.bootstrapOK(t, a)
	if _, err := e.m.Unit(api.ServiceHoneypot); err == nil {
		t.Error("a service that was not asked for got a unit")
	}
	if _, err := e.m.Unit(api.ServiceSensor); err != nil {
		t.Error("sensor has no unit")
	}
	if got := e.versionsFile(t, api.ServiceCore); got.Current == nil {
		t.Error("core has no current")
	}
}

func TestContract_Bootstrap_EveryVerificationRefusalOfPullAppliesAndNothingIsWritten(t *testing.T) {
	t.Parallel()
	other := opstest.Digest('9')
	for _, c := range []struct {
		name string
		code string
		a    func(e *updEnv, t *testing.T) ops.BootstrapArgs
	}{
		{"bad index signature", api.CodeSignatureInvalid, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			a := e.bsDocs(t, 5, v1, bsDigest)
			a.IndexSig = e.rel.Sign([]byte("another document"))
			return a
		}},
		{"bad manifest signature", api.CodeSignatureInvalid, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			a := e.bsDocs(t, 5, v1, bsDigest)
			a.ManifestSig = e.rel.Sign([]byte("another document"))
			return a
		}},
		{"garbage signature", api.CodeSignatureInvalid, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			a := e.bsDocs(t, 5, v1, bsDigest)
			a.ManifestSig = []byte("not a minisig")
			return a
		}},
		{"release revoked", api.CodeReleaseRevoked, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(idx, _ opstest.Doc) { idx["revoked"] = []any{opstest.Revocation("release", v1)} })
		}},
		{"image digest revoked", api.CodeReleaseRevoked, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(idx, _ opstest.Doc) { idx["revoked"] = []any{opstest.Revocation("image_digest", d3)} })
		}},
		{"signing key revoked", api.CodeKeyRevoked, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			a := e.bsDocs(t, 5, v1, bsDigest, func(idx, _ opstest.Doc) { idx["revoked"] = []any{opstest.Revocation("key", e.rel.ActiveKeyID())} })
			a.IndexSig = e.rel.SignBackup(a.Index) // the active key cannot revoke itself: the offline key signs this index
			return a
		}},
		{"platform", api.CodePlatformMismatch, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(_, man opstest.Doc) {
				for _, im := range man["images"].([]any) {
					im.(opstest.Doc)["platforms"] = []string{"linux/arm64"}
				}
			})
		}},
		{"install mode", api.CodeNotAppliance, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(_, man opstest.Doc) { man["install_modes"] = []string{"container"} })
		}},
		{"manifest sha in index", api.CodeManifestMismatch, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(idx, _ opstest.Doc) { idx["channels"].(opstest.Doc)["stable"].(opstest.Doc)["latest"] = v1 })
		}},
		{"scan missing from the manifest", api.CodeDigestNotInManifest, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(_, man opstest.Doc) { man["images"] = man["images"].([]any)[:3] })
		}},
		{"cosign of another digest", api.CodeSignatureInvalid, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(_, man opstest.Doc) {
				man["images"].([]any)[2].(opstest.Doc)["cosign"] = e.rel.CosignSig(api.ServiceHoneypot, other)
			})
		}},
		{"manifest of another registry", api.CodeRegistryNotAllowed, func(e *updEnv, t *testing.T) ops.BootstrapArgs {
			return e.bsDocs(t, 5, v1, bsDigest, func(_, man opstest.Doc) {
				man["images"].([]any)[0].(opstest.Doc)["ref"] = "docker.io/evil/vedette-core:" + v1
			})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			e.bsRefused(t, c.name, c.a(e, t), c.code)
		})
	}
}

func TestContract_Bootstrap_SequenceNeverGoesBackAndTheBuildNeedsKeys(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	a := e.bsDocs(t, 10, v1, bsDigest)
	a.Services = []string{api.ServiceCore}
	e.bootstrapOK(t, a)
	old := e.bsDocs(t, 9, v1, bsDigest)
	_, err := e.bootstrap(old)
	if code, _ := ops.BootstrapCode(err); code != api.CodeSequenceRegress {
		t.Fatalf("an older index: %v", err)
	}
	// A build with no keys refuses everything.
	n := startUpd(t, func(_ *ops.Config, d *ops.Deps) {
		d.Keys = func() (release.Trust, error) { return release.Trust{}, release.ErrNoTrustKeys }
	})
	n.bsRefused(t, "no keys", n.bsDocs(t, 5, v1, bsDigest), api.CodeNoTrustedKeys)
}

func TestContract_Bootstrap_RefusesWhatIsNotAnApplianceOrIsMisconfigured(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.OSRelease("fedora", "40", "Fedora 40")
	e.bsRefused(t, "not debian or ubuntu", e.bsDocs(t, 5, v1, bsDigest), api.CodeNotAppliance)

	i := startUpd(t, func(c *ops.Config, _ *ops.Deps) { c.SensorUID, c.SensorGID = 0, 0 })
	i.bsRefused(t, "no sensor ids", i.bsDocs(t, 5, v1, bsDigest), api.CodeHostConfIncomplete)

	w := startUpd(t)
	if err := os.Chmod(w.m.UnitsDir(), 0o777); err != nil { //nolint:gosec // test: an unsafe unit directory
		t.Fatal(err)
	}
	w.bsRefused(t, "unit directory open to others", w.bsDocs(t, 5, v1, bsDigest), api.CodeUnitUnsafe)
}

func TestContract_Bootstrap_AlreadyInstalledRefusesAnotherRelease(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	units := map[string]string{}
	for _, s := range bsOrder {
		units[s] = e.unit(t, s)
	}
	e.forget()
	v2d := map[string]string{api.ServiceCore: opstest.Digest('5'), api.ServiceSensor: opstest.Digest('6'), api.ServiceHoneypot: opstest.Digest('7'), api.ServiceScan: opstest.Digest('8')}
	_, err := e.bootstrap(e.bsDocs(t, 6, v2, v2d))
	if code, _ := ops.BootstrapCode(err); code != ops.BootstrapAlreadyInstalled {
		t.Fatalf("err = %v", err)
	}
	if w := e.writes(); len(w) != 0 {
		t.Errorf("a refused bootstrap pulled: %v", w)
	}
	for _, s := range bsOrder {
		if e.unit(t, s) != units[s] || e.versionsFile(t, s).Current.Version != v1 {
			t.Errorf("%s changed", s)
		}
	}
	// Even with -force-units: a recorded release is never overwritten by the bootstrap.
	a := e.bsDocs(t, 7, v2, v2d)
	a.ForceUnits = true
	_, err = e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != ops.BootstrapAlreadyInstalled {
		t.Fatalf("forced: %v", err)
	}
}

func TestContract_Bootstrap_ForeignUnitNeedsForceAndTheOldBytesAreKept(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	foreign := "[Container]\nImage=ghcr.io/knt048/vedette-core@" + d1 + "\n# edited by hand\n"
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-core.container"), []byte(foreign), 0o644); err != nil { //nolint:gosec // test: a unit file of the fake root
		t.Fatal(err)
	}
	a := e.bsDocs(t, 5, v1, bsDigest)
	_, err := e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != ops.BootstrapUnitForeign {
		t.Fatalf("err = %v", err)
	}
	if e.unit(t, api.ServiceCore) != foreign {
		t.Error("a refused bootstrap changed the foreign unit")
	}
	if w := e.writes(); len(w) != 0 {
		t.Errorf("a refused bootstrap pulled: %v", w)
	}
	for _, s := range bsOrder[1:] {
		if _, err := e.m.Unit(s); err == nil {
			t.Errorf("%s got a unit although the bootstrap was refused", s)
		}
	}

	a.ForceUnits = true
	lines := e.bootstrapOK(t, a)
	if got := e.unit(t, api.ServiceCore); got != e.render(t, api.ServiceCore, d1) {
		t.Errorf("not replaced:\n%s", got)
	}
	if prev, err := e.m.Prev(api.ServiceCore); err != nil || prev != foreign {
		t.Errorf("the replaced bytes were not kept: %q %v", prev, err)
	}
	var said int
	for _, l := range lines {
		if strings.Contains(l, "replacing vedette-core.container") {
			said++
		}
		if strings.Contains(l, "replacing vedette-sensor.container") {
			t.Errorf("a unit that was not there was reported replaced: %q", l)
		}
	}
	if said != 1 {
		t.Errorf("replaced files reported %d times: %v", said, lines)
	}
}

func TestContract_Bootstrap_OurUnitOfAnotherImageIsRefusedWithoutForce(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit(api.ServiceSensor, opstest.Digest('a'), true) // installed by something else, no versions record
	a := e.bsDocs(t, 5, v1, bsDigest)
	_, err := e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != ops.BootstrapAlreadyInstalled {
		t.Fatalf("err = %v", err)
	}
	// A unit that already pins this very image (an installer that wrote it) is left alone and only recorded.
	e2 := startUpd(t)
	e2.m.InstallUnit(api.ServiceSensor, d2, false) // stopped with persist: no [Install]; it stays so
	before := e2.unit(t, api.ServiceSensor)
	e2.bootstrapOK(t, e2.bsDocs(t, 5, v1, bsDigest))
	if e2.unit(t, api.ServiceSensor) != before {
		t.Error("a unit that is ours and pins this image was rewritten")
	}
	if v := e2.versionsFile(t, api.ServiceSensor); v.Current == nil || v.Current.Digest != d2 {
		t.Errorf("versions %+v", v)
	}
}

func TestContract_Bootstrap_AFailedPullLeavesNoUnitAndARerunFinishes(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	// The third image (honeypot) cannot be pulled, until the marker is lifted.
	e.m.Rule("podman", "pull -q ghcr.io/knt048/vedette-honeypot@", "", 125, "honeypot-down", "")
	e.m.Mark("honeypot-down", true)
	a := e.bsDocs(t, 5, v1, bsDigest)
	_, err := e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != api.CodePullFailed {
		t.Fatalf("err = %v", err)
	}
	for _, s := range bsOrder {
		if _, err := e.m.Unit(s); err == nil {
			t.Errorf("%s has a unit after a failed bootstrap", s)
		}
		if _, err := os.Lstat(filepath.Join(e.m.State, "containers", "versions-"+s+".json")); err == nil {
			t.Errorf("%s has a version record after a failed bootstrap", s)
		}
	}
	// What was verified and pulled stays (a retry finds it), and the host can still do its normal work.
	if st := e.state(t); st[api.ServiceCore].LatestPulled == nil || st[api.ServiceHoneypot].LatestPulled != nil {
		t.Errorf("pulled records after the failure: core %+v honeypot %+v", st[api.ServiceCore].LatestPulled, st[api.ServiceHoneypot].LatestPulled)
	}
	e.m.Mark("honeypot-down", false)
	e.forget()
	e.bootstrapOK(t, a)
	for _, s := range bsOrder {
		if e.unit(t, s) != e.render(t, s, bsDigest[s]) || e.versionsFile(t, s).Current == nil {
			t.Errorf("%s not installed after the rerun", s)
		}
	}
	for _, w := range e.writes() { // core and sensor were pulled and tagged before: the rerun does not touch them
		if strings.Contains(w, "vedette-core@") || strings.Contains(w, "vedette-sensor@") {
			t.Errorf("the rerun pulled again: %s", w)
		}
	}
}

func TestContract_Bootstrap_MakesCoreDataWhenMissing(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	if err := os.RemoveAll(e.m.CoreData); err != nil {
		t.Fatal(err)
	}
	e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	st, err := os.Stat(e.m.CoreData)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("core_data: %v %v", st, err)
	}
	// An existing one is core's own and is left as it is.
	e2 := startUpd(t)
	if err := os.Chmod(e2.m.CoreData, 0o750); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	e2.bootstrapOK(t, e2.bsDocs(t, 5, v1, bsDigest))
	if st, _ := os.Stat(e2.m.CoreData); st.Mode().Perm() != 0o750 {
		t.Errorf("an existing core_data was changed: %v", st.Mode())
	}
	// Not a directory: refused, nothing written.
	e3 := startUpd(t)
	_ = os.RemoveAll(e3.m.CoreData)
	if err := os.WriteFile(e3.m.CoreData, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e3.bsRefused(t, "core_data is a file", e3.bsDocs(t, 5, v1, bsDigest), api.CodeCoreDataInvalid)
}

// After the bootstrap the versions are known: a newer pulled release switches (no current_version_unknown),
// and the downgrade rule has something to compare.
func TestContract_Bootstrap_ThenContainerStartSwitchesAndDowngradesAreRefused(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	e.seq = 5
	e.m.SetRunning(api.ServiceSensor, true) // the installer started it
	newer := relSpec{version: v2, core: opstest.Digest('5'), sensor: opstest.Digest('6')}
	e.pullRel(t, api.ServiceSensor, newer)
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs(api.ServiceSensor, v2)))
	if !res.Restarted || res.Version == nil || *res.Version != v2 || res.Digest != newer.sensor {
		t.Fatalf("%+v", res)
	}
	if v := e.versionsFile(t, api.ServiceSensor); v.Current.Version != v2 || v.Previous == nil || v.Previous.Version != v1 {
		t.Fatalf("versions %+v", v)
	}
	older := relSpec{version: "0.9.0", core: opstest.Digest('b'), sensor: opstest.Digest('c')}
	e.pullRel(t, api.ServiceSensor, older)
	e.m.PresentImage(api.ServiceSensor, older.sensor, older.version)
	e.refused(t, api.CmdContainerStart, e.startArgs(api.ServiceSensor, older.version), 412, api.CodeDowngradeNotAllowed)
}

// ---- real vectors (go test -tags releasetestkeys) ---------------------------------------------------

func TestContract_Bootstrap_TheCommittedVectorsOfThisBuild(t *testing.T) {
	t.Parallel()
	_, kerr := release.Embedded()
	e := startSys(t) // no Deps.Keys: the keys compiled into this build
	e.m.StatefulPodman()
	e.m.MakeUnitsDir()
	rd := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "release", "testdata", "release", name)) //nolint:gosec // test: fixed vector names
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a := ops.BootstrapArgs{
		Index: rd("index.json"), IndexSig: rd("index.json.minisig"), Manifest: rd("release-manifest.json"), ManifestSig: rd("release-manifest.json.minisig"),
		Services: []string{api.ServiceCore, api.ServiceSensor},
	}
	run := func(a ops.BootstrapArgs) error { return e.o.Bootstrap(context.Background(), a, func(string) {}) }
	if kerr != nil { // a production build without keys refuses everything
		if code, _ := ops.BootstrapCode(run(a)); code != api.CodeNoTrustedKeys {
			t.Fatalf("code %s", code)
		}
		if _, err := e.m.Unit(api.ServiceCore); err == nil {
			t.Fatal("a build without keys wrote a unit")
		}
		return
	}
	if err := run(a); err != nil {
		t.Fatal(err)
	}
	const vectorCore = "sha256:449b697acb4a314e61ae461e8c35e3422924f1d126a22e70eed0ab0b1e0ccb0a"
	u, err := e.m.Unit(api.ServiceCore)
	if err != nil || !strings.Contains(u, "@"+vectorCore+"\n") {
		t.Fatalf("unit %q %v", u, err)
	}
	// A bit flipped in a signed vector is refused with the committed signatures, and the box keeps what it has.
	bad := a
	bad.Manifest = append([]byte{}, a.Manifest...)
	bad.Manifest[20] ^= 0x01
	if code, _ := ops.BootstrapCode(run(bad)); code != api.CodeSignatureInvalid {
		t.Fatalf("a flipped bit: %s", code)
	}
}

// ---- the way out of core_data_unrecoverable ------------------------------------------------------------

// unrecoverable writes the journal the host leaves when it gave up putting core's data back (D-138 N1c).
func (e *updEnv) unrecoverable(t *testing.T, unrecoverable bool) {
	t.Helper()
	sha := strings.Repeat("a", 64)
	j := map[string]any{
		"service": "core", "op": "start", "phase": "pending", "digest": d1, "prev_sha256": sha, "new_sha256": sha,
		"was_active": true, "at": "2026-11-10T08:00:00Z", "run_id": "", "unrecoverable": unrecoverable, "db_revert": "backup", "backup_id": strings.Repeat("b", 32),
	}
	b, _ := json.Marshal(j)
	if err := os.WriteFile(e.m.TransitionPath("core"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestContract_Restore_IsTheWayOutOfCoreDataUnrecoverable(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit(api.ServiceCore, d1, true)
	e.m.SetRunning(api.ServiceCore, true)
	e.m.WriteDB("db: good")
	b := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual", IncludeSecrets: true}))
	e.m.WriteDB("db: damaged by the interrupted change")

	e.unrecoverable(t, true)
	// Every other command that touches core is still refused.
	e.refused(t, api.CmdContainerStart, e.startArgs(api.ServiceCore, ""), 412, api.CodeTransitionPending)
	e.refused(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"}, 412, api.CodeTransitionPending)
	// And a journal the host is still working on is not a way out: the restore must not run on a half-swapped core.
	e.unrecoverable(t, false)
	e.refused(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: b.BackupID, Snapshot: e.snap()}, 412, api.CodeTransitionPending)
	if e.m.DB() != "db: damaged by the interrupted change" {
		t.Fatal("a refused restore changed core's database")
	}

	e.unrecoverable(t, true)
	r := e.ok(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: b.BackupID, Snapshot: e.snap()})
	if res := result[api.BackupRestoreResult](t, r); res.RestoredBackupID != b.BackupID || len(res.Health) != 1 || !res.Health[0].OK {
		t.Fatalf("%+v", res)
	}
	if e.m.DB() != "db: good" {
		t.Errorf("the database is %q", e.m.DB())
	}
	if e.journal(api.ServiceCore) {
		t.Error("the journal of the unrecoverable change is still there")
	}
	if n := e.notes(t, "core_data_recovered"); len(n) != 1 || n[0]["restored_backup_id"] != b.BackupID {
		t.Errorf("audit lines: %v", n)
	}
	// Core's commands work again.
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"})
}

func TestContract_Restore_AFailedRecoveryKeepsTheJournal(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit(api.ServiceCore, d1, true)
	e.m.SetRunning(api.ServiceCore, true)
	b := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual", IncludeSecrets: true}))
	e.unrecoverable(t, true)
	// Core does not come up on the restored data: the previous state is put back and the journal stays.
	e.m.SetHealthSequence(api.ServiceCore, "unhealthy")
	e.m.Rule("systemctl", "start vedette-core.service", "", 1, "", "")
	e.final(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: b.BackupID, Snapshot: e.snap()}, api.StatusFailed, "")
	if !e.journal(api.ServiceCore) {
		t.Error("the journal was removed although the restore did not work")
	}
	if n := e.notes(t, "core_data_recovered"); len(n) != 0 {
		t.Errorf("recovery audited for a failed restore: %v", n)
	}
}
