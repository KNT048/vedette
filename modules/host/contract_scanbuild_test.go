package host_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

// container.pull of scan builds the image with nmap on the box (host CONTRACT INV-17 and INV-19; D-113 (7), D-147): the signed base is
// pulled, verified and tagged like any image, then podman builds localhost/vedette-scan-nmap:<version> from the constant Containerfile with a
// fixed argv, the host looks at the effect (nmap --version in the new image), and the record holds the built image's ID.

var scanBase = opstest.Digest('7')

const scanTag = "localhost/vedette-scan-nmap:"

// scanArgs is a pull of scan at version with the given index sequence; the manifest holds only the scan base image.
func (e *updEnv) scanArgs(t *testing.T, version string) api.ContainerPullArgs {
	t.Helper()
	e.seq++
	man := e.rel.ManifestDoc(version, opstest.Img{Service: api.ServiceScan, Digest: scanBase, Size: 4000})
	return e.argsFor(t, api.ServiceScan, version, e.rel.IndexDoc(e.seq), man)
}

type scanRecord struct {
	Version, Digest, BaseDigest, NmapVersion string
}

func (e *updEnv) scanRecord(t *testing.T) scanRecord {
	t.Helper()
	b, err := os.ReadFile(e.pulledFile(api.ServiceScan))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Version     string `json:"version"`
		Digest      string `json:"digest"`
		BaseDigest  string `json:"base_digest"`
		NmapVersion string `json:"nmap_version"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return scanRecord{r.Version, r.Digest, r.BaseDigest, r.NmapVersion}
}

func TestContract_Scan_PullBuildsTheImageOnTheBoxAndRecordsIt(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.pull(t, e.scanArgs(t, v1))
	// The fixed argv, in order: pull the verified base by digest, tag it, then build over a context of the host's own, and check nmap by running it.
	var seq []string
	for _, c := range e.podman() {
		if slices.Contains([]string{"pull", "tag", "build", "run"}, c[0]) {
			seq = append(seq, c[0])
		}
	}
	if !slices.Equal(seq, []string{"pull", "tag", "build", "run"}) {
		t.Fatalf("podman did %v", seq)
	}
	builds := e.m.Builds()
	if len(builds) != 1 {
		t.Fatalf("builds: %v", builds)
	}
	f := strings.Fields(builds[0])
	// The build's network is vedette-int and nothing else (#467: the one network Docker's FORWARD drop lets through, D-267).
	if len(f) != 14 || f[0] != "build" || f[1] != "--pull=never" || f[2] != "--no-cache" || f[3] != "--network" || f[4] != "vedette-int" || f[5] != "--iidfile" ||
		f[6] != f[13]+"/iid" || f[8] != "BASE_IMAGE=ghcr.io/knt048/vedette-scan@"+scanBase || f[10] != "NMAP_MIN_VERSION=7.95" || f[12] != scanTag+v1 || !filepath.IsAbs(f[13]) {
		t.Errorf("build argv: %q", f)
	}
	for _, a := range f {
		if strings.HasPrefix(a, "--network=") || strings.HasPrefix(a, "--net=") || a == "host" {
			t.Errorf("the build argv sets another network: %q", f)
		}
	}
	// Nothing of the build is left behind in the state directory.
	if _, err := os.Stat(filepath.Join(e.m.State, "build")); err == nil {
		t.Error("the build context was not removed")
	}
	id := opstest.BuiltID(1)
	runs := e.m.NmapRuns()
	if len(runs) != 1 || !strings.Contains(runs[0], "--network none") || !strings.Contains(runs[0], "--read-only") || !strings.Contains(runs[0], "--cap-drop ALL") || !strings.Contains(runs[0], "--memory=256m --pids-limit=64 ") ||
		!strings.HasSuffix(runs[0], "--entrypoint nmap "+id+" --version") {
		t.Errorf("the nmap check: %v", runs)
	}
	if got := e.m.ImageTag(scanTag + v1); got != "sha256:"+id {
		t.Errorf("the tag %s%s points at %q", scanTag, v1, got)
	}
	// The record: Digest is the built image's ID (what the unit pins), BaseDigest the signed one, and the nmap version that was installed.
	if r := e.scanRecord(t); r.Version != v1 || r.Digest != "sha256:"+id || r.BaseDigest != scanBase || r.NmapVersion != "7.95" {
		t.Errorf("record: %+v", r)
	}
	if st := e.state(t)[api.ServiceScan]; st.LatestPulled == nil || st.LatestPulled.Digest != "sha256:"+id {
		t.Errorf("state: %+v", st.LatestPulled)
	}
	// A second pull of the same version builds again (a newer nmap may be out) and the previous image is not removed by the pull.
	e.pull(t, e.scanArgs(t, v1))
	if got := e.m.ImageTag(scanTag + v1); got != "sha256:"+opstest.BuiltID(2) || !e.m.ImagePresent("sha256:"+id) {
		t.Errorf("after the second pull: tag %q, first image present %t", got, e.m.ImagePresent("sha256:"+id))
	}
}

func TestContract_Scan_AFailedBuildKeepsThePreviousImageAndReportsScanBuildFailed(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		setup func(e *updEnv)
		built bool // a second image was made (and must be gone again)
		// tagLost: the step that puts the tag back failed, so the tag is gone with the new image; the previous image itself must stay.
		tagLost bool
	}{
		"podman build fails (no mirror)":   {setup: func(e *updEnv) { e.m.Mark("build-fails", true) }},
		"podman leaves no tag":             {setup: func(e *updEnv) { e.m.Mark("build-no-tag", true) }, built: true},
		"podman writes no iid file":        {setup: func(e *updEnv) { e.m.Mark("build-no-iid", true) }, built: true},
		"the iid file is not an ID":        {setup: func(e *updEnv) { e.m.Mark("build-bad-iid", true) }, built: true},
		"the tag cannot be put back":       {setup: func(e *updEnv) { e.m.Mark("nmap-garbage", true); e.m.Mark("tag-id-fails", true) }, built: true, tagLost: true},
		"nmap does not run":                {setup: func(e *updEnv) { e.m.Mark("nmap-fails", true) }, built: true},
		"the version line is not nmap's":   {setup: func(e *updEnv) { e.m.Mark("nmap-garbage", true) }, built: true},
		"nmap is older than the floor":     {setup: func(e *updEnv) { e.m.NmapVersion("7.80") }, built: true},
		"the version line carries a shell": {setup: func(e *updEnv) { e.m.NmapVersion("7.95$(id)") }, built: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			e.pull(t, e.scanArgs(t, v1)) // image 1, tagged, recorded
			first := "sha256:" + opstest.BuiltID(1)
			before, _ := os.ReadFile(e.pulledFile(api.ServiceScan))
			c.setup(e)
			r := e.final(t, api.CmdContainerPull, e.scanArgs(t, v1), api.StatusFailed, api.CodeScanBuildFailed)
			if r.Error == nil || strings.Contains(r.Error.Message, "7.95$(id)") {
				t.Errorf("error: %+v", r.Error)
			}
			// The previous image is where it was: present, with the tag, and the record of the pull is as it was.
			if !e.m.ImagePresent(first) || (!c.tagLost && e.m.ImageTag(scanTag+v1) != first) {
				t.Errorf("the previous image: present %t, tag %q", e.m.ImagePresent(first), e.m.ImageTag(scanTag+v1))
			}
			after, _ := os.ReadFile(e.pulledFile(api.ServiceScan))
			if string(before) != string(after) {
				t.Errorf("the record changed:\n%s\n%s", before, after)
			}
			if second := "sha256:" + opstest.BuiltID(2); c.built && (e.m.ImagePresent(second) || !slices.Contains(e.m.ImageRemoved(), second)) {
				t.Errorf("the image that failed the check was not removed (removed: %v)", e.m.ImageRemoved())
			}
			// The pull of the base counts: it is on the machine, tagged, and a retry pulls nothing.
			if !e.m.ImagePresent(scanBase) || e.m.ImageTag("localhost/vedette-scan:"+v1) != scanBase {
				t.Error("the base image is not where the pull left it")
			}
		})
	}
}

// L6: a first build (nothing to put back) that fails the nmap check leaves no image, no tag and no record.
func TestContract_Scan_AFirstBuildThatFailsTheCheckLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.Mark("nmap-garbage", true)
	e.final(t, api.CmdContainerPull, e.scanArgs(t, v1), api.StatusFailed, api.CodeScanBuildFailed)
	first := "sha256:" + opstest.BuiltID(1)
	if e.m.ImagePresent(first) || e.m.ImageTag(scanTag+v1) != "" || !slices.Contains(e.m.ImageRemoved(), first) {
		t.Errorf("the failed image is still there: present %t tag %q removed %v", e.m.ImagePresent(first), e.m.ImageTag(scanTag+v1), e.m.ImageRemoved())
	}
	if _, err := os.Stat(e.pulledFile(api.ServiceScan)); err == nil {
		t.Error("a record was made")
	}
	if !e.m.ImagePresent(scanBase) {
		t.Error("the base image is gone")
	}
}

// L1: the host never removes an image that a unit, record or container names, even when it is the one a failed build made.
func TestContract_Scan_AFailedBuildDoesNotRemoveAnImageTheUnitPins(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	second := "sha256:" + opstest.BuiltID(2)
	e.m.InstallUnit(api.ServiceScan, second, true) // the unit already pins what the next build will be called
	e.m.Mark("nmap-garbage", true)
	e.final(t, api.CmdContainerPull, e.scanArgs(t, v1), api.StatusFailed, api.CodeScanBuildFailed) // build 1 (not pinned): removed
	e.final(t, api.CmdContainerPull, e.scanArgs(t, v1), api.StatusFailed, api.CodeScanBuildFailed) // build 2 is the pinned one
	if !e.m.ImagePresent(second) || slices.Contains(e.m.ImageRemoved(), second) {
		t.Errorf("the image the unit pins was removed: present %t, removed %v", e.m.ImagePresent(second), e.m.ImageRemoved())
	}
	if !slices.Contains(e.m.ImageRemoved(), "sha256:"+opstest.BuiltID(1)) {
		t.Errorf("the first, unpinned image was not removed: %v", e.m.ImageRemoved())
	}
}

func TestContract_Scan_ABuildThatCannotRunLeavesNoRecordOnAFirstPull(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.Mark("build-fails", true)
	e.final(t, api.CmdContainerPull, e.scanArgs(t, v1), api.StatusFailed, api.CodeScanBuildFailed)
	if _, err := os.Stat(e.pulledFile(api.ServiceScan)); err == nil {
		t.Error("a record was made for a pull whose build failed")
	}
	if e.state(t)[api.ServiceScan].LatestPulled != nil {
		t.Error("the state shows a pulled scan")
	}
	// A retry once the mirror is back: the base is already here (no second pull), the build runs and the record is made.
	e.m.Mark("build-fails", false)
	e.forget()
	e.pull(t, e.scanArgs(t, v1))
	if e.pulls() != 0 {
		t.Errorf("the retry pulled the base again: %v", e.podman())
	}
	if r := e.scanRecord(t); r.Digest != "sha256:"+opstest.BuiltID(1) {
		t.Errorf("record: %+v", r)
	}
}

// container.start of scan runs the locally built image: the unit pins the image ID, the effect check compares the container's image ID,
// a rollback goes back to the previous built image, and the journal and ourUnit logic recognise every unit on the way (D-105, D-138, D-147).
func TestContract_Scan_StartAndRollbackUseTheLocallyBuiltImage(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.pull(t, e.scanArgs(t, v1))
	id1, id2 := "sha256:"+opstest.BuiltID(1), "sha256:"+opstest.BuiltID(2)
	// The bootstrap leaves a unit pinning the built image; the first start with its version records what runs.
	e.m.InstallUnit(api.ServiceScan, id1, true)
	e.m.SetRunning(api.ServiceScan, true)
	res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v1)))
	if res.Restarted || res.Digest != id1 {
		t.Fatalf("adopt: %+v", res)
	}
	// A plain start restarts the unit and sees the image ID healthy.
	if r := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceScan, Restart: true})); !r.Healthy || r.Digest != id1 {
		t.Fatalf("restart: %+v", r)
	}
	// A new release: pulled (second build), then started: the unit is rewritten to pin the new ID and the effect check wants that ID.
	e.pull(t, e.scanArgs(t, v2))
	res = result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v2)))
	if !res.Restarted || !res.Healthy || res.Digest != id2 || res.PreviousDigest == nil || *res.PreviousDigest != id1 {
		t.Fatalf("switch: %+v", res)
	}
	if got, want := e.unit(t, api.ServiceScan), e.render(t, api.ServiceScan, id2); got != want || !strings.Contains(got, "\nImage="+strings.TrimPrefix(id2, "sha256:")+"\n") {
		t.Errorf("the unit after the switch:\n%s", got)
	}
	if e.journal(api.ServiceScan) {
		t.Error("a journal is left")
	}
	// The image the new unit asks for must be the one that runs: a container that reports another ID is not "healthy".
	if v := e.versionsFile(t, api.ServiceScan); v.Current == nil || v.Current.Digest != id2 || v.Previous == nil || v.Previous.Digest != id1 {
		t.Errorf("versions: %+v", v)
	}
	// Roll back: the previous built image is still on the machine (retention keeps it), the unit pins it again.
	if !e.m.ImagePresent(id1) {
		t.Fatal("the previous built image is gone")
	}
	// L5: the switch wrote the credential volume units (a start); a rollback only puts the previous unit back and does not write them.
	for _, role := range []string{"passive", "active"} {
		p := filepath.Join(e.m.UnitsDir(), "vedette-creds-"+role+".volume")
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the switch left no %s: %v", p, err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	rb := result[api.ContainerRollbackResult](t, e.ok(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: api.ServiceScan}))
	for _, role := range []string{"passive", "active"} {
		if _, err := os.Stat(filepath.Join(e.m.UnitsDir(), "vedette-creds-"+role+".volume")); err == nil {
			t.Errorf("a rollback wrote the %s volume unit", role)
		}
	}
	if rb.Digest != id1 || rb.FromDigest != id2 {
		t.Errorf("rollback: %+v", rb)
	}
	if e.unit(t, api.ServiceScan) != e.render(t, api.ServiceScan, id1) {
		t.Error("the unit after the rollback is not the previous one")
	}
	// The built images carry names of the scan repositories, so retention treats them as the service's; none was removed that a record names.
	for _, d := range e.m.ImageRemoved() {
		if d == id1 || d == id2 {
			t.Errorf("retention removed %s, which a record names", d)
		}
	}
}

func TestContract_Scan_AStartWhoseImageIsGoneIsRefusedAndAnUnhealthyNewImageIsRolledBack(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.pull(t, e.scanArgs(t, v1))
	id1, id2 := "sha256:"+opstest.BuiltID(1), "sha256:"+opstest.BuiltID(2)
	e.m.InstallUnit(api.ServiceScan, id1, true)
	e.m.SetRunning(api.ServiceScan, true)
	e.ok(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v1))
	e.pull(t, e.scanArgs(t, v2))
	// The new image does not become healthy: the old unit comes back, and the service runs the first image again.
	e.m.BadImage(id2)
	r := e.final(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v2), api.StatusReverted, api.CodeUnitFailed)
	_ = r
	if e.unit(t, api.ServiceScan) != e.render(t, api.ServiceScan, id1) {
		t.Error("the old unit was not put back")
	}
	// The image of the pulled version is removed from the machine: the start is refused (not_pulled), nothing is written.
	e.m.RemoveImage(id2)
	e.refused(t, api.CmdContainerStart, e.startArgs(api.ServiceScan, v2), 412, api.CodeNotPulled)
}

// bsNothingButScan asserts the first install wrote no unit and no versions file for any service but the foreign scan unit it was given.
func (e *updEnv) bsNothingButScan(t *testing.T, name string) {
	t.Helper()
	for _, s := range bsOrder {
		if s != api.ServiceScan {
			if _, err := e.m.Unit(s); err == nil {
				t.Errorf("%s: a unit for %s was written", name, s)
			}
		}
		if _, err := os.Lstat(filepath.Join(e.m.State, "containers", "versions-"+s+".json")); err == nil {
			t.Errorf("%s: a versions file for %s was written", name, s)
		}
	}
}

// INV-22 (M1): every refusal of the bootstrap is decided before the first unit is written, scan's included. A scan unit that is not
// ours is refused before any pull, and one that pins another image is refused after the build but before any write.
func TestContract_Bootstrap_AScanRefusalComesBeforeTheFirstWrite(t *testing.T) {
	t.Parallel()
	const foreign = "[Container]\nImage=docker.io/library/alpine\n"
	e := startUpd(t)
	a := e.bsDocs(t, 5, v1, bsDigest)
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-scan.container"), []byte(foreign), 0o644); err != nil { //nolint:gosec // a unit file of the fake root
		t.Fatal(err)
	}
	_, err := e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != ops.BootstrapUnitForeign {
		t.Fatalf("a foreign scan unit: %v", err)
	}
	e.bsNothingButScan(t, "foreign")
	if w := e.writes(); len(w) != 0 {
		t.Errorf("podman wrote before the refusal: %v", w)
	}
	if got := e.unit(t, api.ServiceScan); got != foreign {
		t.Errorf("the foreign unit was changed: %q", got)
	}

	// A unit of ours that pins another image: known only after the build, still before any write.
	e2 := startUpd(t)
	e2.m.InstallUnit(api.ServiceScan, "sha256:"+opstest.BuiltID(99), true)
	before := e2.unit(t, api.ServiceScan)
	_, err = e2.bootstrap(e2.bsDocs(t, 5, v1, bsDigest))
	// L-d: the rebuilt image has a new ID; the message says what to do, and does not send the operator to container.pull.
	if code, msg := ops.BootstrapCode(err); code != ops.BootstrapAlreadyInstalled || !strings.Contains(msg, "-force-units") || !strings.Contains(msg, "container.start") || strings.Contains(msg, "container.pull") {
		t.Fatalf("a scan unit pinning another image: %v", err)
	}
	e2.bsNothingButScan(t, "pins another image")
	if e2.unit(t, api.ServiceScan) != before {
		t.Error("the scan unit was changed")
	}
}

// M2: a box that cannot build the scan image (no Debian mirror) still gets core, sensor and honeypot; scan is skipped with a line, no
// unit, no version, no record, and the bootstrap succeeds. Running it again once the build works installs scan.
func TestContract_Bootstrap_AFailedScanBuildSkipsScanAndInstallsTheRest(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.Mark("build-fails", true)
	lines := e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	for _, s := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot} {
		if e.unit(t, s) != e.render(t, s, bsDigest[s]) || e.versionsFile(t, s).Current == nil {
			t.Errorf("%s not installed", s)
		}
	}
	if _, err := e.m.Unit(api.ServiceScan); err == nil {
		t.Error("a scan unit was written")
	}
	for _, f := range []string{"versions-scan.json", "pulled-scan.json"} {
		if _, err := os.Lstat(filepath.Join(e.m.State, "containers", f)); err == nil {
			t.Errorf("%s exists", f)
		}
	}
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "skipped scan:") && strings.Contains(l, "deb.debian.org")
	}) ||
		!slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "skipped: scan") }) {
		t.Errorf("the output does not say scan was skipped:\n%s", strings.Join(lines, "\n"))
	}
	if !e.m.ImagePresent(bsDigest[api.ServiceScan]) {
		t.Error("the verified base image is not kept")
	}
	// Once the mirror is reachable the same bootstrap finishes the job: scan is installed, the rest is left as it is.
	e.m.Mark("build-fails", false)
	e.forget()
	e.bootstrapOK(t, e.bsDocs(t, 5, v1, bsDigest))
	if e.unit(t, api.ServiceScan) != e.render(t, api.ServiceScan, bsUnitDigest(api.ServiceScan)) || e.versionsFile(t, api.ServiceScan).Current == nil {
		t.Error("scan was not installed by the rerun")
	}
}

// L-a: when every requested service was skipped nothing was installed, which is a failure; and a skip is never reported as "nothing to do".
func TestContract_Bootstrap_AllSkippedFailsAndASkipIsNeverNothingToDo(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.Mark("build-fails", true)
	a := e.bsDocs(t, 5, v1, bsDigest)
	a.Services = []string{api.ServiceScan}
	lines, err := e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != api.CodeScanBuildFailed {
		t.Fatalf("only scan requested and its build fails: %v", err)
	}
	if slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "nothing to do") }) {
		t.Errorf("a failure said nothing to do:\n%s", strings.Join(lines, "\n"))
	}
	if _, err := e.m.Unit(api.ServiceScan); err == nil {
		t.Error("a scan unit was written")
	}

	// The others are installed, scan is skipped again: exit 0, but the output says what was skipped and not "nothing to do".
	e2 := startUpd(t)
	e2.m.Mark("build-fails", true)
	e2.bootstrapOK(t, e2.bsDocs(t, 5, v1, bsDigest))
	lines = e2.bootstrapOK(t, e2.bsDocs(t, 5, v1, bsDigest))
	if slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "nothing to do") }) ||
		!slices.ContainsFunc(lines, func(l string) bool {
			return strings.Contains(l, "nothing more to install") && strings.Contains(l, "scan was skipped")
		}) {
		t.Errorf("the rerun with scan skipped:\n%s", strings.Join(lines, "\n"))
	}
}

// L-b: a link at a credential volume unit name is refused in step 1, so no unit of any requested service is written first.
func TestContract_Bootstrap_ABadVolumeFileIsRefusedBeforeAnyUnitIsWritten(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	target := filepath.Join(e.m.Root, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(e.m.UnitsDir(), "vedette-creds-active.volume")); err != nil {
		t.Fatal(err)
	}
	a := e.bsDocs(t, 5, v1, bsDigest)
	a.Services = []string{api.ServiceHoneypot, api.ServiceCore}
	_, err := e.bootstrap(a)
	if code, _ := ops.BootstrapCode(err); code != api.CodeUnitUnsafe {
		t.Fatalf("%v", err)
	}
	e.bsNothingButScan(t, "bad volume file")
	if w := e.writes(); len(w) != 0 {
		t.Errorf("podman wrote before the refusal: %v", w)
	}
	if b, _ := os.ReadFile(target); string(b) != "x" { //nolint:gosec // test: a path under the fake root
		t.Error("the host wrote through the link")
	}
}

// L6: the step that puts the tag back on the previous image is run (with that image's ID), fails, and the pull still ends as
// scan_build_failed with the previous image kept and the record untouched.
func TestContract_Scan_TheTagBackStepRunsAndItsFailureIsSurvived(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.pull(t, e.scanArgs(t, v1))
	first := opstest.BuiltID(1)
	before, _ := os.ReadFile(e.pulledFile(api.ServiceScan))
	e.forget()
	e.m.Mark("nmap-fails", true)
	e.m.Mark("tag-id-fails", true)
	r := e.final(t, api.CmdContainerPull, e.scanArgs(t, v1), api.StatusFailed, api.CodeScanBuildFailed)
	if r.Error == nil {
		t.Fatal("no error")
	}
	want := "tag " + first + " " + scanTag + v1
	if !slices.ContainsFunc(e.podman(), func(c []string) bool { return strings.Join(c, " ") == want }) {
		t.Errorf("the tag-back step did not run (%q): %v", want, e.podman())
	}
	if !e.m.ImagePresent("sha256:"+first) || !slices.Contains(e.m.ImageRemoved(), "sha256:"+opstest.BuiltID(2)) {
		t.Errorf("previous image present %t, removed %v", e.m.ImagePresent("sha256:"+first), e.m.ImageRemoved())
	}
	if after, _ := os.ReadFile(e.pulledFile(api.ServiceScan)); string(before) != string(after) {
		t.Error("the record changed")
	}
}

// The host's own state of a scan pull that never built (a record from before the build existed, with no base digest) is no record.
func TestContract_Scan_ARecordWithoutTheBuiltImageIsNoRecord(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.pull(t, e.scanArgs(t, v1))
	b, err := os.ReadFile(e.pulledFile(api.ServiceScan))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "base_digest")
	nb, _ := json.Marshal(m)
	if err := os.WriteFile(e.pulledFile(api.ServiceScan), nb, 0o600); err != nil {
		t.Fatal(err)
	}
	if e.state(t)[api.ServiceScan].LatestPulled != nil {
		t.Error("a scan record with no base digest was believed")
	}
}

// D-318: a link at the honeypot log volume unit is refused in step 1 too, whichever of core and honeypot is requested, before any
// credential volume or unit is written.
func TestContract_Bootstrap_ALinkAtTheLogVolumeIsRefusedBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	for _, svcs := range [][]string{{api.ServiceHoneypot}, {api.ServiceCore}, {api.ServiceHoneypot, api.ServiceCore}} {
		e := startUpd(t)
		target := filepath.Join(e.m.Root, "elsewhere")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(e.m.UnitsDir(), "vedette-hp-log.volume")); err != nil {
			t.Fatal(err)
		}
		a := e.bsDocs(t, 5, v1, bsDigest)
		a.Services = svcs
		_, err := e.bootstrap(a)
		if code, _ := ops.BootstrapCode(err); code != api.CodeUnitUnsafe {
			t.Fatalf("%v: %v", svcs, err)
		}
		e.bsNothingButScan(t, "bad log volume file")
		if w := e.writes(); len(w) != 0 {
			t.Errorf("%v: podman wrote before the refusal: %v", svcs, w)
		}
		for _, role := range []string{"passive", "active"} {
			if _, err := os.Lstat(filepath.Join(e.m.UnitsDir(), "vedette-creds-"+role+".volume")); err == nil {
				t.Errorf("%v: a credential volume was written before the refusal", svcs)
			}
		}
		if b, _ := os.ReadFile(target); string(b) != "x" { //nolint:gosec // test: a path under the fake root
			t.Errorf("%v: the host wrote through a link: %q", svcs, b)
		}
	}
}

// D-318: core and honeypot share the log volume, so one of them must not move to it while the other still binds the old directory
// (core would read an empty tmpfs while the honeypot writes to disk: every hit lost without an error).
func TestContract_Bootstrap_CoreAndHoneypotMoveToTheLogVolumeTogether(t *testing.T) {
	t.Parallel()
	oldUnit := "[Container]\nVolume=/var/lib/vedette-honeypot/log:/var/lib/vedette/honeypot/log:U\n"
	for _, c := range []struct{ asked, other string }{{api.ServiceCore, api.ServiceHoneypot}, {api.ServiceHoneypot, api.ServiceCore}} {
		e := startUpd(t)
		e.m.WriteRoot("etc/containers/systemd/vedette-"+c.other+".container", oldUnit)
		a := e.bsDocs(t, 5, v1, bsDigest)
		a.Services = []string{c.asked}
		a.ForceUnits = true
		_, err := e.bootstrap(a)
		if code, _ := ops.BootstrapCode(err); code != "invalid_args" {
			t.Errorf("%s alone beside an old %s unit: %v", c.asked, c.other, err)
		}
		if _, err := e.m.Unit(c.asked); err == nil {
			t.Errorf("a unit for %s was written", c.asked)
		}
		if b, _ := e.m.Unit(c.other); b != oldUnit {
			t.Errorf("the %s unit changed: %q", c.other, b)
		}
		// both together are accepted
		a.Services = []string{api.ServiceCore, api.ServiceHoneypot}
		if _, err := e.bootstrap(a); err != nil {
			t.Errorf("core and honeypot together: %v", err)
		}
	}
	// no honeypot unit at all (module never enabled): core alone is fine
	e := startUpd(t)
	a := e.bsDocs(t, 5, v1, bsDigest)
	a.Services = []string{api.ServiceCore}
	if _, err := e.bootstrap(a); err != nil {
		t.Errorf("core alone, no honeypot unit: %v", err)
	}
}
