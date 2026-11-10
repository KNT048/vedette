package host_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
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
	if len(f) != 10 || f[0] != "build" || f[1] != "--pull=never" || f[2] != "--no-cache" || f[4] != "BASE_IMAGE=ghcr.io/knt048/vedette-scan@"+scanBase ||
		f[6] != "NMAP_MIN_VERSION=7.95" || f[8] != scanTag+v1 || !filepath.IsAbs(f[9]) {
		t.Errorf("build argv: %q", f)
	}
	for _, a := range f {
		if strings.Contains(a, "--network") || a == "host" {
			t.Errorf("the build argv sets a network: %q", f)
		}
	}
	// Nothing of the build is left behind in the state directory.
	if _, err := os.Stat(filepath.Join(e.m.State, "build")); err == nil {
		t.Error("the build context was not removed")
	}
	id := opstest.BuiltID(1)
	runs := e.m.NmapRuns()
	if len(runs) != 1 || !strings.Contains(runs[0], "--network none") || !strings.Contains(runs[0], "--read-only") || !strings.Contains(runs[0], "--cap-drop ALL") ||
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
	}{
		"podman build fails (no mirror)":   {setup: func(e *updEnv) { e.m.Mark("build-fails", true) }},
		"podman leaves no tag":             {setup: func(e *updEnv) { e.m.Mark("build-no-tag", true) }},
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
			if !e.m.ImagePresent(first) || e.m.ImageTag(scanTag+v1) != first {
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
	rb := result[api.ContainerRollbackResult](t, e.ok(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: api.ServiceScan}))
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
