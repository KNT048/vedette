package core_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/modules/core"
)

// The system helper step of the software run (S-CORE-2 criterion D-316, plan slice 5), against updHost: core and the
// helper run 1.3.0, and release 1.4.0 brings helper 1.4.0 whose package the release server serves as served.

const hostPkgPath = "/v1.4.0/vedette-host_1.4.0_amd64.deb"

func newHostRunEnv(t *testing.T, helper string, served []byte) (*runEnv, *updHost) {
	t.Helper()
	pkg := opstest.HostPackage("1.4.0")
	if served == nil {
		served = pkg
	}
	fh := newUpdHost(t, lockstep("1.3.0", "1.2.0"))
	fh.hostVersion, fh.pkgSHA = helper, opstest.SHA(pkg)
	e, _ := newRunEnvWith(t, fh, "1.3.0", true, func(d opstest.Doc) {
		f := opstest.HostFileOf("1.4.0", pkg)
		d["host"] = opstest.Doc{"version": "1.4.0", "files": []any{opstest.Doc{"name": f.Name, "sha256": f.SHA256, "size": f.Size}}}
	})
	e.srv.put(hostPkgPath, served)
	fh.coreData = e.m.CoreData
	core.SetUpdateRetryForTest(e.handler, time.Millisecond)
	return e, fh
}

func (e *runEnv) hostPackagesLeft(t *testing.T) []string {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(e.m.CoreData, "host-packages"))
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	return out
}

// waitNoPackages waits for the run's cleanup: the run reads "done" a moment before the package is removed.
func (e *runEnv) waitNoPackages(t *testing.T) {
	t.Helper()
	eventuallyOS(t, "the host package to be removed", func() bool { return len(e.hostPackagesLeft(t)) == 0 })
}

func componentOf(r reply, id string) map[string]any {
	for _, c := range getArr(r, "components") {
		if m, _ := c.(map[string]any); m["id"] == id {
			return m
		}
	}
	return nil
}

// Criteria (b) and the check side: the offer names the new helper, the run updates it first with the package
// checked before the call, the history gets a host entry, and the images follow.
func TestUpdateHostStepGoesFirstThenTheImages(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", nil)
	before := e.admin.get("/core/updates")
	if a := getArr(before, "available")[0].(map[string]any); a["host_version"] != "1.4.0" {
		t.Errorf("available = %v", a)
	}
	if h := componentOf(before, "host"); h == nil || h["version"] != "1.3.0" || h["previous"] != nil || h["kind"] != "software" {
		t.Errorf("host component = %v", h)
	}
	r := e.admin.post("/core/updates/apply", map[string]any{"component": "software"})
	wantOK(t, r, 200)
	if run := runOf(t, r); steps(run) != "host,download,start,restart" {
		t.Fatalf("run = %v", run)
	}
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
	calls := fh.callList()
	if len(calls) < 2 || calls[0] != "self_update host 1.4.0 pkg-ok" || !strings.HasPrefix(calls[1], "pull ") {
		t.Errorf("calls = %q", calls)
	}
	after := e.admin.get("/core/updates")
	hist := getArr(after, "history")
	if len(hist) != 2 {
		t.Fatalf("history = %v", hist)
	}
	if h := hist[1].(map[string]any); h["component"] != "host" || h["from"] != "1.3.0" || h["to"] != "1.4.0" || h["action"] != "update" {
		t.Errorf("host history = %v", h)
	}
	if h := componentOf(after, "host"); h["version"] != "1.4.0" {
		t.Errorf("host component after = %v", h)
	}
	e.waitNoPackages(t)
}

// Criterion (f): an image step that fails after the helper moved leaves the helper on the new version.
func TestUpdateHostStaysNewWhenAnImageFailsLater(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", nil)
	fh.ends["start sensor"] = api.RunError{Code: api.CodeUnitFailed}
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	if run := endedRun(t, e); run["status"] != "reverted" {
		t.Fatalf("run = %v", run)
	}
	calls := fh.callList()
	if countOf(calls, "self_update host 1.4.0 pkg-ok") != 1 || slices.ContainsFunc(calls, func(c string) bool { return strings.HasSuffix(c, " host") }) {
		t.Errorf("calls = %q", calls)
	}
	r := e.admin.get("/core/updates")
	if hist := getArr(r, "history"); len(hist) != 1 || hist[0].(map[string]any)["component"] != "host" || hist[0].(map[string]any)["to"] != "1.4.0" {
		t.Errorf("history = %v", hist)
	}
	if h := componentOf(r, "host"); h["version"] != "1.4.0" {
		t.Errorf("host component = %v", h)
	}
}

// Criterion (c): the new helper did not start, the host went back by itself; the run stops before any image.
func TestUpdateHostRevertedStopsBeforeAnyImage(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", nil)
	fh.ends["self_update host"] = api.RunError{Code: api.CodeSelfUpdateUnhealthy}
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "reverted" || run["error"] != "The new system helper 1.4.0 did not start correctly, so the box went back to 1.3.0 by itself. Nothing else was changed." {
		t.Fatalf("run = %v", run)
	}
	if got := fh.callList(); !slices.Equal(got, []string{"self_update host 1.4.0 pkg-ok"}) {
		t.Errorf("calls = %q", got)
	}
	if hist := getArr(e.admin.get("/core/updates"), "history"); len(hist) != 0 {
		t.Errorf("history = %v", hist)
	}
}

// Criterion (d): a refusal ends the run failed with its sentence; no image is touched.
func TestUpdateHostRefusalStopsTheRun(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", nil)
	fh.refuse["self_update host"] = api.CodeDependenciesUnavailable
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "failed" || run["error"] != "The new system helper needs operating system packages that the box's package sources do not offer. Nothing was installed." {
		t.Fatalf("run = %v", run)
	}
	if got := fh.callList(); !slices.Equal(got, []string{"self_update host 1.4.0 pkg-ok"}) {
		t.Errorf("calls = %q", got)
	}
}

// Criterion (a): the helper restarts while it takes the call (the answer is lost, then it is not up for a moment);
// core finds the run by its key and never sends it twice.
func TestUpdateHostRestartMidRunIsFoundByItsKey(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", nil)
	fh.lost, fh.down = true, 1
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
	if n := countOf(fh.callList(), "self_update host 1.4.0 pkg-ok"); n != 1 {
		t.Errorf("self_update sent %d times (calls %q)", n, fh.callList())
	}
}

// Criterion (d): a download that is not the signed package is never handed to the host.
func TestUpdateHostPackageThatDoesNotMatchIsNeverSent(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", []byte("!<arch>\nsomething else\n"))
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "failed" || run["error"] != "The downloaded system helper does not match the signed release. Nothing was installed." {
		t.Fatalf("run = %v", run)
	}
	if got := fh.callList(); len(got) != 0 {
		t.Errorf("calls = %q", got)
	}
	if left := e.hostPackagesLeft(t); len(left) != 0 {
		t.Errorf("packages left = %v", left)
	}
}

// Criterion (h): a helper without host.self_update ends the run before any host call, download or image.
func TestUpdateHostTooOldStopsBeforeAnyCall(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.3.0", nil)
	fh.commands = []string{api.CmdContainerPull}
	r := e.admin.post("/core/updates/apply", map[string]any{"component": "software"})
	wantOK(t, r, 200)
	want := "This box's system helper (1.3.0) is too old to update itself. Run install.sh of release 1.4.0 on the box (it upgrades the helper and keeps your data), then apply again."
	if run := runOf(t, r); run["status"] != "failed" || run["error"] != want || steps(run) != "host,download,start,restart" {
		t.Fatalf("run = %v", run)
	}
	if got := fh.callList(); len(got) != 0 || e.srv.hit(hostPkgPath) != 0 {
		t.Errorf("calls = %q, package downloads = %d", got, e.srv.hit(hostPkgPath))
	}
	if a := e.actions(); countOf(a, "update.apply") != 1 || countOf(a, "update.apply_done") != 1 {
		t.Errorf("audit = %v", a)
	}
}

// Criterion (g): a release whose helper is not newer has no host step.
func TestUpdateWithoutANewerHostHasNoHostStep(t *testing.T) {
	t.Parallel()
	e, fh := newHostRunEnv(t, "1.4.0", nil)
	if a := getArr(e.admin.get("/core/updates"), "available")[0].(map[string]any); a["host_version"] != nil {
		t.Errorf("available = %v", a)
	}
	r := e.admin.post("/core/updates/apply", map[string]any{"component": "software"})
	wantOK(t, r, 200)
	if run := runOf(t, r); steps(run) != "download,start,restart" {
		t.Fatalf("run = %v", run)
	}
	if run := endedRun(t, e); run["status"] != "done" || slices.ContainsFunc(fh.callList(), func(c string) bool { return strings.HasPrefix(c, "self_update") }) {
		t.Fatalf("run = %v, calls = %q", run, fh.callList())
	}
}

// Criteria (c), (d), (e), (h): the host's end codes map to the story's sentences (the GUI mock's hostError holds the
// same words), and after a stop half way every other helper action is refused with the runbook section named.
func TestUpdateHostSentences(t *testing.T) {
	t.Parallel()
	half := "The system helper update stopped half way and could not be undone. Vedette keeps running; follow the runbook section \"vedette-host self-update stopped half way\"."
	for code, want := range map[string]string{
		api.CodeSelfUpdateUnhealthy:     "The new system helper 1.5.0 did not start correctly, so the box went back to 1.4.0 by itself. Nothing else was changed.",
		api.CodeInstallFailed:           "The new system helper 1.5.0 did not start correctly, so the box went back to 1.4.0 by itself. Nothing else was changed.",
		api.CodeSignatureInvalid:        "The system helper in this update is not signed by the Vedette release key. Nothing was installed.",
		api.CodeChecksumMismatch:        "The downloaded system helper does not match the signed release. Nothing was installed.",
		api.CodeDowngradeNotAllowed:     "System helper 1.5.0 is older than the one running (1.4.0). The helper is never taken back by an update.",
		api.CodeTestVersionRefused:      "1.5.0 is a test build. It is never installed on a real box.",
		api.CodeDependenciesUnavailable: "The new system helper needs operating system packages that the box's package sources do not offer. Nothing was installed.",
		api.CodeDpkgLocked:              "The box is installing operating system packages. Try again in a few minutes.",
		api.CodeRollbackFailed:          half,
		"self_update_rollback_failed":   half,
		api.CodeSelfUpdateInterrupted:   half,
		"host_too_old":                  "This box's system helper (1.4.0) is too old to update itself. Run install.sh of release 1.5.1 on the box (it upgrades the helper and keeps your data), then apply again.",
		api.CodeCurrentPackageMissing:   "Updating the system helper to 1.5.0 failed: the box has no copy of the running helper to go back to, so it was not updated. Run install.sh of release 1.5.1 on the box (it keeps your data), then apply again.",
		"host_download_failed":          "Updating the system helper to 1.5.0 failed: its package could not be downloaded. Check that the box can reach github.com over HTTPS, then apply again.",
	} {
		if got := core.HostWhyForTest(code, "1.5.0", "1.4.0", "1.5.1"); got != want {
			t.Errorf("%s:\n got %q\nwant %q", code, got, want)
		}
	}
	if ae := core.MapHostCodeForTest(api.CodeTransitionPending); ae.Status != 409 || !strings.Contains(ae.Message, "\"vedette-host self-update stopped half way\"") {
		t.Errorf("transition_pending = %d %q", ae.Status, ae.Message)
	}
}
