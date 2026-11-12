package core_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/core"
)

// The run side of the software update (S-CORE-2, D-340, D-342) through the real HTTP stack, against updHost: a
// fake vedette-host that records the container calls, keeps their runs (idempotent by request id like the real
// one) and changes the versions it reports as the calls succeed. The check side is stood in for by
// core.SetUpdateOfferForTest.

var allServices = []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan, api.ServiceGreenbone}

type updRun struct {
	run      api.Run
	svc, ver string
}

type updHost struct {
	core.Host // any call the run side should not make panics

	cl *hostclient.Client // only for Events: a tiny SSE server that ends every stream at once

	mu     sync.Mutex
	st     api.ContainersState
	runs   []*updRun // newest first
	calls  []string
	hold   map[string]bool         // "start core": the run stays running until release
	refuse map[string]string       // "pull scan": the 412 code of the refusal
	ends   map[string]api.RunError // "start core": the run ends reverted (unit_failed) or failed with this code
	now    func() time.Time
	seq    int
}

func ver(s string) *string { return &s }

func newUpdHost(t *testing.T, st api.ContainersState) *updHost {
	t.Helper()
	dir, err := os.MkdirTemp("", "vu") // unix socket paths are short: t.TempDir is too long on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "id: 1\ndata: {\"seq\":1,\"kind\":\"state\",\"status\":\"succeeded\"}\n\n")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &updHost{cl: hostclient.New(sock), st: st, hold: map[string]bool{}, refuse: map[string]string{}, ends: map[string]api.RunError{}, now: time.Now}
}

// lockstep is a box whose core and installed services run cur (previous prev, "" = none); honeypot is installed but off.
func lockstep(cur, prev string) api.ContainersState {
	var st api.ContainersState
	for _, s := range allServices {
		cs := api.ContainerState{Service: s, Installed: s != api.ServiceGreenbone, Enabled: s != api.ServiceHoneypot && s != api.ServiceGreenbone, Version: ver(cur)}
		if prev != "" {
			cs.Previous = &api.ContainerVersion{Version: ver(prev), Digest: "sha256:" + strings.Repeat("a", 64)}
		}
		st.Services = append(st.Services, cs)
	}
	return st
}

func (f *updHost) svc(name string) *api.ContainerState {
	for i := range f.st.Services {
		if f.st.Services[i].Service == name {
			return &f.st.Services[i]
		}
	}
	return nil
}

// effect changes the versions as a succeeded call does on the box.
func (f *updHost) effect(r *updRun) {
	s := f.svc(r.svc)
	switch r.run.Command {
	case api.CmdContainerStart:
		s.Previous = &api.ContainerVersion{Version: s.Version}
		s.Version = ver(r.ver)
	case api.CmdContainerRollback:
		cur := s.Version
		s.Version = s.Previous.Version
		s.Previous = &api.ContainerVersion{Version: cur}
	}
}

func (f *updHost) end(r *updRun, key string) {
	fin := f.now()
	r.run.FinishedAt = &fin
	if e, ok := f.ends[key]; ok {
		r.run.Status = api.StatusFailed
		if e.Code == api.CodeUnitFailed {
			r.run.Status = api.StatusReverted
		}
		r.run.Error = &api.RunError{Code: e.Code, Message: "fake"}
		return
	}
	r.run.Status = api.StatusSucceeded
	f.effect(r)
}

func (f *updHost) take(cmd, short, svc, version, extra, rid, actor string) (api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := short + " " + svc
	f.calls = append(f.calls, strings.TrimSpace(key+" "+version+" "+extra))
	for _, r := range f.runs {
		if r.run.RequestID == rid {
			return r.run, nil
		}
	}
	if code := f.refuse[key]; code != "" {
		return api.Run{}, &hostclient.Error{Status: 412, Code: code, Message: "refused by the fake"}
	}
	f.seq++
	r := &updRun{run: api.Run{RunID: fmt.Sprintf("rn_%016x", f.seq), Command: cmd, Status: api.StatusRunning, StartedAt: f.now(), Actor: actor, RequestID: rid}, svc: svc, ver: version}
	if !f.hold[key] {
		f.end(r, key)
	}
	f.runs = append([]*updRun{r}, f.runs...)
	return r.run, nil
}

// release ends the held run of key.
func (f *updHost) release(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hold, key)
	for _, r := range f.runs {
		if r.run.Status == api.StatusRunning && strings.TrimPrefix(r.run.Command, "container.")+" "+r.svc == key {
			f.end(r, key)
		}
	}
}

// addRun puts a finished run of the host's own record (one core never stored, after a database restore).
func (f *updHost) addRun(r api.Run) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append([]*updRun{{run: r}}, f.runs...)
}

func (f *updHost) setState(st api.ContainersState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st = st
}

func (f *updHost) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *updHost) StateContainers(context.Context) (api.ContainersState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.st) // a deep copy
	var out api.ContainersState
	return out, json.Unmarshal(b, &out)
}

func (f *updHost) ContainerPull(_ context.Context, a api.ContainerPullArgs, rid, actor string) (api.Run, error) {
	for _, d := range []string{a.Index, a.IndexSig, a.Manifest, a.ManifestSig} {
		if _, err := base64.StdEncoding.DecodeString(d); err != nil || d == "" || a.Source != api.PullSourceRegistry {
			return api.Run{}, &hostclient.Error{Status: 400, Code: "invalid_args", Message: "documents"}
		}
	}
	return f.take(api.CmdContainerPull, "pull", a.Service, a.Version, "", rid, actor)
}

func (f *updHost) ContainerStart(_ context.Context, a api.ContainerStartArgs, rid, actor string) (api.Run, error) {
	extra := ""
	if a.Snapshot != "" {
		extra = "snap"
	}
	return f.take(api.CmdContainerStart, "start", a.Service, a.Version, extra, rid, actor)
}

func (f *updHost) ContainerRollback(_ context.Context, a api.ContainerRollbackArgs, rid, actor string) (api.Run, error) {
	return f.take(api.CmdContainerRollback, "rollback", a.Service, "", "", rid, actor)
}

func (f *updHost) GetRun(_ context.Context, id string) (api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if r.run.RunID == id {
			return r.run, nil
		}
	}
	return api.Run{}, &hostclient.Error{Status: 404, Code: "run_not_found", Message: "no such run"}
}

func (f *updHost) ListRuns(_ context.Context, limit int) ([]api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []api.Run
	for _, r := range f.runs {
		if len(out) < limit {
			out = append(out, r.run)
		}
	}
	return out, nil
}

func (f *updHost) Events(ctx context.Context, runID string, after uint64) *hostclient.Stream {
	return f.cl.Events(ctx, runID, after)
}

func newUpdEnv(t *testing.T, st api.ContainersState, offer string, restores bool) (*osEnv, *updHost) {
	t.Helper()
	fh := newUpdHost(t, st)
	e := newOSEnv(t, osOpts{host: fh})
	core.SetUpdateOfferForTest(e.handler, offer, allServices, restores)
	return e, fh
}

func runOf(t *testing.T, r reply) map[string]any {
	t.Helper()
	run, _ := r.JSON["run"].(map[string]any)
	if run == nil {
		t.Fatalf("no run in %s", r.Raw)
	}
	return run
}

// endedRun waits for the run to end and returns it.
func endedRun(t *testing.T, e *osEnv) map[string]any {
	t.Helper()
	var run map[string]any
	eventuallyOS(t, "the run to end", func() bool {
		run, _ = e.admin.get("/core/updates").JSON["run"].(map[string]any)
		return run != nil && run["status"] != "running"
	})
	return run
}

func waitCall(t *testing.T, fh *updHost, prefix string) {
	t.Helper()
	eventuallyOS(t, "the call "+prefix, func() bool {
		return slices.ContainsFunc(fh.callList(), func(c string) bool { return strings.HasPrefix(c, prefix) })
	})
}

func steps(run map[string]any) string {
	var s []string
	for _, x := range run["steps"].([]any) {
		s = append(s, x.(string))
	}
	return strings.Join(s, ",")
}

func TestUpdateApplyPullsEveryServiceStartsTheOthersThenCoreLast(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", false)
	r := e.admin.post("/core/updates/apply", map[string]any{"component": "software"})
	wantOK(t, r, 200)
	if run := runOf(t, r); run["status"] != "running" || run["action"] != "update" || run["from"] != "1.4.0" || run["to"] != "1.5.0" || steps(run) != "download,start,restart" {
		t.Fatalf("run at the start = %v", run)
	}
	run := endedRun(t, e)
	if run["status"] != "done" || run["error"] != nil || run["step"] != nil || run["user"] != "admin@acme.example" {
		t.Fatalf("run = %v", run)
	}
	// Every installed service is pulled (honeypot too, though off); the running ones start; honeypot, which is
	// off, does not (SYS-5); greenbone is not installed; core is last, with a snapshot.
	want := []string{"pull core 1.5.0", "pull sensor 1.5.0", "pull honeypot 1.5.0", "pull scan 1.5.0", "start sensor 1.5.0", "start scan 1.5.0", "start core 1.5.0 snap"}
	if got := fh.callList(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if h0 := hist[0].(map[string]any); len(hist) != 1 || h0["action"] != "update" || h0["from"] != "1.4.0" || h0["to"] != "1.5.0" || h0["user"] != "admin@acme.example" {
		t.Errorf("history = %v", hist)
	}
	if a := e.actions(); countOf(a, "update.apply") != 1 || countOf(a, "update.apply_done") != 1 {
		t.Errorf("audit = %v", a)
	}
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot left: %v", d)
	}
}

// core's own switch restarts core: the next process finds the stored run, asks the host about the stored run id
// and settles it once, with the user who started it.
func TestUpdateRunIsCarriedOnAfterCoreRestarts(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", ""), "1.5.0", false)
	fh.hold["start core"] = true
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	eventuallyOS(t, "the restart step", func() bool {
		run, _ := e.admin.get("/core/updates").JSON["run"].(map[string]any)
		return run != nil && run["step"] == "restart" && run["status"] == "running"
	})
	if d := e.snapshotDirs(); len(d) != 1 {
		t.Fatalf("snapshot directories while core switches = %v", d)
	}
	e.handler.Close() // the host stops core
	fh.release("start core")
	e.handler = e.newHandlers(t, fh, 0) // the new version starts on the same database
	run := endedRun(t, e)
	if run["status"] != "done" || run["user"] != "admin@acme.example" {
		t.Fatalf("run after the restart = %v", run)
	}
	if n := countOf(fh.callList(), "start core 1.5.0 snap"); n != 1 {
		t.Errorf("core's switch was sent %d times, want once (calls %q)", n, fh.callList())
	}
	if a := e.actions(); countOf(a, "update.apply_done") != 1 {
		t.Errorf("audit = %v", a)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if len(hist) != 1 || hist[0].(map[string]any)["to"] != "1.5.0" {
		t.Errorf("history = %v", hist)
	}
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot left: %v", d)
	}
}

// After a restart, a switch of core that the host never took is not sent again: the run stops and the services it
// switched go back.
func TestUpdateCoreSwitchIsNotSentAgainAfterARestart(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", false)
	fh.refuse["start core"] = api.CodeBusy // the host does not take it: the follower keeps trying
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	e.handler.Close()
	delete(fh.refuse, "start core")
	e.handler = e.newHandlers(t, fh, 0)
	run := endedRun(t, e)
	if run["status"] != "failed" || !strings.Contains(run["error"].(string), "restarted before it could switch itself") {
		t.Fatalf("run = %v", run)
	}
	calls := fh.callList()
	if !slices.Contains(calls, "rollback sensor") || !slices.Contains(calls, "rollback scan") || slices.Contains(calls[len(calls)-2:], "start core 1.5.0 snap") {
		t.Errorf("calls = %q", calls)
	}
}

func TestUpdateApplyRefusals(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", false)
	wantStatus(t, e.admin.post("/core/updates/apply", map[string]any{"component": "data"}), 404, "no_update")
	wantStatus(t, e.oper.post("/core/updates/apply", map[string]any{"component": "software"}), 403, "forbidden")
	fh.hold["start core"] = true
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	wantStatus(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 409, "busy")
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "busy")
	wantStatus(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 409, "busy")
	if !e.handler.Busy(t.Context()) {
		t.Error("Busy is false while a software run goes (the factory reset must refuse)")
	}
	fh.release("start core")
	endedRun(t, e)

	core.SetUpdateOfferForTest(e.handler, "", allServices, false)
	wantStatus(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 404, "no_update")

	n := newOSEnv(t, osOpts{noHost: true})
	wantStatus(t, n.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 409, "not_appliance")
	wantStatus(t, n.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "not_appliance")
}

func TestUpdatePullRefusedEndsTheRunBeforeAnythingSwitches(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", false)
	fh.refuse["pull scan"] = api.CodeSignatureInvalid
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "failed" || !strings.Contains(run["error"].(string), "Downloading 1.5.0 of the scanner failed: the release did not pass the signature check") {
		t.Fatalf("run = %v", run)
	}
	if slices.ContainsFunc(fh.callList(), func(c string) bool { return strings.HasPrefix(c, "start") || strings.HasPrefix(c, "rollback") }) {
		t.Errorf("calls after a refused pull = %q", fh.callList())
	}
	if hist := e.admin.get("/core/updates").JSON["history"].([]any); len(hist) != 0 {
		t.Errorf("history of a failed run = %v", hist)
	}
}

// core did not become healthy: the host put it back; the run puts the services it switched back too.
func TestUpdateCoreRevertedPutsTheOthersBack(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", false)
	fh.ends["start core"] = api.RunError{Code: api.CodeUnitFailed}
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "reverted" || run["error"] != "Vedette 1.5.0 did not start correctly, so the box went back to 1.4.0. The other services were put back on 1.4.0." {
		t.Fatalf("run = %v", run)
	}
	calls := fh.callList()
	if got := calls[len(calls)-3:]; !slices.Equal(got, []string{"start core 1.5.0 snap", "rollback sensor", "rollback scan"}) {
		t.Errorf("last calls = %q", got)
	}
	st, _ := fh.StateContainers(t.Context())
	for _, s := range st.Services {
		if s.Installed && *s.Version != "1.4.0" {
			t.Errorf("%s runs %s after the revert", s.Service, *s.Version)
		}
	}
}

func TestUpdateRollbackNeedsConfirmWhenItRestoresTheDatabase(t *testing.T) {
	t.Parallel()
	e, _ := newUpdEnv(t, lockstep("1.5.0", "1.4.0"), "", true)
	r := e.admin.post("/core/updates/rollback", map[string]any{"component": "software"})
	wantStatus(t, r, 409, "confirm_required")
	if !strings.Contains(r.Raw, "data written since then is lost") {
		t.Errorf("sentence = %s", r.Raw)
	}
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software", "confirm_data_loss": false}), 409, "confirm_required")
	r = e.admin.post("/core/updates/rollback", map[string]any{"component": "software", "confirm_data_loss": true})
	wantOK(t, r, 200)
	if run := runOf(t, r); run["action"] != "rollback" || steps(run) != "start,restore,restart" || run["from"] != "1.5.0" || run["to"] != "1.4.0" {
		t.Fatalf("run = %v", run)
	}
}

func TestUpdateRollbackOrderCoreLast(t *testing.T) {
	t.Parallel()
	st := lockstep("1.5.0", "1.4.0")
	*st.Services[2].Version = "1.3.0" // honeypot (off) never moved with core
	e, fh := newUpdEnv(t, st, "", false)
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "other"}), 404, "not_found")
	fh.hold["rollback core"] = true
	r := e.admin.post("/core/updates/rollback", map[string]any{"component": "software"})
	wantOK(t, r, 200)
	if run := runOf(t, r); steps(run) != "start,restart" {
		t.Fatalf("run = %v", run)
	}
	waitCall(t, fh, "rollback core")
	e.handler.Close()
	fh.release("rollback core")
	e.handler = e.newHandlers(t, fh, 0)
	run := endedRun(t, e)
	if run["status"] != "done" || run["action"] != "rollback" {
		t.Fatalf("run = %v", run)
	}
	if got, want := fh.callList(), []string{"rollback sensor", "rollback scan", "rollback core"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if h0 := hist[0].(map[string]any); h0["action"] != "rollback" || h0["from"] != "1.5.0" || h0["to"] != "1.4.0" {
		t.Errorf("history = %v", hist)
	}
	if a := e.actions(); countOf(a, "update.rollback") != 1 || countOf(a, "update.rollback_done") != 1 {
		t.Errorf("audit = %v", a)
	}

	// Now core runs 1.4.0 with 1.5.0 as previous: going "back" up is refused before any call.
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "rollback_is_upgrade")
	fh.setState(lockstep("1.5.0", ""))
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "no_previous")
}

// The host refuses core's rollback after the others went back: they go forward again, the words are plain.
func TestUpdateRollbackRefusedByTheHostRollsTheOthersForward(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.5.0", "1.4.0"), "", false)
	fh.refuse["rollback core"] = api.CodeRollbackBackupMissing
	wantOK(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	want := "Rolling back Vedette failed: The copy of the database from before the update is no longer on the box, so the rollback cannot put it back. The other services were put back on 1.5.0."
	if run["status"] != "failed" || run["error"] != want {
		t.Fatalf("run = %v", run)
	}
	if got, want := fh.callList(), []string{"rollback sensor", "rollback scan", "rollback core", "rollback sensor", "rollback scan"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	for _, code := range []string{api.CodeNoPrevious, api.CodePreviousRevoked, api.CodeRollbackNotAllowed, api.CodeRollbackBackupMissing, api.CodeRollbackIsUpgrade, api.CodeTransitionPending, api.CodeCurrentVersionUnknown} {
		if ae := core.MapHostCodeForTest(code); ae.Status != 409 || ae.Code != code || strings.Contains(ae.Message, "_") {
			t.Errorf("%s maps to %d %s %q", code, ae.Status, ae.Code, ae.Message)
		}
	}
}

// A rollback that put the database back replaced the database with the one from before the update: the stored
// run is the update, at its last step. The next process settles the update and rebuilds the rollback from the
// host's record.
func TestUpdateRollbackLostToARestoredDatabaseIsRebuiltFromTheHost(t *testing.T) {
	t.Parallel()
	e, fh := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", true)
	fh.hold["start core"] = true
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	eventuallyOS(t, "the run id of core's switch to be stored", func() bool {
		var raw string
		_ = e.env.DB.Reader().QueryRowContext(t.Context(), "SELECT value FROM core_setting WHERE key = 'core_update_run'").Scan(&raw)
		return strings.Contains(raw, `"service":"core","request_id"`) && strings.Count(raw, `"run_id"`) == 7
	})
	e.handler.Close()
	fh.release("start core")
	// Later, in a database that is now gone: the rollback, which put the pre-update copy back.
	fin := time.Now()
	fh.addRun(api.Run{RunID: "rn_00000000000000ff", Command: api.CmdContainerRollback, Status: api.StatusSucceeded, StartedAt: fin.Add(-time.Minute), FinishedAt: &fin,
		Actor: "other@acme.example", RequestID: "11111111-1111-4111-8111-111111111111", Result: json.RawMessage(`{"digest":"d","from_digest":"f","restored_backup_id":"b1"}`)})
	fh.setState(lockstep("1.4.0", "1.5.0"))
	e.handler = e.newHandlers(t, fh, 0)
	run := endedRun(t, e)
	if run["action"] != "rollback" || run["status"] != "done" || run["from"] != "1.5.0" || run["to"] != "1.4.0" || run["user"] != "other@acme.example" {
		t.Fatalf("run = %v", run)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if len(hist) != 2 || hist[0].(map[string]any)["action"] != "rollback" || hist[1].(map[string]any)["action"] != "update" {
		t.Errorf("history = %v", hist)
	}
}

func TestUpdateRunIsHiddenADayAfterItEnded(t *testing.T) {
	t.Parallel()
	e, _ := newUpdEnv(t, lockstep("1.4.0", "1.3.0"), "1.5.0", false)
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	endedRun(t, e)
	e.clock.Advance(23 * time.Hour)
	if r := e.admin.get("/core/updates"); r.JSON["run"] == nil {
		t.Fatal("the run is gone before a day passed")
	}
	e.clock.Advance(2 * time.Hour)
	if r := e.admin.get("/core/updates"); r.JSON["run"] != nil {
		t.Errorf("run a day after it ended = %v", r.JSON["run"])
	}
	if hist := e.admin.get("/core/updates").JSON["history"].([]any); len(hist) != 1 {
		t.Errorf("history = %v", hist)
	}
}
