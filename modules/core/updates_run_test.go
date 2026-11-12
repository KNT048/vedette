package core_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/modules/core"
)

// The run side of the software update (S-CORE-2, D-340, D-342) through the real HTTP stack, against updHost: a
// fake vedette-host that records the container calls, keeps their runs (idempotent by request id like the real
// one) and changes the versions it reports as the calls succeed. The check side is the real one, checking against a
// releaseServer (updates_check_test.go) that offers 1.4.0 with an image of every service.

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
	once   map[string]string       // "start core": refused once with this code, then taken
	args   map[string]string       // request id -> the arguments it was taken with (another set: 422, as the host)
	pulled map[string][]string     // service -> the index of every container.pull sent for it
	ends   map[string]api.RunError // "start core": the run ends reverted (unit_failed) or failed with this code
	now    func() time.Time
	seq    int

	// The system helper (host.self_update, D-316): its version and commands in /v1/info, where core writes the
	// package (core_data) and the SHA-256 the package must have; lost: the next self_update is taken but its answer
	// is lost (the host restarts); down: ListRuns answers that many times as a host that is not up yet.
	hostVersion string
	commands    []string
	coreData    string
	pkgSHA      string
	lost        bool
	down        int
	lists       int
	stateDown   int             // StateContainers answers unreachable that many times
	dropped     map[string]bool // "start core": every call never reaches the host (no run, no answer)
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
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "id: 1\ndata: {\"seq\":1,\"kind\":\"state\",\"status\":\"succeeded\"}\n\n")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &updHost{cl: hostclient.New(sock), st: st, hold: map[string]bool{}, refuse: map[string]string{},
		once: map[string]string{}, dropped: map[string]bool{}, args: map[string]string{}, pulled: map[string][]string{}, ends: map[string]api.RunError{}, now: time.Now,
		hostVersion: "1.3.0", commands: []string{api.CmdContainerPull, api.CmdHostSelfUpdate}}
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
	case api.CmdHostSelfUpdate:
		r.run.Result, _ = json.Marshal(api.HostSelfUpdateResult{From: f.hostVersion, To: r.ver, Changed: true})
		f.hostVersion = r.ver
	}
}

func (f *updHost) end(r *updRun, key string) {
	fin := f.now()
	r.run.FinishedAt = &fin
	if e, ok := f.ends[key]; ok {
		r.run.Status = api.StatusFailed
		if e.Code == api.CodeUnitFailed || e.Code == api.CodeSelfUpdateUnhealthy || e.Code == api.CodeInstallFailed {
			r.run.Status = api.StatusReverted
		}
		r.run.Error = &api.RunError{Code: e.Code, Message: "fake"}
		return
	}
	r.run.Status = api.StatusSucceeded
	f.effect(r)
}

func (f *updHost) take(cmd, short, svc, version, extra, args, rid, actor string) (api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := short + " " + svc
	f.calls = append(f.calls, strings.TrimSpace(key+" "+version+" "+extra))
	if f.dropped[key] {
		return api.Run{}, fmt.Errorf("%w: connection reset by peer", hostclient.ErrUnreachable)
	}
	if a, ok := f.args[rid]; ok && a != args {
		return api.Run{}, &hostclient.Error{Status: 422, Code: "request_id_reuse", Message: "other arguments"}
	}
	for _, r := range f.runs {
		if r.run.RequestID == rid && r.run.Status != api.StatusRefused { // a refusal binds no key (host-api 4)
			return r.run, nil
		}
	}
	if code := f.refuse[key]; code != "" { // like the host, a refusal is also a run in the list, under the call's key
		f.seq++
		now := f.now()
		f.runs = append([]*updRun{{run: api.Run{RunID: fmt.Sprintf("rn_%016x", f.seq), Command: cmd, Status: api.StatusRefused, StartedAt: now, FinishedAt: &now,
			Actor: actor, RequestID: rid, Error: &api.RunError{Code: code, Message: "refused by the fake"}}, svc: svc, ver: version}}, f.runs...)
		return api.Run{}, &hostclient.Error{Status: 412, Code: code, Message: "refused by the fake"}
	}
	if code := f.once[key]; code != "" {
		delete(f.once, key)
		f.seq++
		now := f.now()
		f.runs = append([]*updRun{{run: api.Run{RunID: fmt.Sprintf("rn_%016x", f.seq), Command: cmd, Status: api.StatusRefused, StartedAt: now, FinishedAt: &now,
			Actor: actor, RequestID: rid, Error: &api.RunError{Code: code, Message: "refused once by the fake"}}, svc: svc, ver: version}}, f.runs...)
		return api.Run{}, &hostclient.Error{Status: 412, Code: code, Message: "refused once by the fake"}
	}
	f.args[rid] = args // a refusal frees the id (host-api 4); a run binds it
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

// endRun ends a run addRun put in the list as running: it succeeded.
func (f *updHost) endRun(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fin := f.now()
	for _, r := range f.runs {
		if r.run.RunID == id {
			r.run.Status, r.run.FinishedAt = api.StatusSucceeded, &fin
		}
	}
}

// listed is how many times the run side read the host's list of runs.
func (f *updHost) listed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
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
	if f.stateDown > 0 {
		f.stateDown--
		return api.ContainersState{}, fmt.Errorf("%w: no socket yet", hostclient.ErrUnreachable)
	}
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
	f.mu.Lock()
	f.pulled[a.Service] = append(f.pulled[a.Service], a.Index)
	f.mu.Unlock()
	return f.take(api.CmdContainerPull, "pull", a.Service, a.Version, "", a.Version+a.Index+a.Manifest, rid, actor)
}

func (f *updHost) ContainerStart(_ context.Context, a api.ContainerStartArgs, rid, actor string) (api.Run, error) {
	extra := ""
	if a.Snapshot != "" {
		extra = "snap"
	}
	return f.take(api.CmdContainerStart, "start", a.Service, a.Version, extra, a.Version+a.Snapshot, rid, actor)
}

func (f *updHost) ContainerRollback(_ context.Context, a api.ContainerRollbackArgs, rid, actor string) (api.Run, error) {
	return f.take(api.CmdContainerRollback, "rollback", a.Service, "", "", "", rid, actor)
}

func (f *updHost) Info(context.Context) (api.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return api.Info{HostVersion: f.hostVersion, Commands: slices.Clone(f.commands), Arch: "amd64"}, nil
}

// SelfUpdate notes whether core's package file is there with the signed hash ("pkg-ok") when the call arrives.
func (f *updHost) SelfUpdate(_ context.Context, a api.HostSelfUpdateArgs, rid, actor string) (api.Run, error) {
	f.mu.Lock()
	b, err := os.ReadFile(filepath.Join(f.coreData, "host-packages", a.Package+".deb"))
	pkg, lost := "pkg-missing", f.lost
	if err == nil && opstest.SHA(b) == f.pkgSHA {
		pkg = "pkg-ok"
	}
	f.lost = false
	f.mu.Unlock()
	run, err := f.take(api.CmdHostSelfUpdate, "self_update", "host", a.Version, pkg, a.Version+a.Index+a.Manifest+a.Package, rid, actor)
	if lost {
		return api.Run{}, fmt.Errorf("%w: connection reset by peer", hostclient.ErrUnreachable)
	}
	return run, err
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
	f.lists++
	if f.down > 0 {
		f.down--
		return nil, fmt.Errorf("%w: no socket yet", hostclient.ErrUnreachable)
	}
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

// runEnv is a box whose core talks to an updHost and checks for releases against srv.
type runEnv struct {
	*osEnv
	srv *releaseServer
	fh  *updHost

	retry time.Duration // the follower's wait between tries after e.start (0 = the default)
}

// newRunEnv: the host reports st, core runs running, srv publishes the manifests of running and 1.4.0 (images of
// every service, both with rollback.safe = safe) and an index offering 1.4.0, and the operator has checked once (so
// 1.4.0 is offered when running is older, and the running release's manifest is known).
func newRunEnv(t *testing.T, st api.ContainersState, running string, safe bool) (*runEnv, *updHost) {
	t.Helper()
	return newRunEnvWith(t, newUpdHost(t, st), running, safe, nil)
}

// newRunEnvWith is newRunEnv with the fake host given and extra applied to the manifest of 1.4.0.
func newRunEnvWith(t *testing.T, fh *updHost, running string, safe bool, extra func(opstest.Doc)) (*runEnv, *updHost) {
	t.Helper()
	e := &runEnv{osEnv: newOSEnv(t, osOpts{host: fh}), srv: newReleaseServer(t), fh: fh}
	e.setZone("UTC")
	edit := func(v string) func(opstest.Doc) {
		return func(d opstest.Doc) {
			d["rollback"] = opstest.Doc{"safe": safe, "min_version": ""}
			var images []any
			for i, svc := range allServices {
				images = append(images, e.srv.rel.ImageDoc(v, opstest.Img{Service: svc, Digest: "sha256:" + strings.Repeat(string(rune('a'+i)), 64), Size: 1 << 20}))
			}
			d["images"] = images
		}
	}
	if running != "1.4.0" {
		e.srv.manifest(t, running, edit(running))
	}
	e.srv.index(t, 5, e.srv.manifest(t, "1.4.0", func(d opstest.Doc) {
		edit("1.4.0")(d)
		if extra != nil {
			extra(d)
		}
	}), 100, nil)
	e.handler = e.start(t, running)
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	return e, fh
}

// start builds core's handlers as release version (a second call is core restarting on the same database).
func (e *runEnv) start(t *testing.T, version string) *core.OSHandlers {
	t.Helper()
	h, err := core.NewOSHandlers(core.OSConfig{
		DB: e.env.DB, Auth: e.env.Svc, Audit: e.env.Audit, Log: e.logger(), Host: e.fh,
		DataDir: e.m.CoreData, KeyPath: filepath.Join(e.m.CoreData, "vedette.key"),
		Zone: e.h.OrgTimeZone, Clock: e.clock.Now, Gate: e.purgeGate,
		Version: version, UpdateRetry: e.retry, ReleaseBase: e.srv.URL, HTTPClient: e.srv.Client(), Trust: e.srv.rel.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	api, err := server.New(server.Config{
		API:  fullOSAPI{Fallback: server.Fallback{Log: e.logger()}, ModuleHandlers: core.NewModuleHandlers(e.env.DB, e.reg), APIHandlers: e.h, OSHandlers: h},
		Auth: e.env.Svc.Sessions, Modules: e.reg, Log: e.logger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.api = api
	return h
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
func endedRun(t *testing.T, e *runEnv) map[string]any {
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
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	r := e.admin.post("/core/updates/apply", map[string]any{"component": "software"})
	wantOK(t, r, 200)
	if run := runOf(t, r); run["status"] != "running" || run["action"] != "update" || run["from"] != "1.3.0" || run["to"] != "1.4.0" || steps(run) != "download,start,restart" {
		t.Fatalf("run at the start = %v", run)
	}
	run := endedRun(t, e)
	if run["status"] != "done" || run["error"] != nil || run["step"] != nil || run["user"] != "admin@acme.example" {
		t.Fatalf("run = %v", run)
	}
	// Every installed service is pulled (honeypot too, though off); the running ones start; honeypot, which is
	// off, does not (SYS-5); greenbone is not installed; core is last, with a snapshot.
	want := []string{"pull core 1.4.0", "pull sensor 1.4.0", "pull honeypot 1.4.0", "pull scan 1.4.0", "start sensor 1.4.0", "start scan 1.4.0", "start core 1.4.0 snap"}
	if got := fh.callList(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if h0 := hist[0].(map[string]any); len(hist) != 1 || h0["action"] != "update" || h0["from"] != "1.3.0" || h0["to"] != "1.4.0" || h0["user"] != "admin@acme.example" {
		t.Errorf("history = %v", hist)
	}
	if a := e.actions(); countOf(a, "update.apply") != 1 || countOf(a, "update.apply_done") != 1 {
		t.Errorf("audit = %v", a)
	}
	// The snapshot is removed just after the end is stored, so the run can read done a moment before.
	eventuallyOS(t, "the snapshot to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
}

// core's own switch restarts core: the next process finds the stored run, asks the host about the stored run id
// and settles it once, with the user who started it.
func TestUpdateRunIsCarriedOnAfterCoreRestarts(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", ""), "1.3.0", true)
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
	e.handler = e.start(t, "1.4.0") // the new version starts on the same database
	run := endedRun(t, e)
	if run["status"] != "done" || run["user"] != "admin@acme.example" {
		t.Fatalf("run after the restart = %v", run)
	}
	if n := countOf(fh.callList(), "start core 1.4.0 snap"); n != 1 {
		t.Errorf("core's switch was sent %d times, want once (calls %q)", n, fh.callList())
	}
	if a := e.actions(); countOf(a, "update.apply_done") != 1 {
		t.Errorf("audit = %v", a)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if len(hist) != 1 || hist[0].(map[string]any)["to"] != "1.4.0" {
		t.Errorf("history = %v", hist)
	}
	// The snapshot is removed just after the end is stored, so the run can read done a moment before.
	eventuallyOS(t, "the snapshot to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
}

// After a restart, a switch of core that the host never took is not sent again: the run stops and the services it
// switched go back.
func TestUpdateCoreSwitchIsNotSentAgainAfterARestart(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.dropped["start core"] = true // the call never reaches the host and the answer is lost: core cannot know
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	e.handler.Close()
	e.handler = e.start(t, "1.3.0")
	run := endedRun(t, e)
	if run["status"] != "failed" || !strings.Contains(run["error"].(string), "has no record that Vedette itself switched to 1.4.0") {
		t.Fatalf("run = %v", run)
	}
	calls := fh.callList()
	if !slices.Contains(calls, "rollback sensor") || !slices.Contains(calls, "rollback scan") || slices.Contains(calls[len(calls)-2:], "start core 1.4.0 snap") {
		t.Errorf("calls = %q", calls)
	}
}

func TestUpdateApplyRefusals(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
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

	u, _ := newRunEnv(t, lockstep("1.4.0", "1.3.0"), "1.4.0", false) // the channel's latest is not newer: nothing offered
	wantStatus(t, u.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 404, "no_update")

	n := newOSEnv(t, osOpts{noHost: true})
	wantStatus(t, n.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 409, "not_appliance")
	wantStatus(t, n.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "not_appliance")
}

func TestUpdatePullRefusedEndsTheRunBeforeAnythingSwitches(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.refuse["pull scan"] = api.CodeSignatureInvalid
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "failed" || !strings.Contains(run["error"].(string), "Downloading 1.4.0 of the scanner failed: the release did not pass the signature check") {
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
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.ends["start core"] = api.RunError{Code: api.CodeUnitFailed}
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	if run["status"] != "reverted" || run["error"] != "Vedette 1.4.0 did not start correctly, so the box went back to 1.3.0. The other services were put back on 1.3.0." {
		t.Fatalf("run = %v", run)
	}
	calls := fh.callList()
	if got := calls[len(calls)-3:]; !slices.Equal(got, []string{"start core 1.4.0 snap", "rollback sensor", "rollback scan"}) {
		t.Errorf("last calls = %q", got)
	}
	st, _ := fh.StateContainers(t.Context())
	for _, s := range st.Services {
		if s.Installed && *s.Version != "1.3.0" {
			t.Errorf("%s runs %s after the revert", s.Service, *s.Version)
		}
	}
}

func TestUpdateRollbackNeedsConfirmWhenItRestoresTheDatabase(t *testing.T) {
	t.Parallel()
	e, _ := newRunEnv(t, lockstep("1.4.0", "1.3.0"), "1.4.0", false)
	r := e.admin.post("/core/updates/rollback", map[string]any{"component": "software"})
	wantStatus(t, r, 409, "confirm_required")
	if !strings.Contains(r.Raw, "data written since then is lost") {
		t.Errorf("sentence = %s", r.Raw)
	}
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software", "confirm_data_loss": false}), 409, "confirm_required")
	r = e.admin.post("/core/updates/rollback", map[string]any{"component": "software", "confirm_data_loss": true})
	wantOK(t, r, 200)
	if run := runOf(t, r); run["action"] != "rollback" || steps(run) != "start,restore,restart" || run["from"] != "1.4.0" || run["to"] != "1.3.0" {
		t.Fatalf("run = %v", run)
	}
}

func TestUpdateRollbackOrderCoreLast(t *testing.T) {
	t.Parallel()
	st := lockstep("1.4.0", "1.3.0")
	*st.Services[2].Version = "1.2.0" // honeypot (off) never moved with core
	e, fh := newRunEnv(t, st, "1.3.0", true)
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
	e.handler = e.start(t, "1.3.0")
	run := endedRun(t, e)
	if run["status"] != "done" || run["action"] != "rollback" {
		t.Fatalf("run = %v", run)
	}
	if got, want := fh.callList(), []string{"rollback sensor", "rollback scan", "rollback core"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if h0 := hist[0].(map[string]any); h0["action"] != "rollback" || h0["from"] != "1.4.0" || h0["to"] != "1.3.0" {
		t.Errorf("history = %v", hist)
	}
	if a := e.actions(); countOf(a, "update.rollback") != 1 || countOf(a, "update.rollback_done") != 1 {
		t.Errorf("audit = %v", a)
	}

	// Now core runs 1.3.0 with 1.4.0 as previous: going "back" up is refused before any call.
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "rollback_is_upgrade")
	fh.setState(lockstep("1.4.0", ""))
	wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "no_previous")
}

// The host refuses core's rollback after the others went back: they go forward again, the words are plain.
func TestUpdateRollbackRefusedByTheHostRollsTheOthersForward(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.4.0", "1.3.0"), "1.4.0", true)
	fh.refuse["rollback core"] = api.CodeRollbackBackupMissing
	wantOK(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 200)
	run := endedRun(t, e)
	want := "Rolling back Vedette failed: The copy of the database from before the update is no longer on the box, so the rollback cannot put it back. The other services were put back on 1.4.0."
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
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", false)
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
	fh.setState(lockstep("1.3.0", "1.4.0"))
	e.clock.Advance(7 * time.Hour) // the restored run is older than the 6-hour rule: it is still settled from the host
	e.handler = e.start(t, "1.3.0")
	run := endedRun(t, e)
	if run["action"] != "rollback" || run["status"] != "done" || run["from"] != "1.4.0" || run["to"] != "1.3.0" || run["user"] != "other@acme.example" {
		t.Fatalf("run = %v", run)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if len(hist) != 2 || hist[0].(map[string]any)["action"] != "rollback" || hist[1].(map[string]any)["action"] != "update" {
		t.Errorf("history = %v", hist)
	}
}

// The lab sequence: the rollback restored the database, core is back up and follows the restored update run while the
// host has not ended the rollback's run yet (it waits for core's health first). The update must not be settled done
// then: it waits for the host's run to end, and the rollback is rebuilt from it.
func TestUpdateRollbackStillRunningAtTheHostIsWaitedFor(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", false)
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
	fh.addRun(api.Run{RunID: "rn_00000000000000ff", Command: api.CmdContainerRollback, Status: api.StatusRunning, StartedAt: time.Now(),
		Actor: "other@acme.example", RequestID: "11111111-1111-4111-8111-111111111111", Result: json.RawMessage(`{"digest":"d","from_digest":"f","restored_backup_id":"b1"}`)})
	nilCore := lockstep("1.3.0", "1.4.0") // the real host reports core's version as null until the rollback's run ends
	nilCore.Services[0].Version = nil
	fh.setState(nilCore)
	e.retry = time.Millisecond
	before := fh.listed()
	e.handler = e.start(t, "1.3.0")
	eventuallyOS(t, "the follower to look at the host's runs more than once", func() bool { return fh.listed() >= before+4 })
	if r, _ := e.admin.get("/core/updates").JSON["run"].(map[string]any); r == nil || r["status"] != "running" {
		t.Fatalf("the run was settled while the rollback still ran at the host: %v", r)
	}
	fh.setState(lockstep("1.3.0", "1.4.0"))
	fh.endRun("rn_00000000000000ff")
	run := endedRun(t, e)
	if run["action"] != "rollback" || run["status"] != "done" || run["from"] != "1.4.0" || run["to"] != "1.3.0" {
		t.Fatalf("run = %v", run)
	}
	hist := e.admin.get("/core/updates").JSON["history"].([]any)
	if len(hist) != 2 || hist[0].(map[string]any)["action"] != "rollback" {
		t.Errorf("history = %v", hist)
	}
}

// A host that answers rebooting, dpkg_locked or install_in_progress is busy for a while, not final: the run keeps
// waiting under the same key and goes on when the host takes the call (the refused runs the host records are not
// the call's outcome).
func TestUpdateRunWaitsOutATransientHostRefusal(t *testing.T) {
	t.Parallel()
	for _, code := range []string{api.CodeRebooting, api.CodeDpkgLocked, api.CodeInstallInProgress} {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
			core.SetUpdateRetryForTest(e.handler, time.Millisecond)
			fh.refuse["start core"] = code
			wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
			eventuallyOS(t, "core's switch to be sent three times", func() bool { return countOf(fh.callList(), "start core 1.4.0 snap") >= 3 })
			if r, _ := e.admin.get("/core/updates").JSON["run"].(map[string]any); r == nil || r["status"] != "running" {
				t.Fatalf("the run ended on %s: %v", code, r)
			}
			fh.mu.Lock()
			delete(fh.refuse, "start core")
			fh.mu.Unlock()
			if run := endedRun(t, e); run["status"] != "done" {
				t.Fatalf("run = %v", run)
			}
		})
	}
}

// coreSwitchSent reads the stored run: is core's switch marked as sent?
func coreSwitchSent(t *testing.T, e *runEnv) bool {
	t.Helper()
	var raw string
	_ = e.env.DB.Reader().QueryRowContext(t.Context(), "SELECT value FROM core_setting WHERE key = 'core_update_run'").Scan(&raw)
	var rec struct {
		Calls []struct {
			Service, Command string
			Sent             bool
		}
	}
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Calls {
		if c.Service == api.ServiceCore && c.Command == api.CmdContainerStart {
			return c.Sent
		}
	}
	return false
}

// The host refuses core's switch because the box is rebooting; core restarts with the box. The refusal bound no key,
// so the switch was not sent: the run sends it again and ends done (not "no record that Vedette switched").
func TestUpdateCoreSwitchRefusedAsRebootingIsSentAfterTheRestart(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.refuse["start core"] = api.CodeRebooting
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	eventuallyOS(t, "the refused switch to be marked as not sent", func() bool { return !coreSwitchSent(t, e) })
	e.handler.Close()
	fh.mu.Lock()
	delete(fh.refuse, "start core")
	fh.mu.Unlock()
	e.handler = e.start(t, "1.3.0")
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
}

// A host that cannot be read when the update is settled does not make the run forget the rollback: it is tried again.
func TestUpdateRollbackLostToARestoredDatabaseSurvivesFailedHostReads(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", false)
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
	fin := time.Now()
	fh.addRun(api.Run{RunID: "rn_00000000000000ff", Command: api.CmdContainerRollback, Status: api.StatusSucceeded, StartedAt: fin.Add(-time.Minute), FinishedAt: &fin,
		Actor: "other@acme.example", RequestID: "11111111-1111-4111-8111-111111111111", Result: json.RawMessage(`{"digest":"d","from_digest":"f","restored_backup_id":"b1"}`)})
	fh.setState(lockstep("1.3.0", "1.4.0"))
	fh.mu.Lock()
	fh.stateDown, fh.down = 3, 2
	fh.mu.Unlock()
	e.retry = time.Millisecond
	e.handler = e.start(t, "1.3.0")
	// the follower meets the failed reads, not the page's GET below
	eventuallyOS(t, "the failed state reads to be used up", func() bool { fh.mu.Lock(); defer fh.mu.Unlock(); return fh.stateDown == 0 })
	if run := endedRun(t, e); run["action"] != "rollback" || run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
}

func TestRetryWait(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want time.Duration
	}{
		{"no error", nil, 5 * time.Second},
		{"unrelated error", errors.New("x"), 5 * time.Second},
		{"no retry_after_s", &hostclient.Error{Code: api.CodeBusy}, 5 * time.Second},
		{"shorter than the pause", &hostclient.Error{Code: api.CodeRateLimited, RetryAfterS: 2}, 5 * time.Second},
		{"longer than the pause", &hostclient.Error{Code: api.CodeDpkgLocked, RetryAfterS: 60}, time.Minute},
		{"wrapped", fmt.Errorf("x: %w", &hostclient.Error{Code: api.CodeDpkgLocked, RetryAfterS: 60}), time.Minute},
		{"capped", &hostclient.Error{Code: api.CodeDpkgLocked, RetryAfterS: 99999}, 5 * time.Minute},
	} {
		if got := core.RetryWaitForTest(tc.err, 5*time.Second); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestUpdateRunIsHiddenADayAfterItEnded(t *testing.T) {
	t.Parallel()
	e, _ := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
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

// The rollback after an Apply asks for the confirmation when the release now running (the one that was offered, not
// yet stored as running by a check) says rollback.safe=false, and does not when it says true; a running release whose
// manifest is unknown asks too (D-342 (8)). The real check side, no stand-in.
func TestUpdateRollbackAfterAnApplyReadsTheReleaseItInstalled(t *testing.T) {
	t.Parallel()
	for _, safe := range []bool{false, true} {
		e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", safe)
		fh.hold["start core"] = true
		wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
		waitCall(t, fh, "start core")
		e.handler.Close()
		fh.release("start core")
		e.handler = e.start(t, "1.4.0") // the new release starts
		if run := endedRun(t, e); run["status"] != "done" {
			t.Fatalf("run = %v", run)
		}
		comp, _ := getArr(e.admin.get("/core/updates"), "components")[0].(map[string]any)
		if comp["version"] != "1.4.0" || comp["rollback_restores_data"] != !safe {
			t.Errorf("safe=%t: component = %v", safe, comp)
		}
		r := e.admin.post("/core/updates/rollback", map[string]any{"component": "software"})
		if safe {
			wantOK(t, r, 200)
			continue
		}
		wantStatus(t, r, 409, "confirm_required")
		e.handler.Close()
		e.handler = e.start(t, "1.4.1") // a build whose manifest the box never saw
		wantStatus(t, e.admin.post("/core/updates/rollback", map[string]any{"component": "software"}), 409, "confirm_required")
	}
}

// A snapshot the host finds too old or invalid at core's switch is taken again with the same key; the run goes on.
func TestUpdateCoreSwitchRetriesWithANewSnapshot(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.once["start core"] = api.CodeSnapshotRequired
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
	if n := countOf(fh.callList(), "start core 1.4.0 snap"); n != 2 {
		t.Errorf("core's switch sent %d times, want 2 (calls %q)", n, fh.callList())
	}
	// The snapshot is removed just after the end is stored, so the run can read done a moment before.
	eventuallyOS(t, "the snapshot to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
}

// A host that refuses every snapshot ends the run after maxSnapRefused new ones, not in an endless loop.
func TestUpdateCoreSwitchStopsAfterRepeatedSnapshotRefusals(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.refuse["start core"] = api.CodeSnapshotInvalid
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	if run := endedRun(t, e); run["status"] == "done" || run["status"] == "running" {
		t.Fatalf("run = %v, want it ended without the switch", run)
	}
	if n := countOf(fh.callList(), "start core 1.4.0 snap"); n > 3 {
		t.Errorf("core's switch sent %d times, want at most 3 (calls %q)", n, fh.callList())
	}
}

// A host that answers busy for ever does not keep the run alive: resends are not progress, so the 6-hour rule ends it.
func TestUpdateRunThatTheHostKeepsRefusingMeetsTheSixHourRule(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.refuse["start core"] = api.CodeBusy
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	e.clock.Advance(7 * time.Hour)
	if run := endedRun(t, e); run["status"] == "done" {
		t.Fatalf("run = %v, want it ended by the 6-hour rule", run)
	}
}

// A run whose end could not be stored is settled again later, not dropped as settled.
func TestUpdateRunEndThatCouldNotBeStoredIsSettledLater(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.hold["start core"] = true
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "start core")
	e.setting("core_update_history", `{"not":"a list"}`) // the end cannot be written while this is there
	fh.release("start core")
	pause(t, 300*time.Millisecond)
	var status string
	_ = e.env.DB.Reader().QueryRowContext(t.Context(), "SELECT json_extract(value, '$.status') FROM core_setting WHERE key = 'core_update_run'").Scan(&status)
	if status != "running" {
		t.Fatalf("stored status with an unreadable history = %q", status)
	}
	e.setting("core_update_history", "[]")
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
}

// An Apply that lands while the previous follower is ending is followed by that follower.
func TestUpdateApplyWhileTheFollowerEndsIsFollowed(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	core.HoldFollowerForTest(e.handler)
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	pause(t, 200*time.Millisecond)
	if c := fh.callList(); len(c) != 0 {
		t.Fatalf("calls with the follower held = %q", c)
	}
	core.EndFollowerForTest(e.handler)
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
}

// Apply is refused before any call when the host has no record of the running version.
func TestUpdateApplyNeedsTheRunningVersion(t *testing.T) {
	t.Parallel()
	st := lockstep("1.3.0", "1.2.0")
	st.Services[0].Version = nil
	e, fh := newRunEnv(t, st, "1.3.0", true)
	wantStatus(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 409, "current_version_unknown")
	if c := fh.callList(); len(c) != 0 {
		t.Errorf("calls = %q", c)
	}
}

// After a restart a pull is sent again with the bytes the run started with, even when a newer check changed the offer.
func TestUpdatePullIsResentWithTheStoredRelease(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	fh.refuse["pull sensor"] = api.CodeBusy // not taken: the follower keeps trying with the same key
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	waitCall(t, fh, "pull sensor")
	e.handler.Close()
	e.srv.mu.Lock()
	m := e.srv.files["/v1.4.0/release-manifest.json"]
	e.srv.mu.Unlock()
	e.srv.index(t, 6, m, 100, nil) // a newer index offering the same release
	e.handler = e.start(t, "1.3.0")
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	fh.mu.Lock()
	delete(fh.refuse, "pull sensor")
	fh.mu.Unlock()
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
	fh.mu.Lock()
	defer fh.mu.Unlock()
	sent := fh.pulled[api.ServiceSensor]
	if len(sent) < 2 || slices.ContainsFunc(sent, func(x string) bool { return x != sent[0] }) || sent[0] != fh.pulled[api.ServiceCore][0] {
		t.Errorf("indexes sent with the sensor's pulls differ: %d sends", len(sent))
	}
}
