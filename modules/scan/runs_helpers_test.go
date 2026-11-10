package scan

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/pack"
)

// The sample devices of the tests. a-nas02 is fragile and has the finding of CVE-2022-27593, which the pack has a
// template for; a-web01 has CVE-2024-3400 (template) and CVE-2021-44228 (none); a-srv has no finding.
func sampleDevices() []Device {
	return []Device{
		{ID: "a-nas02", Label: "NAS-PHOTOS", IP: "192.168.10.21", Kind: "nas", Approved: true, Fragile: true, Services: []OpenPort{{Port: 5000, Name: "http"}, {Port: 22, Name: "ssh"}}},
		{ID: "a-web01", Label: "WEB01", IP: "192.168.10.12", Kind: "web", Approved: true, Services: []OpenPort{{Port: 443, Name: "https"}}},
		{ID: "a-srv", Label: "SRV-AD", IP: "192.168.10.10", Kind: "server", Approved: true},
		{ID: "a-unk", Label: "192.168.10.157", IP: "192.168.10.157", Kind: "unknown", Approved: false},
		{ID: "a-box", Label: "vedette", IP: "192.168.10.250", Kind: "server", Approved: true},
		{ID: "a-never", Label: "PLC-1", IP: "192.168.20.40", Kind: "iot", Approved: true},
		{ID: "a-far", Label: "FAR", IP: "10.9.9.9", Kind: "pc", Approved: true},
	}
}

// fakePolicy answers VulnScanPolicy like inventory does for the sample (D-126): the box and "never" always refused, a
// fragile device only when explicit.
func samplePolicy(id string, explicit bool) Decision {
	switch id {
	case "a-box":
		return Decision{Reason: reasonBox}
	case "a-never":
		return Decision{Reason: reasonNever}
	case "a-far":
		return Decision{Reason: reasonOutOfScope}
	case "a-nas02":
		if !explicit {
			return Decision{Reason: "fragile_passive_only"}
		}
		return Decision{Allowed: true, Reason: "ok", Careful: true}
	}
	return Decision{Allowed: true, Reason: "ok"}
}

type policyCall struct {
	id       string
	explicit bool
}

// runInventory extends fakeInventory with devices and the policy.
type runInventory struct {
	fakeInventory
	mu      sync.Mutex
	devices []Device
	policy  func(id string, explicit bool) Decision
	calls   []policyCall
}

func (f *runInventory) Devices(context.Context) ([]Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.devices), nil
}

func (f *runInventory) VulnScanPolicy(_ context.Context, id string, explicit bool) (Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, policyCall{id, explicit})
	d := f.policy(id, explicit)
	if d.IP == "" {
		for _, dev := range f.devices { // the address the inventory decided on: the device's current one
			if dev.ID == id {
				d.IP = dev.IP
			}
		}
	}
	return d, nil
}

func (f *runInventory) setPolicy(p func(id string, explicit bool) Decision) {
	f.mu.Lock()
	f.policy = p
	f.mu.Unlock()
}

func (f *runInventory) edit(id string, fn func(*Device)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.devices {
		if f.devices[i].ID == id {
			fn(&f.devices[i])
		}
	}
}

type fakeFindings struct {
	mu        sync.Mutex
	list      []FindingRef
	confirmed []Evidence
	confirms  []string // asset|cve
	lists     int      // List calls
}

func (f *fakeFindings) listCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
}

func (f *fakeFindings) List(_ context.Context, assetID string) ([]FindingRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	var out []FindingRef
	for _, r := range f.list {
		if assetID == "" || r.AssetID == assetID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeFindings) ConfirmFromScan(_ context.Context, assetID, cve string, ev Evidence) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirms = append(f.confirms, assetID+"|"+cve)
	f.confirmed = append(f.confirmed, ev)
	for _, r := range f.list {
		if r.AssetID == assetID && r.CVE == cve {
			return r.ID, nil
		}
	}
	return "", errors.New("no such finding")
}

func sampleFindings() []FindingRef {
	return []FindingRef{
		{ID: "f-1", AssetID: "a-nas02", CVE: "CVE-2022-27593", Status: "confirmed"},
		{ID: "f-2", AssetID: "a-web01", CVE: "CVE-2024-3400", Status: "suspected"},
		{ID: "f-3", AssetID: "a-web01", CVE: "CVE-2021-44228", Status: "suspected"},
	}
}

// runEngine is the scanner seam in tests: it records every job and answers with what reply returns for it.
// block makes Run wait until its context ends (a device that is being scanned when Stop now comes).
type runEngine struct {
	fakeEngine
	mu       sync.Mutex
	jobs     []nucleiargv.Job
	reply    func(j nucleiargv.Job) (Output, error)
	block    chan struct{} // closed: Run is blocking
	onRun    func(j nucleiargv.Job)
	blocked  bool
	stubborn chan struct{} // set: Run ignores its context and returns only when this is closed (a worker that does not stop)
}

func (f *runEngine) Run(ctx context.Context, j nucleiargv.Job) (Output, error) {
	f.mu.Lock()
	f.jobs = append(f.jobs, j)
	reply, onRun, blocked, ch, stubborn := f.reply, f.onRun, f.blocked, f.block, f.stubborn
	f.mu.Unlock()
	if onRun != nil {
		onRun(j)
	}
	if stubborn != nil {
		close(ch)
		<-stubborn
		return Output{}, ctx.Err()
	}
	if blocked {
		close(ch)
		<-ctx.Done()
		return Output{}, ctx.Err()
	}
	return reply(j)
}

func (f *runEngine) sent() []nucleiargv.Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.jobs)
}

// idOf is the template id of a pack path in the test pack (the file is named after its id).
func idOf(p string) string { return strings.TrimSuffix(path.Base(p), ".yaml") }

// lines answers every template of the job on its first target: matched for the ids in hit, an error for every
// template when dead, not matched otherwise.
func lines(hit ...string) func(j nucleiargv.Job) (Output, error) {
	return func(j nucleiargv.Job) (Output, error) {
		var b strings.Builder
		for _, p := range j.Templates {
			id := idOf(p)
			m := slices.Contains(hit, id)
			b.WriteString(`{"template-id":"` + id + `","host":"` + j.Targets[0].Input() + `","matcher-status":`)
			if m {
				b.WriteString(`true,"request":"GET /photo/p/api/video.php HTTP/1.1\r\nHost: x","response":"HTTP/1.1 200 OK\r\n\r\nphoto station"}`)
			} else {
				b.WriteString("false}")
			}
			b.WriteByte('\n')
		}
		return Output{JSONL: []byte(b.String())}, nil
	}
}

func dead(j nucleiargv.Job) (Output, error) {
	var b strings.Builder
	for _, p := range j.Templates {
		b.WriteString(`{"template-id":"` + idOf(p) + `","host":"` + j.Targets[0].Input() + `","matcher-status":false,"error":"context deadline exceeded"}` + "\n")
	}
	return Output{JSONL: []byte(b.String())}, nil
}

type runEnv struct {
	*env
	inv      *runInventory
	findings *fakeFindings
	eng      *runEngine
}

func testPack(t *testing.T) *pack.Index {
	t.Helper()
	b, err := os.ReadFile("pack/testdata/index.json")
	if err != nil {
		t.Fatal(err)
	}
	ix, err := pack.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func newRunEnv(t *testing.T) *runEnv {
	t.Helper()
	e := newEnv(t)
	r := &runEnv{env: e,
		inv:      &runInventory{fakeInventory: fakeInventory{scope: confirmedScope()}, devices: sampleDevices(), policy: samplePolicy},
		findings: &fakeFindings{list: sampleFindings()},
		eng:      &runEngine{reply: lines("CVE-2022-27593")},
	}
	cfg := e.svc.cfg
	cfg.Inventory, cfg.Findings, cfg.Engine, cfg.Pack = r.inv, r.findings, r.eng, testPack(t)
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return r
}

// wait blocks until the run in the background has ended.
func (r *runEnv) wait() {
	r.t.Helper()
	r.svc.mu.Lock()
	l := r.svc.live
	r.svc.mu.Unlock()
	if l == nil {
		return
	}
	select {
	case <-l.done:
	case <-time.After(10 * time.Second):
		r.t.Fatal("the run did not end")
	}
}

func (r *runEnv) start(ids ...string) RunView {
	r.t.Helper()
	v, err := r.svc.StartRun(r.ctx(), "it@acme.example", ids)
	if err != nil {
		r.t.Fatal(err)
	}
	return v
}

func (r *runEnv) run(id string) RunView {
	r.t.Helper()
	v, err := r.svc.Run(r.ctx(), id)
	if err != nil {
		r.t.Fatal(err)
	}
	return v
}

func rowOf(v RunView, target, result string) *RunRow {
	for i, row := range v.Results {
		if row.TargetID == target && (result == "" || row.Result == result) {
			return &v.Results[i]
		}
	}
	return nil
}

type fakeExternal []ExternalTarget

func (f fakeExternal) Targets(context.Context) ([]ExternalTarget, error) { return f, nil }

func (r *runEnv) cfgExternal(ts ...ExternalTarget) { r.svc.cfg.External = fakeExternal(ts) }

// httpRun serves the run env's service through the real server pipeline.
func (r *runEnv) http() *httpEnv {
	r.t.Helper()
	gate := servertest.NewGate()
	h, err := server.New(server.Config{
		API:     scanOnly{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, ScanHandlers: NewScanHandlers(r.svc)},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: gate,
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return &httpEnv{env: r.env, h: h, gate: gate}
}
