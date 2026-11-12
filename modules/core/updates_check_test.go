package core_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/modules/core"
)

// The software update check (D-341) against a local TLS server that plays GitHub releases, with documents signed by
// throwaway keys (opstest.Release); nothing reaches the internet. The running release is 1.3.0, the offered 1.4.0.

const runningVersion = "1.3.0"

// releaseServer serves the release documents at the paths of the GitHub release URLs and counts the requests.
type releaseServer struct {
	*httptest.Server
	rel   *opstest.Release
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newReleaseServer(t *testing.T) *releaseServer {
	t.Helper()
	s := &releaseServer{rel: opstest.NewRelease(t), files: map[string][]byte{}, hits: map[string]int{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		b, ok := s.files[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *releaseServer) put(path string, b []byte) {
	s.mu.Lock()
	s.files[path] = b
	s.mu.Unlock()
}

func (s *releaseServer) hit(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *releaseServer) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range s.hits {
		n += v
	}
	return n
}

func (s *releaseServer) manifestURL(v string) string {
	return s.URL + "/v" + v + "/release-manifest.json"
}

// manifest is a release manifest for v, signed with the active key, published at its path.
func (s *releaseServer) manifest(t *testing.T, v string, edit func(opstest.Doc)) []byte {
	t.Helper()
	d := s.rel.ManifestDoc(v, opstest.Img{Service: "core", Digest: "sha256:" + strings.Repeat("a", 64), Size: 3 << 20},
		opstest.Img{Service: "sensor", Digest: "sha256:" + strings.Repeat("b", 64), Size: 1 << 20})
	d["notes"] = "Faster checks. " + strings.Repeat("x", 600)
	d["bundled"] = []any{opstest.Doc{"service": "honeypot", "name": "opencanary", "version": "0.9.4"}}
	if edit != nil {
		edit(d)
	}
	raw := opstest.JSON(t, d)
	s.put("/v"+v+"/release-manifest.json", raw)
	s.put("/v"+v+"/release-manifest.json.minisig", s.rel.Sign(raw))
	return raw
}

// index publishes an index whose stable channel offers 1.4.0 (manifest raw) to percent of the boxes.
func (s *releaseServer) index(t *testing.T, seq uint64, manifestRaw []byte, percent int, edit func(opstest.Doc)) {
	t.Helper()
	sum := sha256.Sum256(manifestRaw)
	d := s.rel.IndexDoc(seq)
	d["channels"] = opstest.Doc{"stable": opstest.Doc{"latest": "1.4.0", "manifest": s.manifestURL("1.4.0"),
		"manifest_sha256": hex.EncodeToString(sum[:]), "rollout": opstest.Doc{"percent": percent}}}
	d["advisories"] = []any{
		opstest.Doc{"id": "VSA-1", "severity": "high", "title": "Session fixation", "affects": "<1.4.0", "fixed_in": "1.4.0", "url": "https://example.org/a"},
		opstest.Doc{"id": "VSA-2", "severity": "low", "title": "Old bug", "affects": "<1.2.0", "fixed_in": "1.2.0", "url": "https://example.org/b"},
		opstest.Doc{"id": "VSA-3", "severity": "critical", "title": "No fix yet", "affects": "*", "url": "https://example.org/c"},
	}
	if edit != nil {
		edit(d)
	}
	raw := opstest.JSON(t, d)
	s.put("/index/index.json", raw)
	s.put("/index/index.json.minisig", s.rel.Sign(raw))
}

// standard publishes the running release (rollback.safe=false) and an index offering 1.4.0 to every box.
func (s *releaseServer) standard(t *testing.T, seq uint64) {
	t.Helper()
	s.manifest(t, runningVersion, func(d opstest.Doc) { d["rollback"] = opstest.Doc{"safe": false, "min_version": ""} })
	m := s.manifest(t, "1.4.0", func(d opstest.Doc) {
		d["bundled"] = []any{opstest.Doc{"service": "honeypot", "name": "opencanary", "version": "0.9.5"}}
	})
	s.index(t, seq, m, 100, nil)
}

type updEnv struct {
	*osEnv
	srv *releaseServer
	upd *core.OSHandlers
}

// newUpdEnv is an osEnv whose handlers check against srv. The organization exists (install id "ins-test").
func newUpdEnv(t *testing.T, o osOpts) *updEnv {
	t.Helper()
	e := &updEnv{osEnv: newOSEnv(t, o), srv: newReleaseServer(t)}
	e.setZone("UTC")
	var host core.Host
	if !o.noHost {
		host = e.gate
	}
	version, base := runningVersion, e.srv.URL
	if o.testBase {
		version, base = runningVersion+"-test.1", ""
		if err := os.WriteFile(filepath.Join(e.m.CoreData, "test-release-base"), []byte(e.srv.URL+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h, err := core.NewOSHandlers(core.OSConfig{
		DB: e.env.DB, Auth: e.env.Svc, Audit: e.env.Audit, Log: e.logger(), Host: host,
		DataDir: e.m.CoreData, KeyPath: filepath.Join(e.m.CoreData, "vedette.key"),
		Zone: e.h.OrgTimeZone, Clock: e.clock.Now, Gate: e.purgeGate,
		Version: version, ReleaseBase: base, HTTPClient: e.srv.Client(), Trust: e.srv.rel.Keys,
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
	e.api, e.upd = api, h
	return e
}

func cohortOf(id string) int {
	s := sha256.Sum256([]byte(id + "vedette-cohort"))
	return int(binary.BigEndian.Uint32(s[:4]) % 100)
}

func (e *updEnv) wantNothingOffered(t *testing.T, r reply) {
	t.Helper()
	if a := getArr(r, "available"); len(a) != 0 {
		t.Fatalf("available = %v, want none", a)
	}
	if _, err := e.upd.OfferedVersionForTest(t.Context()); !errors.Is(err, core.ErrNoUpdate) {
		t.Fatalf("offered() = %v, want errNoUpdate", err)
	}
}

func TestUpdateCheckOffersTheNewRelease(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	e.srv.standard(t, 5)

	before := e.viewer.get("/core/updates")
	wantOK(t, before, 200)
	if before.str("channel") != "stable" || before.str("mode") != "manual" || getVal(before, "check_enabled") != true ||
		before.JSON["last_check"] != nil || len(getArr(before, "available")) != 0 {
		t.Fatalf("state before any check = %s", before.Raw)
	}

	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	if getVal(r, "applied") != float64(0) || r.str("last_check") == "" {
		t.Errorf("applied/last_check = %v %v", getVal(r, "applied"), r.str("last_check"))
	}
	av := getArr(r, "available")
	if len(av) != 1 {
		t.Fatalf("available = %s", r.Raw)
	}
	a, _ := av[0].(map[string]any)
	if a["component"] != "software" || a["version"] != "1.4.0" || a["channel"] != "stable" || a["size_kb"] != float64(4096) || len([]rune(a["note"].(string))) != 500 {
		t.Errorf("available[0] = %v", a)
	}
	comp, _ := getArr(r, "components")[0].(map[string]any)
	if comp["id"] != "software" || comp["version"] != runningVersion || comp["previous"] != nil || comp["signature"] != "unsigned" || comp["rollback_restores_data"] != true {
		t.Errorf("component = %v", comp)
	}
	adv := getArr(r, "advisories")
	if len(adv) != 2 {
		t.Fatalf("advisories = %v (the one without fixed_in is left out)", adv)
	}
	a1, _ := adv[0].(map[string]any)
	a2, _ := adv[1].(map[string]any)
	if a1["id"] != "VSA-1" || a1["status"] != "affected" || a1["severity"] != "high" || a1["published"] != "2026-12-02" || a1["summary"] != "Session fixation" ||
		a2["status"] != "fixed" || a2["severity"] != "medium" {
		t.Errorf("advisories = %v", adv)
	}
	mg := getArr(r, "managed")
	if len(mg) != 1 || mg[0].(map[string]any)["version"] != "0.9.4" || mg[0].(map[string]any)["status"] != "update_pending" {
		t.Errorf("managed = %v", mg)
	}
	if getVal(r, "run") != nil || len(getArr(r, "history")) != 0 {
		t.Errorf("run/history = %v %v", getVal(r, "run"), getVal(r, "history"))
	}
	if v, err := e.upd.OfferedVersionForTest(t.Context()); err != nil || v != "1.4.0" {
		t.Errorf("offered() = %q %v", v, err)
	}
	if d, err := e.upd.RunningRestoresDataForTest(t.Context()); err != nil || !d {
		t.Errorf("runningRestoresData = %v %v", d, err)
	}
	if acts := e.actions(); !slices.Contains(acts, "update.check") {
		t.Errorf("audit = %v", acts)
	}
	// GET answers from the stored state: no request leaves the box.
	n := e.srv.total()
	g := e.viewer.get("/core/updates")
	wantOK(t, g, 200)
	if len(getArr(g, "available")) != 1 || e.srv.total() != n {
		t.Errorf("GET = %s, requests %d -> %d", g.Raw, n, e.srv.total())
	}
	// The running release's manifest is fetched once per version.
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	if got := e.srv.hit("/v1.3.0/release-manifest.json"); got != 1 {
		t.Errorf("running manifest fetched %d times", got)
	}
	// Another channel: the stored offer is of stable, so nothing is offered until the next check.
	p := e.admin.patch("/core/updates", map[string]any{"channel": "beta", "mode": "auto"})
	wantOK(t, p, 200)
	if p.str("channel") != "beta" || p.str("mode") != "auto" || len(getArr(p, "available")) != 0 {
		t.Errorf("after PATCH = %s", p.Raw)
	}
}

func TestUpdateCheckRespectsTheCohort(t *testing.T) {
	t.Parallel()
	n := cohortOf("ins-test")
	e := newUpdEnv(t, osOpts{noHost: true})
	m := e.srv.manifest(t, "1.4.0", nil)
	e.srv.index(t, 5, m, n, nil) // cohort n is not below n: not yet
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	e.wantNothingOffered(t, r)
	if e.srv.hit("/v1.4.0/release-manifest.json") != 0 {
		t.Error("the manifest was fetched for a box outside the rollout")
	}
	if n < 99 {
		e.srv.index(t, 6, m, n+1, nil)
		r = e.oper.post("/core/updates/check", nil)
		wantOK(t, r, 200)
		if len(getArr(r, "available")) != 1 {
			t.Errorf("percent %d, cohort %d: %s", n+1, n, r.Raw)
		}
	}
}

func TestUpdateCheckBelowMinUpgradeFrom(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	m := e.srv.manifest(t, "1.4.0", func(d opstest.Doc) { d["min_upgrade_from"] = "1.3.5" })
	e.srv.index(t, 5, m, 100, nil)
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	e.wantNothingOffered(t, r)
}

func TestUpdateCheckRevokedRelease(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	e.srv.standard(t, 5)
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	m := e.srv.manifest(t, "1.4.0", func(d opstest.Doc) {
		d["bundled"] = []any{opstest.Doc{"service": "honeypot", "name": "opencanary", "version": "0.9.5"}}
	})
	e.srv.index(t, 6, m, 100, func(d opstest.Doc) { d["revoked"] = []any{opstest.Revocation("release", "1.4.0")} })
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	e.wantNothingOffered(t, r)
}

func TestUpdateCheckRefusesWhatDoesNotVerify(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		code    int
		code2   string
		breakIt func(t *testing.T, e *updEnv)
	}{
		"bad index signature": {502, core.CodeUpdateCheckFailed, func(t *testing.T, e *updEnv) {
			other := opstest.NewRelease(t)
			e.srv.put("/index/index.json.minisig", other.Sign(e.srv.files["/index/index.json"]))
		}},
		"bad manifest signature": {502, core.CodeUpdateCheckFailed, func(t *testing.T, e *updEnv) {
			e.srv.put("/v1.4.0/release-manifest.json.minisig", opstest.NewRelease(t).Sign(e.srv.files["/v1.4.0/release-manifest.json"]))
		}},
		"manifest hash differs": {502, core.CodeUpdateCheckFailed, func(t *testing.T, e *updEnv) {
			e.srv.manifest(t, "1.4.0", func(d opstest.Doc) { d["notes"] = "changed after the index" })
		}},
		"foreign manifest url": {502, core.CodeUpdateCheckFailed, func(t *testing.T, e *updEnv) {
			m := e.srv.files["/v1.4.0/release-manifest.json"]
			e.srv.index(t, 5, m, 100, func(d opstest.Doc) {
				ch := d["channels"].(opstest.Doc)["stable"].(opstest.Doc)
				ch["manifest"] = "https://evil.example/v1.4.0/release-manifest.json"
			})
		}},
		"oversize index": {502, core.CodeUpdateCheckFailed, func(_ *testing.T, e *updEnv) {
			e.srv.put("/index/index.json", make([]byte, release.MaxDocBytes+1))
		}},
		"source down": {503, core.CodeUpdateSourceUnreachable, func(_ *testing.T, e *updEnv) {
			e.srv.mu.Lock()
			delete(e.srv.files, "/index/index.json")
			e.srv.mu.Unlock()
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newUpdEnv(t, osOpts{noHost: true})
			e.srv.standard(t, 5)
			tc.breakIt(t, e)
			r := e.oper.post("/core/updates/check", nil)
			wantStatus(t, r, tc.code, tc.code2)
			if strings.Contains(r.Raw, "evil") || strings.Contains(r.Raw, "HTTP 404") {
				t.Errorf("the answer echoes remote details: %s", r.Raw)
			}
			g := e.viewer.get("/core/updates")
			wantOK(t, g, 200)
			if g.JSON["last_check"] != nil {
				t.Errorf("last_check moved after a failed check: %v", g.JSON["last_check"])
			}
			e.wantNothingOffered(t, g)
			if e.srv.hit("/v1.4.0/release-manifest.json") != 0 && name == "foreign manifest url" {
				t.Error("a manifest was fetched although the index named another host")
			}
			if acts := e.actions(); !slices.Contains(acts, "update.check") {
				t.Errorf("a failed check has no audit row: %v", acts)
			}
		})
	}
}

func TestUpdateCheckRefusesASequenceRegress(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	e.srv.standard(t, 5)
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	e.srv.standard(t, 4)
	wantStatus(t, e.oper.post("/core/updates/check", nil), 502, core.CodeUpdateCheckFailed)
	// The stored index (5) still holds: the offer of the good check stays.
	if v, err := e.upd.OfferedVersionForTest(t.Context()); err != nil || v != "1.4.0" {
		t.Errorf("offered() after a refused regress = %q %v", v, err)
	}
	e.srv.standard(t, 7)
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
}

func TestUpdateCheckOffUnderPrivacy(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	e.srv.standard(t, 5)
	e.setting("core_privacy", `{"update_check":false}`)
	wantStatus(t, e.oper.post("/core/updates/check", nil), 409, core.CodeCheckOff)
	if n := e.srv.total(); n != 0 {
		t.Errorf("%d requests left the box with update checks off", n)
	}
	g := e.viewer.get("/core/updates")
	wantOK(t, g, 200)
	if getVal(g, "check_enabled") != false {
		t.Errorf("check_enabled = %v", getVal(g, "check_enabled"))
	}
	wantStatus(t, e.viewer.post("/core/updates/check", nil), 403, "forbidden")
}

func TestUpdateSettingsPatch(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	if r := e.admin.patch("/core/updates", map[string]any{"channel": "nightly"}); r.Code != 400 {
		t.Errorf("channel nightly = %d %s", r.Code, r.Raw)
	}
	if r := e.admin.patch("/core/updates", map[string]any{"mode": "sometimes"}); r.Code != 400 {
		t.Errorf("mode sometimes = %d %s", r.Code, r.Raw)
	}
	wantStatus(t, e.oper.patch("/core/updates", map[string]any{"mode": "auto"}), 403, "forbidden")
	r := e.admin.patch("/core/updates", map[string]any{"mode": "auto"})
	wantOK(t, r, 200)
	if r.str("mode") != "auto" || r.str("channel") != "stable" {
		t.Errorf("state = %s", r.Raw)
	}
	if acts := e.actions(); !slices.Contains(acts, "update.settings") {
		t.Errorf("audit = %v", acts)
	}
}

// With vedette-host: the page reads the host's record of core (none here: previous null, unsigned), and a release
// that is not for appliance installs is not offered.
func TestUpdateStateWithAHost(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{})
	e.srv.manifest(t, runningVersion, nil)
	m := e.srv.manifest(t, "1.4.0", func(d opstest.Doc) { d["install_modes"] = []string{"container"} })
	e.srv.index(t, 5, m, 100, nil)
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	e.wantNothingOffered(t, r)
	comp, _ := getArr(r, "components")[0].(map[string]any)
	if comp["previous"] != nil || comp["signature"] != "unsigned" || comp["rollback_restores_data"] != false {
		t.Errorf("component = %v", comp)
	}
	m = e.srv.manifest(t, "1.4.0", nil)
	e.srv.index(t, 6, m, 100, nil)
	wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	if v, err := e.upd.OfferedVersionForTest(t.Context()); err != nil || v != "1.4.0" {
		t.Errorf("offered() = %q %v", v, err)
	}
}

// #469: a test-channel build downloads from the local source, but the signed index must still name the project's release
// URL (core.DefaultReleaseBase), exactly as the test channel signs it. A release build ignores the file.
func TestUpdateCheckTestChannelSource(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true, testBase: true})
	m := e.srv.manifest(t, "1.4.0", nil)
	e.srv.index(t, 5, m, 100, func(d opstest.Doc) {
		ch, _ := d["channels"].(opstest.Doc)["stable"].(opstest.Doc)
		ch["manifest"] = core.DefaultReleaseBase + "/v1.4.0/release-manifest.json"
	})
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	if av := getArr(r, "available"); len(av) != 1 {
		t.Fatalf("available = %s", r.Raw)
	}
	if e.srv.hit("/index/index.json") == 0 || e.srv.hit("/v1.4.0/release-manifest.json") == 0 {
		t.Fatal("the documents did not come from the test source")
	}
}

// D-386: a revocation that hits the running release and an index past expires_at are in GET /core/updates.
func TestUpdateStateRevokedRunningAndStale(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	e.srv.standard(t, 5)
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	if getVal(r, "running_revoked") != nil || getVal(r, "stale_since") != nil {
		t.Fatalf("a current index that revokes nothing: %v %v", getVal(r, "running_revoked"), getVal(r, "stale_since"))
	}
	m := e.srv.manifest(t, "1.4.0", nil)
	revoke := func(seq uint64, rs ...opstest.Doc) {
		t.Helper()
		e.srv.index(t, seq, m, 100, func(d opstest.Doc) {
			list := []any{opstest.Revocation("release", "1.2.0")} // another release
			for _, x := range rs {
				list = append(list, x)
			}
			d["revoked"] = list
		})
		wantOK(t, e.oper.post("/core/updates/check", nil), 200)
	}
	want := func(action string) {
		t.Helper()
		g := e.viewer.get("/core/updates")
		wantOK(t, g, 200)
		got, _ := getVal(g, "running_revoked").(map[string]any)
		if got["version"] != runningVersion || got["reason"] != "test" || got["since"] != "2026-12-02T08:00:00Z" || got["action"] != action {
			t.Fatalf("running_revoked = %v, want action %s", getVal(g, "running_revoked"), action)
		}
	}
	revoke(6)
	if g := e.viewer.get("/core/updates"); getVal(g, "running_revoked") != nil {
		t.Fatalf("running_revoked = %v for a revocation of another release", getVal(g, "running_revoked"))
	}
	revoke(7, opstest.Revocation("release", runningVersion))
	want("block_install")
	// a digest of the running release's manifest, with a warning, wins; the earlier revocation is carried (sticky, §8)
	warn := opstest.Revocation("image_digest", "sha256:"+strings.Repeat("a", 64))
	warn["action"] = "block_install_and_warn"
	revoke(8, warn)
	want("block_install_and_warn")

	e.clock.Advance(40 * 24 * time.Hour) // past expires_at (generated 2026-12-02, plus 14 days)
	g := e.viewer.get("/core/updates")
	wantOK(t, g, 200)
	if getVal(g, "stale_since") != "2026-12-16T08:00:00Z" {
		t.Fatalf("stale_since = %v", getVal(g, "stale_since"))
	}
}
