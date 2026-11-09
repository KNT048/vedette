package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// feedsHandler is a tiny module handler: one feeds operation, one core admin operation, a public one
// and a few that misbehave on purpose.
type feedsHandler struct{ seen *seen }

type seen struct {
	mu        sync.Mutex
	principal []server.Principal
	requestID []string
}

func (s *seen) record(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, _ := server.PrincipalFrom(ctx)
	s.principal = append(s.principal, p)
	s.requestID = append(s.requestID, server.RequestIDFrom(ctx))
}

func (h feedsHandler) FeedsGetFeedsStatus(ctx context.Context) (*oas.FeedsGetFeedsStatusOK, error) {
	h.seen.record(ctx)
	return &oas.FeedsGetFeedsStatusOK{}, nil
}

func (h feedsHandler) FeedsGetFeedsWeekly(context.Context) (*oas.FeedsGetFeedsWeeklyOK, error) {
	panic("secret internal detail: /var/lib/vedette/vedette.db")
}

func (h feedsHandler) FeedsGetFeedsSources(context.Context) (*oas.FeedsGetFeedsSourcesOK, error) {
	return nil, errors.New("sql: table feeds_source locked at /var/lib/vedette/vedette.db")
}

type coreHandler struct{ seen *seen }

func (h coreHandler) CoreGetSetup(ctx context.Context) (*oas.CoreGetSetupOK, error) {
	h.seen.record(ctx)
	return &oas.CoreGetSetupOK{Org: "Acme", DataMode: oas.CoreGetSetupOKDataModeClean}, nil
}

func (h coreHandler) CorePostAuthLogout(context.Context) error { return nil }

func (h coreHandler) CorePutCoreGeneral(_ context.Context, req *oas.CorePutCoreGeneralReq) (*oas.CorePutCoreGeneralOK, error) {
	return &oas.CorePutCoreGeneralOK{Name: req.Name, Timezone: req.Timezone}, nil
}

func (h coreHandler) CoreGetCoreGeneral(context.Context) (*oas.CoreGetCoreGeneralOK, error) {
	return nil, apierr.New(http.StatusConflict, "missing_dependencies", "Module x also needs: y.").With("missing", []string{"y"})
}

// composite is the pattern of cmd/vedette: Fallback (which embeds oas.UnimplementedHandler) sits one
// level below the module handlers, so a module's method shadows the 501 stub. Two module handlers
// that implement the same operation make the method ambiguous at the same depth: the struct then no
// longer satisfies oas.Handler and the assignment below stops compiling. Fallback's own NewError
// (depth 1) is the default error response.
type composite struct {
	server.Fallback // depth 1 here; UnimplementedHandler is at depth 2
	feedsHandler    // depth 1
	coreHandler     // depth 1
}

var _ oas.Handler = composite{}

type rig struct {
	h    http.Handler
	auth *servertest.Auth
	gate *servertest.Gate
	seen *seen
	logs *strings.Builder
}

func newRig(t *testing.T, off ...string) *rig {
	t.Helper()
	sn := &seen{}
	logs := &strings.Builder{}
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: logs}, nil))
	auth := &servertest.Auth{Users: servertest.StandardUsers()}
	gate := servertest.NewGate(off...)
	h, err := server.New(server.Config{
		API:  composite{Fallback: server.Fallback{Log: log}, feedsHandler: feedsHandler{sn}, coreHandler: coreHandler{sn}},
		Auth: auth, Modules: gate, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{h: h, auth: auth, gate: gate, seen: sn, logs: logs}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type req struct {
	method, path, user, body string
	csrf                     bool
	header                   map[string]string
}

func (r *rig) do(t *testing.T, q req) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if q.body != "" {
		body = strings.NewReader(q.body)
	}
	hr := httptest.NewRequestWithContext(t.Context(), q.method, server.Prefix+q.path, body)
	if q.body != "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	if q.user != "" {
		hr.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: q.user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	if q.csrf {
		hr.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	}
	for k, v := range q.header {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, hr)
	return rec
}

type errBody struct {
	Error map[string]any `json:"error"`
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) errBody {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	var b errBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, rec.Body)
	}
	if b.Error["code"] != code {
		t.Fatalf("code = %v, want %s; body %s", b.Error["code"], code, rec.Body)
	}
	if msg, _ := b.Error["message"].(string); msg == "" {
		t.Fatalf("empty message: %s", rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type %q", ct)
	}
	return b
}

func TestUnknownRoutesAre404(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	for _, q := range []req{
		{method: "GET", path: "/nope", user: "admin"},
		{method: "GET", path: "/feeds/status/extra", user: "admin"},
		{method: "DELETE", path: "/feeds/status", user: "admin", csrf: true}, // known path, wrong method
		{method: "GET", path: "/nope"},                                       // no session: still 404, not 401
	} {
		wantError(t, r.do(t, q), 404, "not_found")
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", "/elsewhere", nil))
	wantError(t, rec, 404, "not_found")
}

func TestPublicRouteNeedsNoSession(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	rec := r.do(t, req{method: "GET", path: "/setup"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"org":"Acme"`) {
		t.Fatalf("GET /setup = %d %s", rec.Code, rec.Body)
	}
	if r.auth.Calls() != 0 {
		t.Fatalf("a public route ran the authenticator %d times", r.auth.Calls())
	}
	// A public POST needs no CSRF token (API_CONVENTIONS 7.2 point 5).
	if rec := r.do(t, req{method: "POST", path: "/auth/logout"}); rec.Code != 204 {
		t.Fatalf("POST /auth/logout = %d %s", rec.Code, rec.Body)
	}
}

func TestAuthenticationBeforeRole(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	wantError(t, r.do(t, req{method: "GET", path: "/feeds/status"}), 401, "unauthenticated")
	wantError(t, r.do(t, req{method: "GET", path: "/feeds/status", user: "ghost"}), 401, "unauthenticated")
	// No session on an admin route: 401, not 403 (401 before 403).
	wantError(t, r.do(t, req{method: "PUT", path: "/core/general", body: `{"name":"A","timezone":"UTC"}`, csrf: true}), 401, "unauthenticated")
	if r.seen.principal != nil {
		t.Fatal("the handler ran for an unauthenticated request")
	}
}

func TestRoleIsEnforcedFromTheRouteTable(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	body := `{"name":"Acme","timezone":"Asia/Ho_Chi_Minh"}`
	for user, want := range map[string]int{"viewer": 403, "operator": 403, "admin": 200} {
		rec := r.do(t, req{method: "PUT", path: "/core/general", user: user, body: body, csrf: true})
		if rec.Code != want {
			t.Errorf("%s PUT /core/general = %d, want %d; %s", user, rec.Code, want, rec.Body)
		}
		if want == 403 {
			wantError(t, rec, 403, "forbidden")
		}
	}
	// A viewer route is open to every role.
	for _, user := range []string{"viewer", "operator", "admin"} {
		if rec := r.do(t, req{method: "GET", path: "/feeds/status", user: user}); rec.Code != 200 {
			t.Errorf("%s GET /feeds/status = %d", user, rec.Code)
		}
	}
	// A role the table does not know is refused everywhere.
	r.auth.Users["odd"] = server.Principal{ID: "x", Email: "x@y.example", Role: "root"}
	wantError(t, r.do(t, req{method: "GET", path: "/feeds/status", user: "odd"}), 403, "forbidden")
}

func TestCSRFOnStateChangingRequests(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	body := `{"name":"Acme","timezone":"UTC"}`
	wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", body: body}), 403, "csrf_invalid")
	wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", body: body, header: map[string]string{servertest.CSRFHeader: "wrong"}}), 403, "csrf_invalid")
	if rec := r.do(t, req{method: "PUT", path: "/core/general", user: "admin", body: body, csrf: true}); rec.Code != 200 {
		t.Fatalf("with the token: %d %s", rec.Code, rec.Body)
	}
	// GET never needs it.
	if rec := r.do(t, req{method: "GET", path: "/feeds/status", user: "viewer"}); rec.Code != 200 {
		t.Fatalf("GET without a token: %d", rec.Code)
	}
	// Role is checked before CSRF: a viewer without a token learns forbidden, not csrf_invalid.
	wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "viewer", body: body}), 403, "forbidden")
}

// SYS-5: a route of an off module is indistinguishable from a route that does not exist.
func TestOffModuleLooksLikeUnknownRoute(t *testing.T) {
	t.Parallel()
	r := newRig(t, "feeds")
	off := r.do(t, req{method: "GET", path: "/feeds/status", user: "admin"})
	unknown := r.do(t, req{method: "GET", path: "/does/not/exist", user: "admin"})
	wantError(t, off, 404, "not_found")
	if off.Body.String() != unknown.Body.String() {
		t.Fatalf("off module body differs from an unknown route:\n%s\n%s", off.Body, unknown.Body)
	}
	// A route that needs a session answers 401 to an anonymous client whether the module is on or off:
	// the layer order is authenticate, module gate, role, so on/off is not visible without a session.
	wantError(t, r.do(t, req{method: "GET", path: "/feeds/status"}), 401, "unauthenticated")
	// No restart needed: turning it back on opens the route.
	r.gate.Set("feeds", true)
	if rec := r.do(t, req{method: "GET", path: "/feeds/status", user: "admin"}); rec.Code != 200 {
		t.Fatalf("after turning feeds on: %d", rec.Code)
	}
	r.gate.Set("feeds", false)
	wantError(t, r.do(t, req{method: "GET", path: "/feeds/status", user: "admin"}), 404, "not_found")
}

// The leak this order closes: with no session, an off module and an on module look the same (401).
func TestModuleStateDoesNotLeakToAnonymousClients(t *testing.T) {
	t.Parallel()
	r := newRig(t, "feeds")
	off := r.do(t, req{method: "GET", path: "/feeds/status"})
	wantError(t, off, 401, "unauthenticated")
	r.gate.Set("feeds", true)
	on := r.do(t, req{method: "GET", path: "/feeds/status"})
	wantError(t, on, 401, "unauthenticated")
	if off.Body.String() != on.Body.String() {
		t.Fatalf("bodies differ:\n%s\n%s", off.Body, on.Body)
	}
	// A wrong cookie is anonymous too; and a state-changing request without a session is 401, not 404.
	r.gate.Set("feeds", false)
	wantError(t, r.do(t, req{method: "POST", path: "/feeds/weekly/x", csrf: true}), 401, "unauthenticated")
	// Public operations have no session to wait for: the gate answers first.
	r2 := newRig(t, "core")
	wantError(t, r2.do(t, req{method: "GET", path: "/setup"}), 404, "not_found")
	// For a signed-in user the order after authentication is gate (404) before role (403).
	wantError(t, r.do(t, req{method: "PUT", path: "/feeds/sources/x", user: "viewer", csrf: true, body: "{}"}), 404, "not_found")
	r.gate.Set("feeds", true)
	wantError(t, r.do(t, req{method: "PUT", path: "/feeds/sources/x", user: "viewer", csrf: true, body: "{}"}), 403, "forbidden")
}

// The two routes the first mapping got wrong: /scans/credentialed belongs to scan-credentialed and
// POST /findings/{id}/applied|ai to mitigation. Turning the owner off closes the route; turning the
// neighbour off (scan, findings) does not.
func TestOverriddenRoutesFollowTheirOwnModule(t *testing.T) {
	t.Parallel()
	t.Run("scan-credentialed off", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, "scan-credentialed")
		wantError(t, r.do(t, req{method: "GET", path: "/scans/credentialed", user: "admin"}), 404, "not_found")
		wantError(t, r.do(t, req{method: "POST", path: "/scans/credentialed/x/test", user: "admin", csrf: true}), 404, "not_found")
		wantError(t, r.do(t, req{method: "GET", path: "/scans/config", user: "admin"}), 501, "not_implemented") // scan is on
	})
	t.Run("scan off leaves scan-credentialed", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, "scan")
		wantError(t, r.do(t, req{method: "GET", path: "/scans/credentialed", user: "admin"}), 501, "not_implemented")
		wantError(t, r.do(t, req{method: "GET", path: "/scans/config", user: "admin"}), 404, "not_found")
	})
	t.Run("mitigation off", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, "mitigation")
		wantError(t, r.do(t, req{method: "POST", path: "/findings/f1/applied", user: "operator", csrf: true, body: "{}"}), 404, "not_found")
		wantError(t, r.do(t, req{method: "POST", path: "/findings/f1/ai", user: "operator", csrf: true, body: "{}"}), 404, "not_found")
		wantError(t, r.do(t, req{method: "GET", path: "/findings/f1", user: "viewer"}), 501, "not_implemented") // findings is on
	})
	t.Run("findings off leaves mitigation", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, "findings")
		wantError(t, r.do(t, req{method: "GET", path: "/findings/f1", user: "viewer"}), 404, "not_found")
		if rec := r.do(t, req{method: "POST", path: "/findings/f1/applied", user: "operator", csrf: true, body: "{}"}); rec.Code == 404 {
			t.Fatalf("POST /findings/f1/applied is 404 with only findings off: %s", rec.Body)
		}
	})
}

func TestOriginMustMatchOnStateChangingRequests(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	own := "http://example.com" // httptest requests are plain HTTP to example.com
	body := `{"name":"Acme","timezone":"UTC"}`
	put := func(origin string) *httptest.ResponseRecorder {
		q := req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: body}
		if origin != "" {
			q.header = map[string]string{"Origin": origin}
		}
		return r.do(t, q)
	}
	if rec := put(""); rec.Code != 200 {
		t.Fatalf("no Origin (non-browser client): %d %s", rec.Code, rec.Body)
	}
	if rec := put(own); rec.Code != 200 {
		t.Fatalf("same origin: %d %s", rec.Code, rec.Body)
	}
	if rec := put("HTTP://EXAMPLE.COM"); rec.Code != 200 {
		t.Fatalf("same origin, other case: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"http://evil.example", "https://example.com", "http://example.com:81", "http://example.com.evil.example", "null", own + "/", ""} {
		if bad == "" {
			continue
		}
		wantError(t, put(bad), 403, "csrf_invalid")
	}
	// Public POSTs are covered too, and the check runs before authentication and routing.
	evil := map[string]string{"Origin": "http://evil.example"}
	wantError(t, r.do(t, req{method: "POST", path: "/auth/logout", header: evil}), 403, "csrf_invalid")
	wantError(t, r.do(t, req{method: "POST", path: "/nope", header: evil}), 403, "csrf_invalid")
	wantError(t, r.do(t, req{method: "DELETE", path: "/feeds/custom/x", header: evil}), 403, "csrf_invalid")
	if rec := r.do(t, req{method: "POST", path: "/auth/logout", header: map[string]string{"Origin": own}}); rec.Code != 204 {
		t.Fatalf("same-origin public POST: %d", rec.Code)
	}
	// Reads are not state-changing: a foreign Origin on GET is not this check's business.
	if rec := r.do(t, req{method: "GET", path: "/setup", header: evil}); rec.Code != 200 {
		t.Fatalf("GET with a foreign Origin: %d", rec.Code)
	}
	// Two Origin headers are never legitimate.
	hr := httptest.NewRequestWithContext(t.Context(), "POST", server.Prefix+"/auth/logout", nil)
	hr.Header.Add("Origin", own)
	hr.Header.Add("Origin", own)
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, hr)
	wantError(t, rec, 403, "csrf_invalid")
}

func TestPrincipalAndRequestIDReachTheHandler(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	rec := r.do(t, req{method: "GET", path: "/feeds/status", user: "operator", header: map[string]string{"X-Request-Id": "evil\nforged"}})
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	id := rec.Header().Get("X-Request-Id")
	if !strings.HasPrefix(id, "req-") || strings.Contains(id, "evil") {
		t.Fatalf("request id %q: must be generated, not taken from the client", id)
	}
	p := r.seen.principal[0]
	if p.Email != "it@acme.example" || p.Role != routes.Operator {
		t.Fatalf("principal in the handler = %+v", p)
	}
	if r.seen.requestID[0] != id {
		t.Fatalf("handler saw request id %q, header says %q", r.seen.requestID[0], id)
	}
	if r.auth.Calls() != 1 {
		t.Fatalf("Authenticate ran %d times, want exactly 1 (the cookie is decoded once)", r.auth.Calls())
	}
	other := r.do(t, req{method: "GET", path: "/feeds/status", user: "operator"})
	if other.Header().Get("X-Request-Id") == id {
		t.Fatal("two requests got the same id")
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	r := newRig(t, "scan")
	for name, q := range map[string]req{
		"ok":           {method: "GET", path: "/feeds/status", user: "viewer"},
		"401":          {method: "GET", path: "/feeds/status"},
		"404":          {method: "GET", path: "/nope"},
		"off module":   {method: "GET", path: "/scans/config", user: "admin"},
		"public":       {method: "GET", path: "/setup"},
		"handler 500":  {method: "GET", path: "/feeds/sources", user: "viewer"},
		"501":          {method: "GET", path: "/me", user: "viewer"},
		"bad request":  {method: "PUT", path: "/core/general", user: "admin", csrf: true, body: "{"},
		"403":          {method: "PUT", path: "/core/general", user: "viewer", csrf: true, body: "{}"},
		"csrf refused": {method: "PUT", path: "/core/general", user: "admin", body: "{}"},
	} {
		rec := r.do(t, q)
		for h, want := range map[string]string{
			"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "no-referrer",
			"Cache-Control":           "no-store",
		} {
			if got := rec.Header().Get(h); got != want {
				t.Errorf("%s: %s = %q, want %q (status %d)", name, h, got, want, rec.Code)
			}
		}
		if rec.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s: no request id", name)
		}
	}
}

func TestPanicBecomes500WithoutLeak(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	rec := r.do(t, req{method: "GET", path: "/feeds/weekly", user: "viewer"})
	wantError(t, rec, 500, "internal")
	if strings.Contains(rec.Body.String(), "secret internal detail") || strings.Contains(rec.Body.String(), "/var/lib") {
		t.Fatalf("panic text leaked: %s", rec.Body)
	}
	id := rec.Header().Get("X-Request-Id")
	if id == "" || !strings.Contains(r.logs.String(), id) || !strings.Contains(r.logs.String(), "secret internal detail") {
		t.Fatalf("the log must name the request id and the panic; id=%q log=%s", id, r.logs)
	}
	// The server keeps serving afterwards.
	if rec := r.do(t, req{method: "GET", path: "/feeds/status", user: "viewer"}); rec.Code != 200 {
		t.Fatalf("after a panic: %d", rec.Code)
	}
}

func TestErrorMapping(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	t.Run("handler error is not echoed", func(t *testing.T) {
		rec := r.do(t, req{method: "GET", path: "/feeds/sources", user: "viewer"})
		wantError(t, rec, 500, "internal")
		if strings.Contains(rec.Body.String(), "feeds_source") || strings.Contains(rec.Body.String(), "/var/lib") {
			t.Fatalf("internal detail leaked: %s", rec.Body)
		}
		if !strings.Contains(r.logs.String(), "feeds_source locked") {
			t.Fatal("the cause was not logged")
		}
	})
	t.Run("apierr keeps status code message and extras", func(t *testing.T) {
		rec := r.do(t, req{method: "GET", path: "/core/general", user: "viewer"})
		b := wantError(t, rec, 409, "missing_dependencies")
		if b.Error["message"] != "Module x also needs: y." {
			t.Fatalf("message = %v", b.Error["message"])
		}
		if m, _ := b.Error["missing"].([]any); len(m) != 1 || m[0] != "y" {
			t.Fatalf("extra field missing: %s", rec.Body)
		}
	})
	t.Run("unimplemented operation is 501", func(t *testing.T) {
		wantError(t, r.do(t, req{method: "GET", path: "/me", user: "viewer"}), 501, "not_implemented")
	})
	t.Run("malformed JSON is 400 invalid", func(t *testing.T) {
		wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: `{"name":`}), 400, "invalid")
	})
	t.Run("wrong type names the field", func(t *testing.T) {
		rec := r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: `{"name":5,"timezone":"UTC"}`})
		b := wantError(t, rec, 400, "invalid")
		if msg, _ := b.Error["message"].(string); strings.Contains(msg, "unexpected") || strings.Contains(msg, "jx") {
			t.Fatalf("decoder text leaked: %s", msg)
		}
	})
	t.Run("missing field is 400", func(t *testing.T) {
		wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: `{"name":"A"}`}), 400, "invalid")
	})
	t.Run("missing body is 400", func(t *testing.T) {
		wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true}), 400, "invalid")
	})
	t.Run("wrong content type is 400", func(t *testing.T) {
		wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: `{"name":"A","timezone":"UTC"}`, header: map[string]string{"Content-Type": "text/plain"}}), 400, "invalid")
	})
}

func TestBodyCap(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	big := `{"name":"` + strings.Repeat("a", server.DefaultMaxBody) + `","timezone":"UTC"}`
	// Declared length over the cap: refused before any handler work.
	wantError(t, r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: big}), 413, "too_large")

	// Undeclared length (chunked): the stream is cut at the cap and the same answer comes back.
	hr := httptest.NewRequestWithContext(t.Context(), "PUT", server.Prefix+"/core/general", io.NopCloser(strings.NewReader(big)))
	hr.ContentLength = -1
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	hr.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, hr)
	wantError(t, rec, 413, "too_large")

	// Just under the cap still works.
	ok := `{"name":"` + strings.Repeat("a", 100) + `","timezone":"UTC"}`
	if rec := r.do(t, req{method: "PUT", path: "/core/general", user: "admin", csrf: true, body: ok}); rec.Code != 200 {
		t.Fatalf("small body: %d %s", rec.Code, rec.Body)
	}
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	good := server.Config{API: composite{Fallback: server.Fallback{Log: log}}, Auth: &servertest.Auth{}, Modules: servertest.NewGate(), Log: log}
	for name, mod := range map[string]func(*server.Config){
		"no api":     func(c *server.Config) { c.API = nil },
		"no auth":    func(c *server.Config) { c.Auth = nil },
		"no modules": func(c *server.Config) { c.Modules = nil },
		"no log":     func(c *server.Config) { c.Log = nil },
		"neg body":   func(c *server.Config) { c.MaxBody = -1 },
	} {
		c := good
		mod(&c)
		if _, err := server.New(c); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	if _, err := server.New(good); err != nil {
		t.Fatal(err)
	}
}
