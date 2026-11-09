package core_test

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// fullAPI is the composite of the process for the operations of core: the module switch and everything
// else of Handlers, on top of the 501 fallback.
type fullAPI struct {
	server.Fallback
	*core.ModuleHandlers
	*core.Handlers
}

// world is the real stack of the process on a real SQLite database, behind server.New with the real session
// authenticator: no fake auth, no fake mailer other than the one the auth tests use.
type world struct {
	t    *testing.T
	env  *authtest.Env
	reg  *modreg.Registry
	h    *core.Handlers
	api  http.Handler
	logs *bytes.Buffer
}

func newWorld(t *testing.T, modify ...func(*auth.Config)) *world {
	t.Helper()
	env := authtest.New(t, modify...)
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	reg, err := modreg.New(t.Context(), modreg.Config{DB: env.DB, Audit: env.Audit, Manifests: modules.Manifests, Version: "test", Clock: env.Clock.Now, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	h, err := core.NewHandlers(core.HandlersConfig{DB: env.DB, Auth: env.Svc, Reg: reg, Audit: env.Audit, Secrets: env.Secrets, Log: log, Clock: env.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.New(server.Config{
		API:     fullAPI{Fallback: server.Fallback{Log: log}, ModuleHandlers: core.NewModuleHandlers(env.DB, reg), Handlers: h},
		Auth:    env.Svc.Sessions,
		Modules: reg,
		Log:     log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, env: env, reg: reg, h: h, api: api, logs: logs}
}

// client is a browser: it keeps the cookies it was given (and drops the ones that were cleared) and sends the
// CSRF header the way the SPA does.
type client struct {
	w      *world
	jar    map[string]*http.Cookie
	remote string // the peer address of every request, host:port
	seen   map[string]bool
}

func (w *world) client() *client {
	return &client{w: w, jar: map[string]*http.Cookie{}, remote: "192.0.2.10:40000", seen: map[string]bool{}}
}

// reply is a response with its body decoded when it is JSON.
type reply struct {
	Code   int
	Header http.Header
	Raw    string
	JSON   map[string]any
}

// code returns the error code of an error response, "" otherwise.
func (r reply) code() string {
	if e, ok := r.JSON["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (r reply) str(path ...string) string {
	var cur any = r.JSON
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

func (c *client) request(method, path string, body any, mutate ...func(*http.Request)) reply {
	c.w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.w.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequestWithContext(c.w.t.Context(), method, server.Prefix+path, rd)
	r.RemoteAddr = c.remote
	r.Host = "box.test"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("User-Agent", "Test Browser/1.0")
	for _, ck := range c.jar {
		r.AddCookie(ck)
	}
	if csrf, ok := c.jar[auth.CookieCSRF]; ok {
		r.Header.Set(auth.HeaderCSRF, csrf.Value)
	}
	for _, m := range mutate {
		m(r)
	}
	rec := httptest.NewRecorder()
	c.w.api.ServeHTTP(rec, r)
	res := rec.Result()
	for _, ck := range res.Cookies() {
		c.seen[ck.Name] = true
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.jar, ck.Name)
		} else {
			c.jar[ck.Name] = ck
		}
	}
	out := reply{Code: rec.Code, Header: rec.Header(), Raw: rec.Body.String()}
	if strings.Contains(rec.Header().Get("Content-Type"), "json") && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.JSON); err != nil {
			c.w.t.Fatalf("%s %s: body is not JSON: %v: %s", method, path, err, rec.Body)
		}
	}
	return out
}

func (c *client) get(path string) reply           { c.w.t.Helper(); return c.request("GET", path, nil) }
func (c *client) post(path string, b any) reply   { c.w.t.Helper(); return c.request("POST", path, b) }
func (c *client) patch(path string, b any) reply  { c.w.t.Helper(); return c.request("PATCH", path, b) }
func (c *client) putGeneral(b any) reply          { c.w.t.Helper(); return c.request("PUT", "/core/general", b) }
func (c *client) delete(path string) reply        { c.w.t.Helper(); return c.request("DELETE", path, nil) }
func (c *client) cookie(name string) *http.Cookie { return c.jar[name] }
func (c *client) signedIn() bool                  { return c.jar[auth.CookieSession] != nil }
func (c *client) dropSession()                    { delete(c.jar, auth.CookieSession); delete(c.jar, auth.CookieCSRF) }

func wantStatus(t *testing.T, r reply, status int, code string) {
	t.Helper()
	if r.Code != status || r.code() != code {
		t.Fatalf("response = %d %q (%s), want %d %q", r.Code, r.code(), r.Raw, status, code)
	}
}

func wantOK(t *testing.T, r reply, status int) {
	t.Helper()
	if r.Code != status || r.code() != "" {
		t.Fatalf("response = %d %q (%s), want %d", r.Code, r.code(), r.Raw, status)
	}
}

// login signs the client in with email and the standard password.
func (c *client) login(email string) reply {
	c.w.t.Helper()
	return c.post("/auth/login", map[string]any{"email": email, "password": authtest.Password})
}

// signIn creates a user directly in the database and signs the client in as them.
func (w *world) signIn(email string, role string) (*client, auth.User) {
	w.t.Helper()
	u := w.env.User(w.t, email, routesRole(role))
	c := w.client()
	wantOK(w.t, c.login(email), 200)
	return c, u
}

func decodeBase32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func routesRole(r string) routes.Role { return routes.Role(r) }

func auditVerify(t *testing.T, w *world) (bool, error) {
	t.Helper()
	res, err := audit.Verify(t.Context(), w.env.DB.Reader())
	return res.OK, err
}
