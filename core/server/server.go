// Package server builds the http.Handler of /api/v1: panic recovery, request id, security headers,
// Origin check, body cap, then the route table of the contract drives module gating, authentication, role checks
// and CSRF before the request reaches the generated ogen server. The checks are generated from the
// contract tables (core/api/routes), not written per handler (API_CONVENTIONS 7.4).
package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// Prefix is the root of the API.
const Prefix = "/api/v1"

// DefaultMaxBody is the request body cap in bytes (1 MiB) when Config.MaxBody is 0.
const DefaultMaxBody = 1 << 20

// ModuleGate says whether a module is on; modreg.Registry satisfies it. An off module's routes are 404.
type ModuleGate interface {
	Enabled(id string) bool
}

// Config is what New needs; every field except MaxBody is required.
type Config struct {
	API     oas.Handler   // the composite handler: see Fallback
	Auth    Authenticator // sessions and CSRF (WP-04b)
	Modules ModuleGate
	Log     *slog.Logger
	MaxBody int64 // bytes; 0 = DefaultMaxBody
	// BodyLimits raises (or lowers) the cap for single operations, by operationId, e.g. a 5 MiB
	// sample upload (issue #39). Every other operation keeps MaxBody.
	BodyLimits map[string]int64
}

const csp = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

type api struct {
	cfg     Config
	oas     *oas.Server
	max     int64 // cap for operations without an entry in cfg.BodyLimits
	ceiling int64 // largest cap of all: enforced before routing, the operation's own cap after
}

// New returns the handler for URLs under Prefix. It refuses to build when the route table is
// inconsistent (INV-5): a role outside viewer/operator/admin/public, or an operation no module owns.
func New(cfg Config) (http.Handler, error) {
	switch {
	case cfg.API == nil || cfg.Auth == nil || cfg.Modules == nil || cfg.Log == nil:
		return nil, errors.New("server: API, Auth, Modules and Log are required")
	case cfg.MaxBody < 0:
		return nil, errors.New("server: negative MaxBody")
	}
	if err := validateRoutes(routes.Operations); err != nil {
		return nil, err
	}
	a := &api{cfg: cfg, max: cfg.MaxBody}
	if a.max == 0 {
		a.max = DefaultMaxBody
	}
	a.ceiling = a.max
	for id, n := range cfg.BodyLimits {
		if _, ok := routes.Operations[id]; !ok || n <= 0 {
			return nil, fmt.Errorf("server: body limit %d for operation %q: unknown operation or not positive", n, id)
		}
		a.ceiling = max(a.ceiling, n)
	}
	notFound := func(w http.ResponseWriter, _ *http.Request) { apierr.Write(w, apierr.NotFound()) }
	srv, err := oas.NewServer(cfg.API, session{},
		oas.WithPathPrefix(Prefix),
		oas.WithNotFound(notFound),
		oas.WithMethodNotAllowed(func(w http.ResponseWriter, r *http.Request, _ string) { notFound(w, r) }),
		oas.WithErrorHandler(errorHandler(cfg.Log)),
	)
	if err != nil {
		return nil, fmt.Errorf("server: build api: %w", err)
	}
	a.oas = srv
	return Envelope(cfg.Log, a.checkOrigin(a.limitBody(http.HandlerFunc(a.route)))), nil
}

// Envelope is the outermost layer of every response the process produces: panic recovery, a fresh
// request id and the security headers. New applies it to the API; cmd/vedette applies it again around
// the whole top-level handler so responses made outside the API (the ServeMux redirects, 404 for other
// paths) carry the same headers and id. The request id is kept when an outer Envelope already set it.
func Envelope(log *slog.Logger, next http.Handler) http.Handler {
	a := &api{cfg: Config{Log: log}}
	return a.recoverPanic(a.requestID(a.secureHeaders(next)))
}

// checkOrigin refuses a state-changing request, public ones included, whose Origin header names
// another site: scheme and host must equal the request's own. A request without Origin (curl,
// agents, osquery) passes; browsers always send Origin on cross-site POST, so the CSRF token is the
// second line, not the only one. It runs before routing so the answer says nothing about which
// routes or modules exist. The scheme is what this process serves (TLS or not), never a forwarded header.
func (a *api) checkOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Values("Origin"); len(o) > 0 && !slices.Contains(safeMethods, r.Method) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if len(o) != 1 || !strings.EqualFold(o[0], scheme+"://"+r.Host) {
				apierr.Write(w, apierr.CSRFInvalid())
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// validateRoutes is INV-5 at start-up.
func validateRoutes(ops map[string]routes.Operation) error {
	for id, op := range ops {
		if rank(op.MinRole) < 0 {
			return fmt.Errorf("server: operation %s has no valid role (%q)", id, op.MinRole)
		}
		if ModuleOf(op) == "" {
			return fmt.Errorf("server: operation %s belongs to no module", id)
		}
	}
	return nil
}

// recoverPanic turns a panic into 500 internal. The panic value and stack go to the log with the
// request id, never into the response.
func (a *api) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p == http.ErrAbortHandler { //nolint:errorlint // net/http documents comparing the value itself
				panic(p)
			}
			path, secret := logPath(r.URL.Path)
			scrub := func(text string) string {
				if secret == "" {
					return text
				}
				return strings.ReplaceAll(text, secret, "{token}")
			}
			a.cfg.Log.ErrorContext(ctx, "handler panicked", "request_id", w.Header().Get("X-Request-Id"),
				"method", r.Method, "path", path, "panic", scrub(fmt.Sprint(p)), "stack", scrub(string(debug.Stack())))
			apierr.Write(w, apierr.Internal())
		}()
		next.ServeHTTP(w, r)
	})
}

// secretSegments are the path segments that are a credential: the approval link token (/response/approve/{token}) and the block list
// token (/response/blocklist/{token}.txt). A log line must never carry one (response FORBID-4).
var secretSegments = []string{"/approve/", "/blocklist/"}

// logPath returns the path to log, with the credential segment replaced by {token}, and the credential itself (so the panic text and the
// stack can be scrubbed of it too). A path without such a segment is returned as it is.
func logPath(p string) (masked, secret string) {
	for _, m := range secretSegments {
		if i := strings.Index(p, m); i >= 0 {
			rest := p[i+len(m):]
			seg, tail, _ := strings.Cut(rest, "/")
			if tail != "" {
				tail = "/" + tail
			}
			secret = strings.TrimSuffix(seg, ".txt")
			return p[:i+len(m)] + "{token}" + tail, secret
		}
	}
	return p, ""
}

// requestID gives every request a fresh id; an id sent by the client is ignored (it would go into logs).
func (a *api) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestIDFrom(r.Context())
		if id == "" {
			id = store.NewID("req")
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(contextWithRequestID(r.Context(), id)))
	})
}

func (a *api) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store") // API_CONVENTIONS 7.2 point 6: every API response is private
		next.ServeHTTP(w, r)
	})
}

// limitBody refuses an oversized body up front when the length is declared and cuts the stream
// otherwise, at the largest cap of any operation; route then applies the operation's own cap.
func (a *api) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > a.ceiling {
			apierr.Write(w, apierr.TooLarge())
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, a.ceiling)
		next.ServeHTTP(w, r)
	})
}

// opLimit narrows the body cap to the operation's own (MaxBody unless BodyLimits names it). It
// reports false after writing 413 when the declared length is already over.
func (a *api) opLimit(w http.ResponseWriter, r *http.Request, opID string) bool {
	n, ok := a.cfg.BodyLimits[opID]
	if !ok {
		n = a.max
	}
	if n >= a.ceiling {
		return true
	}
	if r.ContentLength > n {
		apierr.Write(w, apierr.TooLarge())
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, n)
	return true
}

var safeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions}

// route is the contract-driven gate. Unknown route and off module are both 404 not_found with the
// same body (SYS-5). Non-public operations: authentication (401), module gate (404), role (403), CSRF
// (403). Public operations: module gate (404) first. Then the generated server.
func (a *api) route(w http.ResponseWriter, r *http.Request) {
	route, ok := a.oas.FindPath(r.Method, r.URL)
	if !ok {
		apierr.Write(w, apierr.NotFound())
		return
	}
	op, ok := routes.Operations[route.OperationID()]
	if !ok { // the contract and the table disagree: fail closed, tell the log
		a.cfg.Log.ErrorContext(r.Context(), "operation missing from the route table", "request_id", RequestIDFrom(r.Context()), "operation", route.OperationID())
		apierr.Write(w, apierr.Internal())
		return
	}
	if !a.opLimit(w, r, route.OperationID()) {
		return
	}
	mod := ModuleOf(op)
	if op.MinRole == routes.Public {
		if !a.cfg.Modules.Enabled(mod) {
			apierr.Write(w, apierr.NotFound())
			return
		}
	} else {
		// Authenticate first: an off module must not tell an anonymous client that its routes exist.
		p, aerr := a.authenticate(r)
		if aerr != nil {
			apierr.Write(w, aerr)
			return
		}
		if !a.cfg.Modules.Enabled(mod) {
			apierr.Write(w, apierr.NotFound())
			return
		}
		if rank(p.Role) < rank(op.MinRole) {
			apierr.Write(w, apierr.Forbidden())
			return
		}
		if !slices.Contains(safeMethods, r.Method) {
			if err := a.cfg.Auth.CheckCSRF(r, p); err != nil {
				if e, ok := apierr.As(err); ok {
					apierr.Write(w, e)
				} else {
					apierr.Write(w, apierr.CSRFInvalid())
				}
				return
			}
		}
		r = r.WithContext(WithPrincipal(r.Context(), p))
	}
	tw := &typedWriter{ResponseWriter: w}
	a.oas.ServeHTTP(tw, r.WithContext(withExchange(r.Context(), tw, r)))
}

func (a *api) authenticate(r *http.Request) (Principal, *apierr.Error) {
	p, err := a.cfg.Auth.Authenticate(r)
	switch {
	case err == nil:
		return p, nil
	case errors.Is(err, ErrNoSession):
		return Principal{}, apierr.Unauthenticated()
	}
	if e, ok := apierr.As(err); ok {
		return Principal{}, e
	}
	a.cfg.Log.ErrorContext(r.Context(), "authentication failed", "request_id", RequestIDFrom(r.Context()), "error", err)
	return Principal{}, apierr.Internal()
}
