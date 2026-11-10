package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ogen-go/ogen/validate"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
)

// INV-5: a table with an operation that declares no valid role stops the server from starting.
func TestValidateRoutes(t *testing.T) {
	t.Parallel()
	good := map[string]routes.Operation{"a": {Method: "GET", Path: "/feeds/hot", MinRole: routes.Viewer, Tag: "feeds"}}
	if err := validateRoutes(good); err != nil {
		t.Fatal(err)
	}
	for name, op := range map[string]routes.Operation{
		"no role":      {Method: "GET", Path: "/feeds/hot", MinRole: "", Tag: "feeds"},
		"unknown role": {Method: "GET", Path: "/feeds/hot", MinRole: "root", Tag: "feeds"},
		"no module":    {Method: "GET", Path: "/zzz", MinRole: routes.Viewer, Tag: ""},
	} {
		err := validateRoutes(map[string]routes.Operation{"bad": op})
		if err == nil || !strings.Contains(err.Error(), "bad") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := validateRoutes(routes.Operations); err != nil {
		t.Fatalf("the generated table fails its own start-up check: %v", err)
	}
}

// HandleSession never decodes the cookie: it only confirms that the middleware found a principal.
func TestHandleSessionNeedsAPrincipal(t *testing.T) {
	t.Parallel()
	var s session
	if _, err := s.HandleSession(t.Context(), oas.CoreGetModulesOperation, oas.Session{APIKey: "anything"}); err == nil {
		t.Fatal("HandleSession accepted a request the middleware did not authenticate")
	}
	ctx := WithPrincipal(context.Background(), Principal{Email: "a@b.example", Role: routes.Admin})
	if _, err := s.HandleSession(ctx, oas.CoreGetModulesOperation, oas.Session{}); err != nil {
		t.Fatal(err)
	}
}

func TestMapErrorNamesTheFullFieldPath(t *testing.T) {
	t.Parallel()
	nested := func(name string, inner error) *validate.Error {
		return &validate.Error{Fields: []validate.FieldError{{Name: name, Error: inner}}}
	}
	leaf := errors.New("out of range")
	tests := []struct {
		name string
		err  error
		path string
	}{
		{"top-level field", nested("lan_ranges", leaf), "lan_ranges"},
		{"object then array element", nested("active", nested("days", nested("[0]", leaf))), "active.days[0]"},
		{"array of objects", nested("items", nested("[2]", nested("port", leaf))), "items[2].port"},
		{"wrapped by ogen", fmt.Errorf("decode: %w", nested("active", nested("rate", leaf))), "active.rate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e, own := mapError(tt.err)
			if own || e.Status != 400 || e.Code != apierr.CodeInvalid {
				t.Fatalf("got %d %s own=%v", e.Status, e.Code, own)
			}
			if e.Extra["field"] != tt.path || !strings.Contains(e.Message, `"`+tt.path+`"`) {
				t.Fatalf("field = %v, message = %q, want path %q", e.Extra["field"], e.Message, tt.path)
			}
		})
	}
	// a path that is not made of contract names is not echoed
	e, _ := mapError(nested("a b<script>", leaf))
	if _, ok := e.Extra["field"]; ok || strings.Contains(e.Message, "script") {
		t.Fatalf("unsafe path echoed: %+v", e)
	}
	e, _ = mapError(&validate.Error{})
	if e.Code != apierr.CodeInvalid || e.Extra != nil {
		t.Fatalf("empty error: %+v", e)
	}
}

// M3 (response FORBID-4): a panic on a route whose path is a credential does not put the credential in the log, not in the path, the panic
// text or anywhere else; a path without one is logged as it is.
func TestPanicLogHasNoPathCredential(t *testing.T) {
	t.Parallel()
	const tok = "v1.SECRETidSECRETidSECRet.SECRETmacSECRETmacSEC"
	for _, tc := range []struct{ path, want string }{
		{"/api/v1/response/approve/" + tok, "/api/v1/response/approve/{token}"},
		{"/api/v1/response/blocklist/abcdef0123456789abcdef0123456789.txt", "/api/v1/response/blocklist/{token}"},
		{"/api/v1/feeds/hot", "/api/v1/feeds/hot"},
	} {
		var buf bytes.Buffer
		h := Envelope(slog.New(slog.NewTextHandler(&buf, nil)), http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			panic("boom while serving " + r.URL.Path) // a handler that puts the whole path in its panic text
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, nil))
		out := buf.String()
		if w.Code != http.StatusInternalServerError || !strings.Contains(out, "handler panicked") || !strings.Contains(out, tc.want) {
			t.Fatalf("%s: status %d, log %q", tc.path, w.Code, out)
		}
		for _, secret := range []string{"SECRET", "abcdef0123456789"} {
			if strings.Contains(tc.path, secret) && strings.Contains(out, secret) {
				t.Errorf("%s: the log holds %q:\n%s", tc.path, secret, out)
			}
		}
	}
}
