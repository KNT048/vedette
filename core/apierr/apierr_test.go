package apierr_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
)

func TestWriteBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		err    *apierr.Error
		status int
		want   string
	}{
		{"unauthenticated", apierr.Unauthenticated(), 401, `{"error":{"code":"unauthenticated","message":"Not signed in."}}`},
		{"extra sits next to code", apierr.New(409, "missing_dependencies", "Turn on x first.").With("missing", []string{"feeds"}), 409,
			`{"error":{"code":"missing_dependencies","message":"Turn on x first.","missing":["feeds"]}}`},
		{"invalid", apierr.Invalid("Name is required."), 400, `{"error":{"code":"invalid","message":"Name is required."}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			apierr.Write(rec, tt.err)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Fatalf("content type = %q", ct)
			}
			var got, want any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("body = %s, want %s", rec.Body.String(), tt.want)
			}
		})
	}
}

func TestWithDoesNotMutateOriginal(t *testing.T) {
	t.Parallel()
	base := apierr.New(409, "missing_dependencies", "m")
	_ = base.With("missing", []string{"a"})
	if len(base.Extra) != 0 {
		t.Fatalf("With mutated the receiver: %v", base.Extra)
	}
}

func TestWithRejectsReservedKeys(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"code", "message"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("With(%q) did not panic", k)
				}
			}()
			_ = apierr.Invalid("x").With(k, 1)
		}()
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		status int
		code   string
	}{{200, "ok"}, {700, "x"}, {400, "Bad-Code"}, {400, ""}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New(%d, %q) did not panic", tt.status, tt.code)
				}
			}()
			_ = apierr.New(tt.status, tt.code, "m")
		}()
	}
}

func TestAs(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("handler: %w", apierr.NotFound())
	if e, ok := apierr.As(wrapped); !ok || e.Code != "not_found" {
		t.Fatalf("As = %v, %v", e, ok)
	}
	if _, ok := apierr.As(errors.New("plain")); ok {
		t.Fatal("As matched a plain error")
	}
}

// The messages of the built-in errors never carry internal detail.
func TestBuiltinMessagesAreSafe(t *testing.T) {
	t.Parallel()
	for _, e := range []*apierr.Error{apierr.Unauthenticated(), apierr.Forbidden(), apierr.CSRFInvalid(), apierr.NotFound(),
		apierr.TooLarge(), apierr.NotImplemented(), apierr.Internal()} {
		if e.Message == "" || strings.ContainsAny(e.Message, "/\\{}<>") || e.Status < 400 {
			t.Errorf("%s: unsafe or empty message %q", e.Code, e.Message)
		}
		if _, ok := apierr.As(e); !ok {
			t.Errorf("%s does not satisfy error", e.Code)
		}
		var _ error = e
		if e.Status != http.StatusInternalServerError && e.Status < 400 {
			t.Errorf("%s: status %d", e.Code, e.Status)
		}
	}
}

// Every code declared in this package is in API_CONVENTIONS section 3.3, except the ones this work
// package proposes (listed here so a new one cannot slip in unnoticed).
func TestCodesAreCatalogued(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile("../../docs/API_CONVENTIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	proposed := map[string]bool{} // codes used here but not yet in §3.3; empty since #18 catalogued csrf_invalid, internal, not_implemented
	for _, code := range []string{
		apierr.CodeUnauthenticated, apierr.CodeForbidden, apierr.CodeNotFound, apierr.CodeInvalid, apierr.CodeTooLarge,
		apierr.CodeCoreModule, apierr.CodeMissingDeps, apierr.CodeCSRFInvalid, apierr.CodeNotImplemented, apierr.CodeInternal,
	} {
		listed := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(code) + "` \\|").Match(doc)
		if proposed[code] == listed {
			t.Errorf("code %q: in section 3.3 = %v, proposed = %v (exactly one must hold)", code, listed, proposed[code])
		}
	}
}
