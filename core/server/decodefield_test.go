package server_test

import (
	"net/http"
	"strings"
	"testing"
)

// D-73: a body that does not decode names the failing field, from contract names only.
func TestDecodeErrorsNameTheField(t *testing.T) {
	t.Parallel()
	const osSettings = "/core/updates/os/settings"
	tests := []struct {
		name, method, path, body, field string
	}{
		{"wrong type at top level", "PATCH", "/core/privacy", `{"telemetry":"false"}`, "telemetry"},
		{"wrong type nested", "PATCH", osSettings, `{"window":{"from":5}}`, "window.from"},
		{"unknown field at top level", "PATCH", "/core/privacy", `{"colour":true}`, "colour"},
		{"unknown field nested", "PATCH", osSettings, `{"window":{"colour":1}}`, "window.colour"},
		// ogen does not index array elements, so the path stops at the array's own name
		{"array element of the wrong type", "PATCH", osSettings, `{"window":{"days":["x"]}}`, "window.days"},
		{"invalid JSON syntax", "PATCH", "/core/privacy", `{"telemetry":`, ""},
		{"value is not echoed", "PATCH", "/core/privacy", `{"telemetry":"SECRET-VALUE"}`, "telemetry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := newRig(t).do(t, req{method: tt.method, path: tt.path, user: "admin", csrf: true, body: tt.body})
			b := wantError(t, rec, http.StatusBadRequest, "invalid")
			got, has := b.Error["field"]
			if tt.field == "" {
				if has {
					t.Fatalf("field = %v, want none; %s", got, rec.Body)
				}
				return
			}
			if got != tt.field {
				t.Fatalf("field = %v, want %q; %s", got, tt.field, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), `"`+tt.field+`"`) || strings.Contains(rec.Body.String(), "SECRET-VALUE") {
				t.Fatalf("message wrong or echoes the value: %s", rec.Body)
			}
		})
	}
}

// A key in the body is attacker-controlled: one that is not a contract-shaped name is never echoed.
func TestDecodeErrorDoesNotEchoUnsafeKeys(t *testing.T) {
	t.Parallel()
	keys := map[string]string{
		"quote":    `a\"b`,
		"newline":  `a\nb`,
		"script":   `<script>alert(1)</script>`,
		"long":     strings.Repeat("k", 200),
		"decodeIn": `x\" decode field \"telemetry`,
	}
	for name, key := range keys {
		for _, body := range []string{`{"` + key + `":1}`, `{"window":{"` + key + `":1}}`} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				rec := newRig(t).do(t, req{method: "PATCH", path: "/core/updates/os/settings", user: "admin", csrf: true, body: body})
				b := wantError(t, rec, http.StatusBadRequest, "invalid")
				if f, has := b.Error["field"]; has {
					t.Fatalf("field = %v, want none; %s", f, rec.Body)
				}
				out := rec.Body.String()
				for _, bad := range []string{"script", "kkkk", `a\"b`, `\n`, "decode field"} {
					if strings.Contains(out, bad) {
						t.Fatalf("response echoes %q: %s", bad, out)
					}
				}
			})
		}
	}
}
