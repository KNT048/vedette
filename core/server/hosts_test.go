package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
)

func TestHostAllowlist(t *testing.T) {
	t.Parallel()
	called := 0
	h := server.HostAllowlist([]string{"Box.Acme.Example", "192.0.2.10", "2001:db8::10", "ignored host!"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(204)
	}))
	for host, want := range map[string]int{
		// allowed: configured names without case or port or trailing dot, IP literals in any spelling, loopback always
		"box.acme.example": 204, "BOX.ACME.EXAMPLE:8443": 204, "box.acme.example.": 204, "192.0.2.10": 204, "192.0.2.10:443": 204,
		"[2001:db8::10]:443": 204, "[2001:db8:0:0:0:0:0:10]": 204, "localhost": 204, "LOCALHOST:8080": 204, "127.0.0.1:1": 204, "[::1]:1": 204, "127.0.0.2": 421,
		// refused: anything else, lookalikes, suffix tricks, the empty and the odd
		"evil.example": 421, "box.acme.example.evil.example": 421, "xbox.acme.example": 421, "acme.example": 421, "192.0.2.11": 421,
		"192.0.2.10.evil.example": 421, "box.acme.example@evil.example": 421, "box.acme.example/": 421, "[2001:db8::11]": 421,
		"ignored host!": 421, "": 421, " ": 421, "box.acme.example:80:90": 421,
	} {
		before := called
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/setup", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q = %d, want %d", host, rec.Code, want)
		}
		if want == 421 {
			if called != before {
				t.Errorf("Host %q reached the next handler", host)
			}
			if !strings.Contains(rec.Body.String(), `"code":"misdirected_request"`) {
				t.Errorf("Host %q body = %s", host, rec.Body)
			}
		}
	}
}

// Every method and path is refused, not only the API: the check runs before routing.
func TestHostAllowlistCoversEveryRequest(t *testing.T) {
	t.Parallel()
	h := server.HostAllowlist(nil, http.NotFoundHandler())
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"} {
		for _, p := range []string{"/", "/api/v1/modules", "/assets/app.js", "/anything"} {
			req := httptest.NewRequestWithContext(t.Context(), m, p, nil)
			req.Host = "evil.example"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 421 {
				t.Errorf("%s %s = %d", m, p, rec.Code)
			}
		}
	}
}
