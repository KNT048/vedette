package server_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

type statusModule struct{}

func (statusModule) FeedsGetFeedsStatus(context.Context) (*oas.FeedsGetFeedsStatusOK, error) {
	return &oas.FeedsGetFeedsStatusOK{}, nil
}

// ExampleFallback shows how modules plug into the server: each module's handler struct implements only
// its own operations; the composite embeds server.Fallback (which embeds oas.UnimplementedHandler one
// level deeper) and every module handler at the same depth, so
//   - an operation nobody implements answers 501 not_implemented,
//   - a module's method shadows the stub, and
//   - two modules that implement the same operation make the method ambiguous, the composite stops
//     satisfying oas.Handler and the build fails (the assertion below is that compile-time check).
func ExampleFallback() {
	type api struct {
		server.Fallback // depth 1 (UnimplementedHandler is at depth 2)
		statusModule    // depth 1
	}
	var _ oas.Handler = api{} // does not compile when two embedded modules implement one operation

	log := slog.New(slog.DiscardHandler)
	h, err := server.New(server.Config{
		API:     api{Fallback: server.Fallback{Log: log}},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: servertest.NewGate(),
		Log:     log,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	get := func(path string) int {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, server.Prefix+path, nil)
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "viewer", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	fmt.Println(get("/feeds/status"), get("/me"))
	// Output: 200 501
}
