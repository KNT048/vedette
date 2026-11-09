package server

import (
	"context"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
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
