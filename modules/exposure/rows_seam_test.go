package exposure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// get serves one GET through the real handlers and returns the status and the raw body.
func (e *httpEnv) get(path string) (int, []byte) {
	e.t.Helper()
	r := httptest.NewRequestWithContext(e.t.Context(), http.MethodGet, server.Prefix+path, nil)
	r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "viewer", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// Rows made by the scan writer reach the API in the shape of the contract: the stored scans of a test network (targets, hosts,
// addresses, services, issues and scans) are served by the real handlers, and every body is decoded by the generated types of
// api/openapi.json, which refuse a missing or unknown field, a wrong enum value and a malformed time.
func TestRowsSeam_WriterRowsServeInTheContractShape(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := httpOn(replayEnv(t, f))
	for _, s := range f.Scans {
		e.replay(s.Target, s.StartedAt, s.Content.content())
	}

	decode := func(path string, into json.Unmarshaler) {
		t.Helper()
		code, body := e.get(path)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, code, body)
		}
		if err := into.UnmarshalJSON(body); err != nil {
			t.Fatalf("GET %s does not fit the contract: %v\n%s", path, err, body)
		}
	}

	var tree oas.ExposureGetExposureTreeOK
	decode("/exposure/tree", &tree)

	// each kind of row is served for at least one target, so the lists below are never all empty
	var scans, hosts, addrs, services, issues int
	for _, x := range f.Targets {
		base := "/exposure/tree/" + x.ID
		var node oas.ExposureGetExposureTreeIDOK
		decode(base, &node)
		var sc oas.ExposureGetExposureTreeIDScansOK
		decode(base+"/scans", &sc)
		var h oas.ExposureGetExposureTreeIDHostsOK
		decode(base+"/hosts", &h)
		var a oas.ExposureGetExposureTreeIDAddressesOK
		decode(base+"/addresses", &a)
		var sv oas.ExposureGetExposureTreeIDServicesOK
		decode(base+"/services", &sv)
		var is oas.ExposureGetExposureTreeIDIssuesOK
		decode(base+"/issues", &is)
		scans += len(sc.Items)
		hosts += len(h.Items)
		addrs += len(a.Items)
		services += len(sv.Items)
		issues += len(is.Items)
	}
	for name, n := range map[string]int{"scans": scans, "hosts": hosts, "addresses": addrs, "services": services, "issues": issues} {
		if n == 0 {
			t.Errorf("no %s rows reached the API: the test no longer covers them", name)
		}
	}
}
