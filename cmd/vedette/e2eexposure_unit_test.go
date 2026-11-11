package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/modules/exposure"
)

// TestE2EExposureFakes pins what the specs rely on: the defaults offer no address, no record and no scan result; the control calls steer
// the three fakes; the seam is installed while a box runs and removed after.
func TestE2EExposureFakes(t *testing.T) {
	release := e2eExposureFakes()
	if exposureTestConfig == nil {
		t.Fatal("the seam was not installed")
	}
	var cfg exposure.Config
	exposureTestConfig(&cfg)
	if cfg.Prober == nil || cfg.Resolver == nil || cfg.Runner == nil {
		t.Fatalf("the seam left a real dependency: %+v", cfg)
	}
	if _, err := cfg.Prober.Round(t.Context()); !errors.Is(err, exposure.ErrServicesDown) {
		t.Fatalf("default prober = %v, want ErrServicesDown", err)
	}
	mux := http.NewServeMux()
	e2eExposureRoutes(mux)
	post := func(path, body string, want int) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewBufferString(body)))
		if rec.Code != want {
			t.Fatalf("POST %s %s = %d, want %d", path, body, rec.Code, want)
		}
	}
	post("/exposure/prober", `{"ip":"203.0.113.7"}`, 204)
	if ip, err := cfg.Prober.Round(t.Context()); err != nil || ip != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("prober = %v %v", ip, err)
	}
	post("/exposure/prober", `{"mode":"disagree"}`, 204)
	if _, err := cfg.Prober.Round(t.Context()); !errors.Is(err, exposure.ErrNoAgreement) {
		t.Fatalf("prober = %v, want ErrNoAgreement", err)
	}
	post("/exposure/prober", `{"ip":"nope"}`, 400)
	post("/exposure/prober", `{"mode":"x"}`, 400)
	post("/exposure/prober", `{}`, 204) // back to the default
	if _, err := cfg.Prober.Round(t.Context()); !errors.Is(err, exposure.ErrServicesDown) {
		t.Fatalf("prober = %v", err)
	}
	if _, err := cfg.Resolver.LookupTXT(t.Context(), "example.test"); err == nil {
		t.Fatal("a name without a record resolved")
	}
	post("/exposure/txt", `{"domain":"example.test","values":["vedette-verify=abc"]}`, 204)
	if v, err := cfg.Resolver.LookupTXT(t.Context(), "example.test"); err != nil || len(v) != 1 || v[0] != "vedette-verify=abc" {
		t.Fatalf("txt = %v %v", v, err)
	}
	post("/exposure/txt", `{"domain":"example.test"}`, 204)
	if _, err := cfg.Resolver.LookupTXT(t.Context(), "example.test"); err == nil {
		t.Fatal("a removed record still resolved")
	}
	post("/exposure/txt", `{}`, 400)
	post("/exposure/scan", `{"error":"boom"}`, 204)
	if _, err := cfg.Runner.Scan(t.Context(), exposure.ScanTarget{}); err == nil {
		t.Fatal("the scan did not fail")
	}
	post("/exposure/scan", `{"content":{"hosts":[]}}`, 204)
	if _, err := cfg.Runner.Scan(t.Context(), exposure.ScanTarget{}); err != nil {
		t.Fatal(err)
	}
	release()
	if exposureTestConfig != nil {
		t.Fatal("the seam stayed installed")
	}
}
