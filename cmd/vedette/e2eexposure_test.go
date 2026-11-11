package main

// The exposure fakes of the box of the real-backend end-to-end run (WP-30, #263): the box never calls the three public "what is my IP"
// services, the real DNS or a real scan. Exposure gets a fake EgressProber, a fake Resolver and a fake scan Runner through the
// exposureTestConfig seam of exposure.go; the specs steer them through the control server (e2ebox_test.go). Defaults: the prober says "the
// services are down" (the first-start detection of INV-11 fires during the setup wizard and must find no address), no domain has a TXT
// record, and the runner returns an empty scan. The fakes are shared by every box of the process (the bare box too).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync"

	"github.com/knt048/vedette/modules/exposure"
)

type e2eExpFakes struct {
	mu      sync.Mutex
	ip      netip.Addr // invalid: not set
	probe   string     // "" (answer ip), "disagree" or "down"
	txt     map[string][]string
	scan    exposure.Content
	scanErr string
}

var (
	e2eExpMu sync.Mutex
	e2eExpN  int
	e2eExp   = &e2eExpFakes{probe: "down", txt: map[string][]string{}}
)

// Round answers like PublicServiceProber: the address the specs set, or ErrNoAgreement, or ErrServicesDown.
func (f *e2eExpFakes) Round(context.Context) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.probe == "disagree":
		return netip.Addr{}, exposure.ErrNoAgreement
	case f.probe == "down" || !f.ip.IsValid():
		return netip.Addr{}, exposure.ErrServicesDown
	}
	return f.ip, nil
}

// LookupTXT answers the records the specs set for a name; no record is "no such host", like a domain without the record.
func (f *e2eExpFakes) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.txt[name]; ok {
		return append([]string{}, v...), nil
	}
	return nil, &e2eNotFound{}
}

type e2eNotFound struct{}

func (*e2eNotFound) Error() string  { return "no such host" }
func (*e2eNotFound) NotFound() bool { return true }

func (f *e2eExpFakes) Scan(context.Context, exposure.ScanTarget) (exposure.Content, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scanErr != "" {
		return exposure.Content{}, errors.New(f.scanErr)
	}
	return f.scan, nil
}

// e2eExposureFakes installs the seam (the first box of the process) and returns the func that removes it (the last box).
func e2eExposureFakes() func() {
	e2eExpMu.Lock()
	defer e2eExpMu.Unlock()
	if e2eExpN++; e2eExpN == 1 {
		exposureTestConfig = func(c *exposure.Config) { c.Prober, c.Resolver, c.Runner = e2eExp, e2eExp, e2eExp }
	}
	return func() {
		e2eExpMu.Lock()
		defer e2eExpMu.Unlock()
		if e2eExpN--; e2eExpN == 0 {
			exposureTestConfig = nil
		}
	}
}

// e2eExposureRoutes adds the calls that steer the fakes (all 204, JSON bodies):
//
//	POST /exposure/prober {"ip": "203.0.113.7"} the three services agree on that address; {"mode": "disagree"|"down"} they disagree / are down
//	POST /exposure/txt    {"domain": "...", "values": [...]} the TXT records of a name; no values removes the name
//	POST /exposure/scan   {"content": {hosts, ports, admin_panels, certs}} what a scan returns; {"error": "..."} makes the scan fail
func e2eExposureRoutes(mux *http.ServeMux) {
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /exposure/prober", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ IP, Mode string }
		if !decode(w, r, &in) {
			return
		}
		var ip netip.Addr
		if in.IP != "" {
			var err error
			if ip, err = netip.ParseAddr(in.IP); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if in.Mode != "" && in.Mode != "disagree" && in.Mode != "down" {
			http.Error(w, "mode is disagree or down", http.StatusBadRequest)
			return
		}
		e2eExp.mu.Lock()
		e2eExp.ip, e2eExp.probe = ip, in.Mode
		e2eExp.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /exposure/txt", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Domain string   `json:"domain"`
			Values []string `json:"values"`
		}
		if !decode(w, r, &in) || in.Domain == "" {
			if in.Domain == "" {
				http.Error(w, "domain is required", http.StatusBadRequest)
			}
			return
		}
		e2eExp.mu.Lock()
		if len(in.Values) == 0 {
			delete(e2eExp.txt, in.Domain)
		} else {
			e2eExp.txt[in.Domain] = in.Values
		}
		e2eExp.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /exposure/scan", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Content exposure.Content `json:"content"`
			Error   string           `json:"error"`
		}
		if !decode(w, r, &in) {
			return
		}
		e2eExp.mu.Lock()
		e2eExp.scan, e2eExp.scanErr = in.Content, in.Error
		e2eExp.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
}
