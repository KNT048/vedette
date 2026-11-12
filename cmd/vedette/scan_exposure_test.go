package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/surface"
)

// D-229, exposure INV-12: exposure scans with the scan module's runner, which follows that module's switch. Off (the default), the
// answer is 409 module_off and nothing is probed; on, it scans, and only what exposure's own public-address rule allows.
func TestExposureRunnerFollowsTheScanModule(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r := scanRunner(deps{Log: log, DB: db, Reg: reg})
	private := exposure.ScanTarget{ID: "xt-1", Kind: exposure.KindIP, Value: "10.0.0.1"}
	var ae *exposure.APIError
	if _, err := r.Scan(ctx, private); !errors.As(err, &ae) || ae.HTTP != 409 || ae.Code != "module_off" {
		t.Fatalf("scan module off: %v", err)
	}
	var ch modreg.Change
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		ch, err = reg.Enable(ctx, tx, "admin@acme.example", "scan", true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reg.Publish(ch)
	// on: a private address is refused by exposure's rule before anything is dialed
	if _, err := r.Scan(ctx, private); !errors.Is(err, surface.ErrNotPublic) {
		t.Fatalf("scan module on, private IP: %v", err)
	}
}

type fakeSurface struct {
	res    surface.Result
	err    error
	domain string
	ip     netip.Addr
}

func (f *fakeSurface) Domain(_ context.Context, d string) (surface.Result, error) {
	f.domain = d
	return f.res, f.err
}

func (f *fakeSurface) IP(_ context.Context, ip netip.Addr) (surface.Result, error) {
	f.ip = ip
	return f.res, f.err
}

// The surface result in exposure's shape, and the failures of a scan as the person reads them.
func TestExposureRunnerResult(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("203.0.113.10")
	f := &fakeSurface{res: surface.Result{
		Hosts: []surface.Host{{Name: "acme.example", IP: ip}},
		Ports: []surface.Port{{IP: ip, Port: 443, Service: "https", Product: "FortiGate"}, {IP: ip, Port: 3000, Service: "http"}},
		Admin: []surface.Admin{{URL: "https://acme.example", Product: "FortiGate", IP: ip, Port: 443, Danger: true}, {URL: "http://acme.example:3000", Product: "Grafana", IP: ip, Port: 3000}},
		Certs: []surface.Cert{{Host: "acme.example", Issuer: "R11", NotAfter: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)}},
	}}
	r := exposureRunner{on: func() bool { return true }, scan: f}
	c, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "xt-1", Kind: exposure.KindDomain, Value: "acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	if f.domain != "acme.example" || len(c.Hosts) != 1 || c.Hosts[0] != (exposure.HostRow{Name: "acme.example", IP: "203.0.113.10"}) ||
		len(c.Ports) != 2 || c.Ports[0] != (exposure.PortRow{IP: "203.0.113.10", Port: 443, Service: "https", Product: "FortiGate"}) ||
		len(c.AdminPanels) != 2 || c.AdminPanels[0].Risk != "danger" || c.AdminPanels[1].Risk != "warn" ||
		len(c.Certs) != 1 || c.Certs[0] != (exposure.CertRow{Host: "acme.example", Issuer: "R11", ExpiresAt: "2027-01-02T03:04:05Z"}) {
		t.Fatalf("content %+v", c)
	}
	if _, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "xt-2", Kind: exposure.KindIP, Value: "203.0.113.10"}); err != nil || f.ip != ip {
		t.Fatalf("IP scan: %v, asked %v", err, f.ip)
	}
	for _, c := range []struct {
		err  error
		want *exposure.APIError
	}{
		{fmt.Errorf("%w: crt.sh answered 502", surface.ErrCT), exposure.ErrCTDown},
		{surface.ErrTooLong, exposure.ErrScanTooLong},
	} {
		f.err = c.err
		var ae *exposure.APIError
		if _, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "xt-1", Kind: exposure.KindDomain, Value: "acme.example"}); !errors.As(err, &ae) || ae != c.want {
			t.Fatalf("%v: got %v", c.err, err)
		}
	}
}
