package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureTestConfig is a seam for the end-to-end box (cmd/vedette/e2eexposure_test.go, WP-30, #263): a test binary sets it to swap the
// prober, the resolver and the scan runner for loopback fakes. It is nil in the production binary, which keeps the real ones.
var exposureTestConfig func(*exposure.Config)

var (
	exposureMu       sync.Mutex
	exposureServices = map[*store.DB]*exposure.Service{}
)

// exposureService builds the exposure service once per database, so the handlers and the auto-detect job share it
// (and its one-detection-at-a-time lock). The box finds its public IP through three public services fixed in code
// (D-81); events go to deps.Bus. The scan itself is the scan module's runner (scanRunner, D-229): while that module is off,
// POST …/scan answers 409 module_off after the gate.
func exposureService(d deps) *exposure.Service {
	exposureMu.Lock()
	defer exposureMu.Unlock()
	if s := exposureServices[d.DB]; s != nil {
		return s
	}
	prober, err := exposure.NewPublicServiceProber(nil, nil, 0)
	if err != nil { // the addresses are constants of the package: a programming error, caught at start-up
		panic("vedette: " + err.Error())
	}
	// D-558: "What the Internet sees" asks Shodan InternetDB, only on an administrator's click (no job).
	outside, err := exposure.NewInternetDB("", nil)
	if err != nil { // the address is a constant of the package
		panic("vedette: " + err.Error())
	}
	cfg := exposure.Config{DB: d.DB, Audit: d.Audit, Resolver: net.DefaultResolver, Prober: prober, Runner: scanRunner(d), Outside: outside, Log: d.Log, Clock: d.Clock}
	if d.Auth != nil { // D-473: the first scan of a target records the commitment only for an administrator with two-step sign-in
		cfg.TwoStep = exposureTwoStep(d.Auth)
	}
	if d.Inventory != nil && d.Findings != nil { // D-492; a nil service would only fail at the first read
		g := exposureGateway{inv: d.Inventory, fnd: d.Findings}
		if d.HostSocket != "" {
			g.state = hostclient.New(d.HostSocket)
		}
		cfg.Gateway = g
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Publisher = d.Bus
	}
	// S-EXP-2 (INV-19, INV-20, D-553): identified services are compared with exploited CVEs when a snapshot is read. cfg.Services is
	// the scan container's nmap -sV on the box's own verified public IP (sensor-active ScanExternal, D-514). The commitment sentence of
	// NoticeVersion 2026-11-14 (D-559, K-4) already names service identification, so wiring it leaves NoticeVersion alone (a second bump
	// would ask every customer again); PRIVACY flow 9, Settings -> Privacy and the nmap row of THIRD_PARTY_NOTICES say what is sent.
	cfg.Services = exposureServicesFor(d, func(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
		return exposureService(d).ScannableIP(ctx, actor, ip) // called at scan time, after this function returned
	})
	clock := d.Clock
	if clock == nil {
		clock = time.Now
	}
	m := exposureMatcher{vulns: exposureVulns(d), now: clock}
	if d.Inventory != nil {
		m.catalog = d.Inventory.KevKeysByCPE
	}
	cfg.Matcher = m
	if exposureTestConfig != nil {
		exposureTestConfig(&cfg)
	}
	svc, err := exposure.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	exposureServices[d.DB] = svc
	if d.Reg != nil { // INV-18: switching the module off stops the scan that runs (SYS-5); the registry's goroutine must not wait for it
		d.Reg.OnChange(func(id string, enabled bool) {
			if id == exposure.ModuleID {
				svc.ModuleSwitched(enabled)
			}
		})
	}
	return svc
}

// exposureJobs is the Jobs func of the exposure entry in wiredModules.
func exposureJobs(d deps) []jobs.Job { return exposure.Jobs(exposureService(d)) }

// exposureTwoStep says how a user meets two-step sign-in for the first Scan now of a target (D-473): Vedette's own method, or "sso"
// for an account made by an SSO sign-in, whose MFA the identity provider owns (Vedette two-step cannot be turned on for it, D-195).
func exposureTwoStep(a *auth.Service) exposure.TwoStep {
	return func(ctx context.Context, userID string) (string, error) {
		u, err := a.GetUser(ctx, userID)
		if err != nil {
			return "", err
		}
		if u.TwofaMethod == "" && u.SSO {
			return "sso", nil
		}
		return u.TwofaMethod, nil
	}
}
