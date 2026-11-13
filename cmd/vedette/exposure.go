package main

import (
	"net"
	"sync"

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
	cfg := exposure.Config{DB: d.DB, Audit: d.Audit, Resolver: net.DefaultResolver, Prober: prober, Runner: scanRunner(d), Log: d.Log, Clock: d.Clock}
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
	if exposureTestConfig != nil {
		exposureTestConfig(&cfg)
	}
	svc, err := exposure.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	exposureServices[d.DB] = svc
	return svc
}

// exposureJobs is the Jobs func of the exposure entry in wiredModules.
func exposureJobs(d deps) []jobs.Job { return exposure.Jobs(exposureService(d)) }
