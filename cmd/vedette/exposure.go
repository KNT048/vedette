package main

import (
	"net"
	"sync"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
)

var (
	exposureMu       sync.Mutex
	exposureServices = map[*store.DB]*exposure.Service{}
)

// exposureService builds the exposure service once per database, so the handlers and the auto-detect job share it
// (and its one-detection-at-a-time lock). The box finds its public IP through three public services fixed in code
// (D-81); events go to deps.Bus. ponytail: no scan module yet: it registers its Runner with SetRunner, so
// POST …/scan answers 501 after the gate until then.
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
	cfg := exposure.Config{DB: d.DB, Audit: d.Audit, Resolver: net.DefaultResolver, Prober: prober, Log: d.Log, Clock: d.Clock}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Publisher = d.Bus
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
