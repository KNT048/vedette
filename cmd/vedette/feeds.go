package main

import (
	"sync"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
)

var (
	feedsMu       sync.Mutex
	feedsServices = map[*store.DB]*feeds.Service{}

	// feedsClient is the one guarded client of every pull (connection reuse, the address guard of feeds.NewClient).
	feedsClient = feeds.NewClient(feeds.DefaultFetchTimeout)
)

// feedsService builds the feeds service once per database, so the handlers and the pull job share it (and its
// per-feed pull locks). The built-in feeds are seeded on first use (Service.ready). Events go to deps.Bus (issue #39);
// inventory (feeds.Inventory) is not wired yet, so feeds answers you_have null (wiring PR for #38/#39).
func feedsService(d deps) (*feeds.Service, error) {
	feedsMu.Lock()
	defer feedsMu.Unlock()
	if s := feedsServices[d.DB]; s != nil {
		return s, nil
	}
	fd := feeds.Deps{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Modules: d.Reg, Log: d.Log,
		Fetcher: feeds.Fetcher{Client: feedsClient, Version: version}, Clock: d.Clock}
	fd.Fetcher.BoxAddrs = notifyBoxAddrs(d.HostNet) // D-208: a pull never connects to the box itself; unknown addresses refuse every pull
	fd.Fetcher.Gateway = procGateway                // the container's default gateway is the box too (as core/conn's box set)
	if d.Inventory != nil {
		fd.Inventory = feedsInventory{d.Inventory}
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		fd.Events = d.Bus
	}
	s, err := feeds.NewService(fd)
	if err != nil {
		return nil, err
	}
	feedsServices[d.DB] = s
	return s, nil
}

// feedsJobs is the Jobs func of the feeds entry in wiredModules.
func feedsJobs(d deps) []jobs.Job {
	s, err := feedsService(d)
	if err != nil {
		d.Log.Error("feeds: the module cannot start, its pull job is not registered", "error", err)
		return nil
	}
	return s.Jobs()
}

// feedsHandlers is the handler constructor of the feeds entry in newHandler. A service that cannot be built means
// a broken database or key: that is a failure to start, not a state to serve in.
func feedsHandlers(d deps) *feeds.FeedHandlers {
	s, err := feedsService(d)
	if err != nil {
		panic("feeds: cannot build the module: " + err.Error())
	}
	return feeds.NewHandlers(s)
}
