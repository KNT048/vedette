package main

import (
	"context"
	"sync"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
)

var (
	feedsMu       sync.Mutex
	feedsServices = map[*store.DB]*feeds.Service{}
)

// feedsService builds the feeds service once per database, so the handlers and the pull job share it (and its
// per-feed pull locks), and seeds the built-in feeds. Inventory and the event bus are not wired yet
// (core/events and the inventory module are not on main): feeds answers you_have null and publishes nothing.
func feedsService(d deps) (*feeds.Service, error) {
	feedsMu.Lock()
	defer feedsMu.Unlock()
	if s := feedsServices[d.DB]; s != nil {
		return s, nil
	}
	s, err := feeds.NewService(feeds.Deps{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Modules: d.Reg, Log: d.Log,
		Fetcher: feeds.Fetcher{Version: version}, Clock: d.Clock})
	if err != nil {
		return nil, err
	}
	if err := s.Seed(context.Background()); err != nil {
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
