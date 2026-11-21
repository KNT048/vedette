package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
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
		Fetcher: feeds.Fetcher{Client: feedsClient, Version: version}, Clock: d.Clock, Zone: orgTimeZone(&d), DataDir: d.DataDir} // built after core (buildServices)
	fd.Fetcher.BoxAddrs = machineAddrs(&d) // Never Vedette itself; unknown host addresses allow only global unicast pulls
	fd.Fetcher.Self = vedetteSelf(&d)      // the honeypot's decoys: every port
	if d.Inventory != nil {
		fd.Inventory = feedsInventory{d.Inventory}
	}
	db := d.DB
	fd.Pins = func(ctx context.Context) ([]string, error) { return findings.PinnedCVEs(ctx, db) } // the catalogue keeps a finding's CVE
	if d.Bus != nil {                                                                             // a nil *events.Bus inside the interface would not compare equal to nil
		fd.Events = d.Bus
	}
	// The alert of the CISA list (both copies failing at two checks in a row, or six checks old) and its "up to date
	// again" go to the admins' alert channels through notify's system notice path, as the AI budget and activity-log alerts do
	// (cmd/vedette/ai.go): an incident-kind notice. The alert is critical (#946 r1: a channel set to critical only carries exactly the
	// KEV alerts that stop when the list breaks), the recovery high. newNotify is read at send time (notify is built after feeds).
	// Notify off: ErrAlertOff, the watch tries again at its next tick.
	fd.Alert = func(ctx context.Context, id, title, text string, critical bool) error {
		sev := notify.High
		if critical {
			sev = notify.Critical
		}
		err := newNotify(&d).Publish(ctx, notify.Notice{ID: id, Kind: notify.KindIncident, Severity: sev, Title: title, What: text, At: d.Clock()})
		if errors.Is(err, notify.ErrModuleOff) {
			return fmt.Errorf("%w: %w", feeds.ErrAlertOff, err)
		}
		return err
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

// learnWindowsReleases hands the Windows releases the feed windows-releases stored to core/winrel at start, so a device on a
// release newer than core/winrel's table is read by its build from the first agent report and match, not only after the first pull
// job. A failure is logged: the feeds module reads them again when it starts pulling.
func learnWindowsReleases(ctx context.Context, d deps) {
	s, err := feedsService(d)
	if err == nil {
		err = s.LearnWindowsReleases(ctx)
	}
	if err != nil {
		d.Log.ErrorContext(ctx, "feeds: reading the Windows releases failed", "error", err)
	}
}
