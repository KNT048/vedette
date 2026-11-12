package main

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/inventory"
)

// fallbackBoxName is the box's name when nothing better is known.
const fallbackBoxName = "vedette"

const (
	boxNameTTL     = 10 * time.Minute // a name the host gave (or its answer without one) is used this long
	boxNameRetry   = 30 * time.Second // after the host did not answer, the last name is used this long before asking again
	boxNameTimeout = 2 * time.Second  // one socket call
)

// boxHostName is the box's own name (#471): the name of its device row in the inventory, the host name on the Logs sources page
// and the HOSTNAME of every record sent to a SIEM. core runs in a container, whose host name is the container's, so on an
// appliance it is the OS host name vedette-host reports in GET /v1/info, checked again here (api.ValidHostname); "vedette" while
// the host has given no valid name (an older host, a name that is not RFC 1123). A host that stops answering keeps the last name it
// gave; a host that has not answered since core started gives the name of the box's device row (the last name a host gave, kept
// across restarts of core; see useRow), "vedette" when there is none. Without a host (container-only, development) it is core's own
// host name when valid (the compose file names the container "vedette"), else "vedette". The same name goes into the box's
// self-signed certificate and its Host allowlist (certBoxName, tls.go), the honeypot's box and the passive sensor's display name.
// Safe on nil ("vedette") and for concurrent use; the lock is held across the one socket call, at most every boxNameRetry.
type boxHostName struct {
	info  func(ctx context.Context) (api.Info, error) // nil: no host
	local string                                      // the name without a host
	now   func() time.Time

	mu       sync.Mutex
	name     string                           // the last valid name the host gave; "" none
	until    time.Time                        // the host is asked again after this
	answered bool                             // the host has answered at least once (with or without a name)
	row      func(ctx context.Context) string // the name of the box's device row; nil none (useRow)
	rowName  string                           // what row gave, read once
	rowRead  bool
}

// useRow gives Get the name of the box's device row (row), for the time the host has not answered since core started (a restart of
// core while the host is down, during a host upgrade): without it the Logs sources page and SIEM records would say "vedette" while
// the row keeps the real name. It is read once, when first needed, and checked again (api.ValidHostname). Safe on nil.
func (b *boxHostName) useRow(row func(ctx context.Context) string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.row = row
	b.mu.Unlock()
}

// newBoxHostName asks the vedette-host of socket ("" = no host).
func newBoxHostName(socket string) *boxHostName {
	if socket == "" {
		return newBoxHostNameFrom(nil, time.Now)
	}
	return newBoxHostNameFrom(hostclient.New(socket).Info, time.Now)
}

func newBoxHostNameFrom(info func(ctx context.Context) (api.Info, error), now func() time.Time) *boxHostName {
	b := &boxHostName{info: info, local: fallbackBoxName, now: now}
	if h, err := os.Hostname(); err == nil && api.ValidHostname(h) {
		b.local = h
	}
	return b
}

// Name is Get without ok: the name to show or send now.
func (b *boxHostName) Name(ctx context.Context) string {
	name, _ := b.Get(ctx)
	return name
}

// Get returns the name, asking the host when the one in memory is older than boxNameTTL. ok is false only while the host has not
// answered once since core started (a host restarting during an upgrade): name is then the device row's name (useRow), or "vedette"
// for want of better; the box job keeps the name the device row already has instead of writing it (#471), and the certificate takes
// no name from it. A call whose own ctx ended is not held against the host: the next caller asks again.
func (b *boxHostName) Get(ctx context.Context) (name string, ok bool) {
	if b == nil {
		return fallbackBoxName, true
	}
	if b.info == nil {
		return b.local, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := b.now(); !now.Before(b.until) {
		cctx, cancel := context.WithTimeout(ctx, boxNameTimeout)
		inf, err := b.info(cctx)
		cancel()
		switch {
		case err != nil && ctx.Err() != nil: // the caller gave up, not the host
		case err != nil:
			b.until = now.Add(boxNameRetry)
		case api.ValidHostname(inf.Hostname):
			b.name, b.until, b.answered = inf.Hostname, now.Add(boxNameTTL), true
		default: // the host answered without a usable name: it will not have one until it is updated or renamed
			b.name, b.until, b.answered = "", now.Add(boxNameTTL), true
		}
	}
	switch {
	case b.name != "":
		return b.name, true
	case b.answered:
		return fallbackBoxName, true
	}
	if !b.rowRead && b.row != nil {
		if s := b.row(ctx); ctx.Err() == nil { // a caller that gave up has not read the row
			b.rowName, b.rowRead = s, true
		}
	}
	if api.ValidHostname(b.rowName) {
		return b.rowName, false
	}
	return fallbackBoxName, false
}

// boxRowName is useRow's row: the host name of the inventory's box device, "" when there is none or it cannot be read.
func boxRowName(inv *inventory.Service) func(ctx context.Context) string {
	return func(ctx context.Context) string {
		if inv == nil {
			return ""
		}
		name, _, found, err := inv.BoxName(ctx)
		if err != nil || !found {
			return ""
		}
		return name
	}
}
