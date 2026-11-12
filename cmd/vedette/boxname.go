package main

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
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
// the host has given no valid name (an older host, a name that is not RFC 1123, a host that has not answered yet). A host that
// stops answering keeps the last name it gave. Without a host (container-only, development) it is core's own host name when valid
// (the compose file names the container "vedette"), else "vedette". Safe on nil ("vedette") and for concurrent use; the lock is
// held across the one socket call, at most every boxNameRetry.
type boxHostName struct {
	info  func(ctx context.Context) (api.Info, error) // nil: no host
	local string                                      // the name without a host
	now   func() time.Time

	mu    sync.Mutex
	name  string    // the last valid name the host gave; "" none
	until time.Time // the host is asked again after this
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

// Get returns the name, asking the host when the one in memory is older than boxNameTTL.
func (b *boxHostName) Get(ctx context.Context) string {
	if b == nil {
		return fallbackBoxName
	}
	if b.info == nil {
		return b.local
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := b.now(); !now.Before(b.until) {
		cctx, cancel := context.WithTimeout(ctx, boxNameTimeout)
		inf, err := b.info(cctx)
		cancel()
		switch {
		case err != nil:
			b.until = now.Add(boxNameRetry)
		case api.ValidHostname(inf.Hostname):
			b.name, b.until = inf.Hostname, now.Add(boxNameTTL)
		default: // the host answered without a usable name: it will not have one until it is updated or renamed
			b.name, b.until = "", now.Add(boxNameTTL)
		}
	}
	if b.name == "" {
		return fallbackBoxName
	}
	return b.name
}
