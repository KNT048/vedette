package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
)

// Event names the forwarder listens to. core/events wants <module>.<object>.<verb>; the producers publish these (findings/ports.go,
// notify/incidents.go, honeypot/types.go; the bad-connection name is the one notify already listens to, L4 publishes it).
const (
	siemEventFindingCreated = "findings.finding.created"
	siemEventFindingStatus  = "findings.finding.status_changed"
	siemEventIncident       = "notify.incident.created"
	siemEventHoneypot       = "honeypot.hit.created"
	siemEventBadAddress     = "logs.bad_address.detected"
)

// SIEM queue and retry bounds (D-292).
const (
	SiemQueueMax   = 1000             // records waiting; past it the oldest goes
	siemBatch      = 50               // records per connection
	siemBackoff0   = time.Second      // first wait after a failed send
	siemBackoffMax = time.Minute      // longest wait
	siemDropEvery  = 10 * time.Minute // at most one "records were dropped" audit row per this
)

// SiemBus is the part of the event bus the forwarder needs; *events.Bus satisfies it.
type SiemBus interface {
	Subscribe(name string, fn events.Handler) (unsubscribe func())
}

// siemQueue is a bounded FIFO. push never blocks and never waits for the network: when full it drops the oldest and counts it, so a
// dead SIEM costs memory for at most SiemQueueMax small records and no time to the publisher.
type siemQueue struct {
	mu      sync.Mutex
	items   []siemRecord
	head    uint64 // sequence number of items[0]
	max     int
	dropped uint64
	gen     uint64 // bumped by every reset: a record built under an older configuration is refused
	wake    chan struct{}
}

func newSiemQueue(max int) *siemQueue { return &siemQueue{max: max, wake: make(chan struct{}, 1)} }

func (q *siemQueue) generation() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.gen
}

// reset empties the queue and starts a new generation.
func (q *siemQueue) reset() {
	q.mu.Lock()
	q.gen++
	q.head += uint64(len(q.items))
	q.items = nil
	q.mu.Unlock()
}

// push adds r unless the configuration changed since gen was read (the record was built for the old one).
func (q *siemQueue) push(r siemRecord, gen uint64) {
	q.mu.Lock()
	if gen != q.gen {
		q.mu.Unlock()
		return
	}
	if len(q.items) >= q.max {
		q.items = q.items[1:]
		q.head++
		q.dropped++
	}
	q.items = append(q.items, r)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// peek copies up to n records from the front and returns the sequence number after the last of them (for ack).
func (q *siemQueue) peek(n int) ([]siemRecord, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n > len(q.items) {
		n = len(q.items)
	}
	return slices.Clone(q.items[:n]), q.head + uint64(n)
}

// ack removes what peek returned that is still there (the oldest may have been dropped meanwhile).
func (q *siemQueue) ack(upTo uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if upTo > q.head {
		n := int(min(upTo-q.head, uint64(len(q.items))))
		q.items = q.items[n:]
		q.head += uint64(n)
	}
}

func (q *siemQueue) clear() {
	q.mu.Lock()
	q.head += uint64(len(q.items))
	q.items = nil
	q.mu.Unlock()
}

func (q *siemQueue) droppedCount() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// siemChanged is called after the configuration was saved: the old copy is forgotten at once (so nothing more is queued for a
// destination or a class that was just switched off) and the job reads the new one.
func (s *Service) siemChanged() {
	s.siemMu.Lock()
	s.siemQ.reset() // records queued for the old setting are not sent to a new destination, and none built for it is added
	s.siemCache.Store(nil)
	s.siemMu.Unlock()
	select {
	case s.siemReload <- struct{}{}:
	default:
	}
}

// Subscribe registers the event handlers on bus and returns a function that removes them. A handler only builds a record and puts it
// in the queue; it does so only while the forwarder job runs (the module is on, SYS-5) and the saved configuration is enabled for
// the class of the event (FORBID-3). Events are not persisted on the bus: a record not yet sent when the process stops is lost, as
// for notify.
func (s *Service) Subscribe(bus SiemBus) (unsubscribe func()) {
	var undo []func()
	on := func(name, class string, build func(m map[string]any) siemRecord) {
		undo = append(undo, bus.Subscribe(name, func(_ context.Context, e events.Event) error {
			if !s.siemRunning.Load() {
				return nil
			}
			gen := s.siemQ.generation() // before the configuration: a save in between makes the push refuse
			cfg := s.siemCache.Load()
			if cfg == nil || !cfg.Enabled || !slices.Contains(cfg.Events, class) {
				return nil
			}
			raw, err := json.Marshal(e.Data)
			if err != nil {
				return nil //nolint:nilerr // data of another module that is not JSON: nothing to forward
			}
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				return nil
			}
			s.siemQ.push(build(m), gen)
			return nil
		}))
	}
	now := s.now
	on(siemEventFindingCreated, "findings", func(m map[string]any) siemRecord {
		return newSiemRecord("finding.created", sevOr(str(m, "severity"), "medium"), now(),
			siemField{Key: "id", CEF: "externalId", Val: str(m, "finding_id")}, siemField{Key: "asset_id", Val: str(m, "asset_id")},
			siemField{Key: "cve", Val: str(m, "cve")}, siemField{Key: "basis", Val: str(m, "basis")})
	})
	on(siemEventFindingStatus, "findings", func(m map[string]any) siemRecord {
		return newSiemRecord("finding.status_changed", "info", now(),
			siemField{Key: "id", CEF: "externalId", Val: str(m, "finding_id")}, siemField{Key: "from", Val: str(m, "from")}, siemField{Key: "to", Val: str(m, "to")})
	})
	on(siemEventIncident, "alerts", func(m map[string]any) siemRecord {
		return newSiemRecord("incident.created", sevOr(str(m, "severity"), "medium"), now(),
			siemField{Key: "id", CEF: "externalId", Val: str(m, "id")}, siemField{Key: "kind", Val: str(m, "kind")})
	})
	on(siemEventHoneypot, "honeypot", func(m map[string]any) siemRecord {
		return newSiemRecord("honeypot.hit", "high", now(),
			siemField{Key: "id", CEF: "externalId", Val: str(m, "id")}, siemField{Key: "kind", Val: str(m, "kind")}, siemField{Key: "service", Val: str(m, "service")},
			siemField{Key: "port", CEF: "dpt", Val: str(m, "port")}, siemField{Key: "src_ip", CEF: "src", Val: str(m, "src_ip")},
			siemField{Key: "decoy", Val: str(m, "decoy")}, siemField{Key: "src_asset_id", Val: str(m, "src_asset_id")})
	})
	on(siemEventBadAddress, "bad_conn", func(m map[string]any) siemRecord {
		return newSiemRecord("ioc.hit", "high", now(),
			siemField{Key: "id", CEF: "externalId", Val: str(m, "id")}, siemField{Key: "src_ip", CEF: "src", Val: str(m, "src_ip")},
			siemField{Key: "dest", CEF: "dst", Val: str(m, "dest")}, siemField{Key: "dest_kind", Val: str(m, "dest_kind")},
			siemField{Key: "seen_via", Val: str(m, "seen_via")}, siemField{Key: "asset_id", Val: str(m, "asset_id")})
	})
	return func() {
		for _, u := range undo {
			u()
		}
	}
}

// str reads a scalar of another module's payload as text; anything else is "".
func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func sevOr(s, def string) string {
	if slices.Contains([]string{"critical", "high", "medium", "low", "info"}, s) {
		return s
	}
	return def
}

// runSiem is the job: it reads the configuration, then sends queued records one batch at a time, with a growing wait after a failure,
// until ctx ends (the module was turned off or the process stops). While it does not run, nothing is queued and nothing is sent.
func (s *Service) runSiem(ctx context.Context) error {
	s.siemQ.clear()
	s.siemRunning.Store(true)
	defer func() {
		s.siemRunning.Store(false)
		s.siemCache.Store(nil)
		s.siemQ.clear()
	}()
	var (
		backoff   time.Duration
		lastDrop  uint64
		lastAudit time.Time
	)
	for {
		if s.siemCache.Load() == nil {
			gen := s.siemQ.generation()
			cfg, err := s.loadSiem(ctx, s.cfg.Config.Reader(), true)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				s.cfg.Log.WarnContext(ctx, "reading the SIEM configuration failed", "error", err)
				if !sleepCtx(ctx, siemBackoffMax) {
					return ctx.Err()
				}
				continue
			}
			s.siemMu.Lock()
			fresh := s.siemQ.generation() == gen // else a save came in while this was read: read again
			if fresh {
				s.siemCache.Store(&cfg)
			}
			s.siemMu.Unlock()
			if !fresh {
				continue
			}
			backoff = 0
		}
		select { // a reload signal that arrived with the cache already fresh is spent
		case <-s.siemReload:
		default:
		}
		lastDrop, lastAudit = s.reportDrops(ctx, lastDrop, lastAudit)
		cfg := s.siemCache.Load()
		var recs []siemRecord
		var upTo uint64
		if cfg != nil && cfg.Enabled {
			recs, upTo = s.siemQ.peek(siemBatch)
		}
		if len(recs) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.siemQ.wake:
			case <-s.siemReload:
			case <-time.After(siemDropEvery):
			}
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 3*siemTimeout)
		_, err := s.sendOut(sctx, *cfg, recs)
		cancel()
		if err == nil {
			s.siemQ.ack(upTo)
			backoff = 0
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if backoff == 0 {
			backoff = siemBackoff0
		} else {
			backoff = min(backoff*2, siemBackoffMax)
		}
		s.cfg.Log.WarnContext(ctx, "forwarding to the SIEM failed", "reason", siemFailure(err, *cfg), "retry_in", backoff.String(), "queued", len(recs))
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-s.siemReload:
			t.Stop()
			backoff = 0
		case <-t.C:
		}
	}
}

// reportDrops writes one audit row when records were dropped since the last one (at most one per siemDropEvery) and logs it.
func (s *Service) reportDrops(ctx context.Context, last uint64, at time.Time) (uint64, time.Time) {
	n := s.siemQ.droppedCount()
	if n == last || s.now().Sub(at) < siemDropEvery {
		return last, at
	}
	s.cfg.Log.WarnContext(ctx, "SIEM queue full: oldest records dropped", "dropped_total", n)
	err := s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: "logs.siem_dropped", Target: "siem",
			Detail: strconv.FormatUint(n-last, 10) + " records dropped: the SIEM did not take them and the queue is full"})
	})
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "recording dropped SIEM records failed", "error", err)
		return last, at
	}
	return n, s.now()
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
