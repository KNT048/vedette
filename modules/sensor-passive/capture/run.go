package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
)

// Link is the sensor side of the protocol (sensor-protocol.md section 6, passive role). *sensorlink.Client implements it for
// the sensor binary; core's sensor-passive service implements it in process for the capture job that stays in core until SP-5.
// Errors are the Client's: a *sensorlink.Error is an answer of core (its Code says what), anything else is "no answer".
type Link interface {
	// Config is one long poll of GET /config.
	Config(ctx context.Context, etag string, wait time.Duration) (sensorlink.ConfigReply, error)
	// PostObservations makes one attempt to deliver one batch. The caller decides whether and how to retry.
	PostObservations(ctx context.Context, req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error)
	// PassiveHeartbeat sends one heartbeat.
	PassiveHeartbeat(ctx context.Context, hb *sensorlink.PassiveHeartbeat) (string, error)
}

// Config is what New needs. Link and Interfaces are required.
type Config struct {
	Link Link
	// Interfaces lists the cards of the machine the capture runs on. Their MACs and addresses are "the box itself" (INV-6),
	// and the list is what core is told in each heartbeat and what SetInterface may choose from (INV-9).
	Interfaces func(ctx context.Context) ([]Interface, error)
	// Open opens a Source for an interface name; default OpenLive. Tests pass a replay of a fixture.
	Open func(iface string) (Source, error)
	// Meta receives SPAN metadata. On the wire there is none (D-112 (7)): nil drops it.
	Meta    MetadataSink
	Clock   func() time.Time
	Log     *slog.Logger
	Version string // SemVer, goes into the heartbeat

	// FlushEvery, HeartbeatEvery and RetryEvery set the pace; zero means 5 s, 30 s and 5 s (the retry grows to 10 min while a
	// capture keeps failing). SummaryEvery is how often a changed drop summary is logged (5 min). ConfigWait is the long-poll
	// wait (25 s), ModuleOffEvery how often a module that is off is asked again (60 s), RetryAfterCap the longest pause a
	// Retry-After from core is allowed to impose (60 s; the cap exists so that tests need not wait seconds).
	FlushEvery, HeartbeatEvery, RetryEvery, SummaryEvery, ConfigWait, ModuleOffEvery, RetryAfterCap time.Duration
}

// Runner is the capture process: it asks core what to do, captures, and reports what it saw. Create it with New and call Run.
// Its memory is the whole queue: there is no disk queue (D-112 (6)).
type Runner struct {
	link    Link
	ifaces  func(context.Context) ([]Interface, error)
	open    func(string) (Source, error)
	meta    MetadataSink
	clock   func() time.Time
	log     *slog.Logger
	version string
	epoch   string

	flushEvery, beatEvery, retryEvery, summaryEvery, configWait, offEvery, retryCap time.Duration

	devices *deviceBook // devices already reported: outlives the Engines (INV-6, SYS-6)

	mu     sync.Mutex
	eng    *Engine          // the running capture, nil when idle
	totals map[string]int64 // counters of finished Engines and of the Runner itself
	seq    uint64           // last batch number handed out
	off    bool             // core said module_off: nothing runs until a config call says the module is on
	cancel context.CancelCauseFunc

	// delivery state (the session goroutine only): a batch that failed poisonTries times in a row is split in half until the
	// item that makes it fail stands alone, see flush.
	failures   int
	holdUntil  time.Time
	retryAfter time.Duration // what core asked for in its last 429 or 503
	poison     batchKey
	poisonN    int
	batchMax   int // batch size while hunting; 0 means maxSubmitBatch. Back to 0 after any delivery
	sizeMax    int // batch size core said fits (413); stays for the life of the process
}

// New returns a Runner with a new epoch: every process start is a new one (sensor-protocol.md 6.2).
func New(cfg Config) (*Runner, error) {
	if cfg.Link == nil || cfg.Interfaces == nil {
		return nil, errors.New("capture: New needs a Link and Interfaces")
	}
	r := &Runner{link: cfg.Link, ifaces: cfg.Interfaces, open: cfg.Open, meta: cfg.Meta, clock: cfg.Clock, log: cfg.Log, version: cfg.Version,
		flushEvery: cfg.FlushEvery, beatEvery: cfg.HeartbeatEvery, retryEvery: cfg.RetryEvery, summaryEvery: cfg.SummaryEvery,
		configWait: cfg.ConfigWait, offEvery: cfg.ModuleOffEvery, retryCap: cfg.RetryAfterCap,
		devices: newDeviceBook(defaultLimits), totals: map[string]int64{}}
	if r.meta == nil {
		r.meta = NoMetadata{}
	}
	if r.clock == nil {
		r.clock = time.Now
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.open == nil {
		r.open = OpenLive
	}
	if r.version == "" {
		r.version = "0.0.0-dev"
	}
	r.flushEvery = orDefault(r.flushEvery, 5*time.Second)
	r.beatEvery = orDefault(r.beatEvery, 30*time.Second)
	r.retryEvery = orDefault(r.retryEvery, 5*time.Second)
	r.summaryEvery = orDefault(r.summaryEvery, 5*time.Minute)
	r.configWait = orDefault(r.configWait, sensorlink.DefaultWait)
	r.offEvery = orDefault(r.offEvery, 60*time.Second)
	r.retryCap = orDefault(r.retryCap, sensorlink.BackoffCap)
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24)
	r.epoch = hex.EncodeToString(b[:])
	return r, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Epoch is the epoch of this process (32 hex).
func (r *Runner) Epoch() string { return r.epoch }

var (
	errChanged    = errors.New("capture: settings changed")
	errStopped    = errors.New("capture: capture not wanted")
	errModuleOff  = errors.New("capture: module off")
	errBadFilters = errors.New("capture: filters cannot be read")
)

// Run asks core for the configuration and follows it until ctx ends: it captures on the interface core names, with the filters
// core sends, and reports what it saw. It returns nil when ctx ends; an unreachable core is not an error (the capture goes
// on with the last configuration, and the batches wait their turn in memory).
//
//   - interface "" in the config: capture stops at once, no last flush (sensor-protocol.md 6.1);
//   - a different interface or filters: the old capture closes after a last flush, the new one opens;
//   - module_off (409) from any call: capture stops, the queue is dropped, no last flush (SYS-5, D-80 (4)); core is asked again
//     every minute;
//   - filters that cannot be read: no capture, counted as filters_invalid in the heartbeat.
//
// Run starts no goroutine that outlives it.
func (r *Runner) Run(ctx context.Context) error {
	r.setOn()
	var wg sync.WaitGroup
	defer wg.Wait()
	hctx, stopBeats := context.WithCancel(ctx)
	defer stopBeats()
	wg.Add(1)
	go func() { defer wg.Done(); r.heartbeats(hctx) }()

	var (
		etag    string
		cur     Settings
		started bool
		done    chan struct{} // closed when the session goroutine has returned
		bo      = sensorlink.NewBackoff(nil)
	)
	stopSession := func(cause error) {
		r.mu.Lock()
		cancel := r.cancel
		r.mu.Unlock()
		if cancel != nil {
			cancel(cause)
		}
		if done != nil {
			<-done
			done = nil
		}
		started = false
	}
	defer stopSession(errStopped)
	for ctx.Err() == nil {
		wasOff := r.isOff()
		rep, err := r.link.Config(ctx, etag, r.configWait)
		switch {
		case ctx.Err() != nil:
			return nil
		case isModuleOff(err):
			r.goOff()
			stopSession(errModuleOff)
			etag, cur = "", Settings{}
			r.sleep(ctx, r.offEvery)
			continue
		case err != nil:
			r.log.WarnContext(ctx, "sensor-passive: no configuration from core, going on with the last one", "error", err)
			r.sleep(ctx, bo.Next())
			continue
		}
		bo.Reset()
		if wasOff {
			r.setOn()
		}
		if r.isOff() { // module_off came from another call while this poll was open: the reply says nothing, ask again
			stopSession(errModuleOff)
			etag, cur = "", Settings{}
			continue
		}
		if rep.NotModified {
			continue
		}
		etag = rep.ETag
		want := settingsOf(rep.Config)
		if started && sameSettings(cur, want) {
			continue
		}
		switch {
		case !started:
		case want.Interface == "":
			stopSession(errStopped) // not wanted any more: no last flush
		default:
			stopSession(errChanged) // another card or other filters: the old capture says its last words
		}
		cur = want
		if want.Interface == "" {
			started = false
			continue
		}
		sctx, cancel := context.WithCancelCause(ctx)
		r.mu.Lock()
		r.cancel = cancel
		r.mu.Unlock()
		done = make(chan struct{})
		started = true
		go func(st Settings, done chan struct{}) {
			defer close(done)
			r.captureLoop(ctx, sctx, st)
		}(want, done)
	}
	return nil
}

func settingsOf(c sensorlink.Config) Settings {
	st := Settings{Interface: c.Interface, Span: c.Span, Extract: Extract{DNS: c.Extract.DNS, TLSSNI: c.Extract.SNI, HTTPHost: c.Extract.HTTP, Flows: c.Extract.Flows}}
	for _, f := range c.Filters {
		st.Filters = append(st.Filters, Filter{Type: f.Type, Value: f.Value})
	}
	return st
}

func sameSettings(a, b Settings) bool {
	return a.Interface == b.Interface && a.Span == b.Span && a.Extract == b.Extract && slices.Equal(a.Filters, b.Filters)
}

func isModuleOff(err error) bool {
	var e *sensorlink.Error
	return errors.As(err, &e) && e.Code == sensorlink.CodeModuleOff
}

func (r *Runner) isOff() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.off }
func (r *Runner) setOn()      { r.mu.Lock(); r.off = false; r.mu.Unlock() }

// goOff records that core said module_off and ends the running capture at once, without a last flush.
func (r *Runner) goOff() {
	r.mu.Lock()
	r.off = true
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel(errModuleOff)
	}
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// maxBackoff is the longest pause between two attempts to open a capture that keeps failing.
const maxBackoff = 10 * time.Minute

// backoff is the pause after the n-th failure in a row: base, 2*base, 4*base ... up to ten minutes. A card
// that is gone must not fill the log every few seconds.
func backoff(base time.Duration, n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := base
	for range min(n-1, 20) {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return min(d, maxBackoff)
}

// captureLoop captures on one interface until sctx ends, retrying with a growing pause when the card cannot be opened or the
// capture fails. pctx is the process context: a session that ends because pctx did writes nothing more.
func (r *Runner) captureLoop(pctx, sctx context.Context, st Settings) {
	failures := 0
	for sctx.Err() == nil {
		got, err := r.session(pctx, sctx, st)
		switch {
		case err == nil: // the recording ended: nothing more until the settings change
			<-sctx.Done()
		case sctx.Err() != nil:
		case errors.Is(err, errBadFilters):
			r.count("filters_invalid")
			r.log.ErrorContext(sctx, "sensor-passive: the filters from core cannot be read, not capturing", "error", err)
			<-sctx.Done() // nothing to retry: only a new configuration helps
		default:
			if got { // a capture that worked for a while and then failed is a new failure, not the next of a series
				failures = 0
			}
			failures++
			r.count("capture_failed")
			wait := backoff(r.retryEvery, failures)
			r.log.WarnContext(sctx, "sensor-passive: capture stopped, will retry", "interface", st.Interface, "retry_in", wait.String(), "error", err)
			r.sleep(sctx, wait)
		}
	}
}

// session captures on one interface until sctx ends, the source ends or fails. It reports whether any frame was received,
// so that captureLoop starts the back-off over after a session that worked.
func (r *Runner) session(pctx, sctx context.Context, st Settings) (received bool, err error) {
	ifaces, err := r.ifaces(sctx)
	if err != nil {
		return false, fmt.Errorf("list interfaces: %w", err)
	}
	var macs []string
	var ips []netip.Addr
	for _, i := range ifaces { // every card of the machine is "the box itself" (INV-6)
		macs = append(macs, i.MAC)
		for _, p := range i.Addresses {
			ips = append(ips, p.Addr())
		}
	}
	eng, err := newEngine(engineConfig{Clock: r.clock, Span: st.Span, Extract: st.Extract, Filters: st.Filters, OwnMACs: macs, OwnIPs: ips, Devices: r.devices})
	if err != nil {
		return false, fmt.Errorf("%w: %w", errBadFilters, err)
	}
	src, err := r.open(st.Interface)
	if err != nil {
		return false, err
	}
	defer func() { _ = src.Close() }()
	r.setEngine(eng)
	defer func() {
		r.setEngine(nil)
		r.mergeCounters(eng)
	}()

	err = r.capture(sctx, src, eng)
	_, _, last := eng.Stats(r.clock())
	received = !last.IsZero()
	cause := context.Cause(sctx)
	switch {
	case pctx.Err() != nil || errors.Is(cause, errModuleOff) || errors.Is(cause, errStopped):
		return received, pctx.Err() // module off, shutdown, or "do not capture": no final flush, nothing is written after that (SYS-5)
	case errors.Is(cause, errChanged):
		r.flush(pctx, eng, true)
		return received, nil
	case errors.Is(err, io.EOF):
		r.flush(sctx, eng, true)
		return received, nil
	}
	return received, err
}

func (r *Runner) setEngine(e *Engine) {
	r.mu.Lock()
	r.eng = e
	r.mu.Unlock()
}

// mergeCounters adds the counters of a finished Engine to the totals the heartbeat reports.
func (r *Runner) mergeCounters(e *Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range e.Counters() {
		r.totals[k] += int64(v) //nolint:gosec // a packet count does not reach 2^63
	}
}

// count adds one to a counter of the Runner itself (what happens outside any Engine).
func (r *Runner) count(why string) {
	r.mu.Lock()
	r.totals[why]++
	r.mu.Unlock()
}

// counters is every counter since the process started: finished Engines, the Runner, and the Engine that runs now.
func (r *Runner) counters() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := maps.Clone(r.totals)
	if r.eng != nil {
		for k, v := range r.eng.Counters() {
			out[k] += int64(v) //nolint:gosec // see mergeCounters
		}
	}
	return out
}

func (r *Runner) nextSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	return r.seq
}

func (r *Runner) capture(ctx context.Context, src Source, eng *Engine) error {
	now := r.clock()
	lastFlush, lastSummary := now, now
	var logged map[string]uint64
	for ctx.Err() == nil {
		p, err := src.Next(ctx)
		switch {
		case err == nil:
			eng.Handle(p)
		case errors.Is(err, ErrIdle):
		case errors.Is(err, ErrDropped):
			eng.CountDrop("unusable_record")
		case ctx.Err() != nil:
			return nil
		default:
			return err // io.EOF ends a recording; anything else is a failure
		}
		now = r.clock()
		if eng.Pending() >= maxSubmitBatch || now.Sub(lastFlush) >= r.flushEvery {
			r.flush(ctx, eng, false)
			lastFlush = now
		}
		if now.Sub(lastSummary) >= r.summaryEvery {
			lastSummary = now
			if c := eng.Counters(); len(c) > 0 && !maps.Equal(c, logged) { // only when something changed
				r.log.InfoContext(ctx, "sensor-passive: packets dropped or ignored since the capture started", "counters", c)
				logged = c
			}
		}
	}
	return nil
}

// maxSubmitBatch is the most items one batch of the protocol carries (sensor-protocol.md section 9).
const maxSubmitBatch = sensorlink.MaxItems

// outcome is what became of one attempt to deliver a batch.
type outcome int

const (
	delivered outcome = iota // core took it; the items it rejected were dropped
	retry                    // core could not take it now (rate limit, updating, unreachable): same items again later, no blame
	busy                     // 503 store_busy: the same, and the only answer that may be about one item of the batch
	tooLarge                 // 413: send fewer
	dropped                  // core refused the batch for good (400 and the like): it was dropped and counted
	wentOff                  // module_off: stop, nothing is sent any more
)

// flush sends what the Engine collected: observations to core (batch by batch, each with its seq) and metadata to the
// MetadataSink. When core cannot be reached the observations go back to the Engine and the next try waits (back-off); a
// batch that keeps failing is split until the item that makes it fail stands alone and is dropped (the poison hunt); items
// core rejects are dropped one by one and never offered again (D-112 (3)). A final flush (the recording ended, the settings
// changed) tries once and forgets what fails.
func (r *Runner) flush(ctx context.Context, eng *Engine, final bool) {
	if !final && r.clock().Before(r.holdUntil) {
		return
	}
	obs, meta := eng.Drain(r.clock(), final)
	for len(obs) > 0 {
		n := min(len(obs), maxSubmitBatch)
		if r.sizeMax > 0 {
			n = min(n, r.sizeMax)
		}
		if r.batchMax > 0 {
			n = min(n, r.batchMax)
		}
		res := r.deliver(ctx, eng, obs[:n])
		switch res {
		case delivered:
			r.batchMax = 0 // the hunt is over: whatever failed is behind us
			r.poisonN = 0
			obs = obs[n:]
			continue
		case dropped:
			obs = obs[n:]
			continue
		case wentOff:
			return // the queue is dropped with the Engine
		case tooLarge:
			if n > 1 {
				r.sizeMax = max(1, n/2) // the same items again, in smaller batches
				continue
			}
			r.dropBatch(ctx, eng, obs[:1], "a single observation is over the size limit")
			obs = obs[1:]
			continue
		}
		if ctx.Err() != nil { // cut by shutdown: nothing is wrong with core
			eng.Requeue(obs)
			return
		}
		// Only a 503 can be about the items, and only while core answers a heartbeat (its store takes a write) at this moment: a
		// rate limit, an update window, a certificate being rotated or no answer at all say nothing about any item.
		if res == busy && !final && r.coreTakesWrites(ctx) && r.poisoned(obs[:n]) {
			if n > 1 {
				r.batchMax = max(1, n/2)
				r.failures = 0 // a split is a new attempt with smaller batches: the pause starts over, the hunt must not crawl
			} else {
				r.dropPoison(ctx, eng, obs[0])
				obs = obs[1:]
				continue
			}
		}
		r.holdOff(ctx, eng, obs, final)
		break
	}
	if len(obs) == 0 {
		r.failures, r.holdUntil, r.poisonN, r.batchMax, r.retryAfter = 0, time.Time{}, 0, 0, 0
	}
	for len(meta) > 0 {
		n := min(len(meta), maxSubmitBatch)
		batch := meta[:n]
		meta = meta[n:]
		if err := r.meta.Metadata(ctx, r.nextSeq(), batch); err != nil {
			eng.CountDrop("metadata_failed")
			r.log.WarnContext(ctx, "sensor-passive: metadata not delivered", "count", len(batch), "error", err)
		}
	}
}

// holdOff handles observations core could not take for a reason that is not about them (busy, failing, unreachable): they go
// back to the Engine and are sent again as a whole after a pause that doubles with every failure in a row (at least what core
// asked for in Retry-After, at most retryCap). When this was the final flush there is no later, so they are forgotten and counted.
func (r *Runner) holdOff(ctx context.Context, eng *Engine, obs []observe.Observation, final bool) {
	r.failures++
	if final {
		eng.Unmark(obs)
		for range obs {
			eng.CountDrop("observation_failed")
		}
		return
	}
	eng.Requeue(obs)
	wait := min(backoff(r.flushEvery, r.failures), maxDeliverPause)
	wait = max(wait, min(r.retryAfter, r.retryCap))
	r.holdUntil = r.clock().Add(wait)
	r.log.WarnContext(ctx, "sensor-passive: core did not take the observations, will retry", "count", len(obs), "retry_in", wait.String())
}

// poisonTries is how many times in a row the same batch may fail before it is split in half.
const poisonTries = 3

// batchKey tells whether the batch that failed now is the one that failed before: its size and its two ends.
type batchKey struct {
	n           int
	first, last observe.Observation
}

// poisoned records a failure of batch and reports whether it is the poisonTries-th in a row of this same batch.
func (r *Runner) poisoned(batch []observe.Observation) bool {
	k := batchKey{n: len(batch), first: batch[0], last: batch[len(batch)-1]}
	if k != r.poison {
		r.poison, r.poisonN = k, 0
	}
	r.poisonN++
	if r.poisonN < poisonTries {
		return false
	}
	r.poisonN = 0
	return true
}

// dropPoison forgets one observation that keeps core from taking whatever batch it is in, and counts it.
func (r *Runner) dropPoison(ctx context.Context, eng *Engine, o observe.Observation) {
	eng.Unmark([]observe.Observation{o})
	eng.Delivered([]observe.Observation{o})
	eng.CountDrop("observation_failed")
	r.batchMax = 0
	r.log.WarnContext(ctx, "sensor-passive: an observation made every batch fail and was dropped", "field", o.Field)
}

// maxDeliverPause is the longest pause between two tries to hand observations to a failing core.
const maxDeliverPause = time.Minute

// coreTakesWrites says whether core answers and its store accepts a write: a heartbeat is a write there. It tells an item that
// makes a batch fail from a store that fails for everything.
func (r *Runner) coreTakesWrites(ctx context.Context) bool {
	return r.sendHeartbeat(ctx) == nil
}

// deliver makes one attempt to deliver batch under a seq of its own. Every attempt has a new seq: the batch of the next
// attempt may be another set of items, and core drops a seq it has already seen (a repeated seq with other items would
// lose them). Items core rejects are dropped and counted; they stay marked as sent, so they are not offered again for
// fifteen minutes.
func (r *Runner) deliver(ctx context.Context, eng *Engine, batch []observe.Observation) outcome {
	rep, err := r.link.PostObservations(ctx, buildRequest(r.epoch, r.nextSeq(), batch))
	if err == nil {
		seen := map[int]bool{}
		later := map[int]bool{} // rejected for want of budget: not wrong, only too many; it may come again
		for _, rj := range rep.Rejected {
			if rj.Index < 0 || rj.Index >= len(batch) || seen[rj.Index] {
				continue
			}
			seen[rj.Index] = true
			later[rj.Index] = rj.Code == "budget_exhausted"
			eng.CountDrop("observation_rejected")
			r.log.WarnContext(ctx, "sensor-passive: core rejected an observation, dropped", "field", batch[rj.Index].Field, "reason", rj.Code)
		}
		var done, again []observe.Observation
		for i, o := range batch {
			if later[i] {
				again = append(again, o)
			} else {
				done = append(done, o)
			}
		}
		eng.Delivered(done) // a vendor row refused for good is no longer owed...
		eng.Unmark(again)   // ...but one that only met a budget still is, and may be offered again
		return delivered
	}
	var e *sensorlink.Error
	switch {
	case ctx.Err() != nil:
		return retry
	case isModuleOff(err):
		r.goOff()
		return wentOff
	case errors.As(err, &e):
		switch {
		case e.Status == 413:
			return tooLarge
		case e.Status == 429 || e.Status == 503 || e.Status == 426 || e.Code == sensorlink.CodeCertRetired:
			r.retryAfter = e.RetryAfter
			r.log.WarnContext(ctx, "sensor-passive: core did not take the observations", "count", len(batch), "code", e.Code, "status", e.Status)
			if e.Status == 503 {
				return busy
			}
			return retry
		}
		r.dropBatch(ctx, eng, batch, fmt.Sprintf("core answered %d %s", e.Status, e.Code))
		return dropped
	}
	r.log.WarnContext(ctx, "sensor-passive: observations not delivered", "count", len(batch), "error", err)
	return retry
}

// dropBatch gives up on a batch core refused for good (OTLP: no retry): counted, and marked as delivered so that the vendor
// debt of its devices does not keep them queued for ever.
func (r *Runner) dropBatch(ctx context.Context, eng *Engine, batch []observe.Observation, why string) {
	for range batch {
		eng.CountDrop("batch_dropped")
	}
	eng.Delivered(batch)
	r.log.WarnContext(ctx, "sensor-passive: a batch was dropped", "count", len(batch), "why", why)
}

func buildRequest(epoch string, seq uint64, batch []observe.Observation) *sensorlink.ObservationsRequest {
	req := &sensorlink.ObservationsRequest{Epoch: epoch, Seq: int64(seq), Items: make([]sensorlink.ObservationItem, 0, len(batch))} //nolint:gosec // seq counts batches, not near 2^63
	for _, o := range batch {
		it := sensorlink.ObservationItem{MAC: o.AssetHint.MAC, Field: string(o.Field), Value: o.Value, Confidence: o.Confidence, SeenAt: o.SeenAt.UTC()}
		if o.AssetHint.IP.IsValid() {
			it.IP = o.AssetHint.IP.String()
		}
		req.Items = append(req.Items, it)
	}
	return req
}

// heartbeats sends one at once and then one per beat, while the module is on.
func (r *Runner) heartbeats(ctx context.Context) {
	for ctx.Err() == nil {
		if !r.isOff() {
			if err := r.sendHeartbeat(ctx); err != nil && ctx.Err() == nil && !isModuleOff(err) {
				r.log.WarnContext(ctx, "sensor-passive: heartbeat not delivered", "error", err)
			}
		}
		r.sleep(ctx, r.beatEvery)
	}
}

func (r *Runner) sendHeartbeat(ctx context.Context) error {
	hb, err := r.heartbeat(ctx)
	if err != nil {
		return err
	}
	if _, err := r.link.PassiveHeartbeat(ctx, hb); err != nil {
		if isModuleOff(err) {
			r.goOff()
		}
		return err
	}
	return nil
}

// heartbeat builds what core is told every 30 s: the cards of this machine, the SPAN measurement, the counters (sensor-protocol.md 6.3).
func (r *Runner) heartbeat(ctx context.Context) (*sensorlink.PassiveHeartbeat, error) {
	ifaces, err := r.ifaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	hb := &sensorlink.PassiveHeartbeat{Version: r.version, Interfaces: []sensorlink.HeartbeatIface{}, Drops: map[string]int64{}}
	for _, i := range ifaces {
		if len(hb.Interfaces) == sensorlink.MaxHeartbeatIfaces {
			break
		}
		if !sensorlink.ValidIfaceName(i.Name) || !sensorlink.ValidMAC(strings.ToLower(i.MAC)) {
			continue
		}
		hi := sensorlink.HeartbeatIface{Name: i.Name, MAC: strings.ToLower(i.MAC), Link: i.Link, IPv4: []string{}}
		for _, p := range i.Addresses {
			if p.Addr().Is4() && len(hi.IPv4) < sensorlink.MaxHeartbeatPrefixes {
				hi.IPv4 = append(hi.IPv4, p.String())
			}
		}
		hb.Interfaces = append(hb.Interfaces, hi)
	}
	now := r.clock()
	r.mu.Lock()
	eng := r.eng
	r.mu.Unlock()
	if eng != nil {
		pps, others, last := eng.Stats(now)
		hb.Span.PPS, hb.Span.OtherMACs = int64(pps), int64(others)
		if !last.IsZero() {
			l := last.UTC()
			hb.Span.LastPacketAt = &l
		}
		hb.DevicesSeen = int64(eng.DevicesSeen(now))
	}
	for k, v := range r.counters() {
		if sensorlink.ValidDropKey(k) {
			hb.Drops[k] = v
		}
	}
	return hb, nil
}
