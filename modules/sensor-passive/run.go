package sensorpassive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// Run is the capture loop. It returns only when ctx is cancelled (the module was turned off, SYS-5, or the
// process stops) or on an error worth the scheduler's attention; wire it as a core/jobs job so that it runs
// only while the module is on. Run opens no goroutine that outlives it.
//
// While no interface is chosen it idles and looks again every few seconds; when the settings change
// (SetInterface) it reopens the capture at once; when a recording ends it waits for the next change.
func (s *Service) Run(ctx context.Context) error {
	if err := s.ensureSensor(ctx); err != nil {
		return ignoreStop(ctx, err)
	}
	failures := 0
	for ctx.Err() == nil {
		select { // a change made before this look is already in what we read next
		case <-s.reload:
		default:
		}
		st, err := s.settings(ctx)
		if err != nil {
			return ignoreStop(ctx, err)
		}
		if st.Interface == "" {
			s.wait(ctx, s.retryEvery)
			continue
		}
		got, err := s.session(ctx, st)
		switch {
		case err == nil || errors.Is(err, errReload):
			failures = 0
			if errors.Is(err, errReload) {
				continue // new settings: start over now
			}
			s.wait(ctx, 24*time.Hour) // the recording ended: nothing more until the settings change
		case ctx.Err() != nil:
		default:
			if got { // a capture that worked for a while and then failed is a new failure, not the next of a series
				failures = 0
			}
			failures++
			wait := backoff(s.retryEvery, failures)
			s.log.WarnContext(ctx, "sensor-passive: capture stopped, will retry", "interface", st.Interface, "retry_in", wait.String(), "error", err)
			s.wait(ctx, wait)
		}
	}
	return nil
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

// ignoreStop turns the error of a stop request (module off) into a clean return.
func ignoreStop(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

var errReload = errors.New("sensorpassive: settings changed")

// wait sleeps for d or until ctx ends or the settings change.
func (s *Service) wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-s.reload:
	case <-t.C:
	}
}

// settings reads the interface and mode chosen in sp_sensor and the extraction switches and filters from the host.
func (s *Service) settings(ctx context.Context) (Settings, error) {
	r, err := s.row(ctx, s.db.Reader())
	if err != nil {
		return Settings{}, err
	}
	st := Settings{Interface: r.iface.String, Span: r.span}
	if st.Interface == "" {
		return st, nil
	}
	if st.Span {
		if st.Extract, st.Filters, err = s.host.SpanOptions(ctx); err != nil {
			return Settings{}, fmt.Errorf("sensorpassive: SPAN options: %w", err)
		}
	}
	return st, nil
}

// session captures on one interface until ctx ends, the settings change, the source ends or fails.
// It reports whether any frame was received, so that Run starts the back-off over after a session that worked.
func (s *Service) session(ctx context.Context, st Settings) (received bool, err error) {
	ifaces, err := s.host.Interfaces(ctx)
	if err != nil {
		return false, fmt.Errorf("list interfaces: %w", err)
	}
	var macs []string
	var ips []netip.Addr
	for _, i := range ifaces { // every card of the box is "the box itself" (INV-6)
		macs = append(macs, i.MAC)
		ips = append(ips, i.Addresses...)
	}
	eng, err := newEngine(engineConfig{Clock: s.clock, Span: st.Span, Extract: st.Extract, Filters: st.Filters, OwnMACs: macs, OwnIPs: ips, Devices: s.devices})
	if err != nil {
		return false, err
	}
	src, err := s.open(st.Interface)
	if err != nil {
		return false, err
	}
	defer func() { _ = src.Close() }()

	sctx, cancel := context.WithCancel(ctx)
	reloaded := make(chan struct{})
	go func() { // turns a settings change into a stop of this session; ends with it
		defer close(reloaded)
		select {
		case <-s.reload:
			cancel()
			reloaded <- struct{}{}
		case <-sctx.Done():
		}
	}()
	s.setEngine(eng)
	defer func() {
		s.setEngine(nil)
	}()

	err = s.capture(sctx, src, eng)
	cancel()
	_, wasReload := <-reloaded
	_, _, last := eng.Stats(s.clock())
	received = !last.IsZero()
	switch {
	case ctx.Err() != nil:
		return received, ctx.Err() // module off or shutdown: no final flush, nothing is written after that (SYS-5)
	case wasReload:
		s.flush(ctx, eng, true)
		return received, errReload
	case errors.Is(err, io.EOF):
		s.flush(ctx, eng, true)
		s.heartbeat(ctx, eng)
		return received, nil
	}
	return received, err
}

func (s *Service) setEngine(e *Engine) {
	s.mu.Lock()
	s.eng = e
	s.mu.Unlock()
}

func (s *Service) capture(ctx context.Context, src Source, eng *Engine) error {
	now := s.clock()
	lastFlush, lastBeat, lastSummary := now, time.Time{}, now
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
		now = s.clock()
		if eng.Pending() >= maxSubmitBatch || now.Sub(lastFlush) >= s.flushEvery {
			s.flush(ctx, eng, false)
			lastFlush = now
		}
		if now.Sub(lastBeat) >= s.beatEvery {
			s.heartbeat(ctx, eng)
			lastBeat = now
		}
		if now.Sub(lastSummary) >= s.summaryEvery {
			lastSummary = now
			if c := eng.Counters(); len(c) > 0 && !maps.Equal(c, logged) { // only when something changed
				s.log.InfoContext(ctx, "sensor-passive: packets dropped or ignored since the capture started", "counters", c)
				logged = c
			}
		}
	}
	return nil
}

// flush sends what the engine collected: observations to the inventory (batch by batch, each with its seq)
// and metadata to the MetadataSink. When the inventory cannot be reached the observations go back to the engine and
// the next try waits (back-off); items the inventory refuses are dropped one by one (see deliver). A final flush
// (the recording ended, the settings changed) tries once and forgets what fails.
func (s *Service) flush(ctx context.Context, eng *Engine, final bool) {
	if !final && s.clock().Before(s.holdUntil) {
		return
	}
	obs, meta := eng.Drain(s.clock(), final)
	for len(obs) > 0 {
		n := min(len(obs), maxSubmitBatch)
		if s.batchMax > 0 {
			n = min(n, s.batchMax)
		}
		if s.deliver(ctx, eng, obs[:n]) {
			obs = obs[n:]
			continue
		}
		if ctx.Err() != nil { // cut by shutdown: nothing is wrong with the inventory
			eng.Requeue(obs)
			return
		}
		if !final && s.poisoned(obs[:n]) {
			if n > 1 {
				s.batchMax = max(1, n/2)
			} else if s.ensureSensor(ctx) == nil { // the store takes writes: this one item is what fails
				s.dropPoison(ctx, eng, obs[0])
				obs = obs[1:]
				continue
			}
		}
		s.holdOff(ctx, eng, obs, final)
		break
	}
	if len(obs) == 0 {
		s.failures, s.holdUntil, s.poisonN, s.batchMax = 0, time.Time{}, 0, 0
	}
	for len(meta) > 0 {
		n := min(len(meta), maxSubmitBatch)
		batch := meta[:n]
		meta = meta[n:]
		seq := s.nextSeq()
		if err := s.meta.Metadata(ctx, seq, batch); err != nil {
			eng.CountDrop("metadata_failed")
			s.log.WarnContext(ctx, "sensor-passive: metadata not delivered", "count", len(batch), "error", err)
			continue
		}
		if err := s.advance(ctx, seq); err != nil {
			s.log.WarnContext(ctx, "sensor-passive: saving the batch number failed", "error", err)
		}
	}
}

// holdOff handles observations the inventory could not take for a reason that is not about them (a busy or failing
// store): they go back to the engine and are sent again as a whole after a pause that doubles with every failure in a
// row. When this was the final flush there is no later, so they are forgotten and counted.
func (s *Service) holdOff(ctx context.Context, eng *Engine, obs []observe.Observation, final bool) {
	s.failures++
	if final {
		eng.Unmark(obs)
		for range obs {
			eng.CountDrop("observation_failed")
		}
		return
	}
	eng.Requeue(obs)
	wait := min(backoff(s.flushEvery, s.failures), maxDeliverPause)
	s.holdUntil = s.clock().Add(wait)
	s.log.WarnContext(ctx, "sensor-passive: the inventory did not take the observations, will retry", "count", len(obs), "retry_in", wait.String())
}

// poisonTries is how many times in a row the same batch may fail before it is split in half.
const poisonTries = 3

// batchKey tells whether the batch that failed now is the one that failed before: its size and its two ends.
type batchKey struct {
	n           int
	first, last observe.Observation
}

// poisoned records a failure of batch and reports whether it is the poisonTries-th in a row of this same batch.
func (s *Service) poisoned(batch []observe.Observation) bool {
	k := batchKey{n: len(batch), first: batch[0], last: batch[len(batch)-1]}
	if k != s.poison {
		s.poison, s.poisonN = k, 0
	}
	s.poisonN++
	if s.poisonN < poisonTries {
		return false
	}
	s.poisonN = 0
	return true
}

// dropPoison forgets one observation that keeps the inventory from taking whatever batch it is in, and counts it.
func (s *Service) dropPoison(ctx context.Context, eng *Engine, o observe.Observation) {
	eng.Unmark([]observe.Observation{o})
	eng.Delivered([]observe.Observation{o})
	eng.CountDrop("observation_failed")
	s.batchMax = 0
	s.log.WarnContext(ctx, "sensor-passive: an observation made every batch fail and was dropped", "field", o.Field)
}

// maxDeliverPause is the longest pause between two tries to hand observations to a failing inventory.
const maxDeliverPause = time.Minute

// deliver records one batch and reports whether the inventory could be reached. When the inventory refuses one item
// at its boundary (observe.ErrRejected names it), that item is dropped and counted, and the rest is sent again; the
// refused item stays marked as sent, so it is not offered again for fifteen minutes. Any other error says nothing
// about the items: deliver returns false and the caller retries the whole batch later. A batch the inventory accepted
// is never recorded a second time, even when saving its number fails.
func (s *Service) deliver(ctx context.Context, eng *Engine, batch []observe.Observation) bool {
	seq := s.nextSeq()
	if err := s.ensureSensor(ctx); err != nil { // once per call, not per retry: a refused item costs no write transaction
		s.log.WarnContext(ctx, "sensor-passive: observations not recorded", "count", len(batch), "error", err)
		return false
	}
	for len(batch) > 0 {
		applied, err := s.submit(ctx, seq, batch, false)
		var rej *observe.ErrRejected
		switch {
		case applied:
			if err != nil {
				s.log.WarnContext(ctx, "sensor-passive: saving the batch number failed", "error", err)
			}
			eng.Delivered(batch)
			return true
		case err == nil:
			eng.Delivered(batch)
			return true
		case errors.As(err, &rej) && rej.Index >= 0 && rej.Index < len(batch) && ctx.Err() == nil:
			eng.CountDrop("observation_rejected")
			s.log.WarnContext(ctx, "sensor-passive: an observation was refused and dropped", "field", batch[rej.Index].Field, "error", err)
			batch = slices.Delete(slices.Clone(batch), rej.Index, rej.Index+1) // the caller's slice is not ours to change
		default:
			s.log.WarnContext(ctx, "sensor-passive: observations not recorded", "count", len(batch), "error", err)
			return false
		}
	}
	return true
}

// heartbeat writes last_seen (the sensor is listening), the number of devices heard and the SPAN measurement
// (POST-1, POST-4).
func (s *Service) heartbeat(ctx context.Context, eng *Engine) {
	now := s.clock()
	pps, others, last := eng.Stats(now)
	devices := eng.DevicesSeen(now)
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE sp_sensor SET last_seen = ?, devices_seen = ? WHERE id = ?`, store.FormatTS(now), devices, SensorID); err != nil {
			return err
		}
		var lp any
		if !last.IsZero() {
			lp = store.FormatTS(last)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sp_span_stat (sensor_id, packets_per_s, other_macs, last_packet_at, measured_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (sensor_id) DO UPDATE SET packets_per_s = excluded.packets_per_s, other_macs = excluded.other_macs,
			last_packet_at = excluded.last_packet_at, measured_at = excluded.measured_at`, SensorID, pps, others, lp, store.FormatTS(now))
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "sensor-passive: heartbeat failed", "error", err)
	}
}
