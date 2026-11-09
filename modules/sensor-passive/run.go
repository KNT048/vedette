package sensorpassive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

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
		switch err := s.session(ctx, st); {
		case err == nil || errors.Is(err, errReload):
			if errors.Is(err, errReload) {
				continue // new settings: start over now
			}
			s.wait(ctx, 24*time.Hour) // the recording ended: nothing more until the settings change
		case ctx.Err() != nil:
		default:
			s.log.WarnContext(ctx, "sensor-passive: capture stopped, will retry", "interface", st.Interface, "error", err)
			s.wait(ctx, s.retryEvery)
		}
	}
	return nil
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
func (s *Service) session(ctx context.Context, st Settings) error {
	ifaces, err := s.host.Interfaces(ctx)
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	var macs []string
	var ips []netip.Addr
	for _, i := range ifaces { // every card of the box is "the box itself" (INV-6)
		macs = append(macs, i.MAC)
		ips = append(ips, i.Addresses...)
	}
	eng, err := newEngine(engineConfig{Clock: s.clock, Span: st.Span, Extract: st.Extract, Filters: st.Filters, OwnMACs: macs, OwnIPs: ips})
	if err != nil {
		return err
	}
	src, err := s.open(st.Interface)
	if err != nil {
		return err
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
	switch {
	case ctx.Err() != nil:
		return ctx.Err() // module off or shutdown: no final flush, nothing is written after that (SYS-5)
	case wasReload:
		s.flush(ctx, eng, true)
		return errReload
	case errors.Is(err, io.EOF):
		s.flush(ctx, eng, true)
		s.heartbeat(ctx, eng)
		return nil
	}
	return err
}

func (s *Service) setEngine(e *Engine) {
	s.mu.Lock()
	s.eng = e
	s.mu.Unlock()
}

func (s *Service) capture(ctx context.Context, src Source, eng *Engine) error {
	now := s.clock()
	lastFlush, lastBeat := now, time.Time{}
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
	}
	return nil
}

// flush sends what the engine collected: observations to the inventory (batch by batch, each with its seq)
// and metadata to the MetadataSink. A failed batch is logged and dropped from this round; its observations are
// forgotten by the repeat filter so the next sighting is sent again.
func (s *Service) flush(ctx context.Context, eng *Engine, final bool) {
	obs, meta := eng.Drain(s.clock(), final)
	for len(obs) > 0 {
		n := min(len(obs), maxSubmitBatch)
		batch := obs[:n]
		obs = obs[n:]
		if _, err := s.SubmitBatch(ctx, SensorID, s.nextSeq(), batch); err != nil {
			eng.Unmark(batch)
			eng.CountDrop("submit_failed")
			s.log.WarnContext(ctx, "sensor-passive: observations not recorded", "count", len(batch), "error", err)
		}
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
