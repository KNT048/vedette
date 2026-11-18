package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// owedRetry is how long a device that had a normal or versions scan (successful or not) is left alone before another is queued for it.
const owedRetry = 7 * 24 * time.Hour

// queueOwedNormal queues, once per window, a normal scan for every device the policy lets be scanned normally that had a gentle scan
// and never a normal one (INV-26). A device is scanned once when it is found, gently while its kind is unknown or fragile; when it later becomes
// scannable (a person or a scan gave it a type that is not fragile, the fragile or regular-scan kinds changed, regular_scan=allow)
// nothing else asked for its normal scan before the weekly round (up to a week later), so its services kept no product or version
// and its software list stayed empty. keepNormal records a normal scan's result in sa_all_ports.normal_sw (an empty list too), which is
// what "had one" means; a device whose normal or versions scan ran in the last owedRetry (whatever it found) is not queued again, so a
// device nmap cannot read costs one scan a week, not one a window. Queueing is INSERT OR IGNORE; the scan itself is checked against
// the policy again at its turn.
func (s *Service) queueOwedNormal(ctx context.Context, windowStart time.Time) error {
	if p := s.owedQueued.Load(); p != nil && p.Equal(windowStart) {
		return nil
	}
	s.mu.Lock()
	if s.owedTried == nil {
		s.owedTried = map[string]bool{}
	}
	s.mu.Unlock()
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return err
	}
	since := store.FormatTS(s.clock().Add(-owedRetry))
	for _, id := range addrs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.mu.Lock()
		tried := s.owedTried[id]
		s.mu.Unlock()
		if tried {
			continue
		}
		dec, err := s.inv.ScanPolicy(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return err
		}
		if !dec.Allowed || dec.Never || dec.Fragile || dec.Unclassified || dec.FirstGentle {
			continue
		}
		var busy, gentle int
		err = s.db.Reader().QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM sa_probe p JOIN sa_job j ON j.id = p.job_id WHERE j.asset_id = ?1 AND p.shape IN ('gentle', 'gentle_titles')),
			(SELECT count(*) FROM sa_all_ports WHERE asset_id = ?1 AND normal_sw IS NOT NULL)
			+ (SELECT count(*) FROM sa_queue WHERE asset_id = ?1)
			+ (SELECT count(*) FROM sa_probe p JOIN sa_job j ON j.id = p.job_id WHERE j.asset_id = ?1 AND p.shape IN ('normal', 'versions') AND p.time >= ?2)`,
			id, since).Scan(&gentle, &busy)
		if err != nil {
			return fmt.Errorf("sensoractive: read the scans of a device: %w", err)
		}
		if gentle > 0 && busy == 0 { // only a device whose look so far was gentle: any other device's scan is the queue's and the weekly round's
			if err := s.Enqueue(ctx, id, "normal_owed"); err != nil {
				return err
			}
			s.mu.Lock()
			s.owedTried[id] = true // queued once per device (until the process restarts): a scan the policy refuses at its turn is not queued again every window
			s.mu.Unlock()
		}
	}
	w := windowStart
	s.owedQueued.Store(&w)
	return nil
}
