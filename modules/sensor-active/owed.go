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

// queueOwedNormal queues, once per window, the scan every device is owed. First, a first check for every device the policy allows that
// no check ever reached (INV-27): a device whose network scan a person turned on, or that a new or changed range now covers, was
// refused (and left the queue) while it was out of scope or off, and nothing else asks for it before the weekly round. Then, a normal scan for every device the policy lets be scanned normally that had a gentle scan
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
		if !dec.Allowed || dec.Never {
			continue
		}
		var checked, queuedNow, busy, gentle int
		err = s.db.Reader().QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM sa_probe p JOIN core_run r ON r.id = p.run_id WHERE r.module = ?3 AND r.subject_kind = 'device' AND r.subject_id = ?1
				AND p.shape IN ('gentle', 'gentle_titles')),
			(SELECT count(*) FROM sa_all_ports WHERE asset_id = ?1 AND normal_sw IS NOT NULL)
			+ (SELECT count(*) FROM sa_probe p JOIN core_run r ON r.id = p.run_id WHERE r.module = ?3 AND r.subject_kind = 'device' AND r.subject_id = ?1
				AND p.shape IN ('normal', 'versions') AND p.time >= ?2),
			(SELECT count(*) FROM core_run WHERE module = ?3 AND kind = ?4 AND subject_kind = 'device' AND subject_id = ?1 AND status IN ('queued', 'waiting', 'running')),
			(SELECT count(*) FROM core_run r WHERE r.module = ?3 AND r.kind = ?4 AND r.subject_kind = 'device' AND r.subject_id = ?1
				AND r.status IN ('done', 'partial', 'failed') AND EXISTS (SELECT 1 FROM sa_probe p WHERE p.run_id = r.id))
			+ (SELECT count(*) FROM sa_all_ports WHERE asset_id = ?1 AND normal_sw IS NOT NULL)`,
			id, since, ModuleID, RunCheck).Scan(&gentle, &busy, &queuedNow, &checked)
		if err != nil {
			return fmt.Errorf("sensoractive: read the scans of a device: %w", err)
		}
		reason := ""
		switch {
		case queuedNow > 0:
		case checked == 0: // no check of this device yet, whatever made it scannable (INV-27): its first one is tonight's, not the weekly round's
			reason = "first_check"
		case !dec.Fragile && !dec.Unclassified && !dec.FirstGentle && gentle > 0 && busy == 0:
			// only a device whose look so far was gentle: any other device's scan is the queue's and the weekly round's
			reason = "normal_owed"
		}
		if reason != "" {
			if err := s.Enqueue(ctx, id, reason); err != nil {
				return err
			}
			s.mu.Lock()
			s.owedTried[id] = true // queued once per device (until the process restarts or the settings change): a scan the policy refuses at its turn is not queued again every window
			s.mu.Unlock()
		}
	}
	w := windowStart
	s.owedQueued.Store(&w)
	return nil
}
