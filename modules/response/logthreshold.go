package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// logPollEvery is how often PollLogs asks the Logs module; its counters are 5-minute buckets, so once a minute is plenty.
// logBucket is the width of those buckets: a count covers its window and up to one bucket before it (logs.Counts).
const (
	logPollEvery = time.Minute
	logBucket    = 5 * time.Minute
)

// firedLately reports whether an event of this (source, signature, window, threshold) key was recorded after since: the lines
// that made it still count, so a second event would be the same burst again.
func (s *Service) firedLately(ctx context.Context, key string, since time.Time) (bool, error) {
	var n int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM resp_events WHERE trigger = 'log_threshold' AND substr(id, 1, ?) = ? AND ts > ?`, len(key), key, store2(since)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("response: read the log events: %w", err)
	}
	return n > 0, nil
}

// PollLogs makes the events of the log_threshold trigger (#332, D-287): for every enabled rule of that trigger, it asks each
// declared log source how many lines of the rule's signature arrived in the rule's window, and records one event per (source,
// signature, window, threshold) when the count reached the threshold, and not again while the lines of that burst still count
// (its window and one 5-minute bucket). The event names the log source; the
// address the lines are about is not known (the counts are per source, #338), so source_ip is empty. The evaluate job calls it
// before Evaluate; the Logs module off (or not wired) means no event, never an error.
func (s *Service) PollLogs(ctx context.Context) error {
	if s.cfg.LogCounts == nil {
		return nil
	}
	now := s.now()
	if !s.logPolledAt.IsZero() && now.Sub(s.logPolledAt) < logPollEvery {
		return nil
	}
	rules, err := s.Rules(ctx)
	if err != nil {
		return err
	}
	type want struct {
		sig       string
		n, window int
	}
	var wants []want
	for _, r := range rules {
		if !r.Enabled || r.Trigger != "log_threshold" {
			continue
		}
		for _, c := range r.Conditions {
			if logSignature(r.Trigger, c) && c.N != nil && c.WindowMin != nil {
				wants = append(wants, want{c.Value, *c.N, *c.WindowMin})
			}
		}
	}
	if len(wants) == 0 {
		return nil
	}
	srcs, err := s.cfg.LogCounts.Sources(ctx)
	if err != nil { // the Logs module off answers no source and no error; an error is a real failure, said once a minute
		s.logPolledAt = now
		s.cfg.Log.WarnContext(ctx, "response: the log sources could not be read; log_threshold rules see no count this round", "error", err)
		return nil
	}
	if len(srcs) == 0 { // none declared or the Logs module off: asked again next tick, so the counts start as soon as there are some
		return nil
	}
	s.logPolledAt = now
	for _, w := range wants {
		win := time.Duration(w.window) * time.Minute
		sum := sha256.Sum256([]byte(w.sig))
		for _, src := range srcs {
			key := fmt.Sprintf("log:%s:%s:%d:%d:", oneLine(src.ID, 64), hex.EncodeToString(sum[:8]), w.window, w.n)
			if quiet, err := s.firedLately(ctx, key, now.Add(-win-logBucket)); err != nil || quiet {
				if err != nil {
					return err
				}
				continue // the same burst is still in the counted window: one event per burst, not one per period
			}
			n, err := s.cfg.LogCounts.Counts(ctx, src.ID, w.sig, win)
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "response: a log count failed", "source", src.ID, "error", err)
				continue
			}
			if n < w.n {
				continue
			}
			name := oneLine(src.Name, 100)
			d := Det{ID: key + strconv.FormatInt(now.Unix(), 10), Trigger: "log_threshold", TS: s.ts(),
				Summary: oneLine(fmt.Sprintf("%d lines of %q from %s in %d minutes (at least %d)", n, w.sig, name, w.window, w.n), 300),
				Fields:  map[string]string{"source_device": name, "source_ip": "", "signature": w.sig, "count": itoa(n), "window": itoa(w.window), "threshold": itoa(w.n)}}
			if err := s.StoreEvent(ctx, d); err != nil {
				return err
			}
		}
	}
	return nil
}
