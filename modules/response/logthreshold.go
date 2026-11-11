package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// logPollEvery is how often PollLogs asks the Logs module; its counters are 5-minute buckets, so once a minute is plenty.
const logPollEvery = time.Minute

// PollLogs makes the events of the log_threshold trigger (#332, D-287): for every enabled rule of that trigger, it asks each
// declared log source how many lines of the rule's signature arrived in the rule's window, and records one event per (source,
// signature, window, threshold) and per window when the count reached the threshold. The event names the log source; the
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
	if err != nil { // the Logs module off: asked again next tick, so the counts start as soon as it is on
		s.cfg.Log.DebugContext(ctx, "response: no log counts this round", "error", err)
		return nil
	}
	s.logPolledAt = now
	for _, w := range wants {
		win := time.Duration(w.window) * time.Minute
		sum := sha256.Sum256([]byte(w.sig))
		period := now.Unix() / int64(win.Seconds())
		for _, src := range srcs {
			n, err := s.cfg.LogCounts.Counts(ctx, src.ID, w.sig, win)
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "response: a log count failed", "source", src.ID, "error", err)
				continue
			}
			if n < w.n {
				continue
			}
			name := oneLine(src.Name, 100)
			d := Det{ID: fmt.Sprintf("log:%s:%s:%d:%d:%d", oneLine(src.ID, 64), hex.EncodeToString(sum[:8]), w.window, w.n, period), Trigger: "log_threshold", TS: s.ts(),
				Summary: oneLine(fmt.Sprintf("%d lines of %q from %s in %d minutes (at least %d)", n, w.sig, name, w.window, w.n), 300),
				Fields:  map[string]string{"source_device": name, "source_ip": "", "signature": w.sig, "count": itoa(n), "window": itoa(w.window), "threshold": itoa(w.n)}}
			if err := s.StoreEvent(ctx, d); err != nil {
				return err
			}
		}
	}
	return nil
}
