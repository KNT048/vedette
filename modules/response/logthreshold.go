package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// logPollEvery is how often PollLogs asks the Logs module; its counters are 5-minute buckets, so once a minute is plenty.
// logBucket is the width of those buckets: a count covers its window and up to one bucket before it (logs.Counts).
// logTopAddrs is how many addresses one (rule, source) asks for: logs.MaxTopAddresses, the most it answers.
const (
	logPollEvery = time.Minute
	logBucket    = 5 * time.Minute
	logTopAddrs  = 50
)

// firedLately reports whether an event of this (source, signature, window, threshold) key was recorded after since: the lines
// that made it still count, so a second event would be the same burst again. ponytail: resp_events keeps the newest 500
// processed events of a trigger, so more than 500 keys firing within one window could trim a suppressing event and fire once
// more; upgrade path: keep the last fire time per key in a table of its own.
func (s *Service) firedLately(ctx context.Context, key string, since time.Time) (bool, error) {
	var n int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM resp_events WHERE trigger = 'log_threshold' AND substr(id, 1, ?) = ? AND ts > ?`, len(key), key, store2(since)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("response: read the log events: %w", err)
	}
	return n > 0, nil
}

// PollLogs makes the events of the log_threshold trigger (#332, D-287, D-288): for every enabled rule of that trigger, it asks
// each declared log source how many lines of the rule's signature arrived in the rule's window. When the count reached the
// threshold it asks which remote addresses sent them (logs.TopAddresses): every address that alone sent at least N lines is an
// event of its own with source_ip, so a ban rule bans each attacker and never an address for the lines of others; when none
// did (the lines are spread over many addresses, or name none) the event names the log source only, with source_ip empty.
// Each (source, signature, window, threshold, address or none) makes one event per burst: not again while the lines of that
// burst still count (its window and one 5-minute bucket). The evaluate job calls it before Evaluate; the Logs module off (or
// not wired) means no event, never an error.
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
	s.logPolledAt = now // also with no source (none declared, or the Logs module off), once a minute
	for _, w := range wants {
		win := time.Duration(w.window) * time.Minute
		sum := sha256.Sum256([]byte(w.sig))
		for _, src := range srcs {
			n, err := s.cfg.LogCounts.Counts(ctx, src.ID, w.sig, win)
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "response: a log count failed", "source", src.ID, "error", err)
				continue
			}
			if n < w.n {
				continue
			}
			// The key ends in "<address>/" ("/" alone for the source): never a prefix of another address's key (2001:db8::1 and
			// 2001:db8::1:5), and the source's key never a prefix of an address's.
			key := fmt.Sprintf("log:%s:%s:%d:%d:", oneLine(src.ID, 64), hex.EncodeToString(sum[:8]), w.window, w.n)
			name := oneLine(src.Name, 100)
			hits := s.logAddresses(ctx, src.ID, w.sig, win, w.n)
			if len(hits) == 0 {
				hits = []logHit{{count: n}} // no single address reached N: the source's own event, no address
			}
			for _, h := range hits {
				ip, from := "", name
				if h.addr.IsValid() {
					ip, from = h.addr.String(), h.addr.String()+" via "+name
				}
				k := key + ip + "/"
				quiet, err := s.firedLately(ctx, k, now.Add(-win-logBucket))
				if err != nil {
					return err
				}
				if quiet {
					continue // the same burst is still in the counted window: one event per burst, not one per period
				}
				d := Det{ID: k + strconv.FormatInt(now.Unix(), 10), Trigger: "log_threshold", TS: s.ts(),
					Summary: oneLine(fmt.Sprintf("%d lines of %q from %s in %d minutes (at least %d)", h.count, w.sig, from, w.window, w.n), 300),
					Fields:  map[string]string{"source_device": name, "source_ip": ip, "signature": w.sig, "count": itoa(h.count), "window": itoa(w.window), "threshold": itoa(w.n)}}
				if err := s.StoreEvent(ctx, d); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// logHit is one event of a count that reached its threshold: the address that sent the lines, or none for the source's own.
type logHit struct {
	addr  netip.Addr
	count int
}

// logAddresses returns the remote addresses that alone sent at least n lines of the signature in the window, as single
// addresses (IPv4-mapped as IPv4, like the honeypot's source; one with a zone, or not valid, is never an address to act on).
// The addresses could not be read: none, with a warning, so the count still makes the source's event.
func (s *Service) logAddresses(ctx context.Context, source, signature string, window time.Duration, n int) []logHit {
	top, err := s.cfg.LogCounts.TopAddresses(ctx, source, signature, window, logTopAddrs)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "response: the addresses of a log count could not be read; the event names the log source only", "source", source, "error", err)
		return nil
	}
	var out []logHit
	for _, a := range top {
		if a.Count < n || !a.Addr.IsValid() || a.Addr.Zone() != "" {
			continue
		}
		out = append(out, logHit{a.Addr.Unmap(), a.Count})
	}
	return out
}
