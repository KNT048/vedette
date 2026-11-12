package logs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// MaxAroundKinds is the most kinds of line EventsAround returns, and MaxAroundHits the most connections to listed destinations.
const (
	MaxAroundKinds = 20
	MaxAroundHits  = 20
)

// ErrBadRange is returned by EventsAround for a range that ends before it starts or is longer than CountsMaxWindow.
var ErrBadRange = errors.New("logs: the range must start before it ends and be at most 24 hours long")

// AroundKind is a kind of line that named an address, and how many lines of it a source received in the range.
type AroundKind struct {
	SourceName string
	Signature  string // the text the digest shows; "(other)" for lines past the quota of a source
	Count      int
}

// Around is what the logs counted about one address in a range (the read port of ai's events_around tool, D-223): the kinds of line
// whose remote address it was, with their counts, and the connections to listed destinations it made or received. Never a log line
// (INV-11): signatures and counts only, like the digest.
type Around struct {
	Kinds       []AroundKind // most first, at most MaxAroundKinds
	Lines       int          // every line counted for the address in the range, including kinds past MaxAroundKinds
	Connections []IocHit     // newest first, at most MaxAroundHits; empty while the feeds module is off (PRE-3)
}

// aroundSQL is what EventsAround runs: the address counters of a range of buckets (the primary key starts with the bucket).
const aroundSQL = `SELECT source_id, sig_hash, sum(count) FROM logs_signature_addrs WHERE bucket BETWEEN ?1 AND ?2 AND addr = ?3 GROUP BY source_id, sig_hash`

// EventsAround returns what the logs counted about addr from from to to. The counters are 5 minutes wide and kept 24 hours (the
// range is rounded out to whole buckets; a range older than that is simply empty). The address is the remote peer of the line, as for
// TopAddresses, and the box itself, its gateway and a honeypot decoy are never counted (Config.NeverCount). A range that ends before it
// starts or is longer than 24 hours is ErrBadRange.
func (s *Service) EventsAround(ctx context.Context, addr netip.Addr, from, to time.Time) (Around, error) {
	if to.Before(from) || to.Sub(from) > CountsMaxWindow {
		return Around{}, ErrBadRange
	}
	addr = addr.Unmap()
	out := Around{Kinds: []AroundKind{}, Connections: []IocHit{}}
	if s.cfg.Feeds == nil || s.cfg.Feeds.On() {
		var err error
		ip := addr.String()
		if out.Connections, err = s.iocHits(ctx, `(src_ip = ? OR dest = ?) AND ts >= ? AND ts <= ?`, MaxAroundHits, ip, ip, store.FormatTS(from), store.FormatTS(to)); err != nil {
			return Around{}, err
		}
	}
	if s.neverCounted(ctx)(addr) {
		return out, nil
	}
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, aroundSQL, from.Unix()/bucketSeconds, to.Unix()/bucketSeconds, addr.AsSlice())
	if err != nil {
		return Around{}, fmt.Errorf("logs: reading the lines of an address: %w", err)
	}
	type key struct {
		source string
		hash   int64
	}
	counts := map[key]int{}
	for rows.Next() {
		var k key
		var n int
		if err := rows.Scan(&k.source, &k.hash, &n); err != nil {
			_ = rows.Close()
			return Around{}, fmt.Errorf("logs: reading the lines of an address: %w", err)
		}
		counts[k] = n
		out.Lines += n
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return Around{}, fmt.Errorf("logs: reading the lines of an address: %w", err)
	}
	if len(counts) == 0 {
		return out, nil
	}
	// The counters keep a hash of the signature: its text is in the daily rows of the same source and days.
	names, loaded := map[key]string{}, map[string]bool{}
	for k := range counts {
		if loaded[k.source] {
			continue
		}
		loaded[k.source] = true
		texts, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT signature FROM logs_signature_daily WHERE source_id = ? AND day BETWEEN ? AND ?`,
			k.source, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"))
		if err != nil {
			return Around{}, fmt.Errorf("logs: reading signatures: %w", err)
		}
		for texts.Next() {
			var sig string
			if err := texts.Scan(&sig); err != nil {
				_ = texts.Close()
				return Around{}, fmt.Errorf("logs: reading signatures: %w", err)
			}
			names[key{k.source, sigHash(sig)}] = sig
		}
		_ = texts.Close()
		if err := texts.Err(); err != nil {
			return Around{}, fmt.Errorf("logs: reading signatures: %w", err)
		}
	}
	srcs, err := s.loadSources(ctx)
	if err != nil {
		return Around{}, err
	}
	srcName := map[string]string{}
	for _, r := range srcs {
		srcName[r.ID] = r.Name
	}
	for k, n := range counts {
		sig, ok := names[k]
		if !ok {
			sig = OtherSignature
		}
		out.Kinds = append(out.Kinds, AroundKind{SourceName: srcName[k.source], Signature: sig, Count: n})
	}
	slices.SortFunc(out.Kinds, func(a, b AroundKind) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.SourceName, b.SourceName), cmp.Compare(a.Signature, b.Signature))
	})
	if len(out.Kinds) > MaxAroundKinds {
		out.Kinds = out.Kinds[:MaxAroundKinds]
	}
	return out, nil
}
