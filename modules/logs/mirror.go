package logs

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"github.com/knt048/vedette/modules/logs/signature"
)

// Mirror-port matching (S-LOG-4, SPAN half; INV-2, FORBID-1): the passive sensor reads, on a mirror port, which LAN device asked for
// which name (a DNS query, the server name of a TLS connection, the host of a web request) or had a flow to which address, and core
// hands that to MatchMirror. Every destination is looked up in the threat feeds exactly as a firewall line's is (matchIOC: the same
// cache, the same subdomain rule, the same dedupe and the same events); only the matches are stored, in logs_ioc_hits with seen_via
// span_dns, span_sni, span_http or span_flow. The metadata itself is never stored: no name, flow or count that matches nothing is
// kept anywhere, and no line is added to the log.

// MirrorItem is one piece of mirror-port metadata: Kind is "dns", "sni", "http" (Dest is a name) or "flow" (Dest is an address).
type MirrorItem struct {
	Kind string
	At   time.Time
	Src  netip.Addr
	Dest string
}

// MaxMirrorBatch is the most items one MatchMirror call takes (the sensor protocol's MaxMetadataItems).
const MaxMirrorBatch = 1000

// MirrorSourceID is the source_id of a hit seen on the mirror port: not a log source (the column holds the id of a source whose line
// it was, and a mirror hit has none), and of the shape the column takes.
const MirrorSourceID = "span"

// mirrorSeenBack is how old a mirror item's time may be; an older one, or one in the future, is dated now (the sensor delivers
// within minutes, so such a time is a wrong clock).
const mirrorSeenBack = time.Hour

// mirrorVia is the seen_via of each kind of item.
var mirrorVia = map[string]string{"dns": "span_dns", "sni": "span_sni", "http": "span_http", "flow": "span_flow"}

// ErrMirrorIncomplete is returned by MatchMirror when part of the batch was not looked at (a feed lookup failed, or the batch
// reached MaxIocHitsPerBatch new hits): the hits found are stored, and the caller should send the batch again.
var ErrMirrorIncomplete = errors.New("logs: part of the mirror batch was not matched; send it again")

// ErrMirrorBatchTooLarge is returned by MatchMirror for more than MaxMirrorBatch items.
var ErrMirrorBatchTooLarge = errors.New("logs: mirror batch has more than the allowed number of items")

// MatchMirror matches a batch of mirror-port metadata against the threat feeds and stores the hits (one per device and listed
// destination a day, as for a firewall line), then announces the new ones. Items it cannot use are skipped one by one: an unknown
// kind, a source that is not a LAN address or is the box, its gateway or a decoy (NeverCount), a destination that no feed can list
// (a private or reserved address, a name of a bad shape). It fails when the hits cannot be stored, and with ErrMirrorIncomplete
// when part of the batch could not be looked at.
func (s *Service) MatchMirror(ctx context.Context, items []MirrorItem) error {
	if len(items) > MaxMirrorBatch {
		return ErrMirrorBatchTooLarge
	}
	if s.cfg.Feeds == nil || len(items) == 0 {
		return nil
	}
	never := s.neverCounted(ctx)
	now := s.ts()
	conns := map[connKey]connObs{}
	for _, it := range items {
		via, ok := mirrorVia[it.Kind]
		src := it.Src.Unmap()
		if !ok || !signature.LocalOK(src) || never(src) {
			continue
		}
		var kind, dest string
		if it.Kind == "flow" {
			a, err := netip.ParseAddr(it.Dest)
			if err != nil || !signature.PublicDest(a.Unmap()) {
				continue
			}
			kind, dest = signature.KindIP, a.Unmap().String()
		} else {
			if dest, ok = signature.CleanDomain(it.Dest); !ok {
				continue
			}
			kind = signature.KindDomain
		}
		at := it.At.UTC().Truncate(time.Millisecond)
		if at.IsZero() || at.After(now) || at.Before(now.Add(-mirrorSeenBack)) {
			at = now
		}
		k := connKey{src, kind, dest}
		if o, seen := conns[k]; !seen || at.Before(o.at) {
			conns[k] = connObs{source: MirrorSourceID, at: at, via: via}
		}
	}
	hits, complete := s.matchIOC(ctx, conns, nil) // before the transaction: the writer is not held while the feeds are read
	if len(hits) > 0 {
		var fresh []iocRow
		if err := s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
			fresh = fresh[:0]
			return s.storeIOC(ctx, tx, hits, &fresh)
		}); err != nil {
			return err
		}
		s.announceIOC(ctx, fresh)
	}
	if !complete {
		// The hits found so far are stored; the batch comes again and the stored pairs are skipped as repeats, so the rest is
		// looked at then.
		return ErrMirrorIncomplete
	}
	return nil
}
