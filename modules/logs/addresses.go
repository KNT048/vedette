package logs

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Limits of the address counters (D-210; INV-1: the address a line names is as untrusted as the line).
const (
	// MaxAddrsPerSignature is how many addresses one signature of one source keeps in one 5-minute bucket; MaxAddrRowsPerBucket is how many
	// address rows one source keeps in one bucket, over every signature. An address past them is replaced by a better one (see
	// storeAddrs) or not stored. ponytail: two constants; the bytes this can take are measured in TestMeasureCeilings and written in CONTRACT.
	MaxAddrsPerSignature = 50
	MaxAddrRowsPerBucket = 500
	// MaxTopAddresses is the most addresses TopAddresses returns; a larger n is cut to it.
	MaxTopAddresses = 50
	// neverCountTTL is how long the set of addresses that are never counted is used before it is asked for again.
	neverCountTTL = 30 * time.Second
	// neverCountTimeout bounds one ask of the port.
	neverCountTimeout = 2 * time.Second
)

// ErrBadCount is returned by TopAddresses for an n under 1.
var ErrBadCount = errors.New("logs: n must be at least 1")

// AddressCount is an address and how many lines of a signature it sent.
type AddressCount struct {
	Addr  netip.Addr
	Count int
}

// neverSet is the addresses that are never counted (the box, its gateway, the honeypot's decoys): what Config.NeverCount said.
type neverSet struct {
	at      time.Time
	addr    map[netip.Addr]struct{}
	failing bool // the last ask failed
}

// neverCounted returns the test of "this address is the box" for a batch: the port is asked at most every neverCountTTL (a failed ask keeps
// the set that was there, and uses what it returned only while there is none: the box does not change address because a read failed).
func (s *Service) neverCounted(ctx context.Context) func(netip.Addr) bool {
	if s.cfg.NeverCount == nil {
		return func(netip.Addr) bool { return false }
	}
	s.neverMu.Lock()
	defer s.neverMu.Unlock()
	now := s.now()
	if s.never.addr == nil || now.Sub(s.never.at) >= neverCountTTL || now.Before(s.never.at) {
		cctx, cancel := context.WithTimeout(ctx, neverCountTimeout)
		list, err := s.cfg.NeverCount(cctx)
		cancel()
		if err != nil && !s.never.failing { // said once for a run of failures, not every 30 seconds
			s.cfg.Log.WarnContext(ctx, "logs: the addresses of the box are not known; the last set is used", "error", err)
		}
		s.never.failing = err != nil
		if err == nil || s.never.addr == nil {
			set := make(map[netip.Addr]struct{}, len(list))
			for _, a := range list {
				if a.IsValid() {
					set[a.Unmap().WithZone("")] = struct{}{}
				}
			}
			s.never.addr = set
		}
		s.never.at = now
	}
	set := s.never.addr
	return func(a netip.Addr) bool { _, ok := set[a]; return ok }
}

// addrGroup is one signature of one source in one bucket: the addresses a batch saw.
type addrGroup = map[netip.Addr]int

const (
	selectAddrBucket = `SELECT sig_hash, addr, count FROM logs_signature_addrs WHERE bucket = ?1 AND source_id = ?2`
	bumpAddr         = `UPDATE logs_signature_addrs SET count = count + ?5 WHERE bucket = ?1 AND source_id = ?2 AND sig_hash = ?3 AND addr = ?4`
	insertAddr       = `INSERT INTO logs_signature_addrs (bucket, source_id, sig_hash, addr, count) VALUES (?1, ?2, ?3, ?4, ?5)`
	deleteAddr       = `DELETE FROM logs_signature_addrs WHERE bucket = ?1 AND source_id = ?2 AND sig_hash = ?3 AND addr = ?4`
	// topAddrsSQL is what TopAddresses runs: one source, one signature (by hash), the buckets of the window: the index logs_signature_addrs_source.
	topAddrsSQL = `SELECT addr, sum(count) FROM logs_signature_addrs WHERE source_id = ?1 AND sig_hash = ?2 AND bucket >= ?3 GROUP BY addr`
)

type addrRow struct {
	addr  netip.Addr
	count int
}

// addrBucket is the rows of one source in one bucket (at most MaxAddrRowsPerBucket), by signature hash: read once per batch and followed here.
type addrBucket struct {
	bySig map[int64][]addrRow
	total int
}

// least is the row with the fewest lines in the bucket (ties: the smallest signature hash, then the smallest address: the same every time).
func (b *addrBucket) least() (sig int64, row addrRow, ok bool) {
	for h, rows := range b.bySig {
		for _, r := range rows {
			if !ok || r.count < row.count || r.count == row.count && (h < sig || h == sig && r.addr.Compare(row.addr) < 0) {
				sig, row, ok = h, r, true
			}
		}
	}
	return sig, row, ok
}

// storeAddrs adds the addresses of a batch to the address counters inside the transaction of the batch. Per source and bucket the
// table holds at most MaxAddrsPerSignature rows of a signature and MaxAddrRowsPerBucket rows in all. An address already in a table
// is counted up. A new one is inserted when there is room; at a quota it takes the place of the row with the fewest lines when it has
// more lines in this batch than that row has (the quota of the signature looks at the rows of the signature, the quota of the bucket at
// all of them), and is otherwise not stored. A row is therefore a lower bound of what the address sent (an address that was pushed out and
// came back starts again), never more: nothing is invented to fill a row, so a one-line spoof can never look like an attacker. Groups
// are handled in key order, so that the same input gives the same table.
func (s *Service) storeAddrs(ctx context.Context, tx *sql.Tx, groups map[bucketKey]addrGroup) error {
	keys := make([]bucketKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b bucketKey) int {
		return cmp.Or(cmp.Compare(a.source, b.source), cmp.Compare(a.bucket, b.bucket), cmp.Compare(a.signature, b.signature))
	})
	loaded := map[[2]string]*addrBucket{}
	for _, k := range keys {
		sb, err := s.loadAddrBucket(ctx, tx, loaded, k.source, k.bucket)
		if err != nil {
			return err
		}
		h := sigHash(k.signature)
		have := sb.bySig[h]
		var fresh []addrRow
		for a, n := range groups[k] {
			if i := slices.IndexFunc(have, func(r addrRow) bool { return r.addr == a }); i >= 0 {
				if _, err := tx.ExecContext(ctx, bumpAddr, k.bucket, k.source, h, a.AsSlice(), n); err != nil {
					return fmt.Errorf("logs: counting an address: %w", err)
				}
				have[i].count += n
				continue
			}
			fresh = append(fresh, addrRow{a, n})
		}
		slices.SortFunc(fresh, func(a, b addrRow) int { return cmp.Or(cmp.Compare(b.count, a.count), a.addr.Compare(b.addr)) })
		for _, c := range fresh {
			switch {
			case len(have) < MaxAddrsPerSignature && sb.total < MaxAddrRowsPerBucket:
			case len(have) >= MaxAddrsPerSignature: // the signature is full: the least counted row of the signature may go
				i := leastOf(have)
				if c.count <= have[i].count {
					continue
				}
				if _, err := tx.ExecContext(ctx, deleteAddr, k.bucket, k.source, h, have[i].addr.AsSlice()); err != nil {
					return fmt.Errorf("logs: replacing an address: %w", err)
				}
				have = slices.Delete(have, i, i+1)
				sb.total--
			default: // the bucket is full: the least counted row of the source and bucket may go
				sig := sb.bySig[h]
				sb.bySig[h] = have // the victim may be a row of this signature: it must be looked for in what is current
				vh, v, ok := sb.least()
				if !ok || c.count <= v.count {
					sb.bySig[h] = sig
					continue
				}
				if _, err := tx.ExecContext(ctx, deleteAddr, k.bucket, k.source, vh, v.addr.AsSlice()); err != nil {
					return fmt.Errorf("logs: replacing an address: %w", err)
				}
				sb.bySig[vh] = slices.DeleteFunc(sb.bySig[vh], func(r addrRow) bool { return r.addr == v.addr })
				if vh == h {
					have = sb.bySig[h]
				}
				sb.total--
			}
			if _, err := tx.ExecContext(ctx, insertAddr, k.bucket, k.source, h, c.addr.AsSlice(), c.count); err != nil {
				return fmt.Errorf("logs: counting an address: %w", err)
			}
			have = append(have, c)
			sb.total++
		}
		sb.bySig[h] = have
	}
	return nil
}

// loadAddrBucket reads the rows of one source in one bucket once per batch (a query for the whole bucket and not one per signature: a device
// that makes a new signature in every line would otherwise cost a query per line).
func (s *Service) loadAddrBucket(ctx context.Context, tx *sql.Tx, loaded map[[2]string]*addrBucket, source string, bucket int64) (*addrBucket, error) {
	key := [2]string{source, fmt.Sprint(bucket)}
	if sb := loaded[key]; sb != nil {
		return sb, nil
	}
	rows, err := tx.QueryContext(ctx, selectAddrBucket, bucket, source)
	if err != nil {
		return nil, fmt.Errorf("logs: reading address rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	sb := &addrBucket{bySig: map[int64][]addrRow{}}
	for rows.Next() {
		var h int64
		var raw []byte
		var n int
		if err := rows.Scan(&h, &raw, &n); err != nil {
			return nil, fmt.Errorf("logs: reading address rows: %w", err)
		}
		if a, ok := netip.AddrFromSlice(raw); ok {
			sb.bySig[h] = append(sb.bySig[h], addrRow{a, n})
			sb.total++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("logs: reading address rows: %w", err)
	}
	loaded[key] = sb
	return sb, nil
}

// leastOf is the index of the row with the fewest lines (ties: the smallest address).
func leastOf(rows []addrRow) int {
	best := 0
	for i, r := range rows {
		if r.count < rows[best].count || r.count == rows[best].count && r.addr.Compare(rows[best].addr) < 0 {
			best = i
		}
	}
	return best
}

// TopAddresses is the read port of response's log_threshold for the question "which address": the n remote addresses that sent the most
// lines of one signature from one source in the last window, most first (ties by address, so the answer is the same every time). The
// address is the remote peer the line is about (the client of a failed login, the source of a blocked connection), never the device
// that sent the log, and never the box itself, its gateway or a honeypot decoy (Config.NeverCount); a private LAN address does count.
// source and signature are as for Counts, and so is the window (5 minutes to 24 hours, rounded out to whole buckets: ErrBadWindow
// otherwise). n under 1 is ErrBadCount, and n over MaxTopAddresses is MaxTopAddresses. Counts are lower bounds when the quotas were reached (see
// storeAddrs): an address is never counted for lines it did not send, and one beyond a quota may be missing. A signature never seen,
// or one whose lines name no address, is an empty list, not an error.
func (s *Service) TopAddresses(ctx context.Context, source, signature string, window time.Duration, n int) ([]AddressCount, error) {
	if window < CountsMinWindow || window > CountsMaxWindow {
		return nil, ErrBadWindow
	}
	if n < 1 {
		return nil, ErrBadCount
	}
	n = min(n, MaxTopAddresses)
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, topAddrsSQL, source, sigHash(signature), s.now().Add(-window).Unix()/bucketSeconds)
	if err != nil {
		return nil, fmt.Errorf("logs: reading addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AddressCount
	for rows.Next() {
		var raw []byte
		var c int
		if err := rows.Scan(&raw, &c); err != nil {
			return nil, fmt.Errorf("logs: reading addresses: %w", err)
		}
		if a, ok := netip.AddrFromSlice(raw); ok {
			out = append(out, AddressCount{a, c})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("logs: reading addresses: %w", err)
	}
	slices.SortFunc(out, func(a, b AddressCount) int { return cmp.Or(cmp.Compare(b.Count, a.Count), a.Addr.Compare(b.Addr)) })
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}
