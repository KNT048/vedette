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
	// MaxPendingAddrs is how many addresses that have no row yet (the quota was full, and they did not have more lines than the least counted
	// row) the service remembers the exact count of, in memory, for the buckets that are still open; past it the lowest counts go.
	MaxPendingAddrs = 4096
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
	known   bool // an ask has been answered without an error: the set is the whole box
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
	// Until a full answer has been had (the host has not answered, the decoy record could not be read) the port is asked again at every call:
	// the set is smaller than the box, and each lines of the box's address that are stored meanwhile are dropped again when read (TopAddresses).
	if !s.never.known || now.Sub(s.never.at) >= neverCountTTL || now.Before(s.never.at) {
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
		if err == nil {
			s.never.known = true
		}
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

// pendKey is an address of a signature of a source in a bucket that has no row.
type pendKey struct {
	source string
	bucket int64
	sig    int64
	addr   netip.Addr
}

// pendVal is the exact count of one no-row address and when it was last updated (seq of Service.pendSeq: a clock that needs no time).
type pendVal struct {
	n   int
	seq uint64
}

// pendGroup is the in-memory counts of one signature of one source: the unit of eviction.
type pendGroup struct {
	source string
	sig    int64
	keys   []pendKey
}

// pendingUpdate is what storeAddrs changes in the in-memory counts, applied only after the batch is stored (a transaction that is retried or
// rolled back must not count its lines twice, or at all): a count of 0 deletes the entry.
type pendingUpdate struct{ set map[pendKey]int }

// apply puts the update into the service's memory and keeps it small: buckets older than two before now go, and past MaxPendingAddrs
// entries go from the largest (source, signature) group first, in it the lowest count first and, among equal counts, the least recently
// updated (never by hash or address, which an attacker could choose). So a flood of one-line addresses of one signature only pushes out its
// own entries: a slow attacker on another signature keeps its exact counts (measured in TestPendingFloodStarvesOnlyItsSignature).
func (u *pendingUpdate) apply(s *Service) {
	if u == nil || len(u.set) == 0 {
		return
	}
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	if s.pend == nil {
		s.pend = map[pendKey]pendVal{}
	}
	keys := make([]pendKey, 0, len(u.set))
	for k := range u.set {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b pendKey) int { // the same order every time: a map's order is not one
		return cmp.Or(cmp.Compare(a.source, b.source), cmp.Compare(a.bucket, b.bucket), cmp.Compare(a.sig, b.sig), a.addr.Compare(b.addr))
	})
	for _, k := range keys {
		if n := u.set[k]; n == 0 {
			delete(s.pend, k)
		} else {
			s.pendSeq++
			s.pend[k] = pendVal{n, s.pendSeq}
		}
	}
	if len(s.pend) <= MaxPendingAddrs {
		return
	}
	oldest := s.now().Unix()/bucketSeconds - 2
	for k := range s.pend {
		if k.bucket < oldest {
			delete(s.pend, k)
		}
	}
	if len(s.pend) <= MaxPendingAddrs {
		return
	}
	type groupKey struct {
		source string
		sig    int64
	}
	byGroup := map[groupKey]*pendGroup{}
	for k := range s.pend {
		gk := groupKey{k.source, k.sig}
		g := byGroup[gk]
		if g == nil {
			g = &pendGroup{source: k.source, sig: k.sig}
			byGroup[gk] = g
		}
		g.keys = append(g.keys, k)
	}
	groups := make([]*pendGroup, 0, len(byGroup))
	for _, g := range byGroup {
		// the victim comes from the end: the highest count first inside the slice means the lowest is last
		slices.SortFunc(g.keys, func(a, b pendKey) int {
			x, y := s.pend[a], s.pend[b]
			return cmp.Or(cmp.Compare(y.n, x.n), cmp.Compare(y.seq, x.seq)) // last = lowest count, then least recently updated
		})
		groups = append(groups, g)
	}
	for len(s.pend) > MaxPendingAddrs {
		big := groups[0]
		for _, g := range groups[1:] {
			if len(g.keys) > len(big.keys) || len(g.keys) == len(big.keys) && cmp.Or(cmp.Compare(g.source, big.source), cmp.Compare(g.sig, big.sig)) < 0 {
				big = g
			}
		}
		last := len(big.keys) - 1
		delete(s.pend, big.keys[last])
		big.keys = big.keys[:last]
	}
}

func (s *Service) pendingOf(k pendKey) int {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	return s.pend[k].n
}

// storeAddrs adds the addresses of a batch to the address counters inside the transaction of the batch. Per source and bucket the
// table holds at most MaxAddrsPerSignature rows of a signature and MaxAddrRowsPerBucket rows in all. An address already in a table
// is counted up. A new one is inserted when there is room; at a quota it takes the place of the row with the fewest lines when it has
// more lines than that row has, and is otherwise not stored. "Its lines" are exact: the ones of this batch and the ones of the earlier
// batches of the same bucket that did not get a row, which the service remembers in memory (at most MaxPendingAddrs, the lowest counts go
// first; a restart loses the memory of one bucket at most). So an attacker that sends one line per batch behind a flood of one-line addresses
// gets its row at its second line, with the count it really sent; and a row is never above the lines its address sent (nothing is invented
// to fill a row), so a one-line spoof can never look like an attacker. Groups are handled in key order, so that the same input gives the
// same table. commit gets the new in-memory counts: the caller applies them when the batch is stored.
func (s *Service) storeAddrs(ctx context.Context, tx *sql.Tx, groups map[bucketKey]addrGroup, commit *pendingUpdate) error {
	commit.set = map[pendKey]int{}
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
		pk := func(a netip.Addr) pendKey { return pendKey{k.source, k.bucket, h, a} }
		for a, n := range groups[k] {
			if i := slices.IndexFunc(have, func(r addrRow) bool { return r.addr == a }); i >= 0 {
				if _, err := tx.ExecContext(ctx, bumpAddr, k.bucket, k.source, h, a.AsSlice(), n); err != nil {
					return fmt.Errorf("logs: counting an address: %w", err)
				}
				have[i].count += n
				continue
			}
			fresh = append(fresh, addrRow{a, n + s.pendingOf(pk(a))})
		}
		slices.SortFunc(fresh, func(a, b addrRow) int { return cmp.Or(cmp.Compare(b.count, a.count), a.addr.Compare(b.addr)) })
		for _, c := range fresh {
			switch {
			case len(have) < MaxAddrsPerSignature && sb.total < MaxAddrRowsPerBucket:
			case len(have) >= MaxAddrsPerSignature: // the signature is full: the least counted row of the signature may go
				i := leastOf(have)
				if c.count <= have[i].count {
					commit.set[pk(c.addr)] = c.count
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
					commit.set[pk(c.addr)] = c.count
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
			commit.set[pk(c.addr)] = 0 // it has a row now
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
// that sent the log, and never the box itself, its gateway or a honeypot decoy (Config.NeverCount, applied again when reading: a line stored before the box's address was known is not returned once it is); a private LAN address does count.
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
	never := s.neverCounted(ctx) // asked now: lines stored before the box's address was known (a host that had not answered) are not returned
	var out []AddressCount
	for rows.Next() {
		var raw []byte
		var c int
		if err := rows.Scan(&raw, &c); err != nil {
			return nil, fmt.Errorf("logs: reading addresses: %w", err)
		}
		if a, ok := netip.AddrFromSlice(raw); ok && !never(a) {
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
