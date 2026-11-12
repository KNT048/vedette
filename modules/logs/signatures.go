package logs

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/logs/signature"
)

// Limits of the signature counters (INV-1: a device is an untrusted source, so what it can add to the tables is bounded).
const (
	// MaxMinedPerDay and MaxBoundedPerDay are how many signature rows one source can have in a UTC day, for the signatures that the
	// miner or a free-text profile makes and for the signatures that a vocabulary of shipped data bounds (a known log id, a known event
	// id): separate quotas, so that a flood of the first cannot push the second out. The lines past a quota are counted under
	// OtherSignature. ponytail: 1,000 and 2,000, one constant each; a real device has tens to hundreds of kinds of line, and the
	// vocabularies make at most 540. The bytes this can take are measured in TestMeasureCeilings and written in D-206.
	MaxMinedPerDay   = 1000
	MaxBoundedPerDay = 2000
	// MaxMinedPerBucket and MaxBoundedPerBucket are the same for one 5-minute bucket of the counters that Counts reads. 600 is at least
	// the largest bounded vocabulary (FortiGate: 20 log ids x (26 actions + none) = 540), so every bounded signature has its own row.
	MaxMinedPerBucket   = 200
	MaxBoundedPerBucket = 600
	// OtherSignature is where the lines past the caps are counted.
	OtherSignature = "(other)"
	// MaxSignatureLen and MaxDestLen are the longest signature and destination a row holds (the signature package's limits).
	MaxSignatureLen = signature.MaxSignatureBytes
	MaxDestLen      = signature.MaxDestBytes
	// MaxSampleBytes is how much of the first line of a row is kept as its sample.
	MaxSampleBytes = 300
	// CountsMinWindow and CountsMaxWindow bound what Counts answers (the counters are 5 minutes wide and kept 24 hours and one bucket).
	CountsMinWindow = 5 * time.Minute
	CountsMaxWindow = 24 * time.Hour
)

// ErrBadWindow is returned by Counts for a window outside CountsMinWindow..CountsMaxWindow.
var ErrBadWindow = errors.New("logs: the window must be between 5 minutes and 24 hours")

type dailyKey struct{ day, source, signature string }

type dailyVal struct {
	n      int
	first  time.Time
	sample string
	dest   string // of the latest line
	mined  bool
}

type bucketKey struct {
	source    string
	bucket    int64
	signature string
}

type bucketVal struct {
	n     int
	mined bool
}

// sigBatch is what one batch of lines adds to the counters: a flood of identical lines is one entry.
type sigBatch struct {
	daily  map[dailyKey]*dailyVal
	bucket map[bucketKey]*bucketVal
	addrs  map[bucketKey]addrGroup // the remote addresses of the lines, by the same key as bucket (D-210)
	commit *pendingUpdate          // what storeAddrs leaves in memory once the batch is stored
	conns  map[connKey]connObs     // the connections the lines are about (D-213), the first line of each
}

// tally turns a batch of sanitized lines (in receive order) into counter increments. kinds maps a declared source id to its device
// kind and senders to the address it sends from. never says whether an address is one that is never counted (the box, its gateway, a decoy). Pure: no database (the memo makes a
// flood of identical lines cost one signature, not one per line).
func (s *Service) tally(kinds map[string]string, senders map[string]netip.Addr, keep []Line, never func(netip.Addr) bool) sigBatch {
	type memoKey struct{ kind, text string }
	memo := map[memoKey]signature.Result{}
	b := sigBatch{daily: map[dailyKey]*dailyVal{}, bucket: map[bucketKey]*bucketVal{}, addrs: map[bucketKey]addrGroup{}, commit: &pendingUpdate{}, conns: map[connKey]connObs{}}
	for _, l := range keep {
		kind := kinds[l.SourceID]
		r, ok := memo[memoKey{kind, l.Text}]
		if !ok {
			r = s.sigs.Of(kind, l.Text)
			memo[memoKey{kind, l.Text}] = r
		}
		mined := !r.Bounded
		k := dailyKey{l.At.UTC().Format("2006-01-02"), l.SourceID, r.Signature}
		if v := b.daily[k]; v != nil {
			v.n++
			if l.At.Before(v.first) {
				v.first, v.sample = l.At, sampleOf(l.Text)
			}
			if r.Dest != "" {
				v.dest = r.Dest
			}
		} else {
			b.daily[k] = &dailyVal{n: 1, first: l.At, sample: sampleOf(l.Text), dest: r.Dest, mined: mined}
		}
		bk := bucketKey{l.SourceID, l.At.Unix() / bucketSeconds, r.Signature}
		if v := b.bucket[bk]; v != nil {
			v.n++
		} else {
			b.bucket[bk] = &bucketVal{n: 1, mined: mined}
		}
		if r.Remote.IsValid() && r.Remote != senders[l.SourceID] && !never(r.Remote) { // a line that names no address, the log sender or the box counts everywhere else but here
			g := b.addrs[bk]
			if g == nil {
				g = addrGroup{}
				b.addrs[bk] = g
			}
			g[r.Remote]++
		}
		if c := r.Conn; c.Local.IsValid() && !never(c.Local) { // the box, its gateway and a decoy are not a device that made a connection
			for _, d := range c.Dests {
				if k := (connKey{c.Local, d.Kind, d.Value}); b.conns[k].source == "" {
					b.conns[k] = connObs{l.SourceID, l.At}
				}
			}
		}
	}
	return b
}

func sampleOf(text string) string {
	if len(text) <= MaxSampleBytes {
		return text
	}
	n := MaxSampleBytes
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n]
}

// What one key costs: a key under its quota is one statement, INSERT ... ON CONFLICT DO UPDATE, whose RETURNING says whether the row is
// new (count equal to the added count: 1) or was counted up (0). The number of rows of a class (mined or profile) of a day and source is
// read once per batch, then followed in memory; at the quota a key is only counted up when its row exists (UPDATE), and otherwise
// the lines go to OtherSignature.
const (
	upsertDaily = `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample, mined) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
		ON CONFLICT (day, source_id, signature) DO UPDATE SET count = count + excluded.count, first_seen = min(first_seen, excluded.first_seen),
		    dest = CASE WHEN excluded.dest <> '' THEN excluded.dest ELSE dest END
		RETURNING count = ?5`
	updateDaily = `UPDATE logs_signature_daily SET count = count + ?4, first_seen = min(first_seen, ?5),
		    dest = CASE WHEN ?6 <> '' THEN ?6 ELSE dest END
		WHERE day = ?1 AND source_id = ?2 AND signature = ?3`
	upsertOtherDaily = `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample, mined) VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, ?7)
		ON CONFLICT (day, source_id, signature) DO UPDATE SET count = count + excluded.count, first_seen = min(first_seen, excluded.first_seen)`
	rowsDaily = `SELECT count(*) FROM (SELECT 1 FROM logs_signature_daily WHERE day = ?1 AND source_id = ?2 AND mined = ?3 AND signature <> ?4 LIMIT ?5)`

	upsertBucket = `INSERT INTO logs_signature_buckets (source_id, bucket, sig_hash, count, mined) VALUES (?1, ?2, ?3, ?4, ?5)
		ON CONFLICT (bucket, source_id, sig_hash) DO UPDATE SET count = count + excluded.count
		RETURNING count = ?4`
	updateBucket      = `UPDATE logs_signature_buckets SET count = count + ?4 WHERE source_id = ?1 AND bucket = ?2 AND sig_hash = ?3`
	upsertOtherBucket = `INSERT INTO logs_signature_buckets (source_id, bucket, sig_hash, count, mined) VALUES (?1, ?2, ?3, ?4, ?5)
		ON CONFLICT (bucket, source_id, sig_hash) DO UPDATE SET count = count + excluded.count`
	rowsBucket = `SELECT count(*) FROM (SELECT 1 FROM logs_signature_buckets WHERE bucket = ?1 AND source_id = ?2 AND mined = ?3 AND sig_hash <> ?4 LIMIT ?5)`
	// countsSQL is what Counts runs: one source, one signature (by hash), the buckets of the window: the index logs_signature_buckets_source.
	countsSQL = `SELECT sum(count) FROM logs_signature_buckets WHERE source_id = ?1 AND sig_hash = ?2 AND bucket >= ?3`
	// blankSamplesSQL blanks the sample of a row whose first line is older than the retention; the day bounds it to a range of the key.
	blankSamplesSQL = `UPDATE logs_signature_daily SET sample = '' WHERE day <= ?1 AND first_seen < ?2 AND sample <> ''`
)

// sigHash is the first 64 bits of the SHA-256 of a signature: what the 5-minute counters store instead of its text.
func sigHash(sig string) int64 {
	sum := sha256.Sum256([]byte(sig))
	return int64(binary.BigEndian.Uint64(sum[:8])) //nolint:gosec // the bits are the hash: a negative number is as good a key as a positive one
}

func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}

// prepared prepares each statement of one transaction once. A batch runs the same few upserts for every signature and address in it, and
// parsing them again for each was most of the cost of an ingest (measured: 44% of the CPU of a batch of 2,100 new signatures).
type prepared struct {
	tx *sql.Tx
	m  map[string]*sql.Stmt
}

func newPrepared(tx *sql.Tx) *prepared { return &prepared{tx: tx, m: map[string]*sql.Stmt{}} }

func (p *prepared) stmt(ctx context.Context, q string) (*sql.Stmt, error) {
	if st, ok := p.m[q]; ok {
		return st, nil
	}
	st, err := p.tx.PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	p.m[q] = st
	return st, nil
}

func (p *prepared) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	st, err := p.stmt(ctx, q)
	if err != nil {
		return nil, err
	}
	return st.ExecContext(ctx, args...)
}

// row is QueryRowContext on the prepared statement; a statement that cannot be prepared is run unprepared, which returns its error at Scan.
func (p *prepared) row(ctx context.Context, q string, args ...any) *sql.Row {
	st, err := p.stmt(ctx, q)
	if err != nil {
		return p.tx.QueryRowContext(ctx, q, args...)
	}
	return st.QueryRowContext(ctx, args...)
}

func (p *prepared) close() {
	for _, st := range p.m {
		_ = st.Close()
	}
}

// storeSignatures adds a batch to the counters inside the transaction of the batch (the writer of logs.db, never the main one).
func (s *Service) storeSignatures(ctx context.Context, tx *sql.Tx, b sigBatch) error {
	ps := newPrepared(tx)
	defer ps.close()
	rows := map[[3]string]int{} // rows of a class of a day (or bucket) and source, read when first needed and followed here
	rowsOf := func(q, a, src string, mined bool, quota int, other any) (int, error) {
		k := [3]string{a, src, fmt.Sprint(mined)}
		if n, ok := rows[k]; ok {
			return n, nil
		}
		var n int
		if err := ps.row(ctx, q, a, src, flag(mined), other, quota).Scan(&n); err != nil {
			return 0, fmt.Errorf("logs: counting signature rows: %w", err)
		}
		rows[k] = n
		return n, nil
	}
	for k, v := range b.daily {
		first := store.FormatTS(v.first)
		quota := MaxBoundedPerDay
		if v.mined {
			quota = MaxMinedPerDay
		}
		n, err := rowsOf(rowsDaily, k.day, k.source, v.mined, quota, OtherSignature)
		if err != nil {
			return err
		}
		ck := [3]string{k.day, k.source, fmt.Sprint(v.mined)}
		if n < quota {
			var old int
			if err := ps.row(ctx, upsertDaily, k.day, k.source, k.signature, v.dest, v.n, first, v.sample, flag(v.mined)).Scan(&old); err != nil {
				return fmt.Errorf("logs: counting signatures: %w", err)
			}
			if old == 1 && k.signature != OtherSignature {
				rows[ck]++
			}
			continue
		}
		res, err := ps.exec(ctx, updateDaily, k.day, k.source, k.signature, v.n, first, v.dest)
		if err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
		if c, _ := res.RowsAffected(); c > 0 {
			continue
		}
		if _, err := ps.exec(ctx, upsertOtherDaily, k.day, k.source, OtherSignature, v.n, first, v.sample, flag(v.mined)); err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
	}
	for k, v := range b.bucket {
		quota := MaxBoundedPerBucket
		if v.mined {
			quota = MaxMinedPerBucket
		}
		bk := fmt.Sprint(k.bucket)
		n, err := rowsOf(rowsBucket, bk, k.source, v.mined, quota, sigHash(OtherSignature))
		if err != nil {
			return err
		}
		if n < quota {
			var old int
			if err := ps.row(ctx, upsertBucket, k.source, k.bucket, sigHash(k.signature), v.n, flag(v.mined)).Scan(&old); err != nil {
				return fmt.Errorf("logs: counting signatures: %w", err)
			}
			if old == 1 && k.signature != OtherSignature {
				rows[[3]string{bk, k.source, fmt.Sprint(v.mined)}]++
			}
			continue
		}
		res, err := ps.exec(ctx, updateBucket, k.source, k.bucket, sigHash(k.signature), v.n)
		if err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
		if c, _ := res.RowsAffected(); c > 0 {
			continue
		}
		if _, err := ps.exec(ctx, upsertOtherBucket, k.source, k.bucket, sigHash(OtherSignature), v.n, flag(v.mined)); err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
	}
	return s.storeAddrs(ctx, ps, b.addrs, b.commit)
}

// Counts is the read port of response's log_threshold: how many lines of one signature a source received in the last window.
// source is the id of the declared source (ls-…), signature is the text the digest shows. The counters are 5 minutes wide, so the
// window is rounded out to whole buckets: the answer covers the window and at most 5 minutes before it. A window under 5
// minutes or over 24 hours is ErrBadWindow; a signature never seen is 0, not an error.
func (s *Service) Counts(ctx context.Context, source, signature string, window time.Duration) (int, error) {
	if window < CountsMinWindow || window > CountsMaxWindow {
		return 0, ErrBadWindow
	}
	var n sql.NullInt64
	if err := s.cfg.Volume.Reader().QueryRowContext(ctx, countsSQL, source, sigHash(signature), s.now().Add(-window).Unix()/bucketSeconds).Scan(&n); err != nil {
		return 0, fmt.Errorf("logs: counting a signature: %w", err)
	}
	return int(n.Int64), nil
}
