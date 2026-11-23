package findings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// Match only what changed. The hourly pass matches a device again only when something its match reads moved since the device's last
// pass: its input (MatchInput: rows, OS, corrections, rows a person said are not installed), the catalogue entries that can concern it
// (each entry hashed), which of its findings' CVEs the pass judges, its findings and questions as its last write left them (a person's
// decision, a safe check, a merge or any other write changes them), Home's "I have this" scope, the Windows releases and updates learned
// from Microsoft (winrel.Generation), and every rule that reads the clock (the age and settle rules, the Windows listing margin, news
// against backlog, SNMP freshness, the daily step of last_seen, the end of an accepted risk). The calendar day is in it too, so every
// device is matched in full at least once a day whatever the rules. A device a person ignored, deleted or merged away leaves the pass,
// and its stamp with it: it is matched in full when it comes back. The stamps live in memory: the first pass after a start matches
// every device.

// stamps are the devices' match stamps of their last full match (matchStamp), by device id.
type stamps struct {
	mu sync.Mutex
	m  map[string][32]byte
}

func (st *stamps) get(id string) ([32]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.m[id]
	return v, ok
}

func (st *stamps) set(id string, v [32]byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.m == nil {
		st.m = map[string][32]byte{}
	}
	st.m[id] = v
}

func (st *stamps) drop(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.m, id)
}

// keepOnly drops the stamps of the devices not in live.
func (st *stamps) keepOnly(live map[string]bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for id := range st.m {
		if !live[id] {
			delete(st.m, id)
		}
	}
}

// deviceRows are a device's findings and questions as one read of the database gives them.
type deviceRows struct {
	findings  []Finding
	questions []Question
}

func readDeviceRows(ctx context.Context, q querier, assetID string) (deviceRows, error) {
	fs, err := findingsOf(ctx, q, assetID)
	if err != nil {
		return deviceRows{}, err
	}
	qs, err := questionsOf(ctx, q, assetID)
	if err != nil {
		return deviceRows{}, err
	}
	return deviceRows{findings: fs, questions: qs}, nil
}

// passInput is what one pass reads once for every device's stamp: the set, Home's scope, and whether the stamps can be read at all
// (false when the scope could not be read: every device is matched).
type passInput struct {
	set   *matchSet
	since map[string]Have
	ok    bool
}

// matchStamp hashes everything the match pass reads for device a against the entries idx of the pass's set, with the device's rows
// rows, at now, with the learned Windows releases and updates at generation gen (winrel.Generation, read before the match was
// computed: what is learned during a match is not in it) (see the top of this file). ok is false when something could not be hashed:
// the device is then matched.
func (s *Service) matchStamp(a Asset, in passInput, idx []int, rows deviceRows, now time.Time, gen uint64) (stamp [32]byte, ok bool) {
	h := sha256.New()
	enc := json.NewEncoder(h)
	if err := enc.Encode(a); err != nil {
		return stamp, false
	}
	backlog, recent := s.judgedParts(in.set)
	_, _ = fmt.Fprintf(h, "winrel %d day %s rates %t backlog %t\n", gen, now.UTC().Format(time.DateOnly), s.rates(), s.cfg.Backlog != nil)
	cut := in.set.splitAt.Add(-RecentKEV) // the pass splits news from backlog at one time (judgedParts)
	for _, i := range idx {
		e, ok := in.set.entryHash(i)
		if !ok {
			return stamp, false
		}
		_, _ = h.Write(e[:])
		v := in.set.vulns[i]
		news := !v.DateAdded.IsZero() && !v.DateAdded.Before(cut)
		listedLongAgo := !v.DateAdded.IsZero() && !v.DateAdded.Add(winListedMargin).After(now)
		writeBits(h, aged(v, now), settled(v, now), listedLongAgo, news)
	}
	for _, sw := range slices.Concat(a.Software, a.NotInstalled) {
		writeBits(h, snmpFresh(sw.SeenAt, now))
	}
	writeBits(h, snmpFresh(a.SNMPOSAt, now), snmpFresh(a.StatedOSAt, now))
	for _, f := range rows.findings {
		if err := enc.Encode(f); err != nil {
			return stamp, false
		}
		writeBits(h, now.Sub(f.LastSeen) >= lastSeenStep, backlog[f.CVE], recent[f.CVE], !now.Before(AcceptanceEnds(f.AcceptedUntil)))
	}
	for _, q := range rows.questions {
		if err := enc.Encode(q); err != nil {
			return stamp, false
		}
	}
	if hv, held := in.since[a.ID]; held {
		if err := enc.Encode(hv); err != nil {
			return stamp, false
		}
	}
	h.Sum(stamp[:0])
	return stamp, true
}

func writeBits(h hash.Hash, bits ...bool) {
	b := make([]byte, len(bits)+1)
	for i, x := range bits {
		if x {
			b[i] = '1'
		} else {
			b[i] = '0'
		}
	}
	b[len(bits)] = '|'
	_, _ = h.Write(b)
}

// unchanged says whether device a reads now exactly what it read at its last full match (its stamp): its match would write nothing.
func (s *Service) unchanged(ctx context.Context, a Asset, in passInput) bool {
	if !in.ok {
		return false
	}
	kept, ok := s.stamps.get(a.ID)
	if !ok {
		return false
	}
	rows, err := readDeviceRows(ctx, s.cfg.DB.Reader(), a.ID)
	if err != nil {
		return false
	}
	now := s.now()
	stamp, ok := s.matchStamp(a, in, in.set.devIdx(a), rows, now, winrel.Generation())
	return ok && stamp == kept
}
