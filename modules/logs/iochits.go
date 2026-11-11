package logs

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
)

// IOC matching (L4, S-LOG-2, S-LOG-4 syslog half, INV-7, POST-2, PRE-3, D-213). A line of a device with a profile can say which LAN device
// connected to which public address or name (signature.Conn: read only from fields the format names, once, outside quotes). The
// destination is looked up through the Feeds port (an adapter on the feeds module's indicators, in the box: nothing leaves it); a
// listed one is a hit, stored in logs_ioc_hits (once per (device, destination) per 24 hours), shown in the digest with the device
// resolved when it is read, and announced with two events once the batch is committed.
const (
	// EventIocHit is what response's ioc_connection trigger listens to; EventBadAddress is what notify opens an incident from.
	EventIocHit     = "logs.ioc_hit.detected"
	EventBadAddress = "logs.bad_address.detected"
	// IocDedupe is how long one (device, destination) pair is one hit.
	IocDedupe = 24 * time.Hour
	// MaxIocRows is the most hits the table keeps; the oldest go first. MaxIocHitsPerBatch is the most new hits one batch stores (the
	// pairs past it are not looked at: a device that sends hundreds of distinct bad addresses in one batch is one story, and the first
	// ones tell it). IocEventsPerHour is the most hits announced in an hour; a hit past it is stored and shown in the digest, but not
	// announced (the incident that the earlier ones opened is where a person looks). ponytail: three constants; the upgrade is a summary event.
	MaxIocRows         = 10_000
	MaxIocHitsPerBatch = 50
	IocEventsPerHour   = 100
	// MaxIocFeeds is how many feed names a hit keeps. MaxIocRead is the most hits IocHits returns.
	MaxIocFeeds = 8
	MaxIocRead  = 1000
	// iocLookupTimeout bounds all the lookups of one batch.
	iocLookupTimeout = 5 * time.Second
	// iocAnnounceTimeout bounds the publishing of the events of one batch.
	iocAnnounceTimeout = 10 * time.Second
)

// ErrFeedsOff is what Feeds.Lookup returns while the feeds module is off (PRE-3): no lookup is made and there are no hits.
var ErrFeedsOff = errors.New("logs: the Feeds module is off")

// Listing is what the feeds say about one destination: the names of the feeds that list it now, and how sure they are (0 to 1).
type Listing struct {
	Feeds      []string
	Confidence float64
}

// Feeds is what logs reads from the feeds module (an adapter in cmd/vedette on its indicator store): the listing of an address
// (kind "ip", canonical text) or a domain (kind "domain", lower case). found is false for a destination that no feed lists, and for one
// that no feed lists any more. ErrFeedsOff while the module is off. An error is any other failure; logs goes on without it.
type Feeds interface {
	Lookup(ctx context.Context, kind, value string) (l Listing, found bool, err error)
	// On says whether lookups can be answered now (false while the feeds module is off, PRE-3): the digest shows no bad connections then.
	On() bool
}

// IocHit is a connection to a listed destination as the API shows it (IocHit of contract.ts) and as the event logs.ioc_hit.detected carries it.
type IocHit struct {
	ID        string    `json:"id"`
	TS        time.Time `json:"ts"`
	AssetID   *string   `json:"asset_id"`
	AssetName *string   `json:"asset_name"`
	SrcIP     string    `json:"src_ip"`
	Dest      string    `json:"dest"`
	DestKind  string    `json:"dest_kind"` // ip | domain
	SeenVia   string    `json:"seen_via"`  // syslog:<name of the source>
	Feeds     []string  `json:"feeds"`
	// Confidence is the highest confidence of the feeds that list the destination, between 0 and 1.
	Confidence float64 `json:"confidence"`
}

// BadAddressEvent is the data of logs.bad_address.detected: the fields notify opens an incident from (Source, Target, Title, What, Action,
// Severity, Devices: the same as AnomalyEvent) and the fields the SIEM forwarder sends (ID, SrcIP, Dest, DestKind, SeenVia, AssetID).
// Dest and every name are plain text: untrusted names (a device's host name) have their control characters replaced and are cut; each
// consumer escapes what it shows.
type BadAddressEvent struct {
	Source   string       `json:"source"` // always "logs"
	Target   string       `json:"target"` // "ioc:<destination>": its own namespace in notify's dedupe key, like "sig:" for the signatures
	Title    string       `json:"title"`
	What     string       `json:"what"`
	Action   string       `json:"action"`
	Severity string       `json:"severity"`
	Devices  []DeviceInfo `json:"devices"`
	ID       string       `json:"id"`
	SrcIP    string       `json:"src_ip"`
	Dest     string       `json:"dest"`
	DestKind string       `json:"dest_kind"`
	SeenVia  string       `json:"seen_via"`
	AssetID  *string      `json:"asset_id"`
}

// connKey is a connection seen in a batch; connObs is the first line that showed it.
type connKey struct {
	src        netip.Addr
	kind, dest string
}

type connObs struct {
	source string
	at     time.Time
}

// iocRow is a hit before it is stored.
type iocRow struct {
	id, src, dest, kind, via, source string
	at                               time.Time
	feeds                            []string
	conf                             float64
}

type lookupResult struct {
	l     Listing
	found bool
}

// matchIOC looks up the destinations of a batch (each one once: a flood of lines to the same address is one lookup) and returns the hits,
// oldest line first. It runs before the transaction of the batch (the writer of logs.db is not held while the feeds are read) and never
// fails the batch: with the feeds off there is nothing to do, and any other failure is logged once and the batch is stored without hits.
func (s *Service) matchIOC(ctx context.Context, conns map[connKey]connObs, names map[string]string) []iocRow {
	if s.cfg.Feeds == nil || len(conns) == 0 {
		return nil
	}
	keys := make([]connKey, 0, len(conns))
	for k := range conns {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b connKey) int {
		return cmp.Or(conns[a].at.Compare(conns[b].at), a.src.Compare(b.src), cmp.Compare(a.kind, b.kind), cmp.Compare(a.dest, b.dest))
	})
	ctx, cancel := context.WithTimeout(ctx, iocLookupTimeout)
	defer cancel()
	cache := map[[2]string]lookupResult{}
	var out []iocRow
	cutoff := store.FormatTS(s.ts().Add(-IocDedupe))
	for _, k := range keys {
		if len(out) >= MaxIocHitsPerBatch {
			break
		}
		// A pair that already has a hit in the last 24 hours is not looked up and does not count toward the cap of the batch: a chatty device
		// that keeps meeting its listed addresses must not use the cap that another device's first hit needs (storeIOC dedupes again inside the transaction).
		if s.hasRecentHit(ctx, k, cutoff) {
			continue
		}
		ck := [2]string{k.kind, k.dest}
		res, ok := cache[ck]
		if !ok {
			l, found, err := s.cfg.Feeds.Lookup(ctx, k.kind, k.dest)
			if err != nil {
				s.noteLookupFailure(ctx, err)
				return out // the rest of the batch is stored without a match
			}
			s.iocWarned.Store(nil) // a lookup that worked: the next failure is news again
			res = lookupResult{l, found}
			cache[ck] = res
		}
		if !res.found || len(res.l.Feeds) == 0 {
			continue
		}
		o := conns[k]
		out = append(out, iocRow{id: store.NewID("ih"), src: k.src.String(), dest: k.dest, kind: k.kind, via: "syslog:" + names[o.source], source: o.source, at: o.at,
			feeds: cleanFeeds(res.l.Feeds), conf: clamp01(res.l.Confidence)})
	}
	return out
}

// hasRecentHit says whether the pair has a stored hit newer than cutoff (a read on the reader pool, the index logs_ioc_hits_pair); an error says no.
func (s *Service) hasRecentHit(ctx context.Context, k connKey, cutoff string) bool {
	var one int
	return s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT 1 FROM logs_ioc_hits WHERE src_ip = ? AND dest = ? AND ts > ? LIMIT 1`, k.src.String(), k.dest, cutoff).Scan(&one) == nil
}

// noteLookupFailure logs a failed lookup, once for a run of the same failure; the feeds being off is not a failure (PRE-3).
func (s *Service) noteLookupFailure(ctx context.Context, err error) {
	if errors.Is(err, ErrFeedsOff) {
		return
	}
	msg := err.Error()
	if prev := s.iocWarned.Load(); prev != nil && *prev == msg {
		return
	}
	s.iocWarned.Store(&msg)
	s.cfg.Log.WarnContext(ctx, "logs: the threat feeds could not be read; lines are stored without a match for now", "err", err)
}

func clamp01(f float64) float64 {
	if f != f { //nolint:gocritic // NaN is the only float that differs from itself
		return 0
	}
	return min(1, max(0, f))
}

// cleanFeeds returns the feed names of a listing as plain text, sorted, without repeats, at most MaxIocFeeds of at most 64 characters.
func cleanFeeds(in []string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		if f = clipRunes(plainText(f), 64); f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	if len(out) > MaxIocFeeds {
		out = out[:MaxIocFeeds]
	}
	return out
}

// plainText replaces every control, format, line and paragraph separator character with a space and trims: a name that a device or an
// operator chose is shown as one line of text.
func plainText(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "?")))
}

// storeIOC writes the hits of a batch inside its transaction: a (device, destination) pair that has a hit less than IocDedupe old is not
// a new hit; the table is cut to MaxIocRows. fresh gets the hits that are new, in order.
func (s *Service) storeIOC(ctx context.Context, tx *sql.Tx, rows []iocRow, fresh *[]iocRow) error {
	if len(rows) == 0 {
		return nil
	}
	cutoff := store.FormatTS(s.ts().Add(-IocDedupe))
	for _, r := range rows {
		var one int
		switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM logs_ioc_hits WHERE src_ip = ? AND dest = ? AND ts > ? LIMIT 1`, r.src, r.dest, cutoff).Scan(&one); {
		case err == nil:
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("logs: checking a hit: %w", err)
		}
		feeds, err := json.Marshal(r.feeds)
		if err != nil {
			return fmt.Errorf("logs: storing a hit: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_ioc_hits (id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence, source_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.id, store.FormatTS(r.at), r.src, r.dest, r.kind, r.via, string(feeds), r.conf, r.source); err != nil {
			return fmt.Errorf("logs: storing a hit: %w", err)
		}
		*fresh = append(*fresh, r)
	}
	if len(*fresh) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM logs_ioc_hits WHERE rowid IN (SELECT rowid FROM logs_ioc_hits ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?)`, MaxIocRows); err != nil {
		return fmt.Errorf("logs: cutting the hits: %w", err)
	}
	return nil
}

// noteBudgetOut logs, once per clock hour, that hits were stored and not announced because the hourly budget ran out.
func (s *Service) noteBudgetOut(ctx context.Context, n int) {
	s.iocMu.Lock()
	hour := s.now().Unix() / 3600
	first := s.iocCapLogged != hour
	s.iocCapLogged = hour
	s.iocMu.Unlock()
	if first {
		s.cfg.Log.WarnContext(ctx, "logs: more bad connections than the hourly limit of announcements; they are stored and shown in the digest, not announced", "not_announced", n, "limit", IocEventsPerHour)
	}
}

// iocBudget says how many of n new hits may be announced now: at most IocEventsPerHour in a clock hour.
func (s *Service) iocBudget(n int) int {
	s.iocMu.Lock()
	defer s.iocMu.Unlock()
	if h := s.now().Unix() / 3600; h != s.iocHour {
		s.iocHour, s.iocSent = h, 0
	}
	n = min(n, IocEventsPerHour-s.iocSent)
	if n < 0 {
		n = 0
	}
	s.iocSent += n
	return n
}

// announceIOC publishes the events of the new hits of a committed batch (never inside the transaction: a handler may write, and a
// rolled-back batch must announce nothing). Without a bus nothing is sent. An event that cannot be published is logged; the hit is stored
// and shown in the digest either way.
func (s *Service) announceIOC(ctx context.Context, fresh []iocRow) {
	if s.cfg.Events == nil || len(fresh) == 0 {
		return
	}
	// The batch is stored: announcing must not depend on the caller's context (a listener that is stopping cancels it, and the hit would never be
	// announced while the dedupe hides it for 24 hours), so it runs on its own bounded context.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), iocAnnounceTimeout)
	defer cancel()
	if n := s.iocBudget(len(fresh)); n < len(fresh) {
		s.noteBudgetOut(ctx, len(fresh)-n)
		fresh = fresh[:n]
	}
	if len(fresh) == 0 {
		return
	}
	ips := make([]string, len(fresh))
	for i, r := range fresh {
		ips[i] = r.src
	}
	devices := s.assetsFor(ctx, ips)
	for _, r := range fresh {
		hit := r.hit(devices)
		if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventIocHit, Data: hit}); err != nil {
			s.cfg.Log.WarnContext(ctx, "logs: announcing a bad connection failed", "err", err)
		}
		if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventBadAddress, Data: badAddressEvent(hit)}); err != nil {
			s.cfg.Log.WarnContext(ctx, "logs: announcing a bad connection failed", "err", err)
		}
	}
}

// hit is the API form of a stored row, with the device that has the address (devices: by address; nil or missing = unknown).
func (r iocRow) hit(devices map[string]Device) IocHit {
	h := IocHit{ID: r.id, TS: r.at, SrcIP: r.src, Dest: r.dest, DestKind: r.kind, SeenVia: r.via, Feeds: r.feeds, Confidence: r.conf}
	if d, ok := devices[r.src]; ok && d.ID != "" {
		id, name := d.ID, plainText(d.Name)
		h.AssetID, h.AssetName = &id, &name
	}
	return h
}

// badAddressEvent is the event notify and the SIEM forwarder read.
func badAddressEvent(h IocHit) BadAddressEvent {
	who := h.SrcIP
	devices := []DeviceInfo{}
	if h.AssetID != nil && h.AssetName != nil && *h.AssetName != "" && len(*h.AssetID) <= MaxDeviceID { // a device notify would refuse makes the whole incident fail
		who = *h.AssetName + " (" + h.SrcIP + ")"
		devices = append(devices, DeviceInfo{ID: *h.AssetID, Name: clipRunes(*h.AssetName, MaxDeviceName)})
	}
	sev := "medium"
	if h.Confidence >= 0.7 {
		sev = "high"
	}
	what := fmt.Sprintf("%s connected to %s (%s), which %s. Confidence %d%%. Seen in the log of %s.", clipRunes(who, 300), h.Dest, destWord(h.DestKind),
		listedBy(h.Feeds), int(h.Confidence*100+0.5), clipRunes(strings.TrimPrefix(h.SeenVia, "syslog:"), 120))
	return BadAddressEvent{
		Source: "logs", Target: clipRunes("ioc:"+h.Dest, MaxEventKey),
		Title:    clipRunes(fmt.Sprintf("%s connected to %s, which a threat feed lists", clipRunes(who, 100), h.Dest), MaxEventTitle),
		What:     clipRunes(what, MaxEventText),
		Action:   "Open Logs and look at this connection. If nobody expected this device to talk to that address, take it off the network and ask its user what it was doing.",
		Severity: sev, Devices: devices,
		ID: h.ID, SrcIP: h.SrcIP, Dest: h.Dest, DestKind: h.DestKind, SeenVia: h.SeenVia, AssetID: h.AssetID,
	}
}

func destWord(kind string) string {
	if kind == "domain" {
		return "a domain name"
	}
	return "an IP address"
}

func listedBy(feeds []string) string {
	if len(feeds) == 0 {
		return "a threat feed lists"
	}
	return "is listed by " + clipRunes(strings.Join(feeds, ", "), 300)
}

// assetsFor is the inventory device with each address, by address; no inventory or a failed read is no device (the hit is still worth showing).
func (s *Service) assetsFor(ctx context.Context, ips []string) map[string]Device {
	if s.cfg.Inventory == nil || len(ips) == 0 {
		return nil
	}
	found, err := s.cfg.Inventory.DevicesByIP(ctx, slices.Compact(slices.Sorted(slices.Values(ips))))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "logs: could not look up the devices of the bad connections", "err", err)
		return nil
	}
	return found
}

const iocColumns = `id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence`

// iocHits reads the newest hits since a time with at least minConf, newest first, with the device of each resolved now (INV-7).
func (s *Service) iocHits(ctx context.Context, where string, limit int, args ...any) ([]IocHit, error) {
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT `+iocColumns+` FROM logs_ioc_hits WHERE `+where+` ORDER BY ts DESC, rowid DESC LIMIT `+fmt.Sprint(limit), args...)
	if err != nil {
		return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []IocHit{}
	var ips []string
	for rows.Next() {
		var h IocHit
		var ts, feeds string
		if err := rows.Scan(&h.ID, &ts, &h.SrcIP, &h.Dest, &h.DestKind, &h.SeenVia, &feeds, &h.Confidence); err != nil {
			return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
		}
		if h.TS, err = time.Parse("2006-01-02T15:04:05.000Z", ts); err != nil {
			return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
		}
		if err := json.Unmarshal([]byte(feeds), &h.Feeds); err != nil || h.Feeds == nil {
			h.Feeds = []string{}
		}
		out = append(out, h)
		ips = append(ips, h.SrcIP)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
	}
	devices := s.assetsFor(ctx, ips)
	for i, h := range out {
		if d, ok := devices[h.SrcIP]; ok && d.ID != "" {
			id, name := d.ID, plainText(d.Name)
			out[i].AssetID, out[i].AssetName = &id, &name
		}
	}
	return out, nil
}

// IocHits returns the connections to listed destinations since a time whose confidence is at least minConf, newest first, at most
// MaxIocRead, with the device of each address resolved when it is read (INV-7). The read port of response's ioc_connection trigger.
func (s *Service) IocHits(ctx context.Context, since time.Time, minConf float64) ([]IocHit, error) {
	return s.iocHits(ctx, `ts >= ? AND confidence >= ?`, MaxIocRead, store.FormatTS(since), minConf)
}

// IocHit finds one hit by its id (response's evidence lookup: the same value the digest shows). found is false for an id that is not a
// hit, and for one that was purged.
func (s *Service) IocHit(ctx context.Context, id string) (IocHit, bool, error) {
	if id == "" || len(id) > 64 {
		return IocHit{}, false, nil
	}
	hits, err := s.iocHits(ctx, `id = ?`, 1, id)
	if err != nil || len(hits) == 0 {
		return IocHit{}, false, err
	}
	return hits[0], true, nil
}
