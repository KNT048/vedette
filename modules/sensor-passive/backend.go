package sensorpassive

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// The passive half of sensorlink.Backend (sensor-protocol.md 6.1 to 6.3): Config, Observations and PassiveHeartbeat. The server
// has already checked the role, the module switch, the rate and the size and decoded the body; everything in it is still
// untrusted data about a LAN that a compromised sensor can invent (SYS-6). Combine it with the active half for the listener
// (linktest.Passive in tests; the wiring of core in SP-5).

var epochRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// currentConfig is what the sensor is told now: the card the admin chose, SPAN mode, and for SPAN the switches and filters.
// When the filters cannot be read it says "do not capture" (D-80 (3): ignoring a rule would read traffic the admin excluded).
func (s *Service) currentConfig(ctx context.Context) (sensorlink.Config, error) {
	if err := s.ensureSensor(ctx); err != nil {
		return sensorlink.Config{}, err
	}
	r, err := s.row(ctx, s.db.Reader())
	if err != nil {
		return sensorlink.Config{}, err
	}
	cfg := sensorlink.Config{Interface: r.iface.String, Span: r.span, Filters: []sensorlink.Filter{}}
	if cfg.Interface == "" || !cfg.Span {
		return cfg, nil
	}
	x, f, err := s.host.SpanOptions(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "sensor-passive: SPAN options cannot be read, telling the sensor not to capture", "error", err)
		return sensorlink.Config{Filters: []sensorlink.Filter{}}, nil
	}
	cfg.Extract = x
	if f != nil {
		cfg.Filters = f
	}
	return cfg, nil
}

func etagOf(cfg sensorlink.Config) string {
	b, _ := json.Marshal(cfg) // plain strings and bools: cannot fail
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// Config implements sensorlink.Backend: GET /config as a long poll on the ETag. It answers at once when the sensor's ETag is not
// the current one, and otherwise waits for SetInterface (or the next look at the settings) up to wait, then says 304.
func (s *Service) Config(ctx context.Context, wait time.Duration, ifNoneMatch string) (sensorlink.ConfigReply, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		woke := s.wakeCh() // taken before the look: a change after it is not missed
		cfg, err := s.currentConfig(ctx)
		if err != nil {
			s.log.ErrorContext(ctx, "sensor-passive: config not readable", "error", err)
			return sensorlink.ConfigReply{}, sensorlink.StoreBusy(time.Second)
		}
		etag := etagOf(cfg)
		if etag != ifNoneMatch {
			return sensorlink.ConfigReply{ETag: etag, Config: cfg}, nil
		}
		again := time.NewTimer(s.recheck)
		select {
		case <-woke:
		case <-again.C:
		case <-deadline.C:
			again.Stop()
			return sensorlink.ConfigReply{NotModified: true, ETag: etag}, nil
		case <-ctx.Done(): // the sensor gave up or the server is stopping: nobody reads the answer
			again.Stop()
			return sensorlink.ConfigReply{NotModified: true, ETag: etag}, nil
		}
		again.Stop()
	}
}

// PassiveHeartbeat implements sensorlink.Backend: the sensor says it is alive, which cards it has and what it measured. The
// reply is the instance nonce of this process.
func (s *Service) PassiveHeartbeat(ctx context.Context, hb *sensorlink.PassiveHeartbeat) (string, error) {
	now := s.clock()
	if err := s.ensureSensor(ctx); err != nil {
		s.log.ErrorContext(ctx, "sensor-passive: heartbeat not saved", "error", err)
		return "", sensorlink.StoreBusy(time.Second)
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE sp_sensor SET version = ?, last_seen = ?, devices_seen = ? WHERE id = ?`, hb.Version, store.FormatTS(now), hb.DevicesSeen, SensorID); err != nil {
			return err
		}
		var lp any
		if t := hb.Span.LastPacketAt; t != nil {
			lp = store.FormatTS(minTime(*t, now)) // a sensor cannot have heard a packet from the future
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sp_span_stat (sensor_id, packets_per_s, other_macs, last_packet_at, measured_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (sensor_id) DO UPDATE SET packets_per_s = excluded.packets_per_s, other_macs = excluded.other_macs,
			last_packet_at = excluded.last_packet_at, measured_at = excluded.measured_at`, SensorID, hb.Span.PPS, hb.Span.OtherMACs, lp, store.FormatTS(now))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "sensor-passive: heartbeat not saved", "error", err)
		return "", sensorlink.StoreBusy(time.Second)
	}
	known := make(map[string]int64, len(hb.Drops))
	s.hbMu.Lock()
	for k, v := range hb.Drops {
		switch {
		case sensorlink.ValidDropKey(k):
			known[k] = v
		case !s.unknown[k]: // a newer sensor counts something this core does not know: ignored, said once
			s.unknown[k] = true
			s.log.WarnContext(ctx, "sensor-passive: the sensor reports a counter this core does not know, ignored", "counter", k)
		}
	}
	s.hb = &heartbeat{at: now, ifaces: slices.Clone(hb.Interfaces), drops: known, version: hb.Version}
	s.hbMu.Unlock()
	return s.instance, nil
}

func minTime(a, b time.Time) time.Time {
	if a.After(b) {
		return b
	}
	return a
}

// Drops returns the counters of the last heartbeat (what the capture dropped instead of passing on, by reason); nil before the
// first one. Core logs them and the GUI may show them (deferred).
func (s *Service) Drops() map[string]int64 {
	hb := s.lastBeat()
	if hb == nil {
		return nil
	}
	out := make(map[string]int64, len(hb.drops))
	for k, v := range hb.drops {
		out[k] = v
	}
	return out
}

// Rejection codes of one item (sensor-protocol.md 6.2): a closed set.
const (
	codeInvalidItem    = "invalid_item"
	codeOutOfWindow    = "out_of_window"
	codeBudgetExhaused = "budget_exhausted"
	codeRefused        = "refused"
)

// MaxItemsPerMinute is how many items core takes from the passive role in a minute, whatever they say (the legitimate rate is
// far below: new devices and values are budgeted in the capture too). The rest is rejected budget_exhausted without being read.
const MaxItemsPerMinute = 6000

// Observations implements sensorlink.Backend: POST /observations. In order: the module switch (under the lock, SYS-5), the cap of
// items a minute, the check of each item (a bad one goes into rejected[] and the batch goes on), the addresses of the box (a sensor
// cannot say anything about the box, the host is the authority), the repeat filter (an observation written in the last quarter of
// an hour is acknowledged and not written again), the budgets of new devices, new values and new addresses, and last the
// inventory; an item it refuses at its boundary is rejected as refused and the rest is recorded in the same call. A seq at or
// below the last one of its epoch was applied before: it is acknowledged and not applied again (POST-3). When the store fails
// nothing is recorded, no budget is used and the seq is not saved: the sensor sends the batch again.
func (s *Service) Observations(ctx context.Context, req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	if !epochRE.MatchString(req.Epoch) || req.Seq < 1 || len(req.Items) < 1 || len(req.Items) > sensorlink.MaxItems {
		return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeInvalidRequest)
	}
	seq := uint64(req.Seq)
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if s.off() { // the listener checked before it read the body; the module may have been turned off since (SYS-5)
		return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeModuleOff)
	}
	busy := func(err error) (sensorlink.ObservationsReply, error) {
		s.log.ErrorContext(ctx, "sensor-passive: batch not applied, the sensor will send it again", "error", err)
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	if err := s.ensureSensor(ctx); err != nil {
		return busy(err)
	}
	if err := s.seedBudget(ctx); err != nil {
		return busy(err)
	}
	last, err := s.lastSeq(ctx, req.Epoch)
	if err != nil {
		return busy(err)
	}
	if seq <= last {
		return sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{}}, nil
	}
	box, err := s.boxAddresses(ctx)
	if err != nil {
		return busy(err)
	}
	now := s.clock()
	if now.Sub(s.winStart) >= time.Minute {
		s.winStart, s.winItems = now, 0
	}
	type kept struct {
		index int
		obs   observe.Observation
		claim capture.Claim
	}
	var rejected []sensorlink.Rejected
	var items []kept
	allowed := max(0, MaxItemsPerMinute-s.winItems)
	for i, it := range req.Items {
		if i >= allowed { // over the cap of the minute: not even read
			rejected = append(rejected, sensorlink.Rejected{Index: i, Code: codeBudgetExhaused})
			continue
		}
		o, code := checkItem(it, now)
		if code == "" && box.has(o) {
			code = codeRefused
		}
		if code != "" {
			rejected = append(rejected, sensorlink.Rejected{Index: i, Code: code})
			continue
		}
		if s.repeats.seen(o, now) { // written lately: acknowledged, not written again
			continue
		}
		items = append(items, kept{index: i, obs: o, claim: capture.Claim{MAC: o.AssetHint.MAC, IP: o.AssetHint.IP, Field: o.Field, Value: o.Value}})
	}
	claims := make([]capture.Claim, len(items))
	for i, k := range items {
		claims[i] = k.claim
	}
	verdicts := s.budget.Decide(claims, now)
	refused := make([]bool, len(items))
	var rec []int // indices into items that go to the inventory
	exhausted := 0
	for i, k := range items {
		if !verdicts[i].Pass {
			rejected = append(rejected, sensorlink.Rejected{Index: k.index, Code: codeBudgetExhaused})
			exhausted++
			continue
		}
		rec = append(rec, i)
	}
	if exhausted > 0 && now.Sub(s.budgetAt) >= time.Minute {
		s.budgetAt = now
		s.log.WarnContext(ctx, "sensor-passive: the sensor is over the budget of new devices or values; items rejected as budget_exhausted", "count", exhausted)
	}
	if s.off() { // asked again just before the write
		return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeModuleOff)
	}
	// Record what is left; the inventory names an item it refuses and the rest goes in the same call.
	recorded := slices.Clone(rec)
	for len(rec) > 0 {
		obs := make([]observe.Observation, len(rec))
		for j, i := range rec {
			obs[j] = items[i].obs
		}
		err := s.sink.Record(ctx, obs)
		if err == nil {
			break
		}
		var rj *observe.ErrRejected
		if errors.As(err, &rj) && rj.Index >= 0 && rj.Index < len(rec) {
			i := rec[rj.Index]
			rejected = append(rejected, sensorlink.Rejected{Index: items[i].index, Code: codeRefused})
			refused[i] = true // not recorded, so it does not count against the budget either
			rec = slices.Delete(rec, rj.Index, rj.Index+1)
			continue
		}
		return busy(err)
	}
	var cc []capture.Claim
	var cv []capture.Verdict
	for i := range items {
		if !refused[i] {
			cc, cv = append(cc, claims[i]), append(cv, verdicts[i])
		}
	}
	s.budget.Commit(cc, cv, now)
	for _, i := range recorded {
		if !refused[i] {
			s.repeats.add(items[i].obs, now)
		}
	}
	s.winItems += len(req.Items)
	if err := s.advance(ctx, req.Epoch, seq); err != nil {
		s.log.WarnContext(ctx, "sensor-passive: saving the batch number failed; the batch is in", "error", err)
	}
	sort.Slice(rejected, func(i, j int) bool { return rejected[i].Index < rejected[j].Index })
	if rejected == nil {
		rejected = []sensorlink.Rejected{}
	}
	return sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: rejected}, nil
}

// off reports whether the module is switched off.
func (s *Service) off() bool { return s.enabled != nil && !s.enabled() }

// seedBudget tells the budget about the devices the inventory already has, once (the caller holds submitMu).
func (s *Service) seedBudget(ctx context.Context) error {
	if s.seeded {
		return nil
	}
	if s.knownMACs != nil {
		macs, err := s.knownMACs(ctx)
		if err != nil {
			return err
		}
		s.budget.Seed(macs)
	}
	s.seeded = true
	return nil
}

// boxSet is every MAC and address of the box itself.
type boxSet struct {
	macs map[string]bool
	ips  map[netip.Addr]bool
}

func (b boxSet) has(o observe.Observation) bool {
	return (o.AssetHint.MAC != "" && b.macs[o.AssetHint.MAC]) || (o.AssetHint.IP.IsValid() && b.ips[o.AssetHint.IP])
}

// boxAddresses reads the cards of the box from the host (the authority; the heartbeat of a sensor is not): what a sensor says
// about them is refused, the box is described by the host alone (INV-6, D-118).
func (s *Service) boxAddresses(ctx context.Context) (boxSet, error) {
	cards, err := s.host.Interfaces(ctx)
	if err != nil {
		return boxSet{}, fmt.Errorf("sensorpassive: list interfaces: %w", err)
	}
	b := boxSet{macs: map[string]bool{}, ips: map[netip.Addr]bool{}}
	for _, c := range cards {
		b.macs[strings.ToLower(c.MAC)] = true
		for _, p := range c.Addresses {
			b.ips[p.Addr().Unmap()] = true
		}
	}
	return b, nil
}

// checkItem validates one item as it came off the wire and builds the observation, or says why not (sensor-protocol.md 5 and 6.2).
func checkItem(it sensorlink.ObservationItem, now time.Time) (observe.Observation, string) {
	var o observe.Observation
	if it.MAC == "" && it.IP == "" {
		return o, codeInvalidItem
	}
	if it.MAC != "" {
		if !sensorlink.ValidMAC(it.MAC) || it.MAC == "00:00:00:00:00:00" {
			return o, codeInvalidItem
		}
		if b, ok := hexByte(it.MAC); !ok || b&1 == 1 { // a group address is no device
			return o, codeInvalidItem
		}
		o.AssetHint.MAC = it.MAC
	}
	if it.IP != "" {
		a, err := netip.ParseAddr(it.IP)
		if err != nil || !a.Is4() || !capture.UnicastIP(a) { // observe.AssetHint is IPv4 only
			return o, codeInvalidItem
		}
		o.AssetHint.IP = a
	}
	f := observe.Field(it.Field)
	if !observe.ValidField(f) {
		return o, codeInvalidItem
	}
	if f == observe.MAC && (it.MAC == "" || it.Value != it.MAC) { // a MAC row says the MAC of the device it is about, nothing else
		return o, codeInvalidItem
	}
	if n := len(it.Value); n < 1 || n > capture.MaxValueBytes || !capture.Printable(it.Value) {
		return o, codeInvalidItem
	}
	if math.IsNaN(it.Confidence) || it.Confidence < 0 || it.Confidence > 1 {
		return o, codeInvalidItem
	}
	if it.SeenAt.Before(now.Add(-seenBack)) || it.SeenAt.After(now.Add(seenAhead)) {
		return o, codeOutOfWindow
	}
	limit, ok := capture.MaxConfidence(f, it.Value)
	if !ok { // a kind no parser emits
		return o, codeInvalidItem
	}
	o.Field, o.Value, o.Source, o.SeenAt = f, it.Value, observe.Passive, it.SeenAt
	o.Confidence = min(it.Confidence, limit) // the scale of what a passive sensor can know (INV-5)
	return o, ""
}

// hexByte is the first octet of a MAC in the protocol's form.
func hexByte(m string) (byte, bool) {
	var b byte
	for i := range 2 {
		c := m[i]
		switch {
		case c >= '0' && c <= '9':
			b = b<<4 | (c - '0')
		case c >= 'a' && c <= 'f':
			b = b<<4 | (c - 'a' + 10)
		default:
			return 0, false
		}
	}
	return b, true
}

// lastSeq is the highest seq applied for epoch: the larger of the saved one and the one remembered in memory.
func (s *Service) lastSeq(ctx context.Context, epoch string) (uint64, error) {
	var last int64
	err := s.db.Reader().QueryRowContext(ctx, `SELECT coalesce((SELECT last_seq FROM sp_seq WHERE sensor_id = ? AND epoch = ?), 0)`, SensorID, epoch).Scan(&last)
	if err != nil {
		return 0, fmt.Errorf("sensorpassive: read seq: %w", err)
	}
	return max(uint64(last), s.seqMem[epoch]), nil //nolint:gosec // last_seq has CHECK >= 0
}

// advance saves seq as the last one applied for epoch and forgets all but the newest two epochs of the sensor (a third epoch
// deletes the oldest). The caller holds submitMu.
func (s *Service) advance(ctx context.Context, epoch string, seq uint64) error {
	s.seqMem[epoch] = max(s.seqMem[epoch], seq)
	if len(s.seqMem) > keptEpochs+1 { // the memory is only a safety net for one failed save: keep it small
		for k := range s.seqMem {
			if k != epoch {
				delete(s.seqMem, k)
				break
			}
		}
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sp_seq (sensor_id, epoch, last_seq) VALUES (?, ?, ?)
			ON CONFLICT (sensor_id, epoch) DO UPDATE SET last_seq = max(last_seq, excluded.last_seq)`, SensorID, epoch, seq); err != nil {
			return fmt.Errorf("sensorpassive: save seq: %w", err)
		}
		// rowid grows with every new epoch and does not change when an epoch is updated: the two highest are the newest
		if _, err := tx.ExecContext(ctx, `DELETE FROM sp_seq WHERE sensor_id = ? AND rowid NOT IN
			(SELECT rowid FROM sp_seq WHERE sensor_id = ? ORDER BY rowid DESC LIMIT ?)`, SensorID, SensorID, keptEpochs); err != nil {
			return fmt.Errorf("sensorpassive: prune epochs: %w", err)
		}
		return nil
	})
}
