package sensorpassive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// SensorID is the id of the one sensor of this box (D-24: no other site). It matches the mock.
const SensorID = "sn-local"

const (
	localEpoch     = "local"
	onlineWithin   = 90 * time.Second // three heartbeats of 30 s
	spanFreshness  = 30 * time.Second // a mirror that was silent this long has "no traffic"
	maxSubmitBatch = 500              // docs/specs/sensor-protocol.md 9: events per batch
)

// Errors of Service. ErrBadInterface carries the API code "bad_interface" (INV-9).
var (
	ErrNotFound     = errors.New("sensorpassive: sensor not found")
	ErrBadInterface = errors.New("sensorpassive: bad interface")
	ErrInvalid      = errors.New("sensorpassive: invalid input")
)

// Config is what New needs. DB, Audit, Sink and Host are required; Meta defaults to NoMetadata.
type Config struct {
	DB      *store.DB
	Audit   *audit.Log
	Sink    observe.Sink // the inventory (INV-5); the module never writes inv_* itself
	Meta    MetadataSink
	Host    Host
	Clock   func() time.Time
	Log     *slog.Logger
	Version string
	Name    string // sensor display name; default the host name

	// Open opens a Source for an interface name; default OpenLive. Tests pass a replay of a fixture.
	Open func(iface string) (Source, error)
	// FlushEvery, HeartbeatEvery and RetryEvery set the loop's pace; zero means 5 s, 30 s and 5 s (the retry grows to 10 min while a capture keeps failing); SummaryEvery is how often a changed drop summary is logged, 5 min.
	FlushEvery, HeartbeatEvery, RetryEvery, SummaryEvery time.Duration
}

// Service is the passive sensor of this box. Create it with New.
type Service struct {
	db      *store.DB
	audit   *audit.Log
	sink    observe.Sink
	meta    MetadataSink
	host    Host
	clock   func() time.Time
	log     *slog.Logger
	version string
	name    string
	open    func(string) (Source, error)

	flushEvery, beatEvery, retryEvery, summaryEvery time.Duration

	submitMu sync.Mutex    // one batch at a time, so the same seq cannot be applied twice
	reload   chan struct{} // capacity 1: "the settings changed, reopen the capture"

	mu  sync.Mutex
	eng *Engine // the running capture, nil when idle
	seq uint64  // last batch number handed out
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Sink == nil || cfg.Host == nil {
		return nil, errors.New("sensorpassive: New needs DB, Audit, Sink and Host")
	}
	s := &Service{db: cfg.DB, audit: cfg.Audit, sink: cfg.Sink, meta: cfg.Meta, host: cfg.Host, clock: cfg.Clock, log: cfg.Log,
		version: cfg.Version, name: cfg.Name, open: cfg.Open, flushEvery: cfg.FlushEvery, beatEvery: cfg.HeartbeatEvery,
		retryEvery: cfg.RetryEvery, summaryEvery: cfg.SummaryEvery, reload: make(chan struct{}, 1)}
	if s.meta == nil {
		s.meta = NoMetadata{}
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.open == nil {
		s.open = OpenLive
	}
	if s.name == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			s.name = h
		} else {
			s.name = "vedette"
		}
	}
	if s.version == "" {
		s.version = "dev"
	}
	s.flushEvery = orDefault(s.flushEvery, 5*time.Second)
	s.beatEvery = orDefault(s.beatEvery, 30*time.Second)
	s.retryEvery = orDefault(s.retryEvery, 5*time.Second)
	s.summaryEvery = orDefault(s.summaryEvery, 5*time.Minute)
	return s, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// ensureSensor creates the row of this box's sensor once and refreshes its name and version.
func (s *Service) ensureSensor(ctx context.Context) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sp_sensor (id, name, version) VALUES (?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET name = excluded.name, version = excluded.version`, SensorID, s.name, s.version); err != nil {
			return fmt.Errorf("sensorpassive: create sensor: %w", err)
		}
		var last sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT last_seq FROM sp_seq WHERE sensor_id = ? AND epoch = ?`, SensorID, localEpoch).Scan(&last); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("sensorpassive: read seq: %w", err)
		}
		s.mu.Lock()
		s.seq = max(s.seq, uint64(last.Int64)) //nolint:gosec // last_seq has CHECK >= 0
		s.mu.Unlock()
		return nil
	})
}

// Sensor is one card of GET /inventory/sensors (shape: web/src/features/inventory/contract.ts).
type Sensor struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Interface   *string    `json:"interface"`
	Interfaces  []string   `json:"interfaces"`
	Span        bool       `json:"span"`
	SpanStatus  SpanStatus `json:"span_status"`
	Status      string     `json:"status"` // online | offline
	LastSeen    *string    `json:"last_seen"`
	Version     *string    `json:"version"`
	DevicesSeen int        `json:"devices_seen"`
}

// SpanStatus is Sensor.span_status.
type SpanStatus struct {
	Verdict     string `json:"verdict"`
	PacketsPerS int    `json:"packets_per_s"`
	OtherMACs   int    `json:"other_macs"`
}

type sensorRow struct {
	name, iface       sql.NullString
	span              bool
	version, lastSeen sql.NullString
	devices           int
}

func (s *Service) row(ctx context.Context, q querier) (sensorRow, error) {
	var r sensorRow
	err := q.QueryRowContext(ctx, `SELECT name, interface, span, version, last_seen, devices_seen FROM sp_sensor WHERE id = ?`, SensorID).
		Scan(&r.name, &r.iface, &r.span, &r.version, &r.lastSeen, &r.devices)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, fmt.Errorf("sensorpassive: read sensor: %w", err)
	}
	return r, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func nullable(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

// Status lists the sensors of this box (GET /inventory/sensors): at most one. The interface list comes from
// the host layer on every call; online/offline comes from last_seen; the SPAN verdict is measured.
func (s *Service) Status(ctx context.Context) ([]Sensor, error) {
	if err := s.ensureSensor(ctx); err != nil {
		return nil, err
	}
	r, err := s.row(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	hostIfaces, err := s.host.Interfaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("sensorpassive: list interfaces: %w", err)
	}
	names := make([]string, 0, len(hostIfaces))
	for _, i := range hostIfaces {
		names = append(names, i.Name)
	}
	slices.Sort(names)
	st := s.spanStats(ctx, r, hostIfaces)
	out := Sensor{ID: SensorID, Name: r.name.String, Interface: nullable(r.iface), Interfaces: names, Span: r.span,
		SpanStatus: SpanStatus{st.Verdict, st.PPS, st.OtherMACs}, Status: "offline", LastSeen: nullable(r.lastSeen),
		Version: nullable(r.version), DevicesSeen: r.devices}
	if r.lastSeen.Valid {
		if t, err := time.Parse(time.RFC3339Nano, r.lastSeen.String); err == nil && s.clock().Sub(t) < onlineWithin {
			out.Status = "online"
		}
	}
	s.mu.Lock()
	if s.eng != nil {
		out.DevicesSeen = s.eng.DevicesSeen(s.clock())
	}
	s.mu.Unlock()
	return []Sensor{out}, nil
}

// SpanStats returns the measured health of the mirrored traffic (POST-4).
func (s *Service) SpanStats(ctx context.Context) (SpanStats, error) {
	if err := s.ensureSensor(ctx); err != nil {
		return SpanStats{}, err
	}
	r, err := s.row(ctx, s.db.Reader())
	if err != nil {
		return SpanStats{}, err
	}
	hostIfaces, err := s.host.Interfaces(ctx)
	if err != nil {
		return SpanStats{}, fmt.Errorf("sensorpassive: list interfaces: %w", err)
	}
	return s.spanStats(ctx, r, hostIfaces), nil
}

// spanStats: what the engine measured in this process, never a guess. With no running capture, nothing was
// measured: a SPAN sensor that is not listening has no traffic.
func (s *Service) spanStats(_ context.Context, r sensorRow, ifaces []HostInterface) SpanStats {
	if !r.span {
		return SpanStats{Verdict: VerdictOff}
	}
	link := true
	for _, i := range ifaces {
		if i.Name == r.iface.String {
			link = i.Link
		}
	}
	if !link {
		return SpanStats{Verdict: VerdictNoLink}
	}
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return SpanStats{Verdict: VerdictNoTraffic}
	}
	now := s.clock()
	pps, others, last := eng.Stats(now)
	st := SpanStats{PPS: pps, OtherMACs: others, LastPacket: last}
	switch {
	case last.IsZero() || now.Sub(last) > spanFreshness:
		st.Verdict, st.PPS = VerdictNoTraffic, 0
	case others == 0:
		st.Verdict = VerdictOwnOnly // INV-9: packets arrive, but only the box's own
	default:
		st.Verdict = VerdictOK
	}
	return st
}

// SetInterface chooses the card the sensor listens on and whether it is a SPAN port (PRE-2, POST-2, INV-9).
// iface must be one of the box's interfaces; a SPAN card has no IP address. The change is audited in the same
// transaction and the running capture moves to the new card at once.
func (s *Service) SetInterface(ctx context.Context, actor, id, iface string, span bool) error {
	if id != SensorID {
		return ErrNotFound
	}
	hostIfaces, err := s.host.Interfaces(ctx)
	if err != nil {
		return fmt.Errorf("sensorpassive: list interfaces: %w", err)
	}
	var card *HostInterface
	for i := range hostIfaces {
		if hostIfaces[i].Name == iface {
			card = &hostIfaces[i]
		}
	}
	switch {
	case iface == "" && span:
		return fmt.Errorf("%w: a SPAN port needs an interface", ErrBadInterface)
	case iface != "" && card == nil:
		return fmt.Errorf("%w: %q is not an interface of this box", ErrBadInterface, iface)
	case span && len(card.Addresses) > 0:
		return fmt.Errorf("%w: %q has an IP address; a SPAN port has none", ErrBadInterface, iface)
	}
	if err := s.ensureSensor(ctx); err != nil {
		return err
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE sp_sensor SET interface = ?, span = ? WHERE id = ?`, nullStr(iface), span, id); err != nil {
			return fmt.Errorf("sensorpassive: set interface: %w", err)
		}
		detail := fmt.Sprintf("interface=%q span=%t", iface, span)
		return s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "sensor.interface_set", Target: id, Detail: detail})
	})
	if err != nil {
		return err
	}
	select {
	case s.reload <- struct{}{}:
	default: // one is already pending
	}
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// SubmitBatch records a batch of passive observations with the inventory (PRE-3, POST-3). seq must increase;
// a batch whose seq is not above the last accepted one was already applied, so it is acknowledged and not
// applied again (applied=false). Every observation must have source "passive" (INV-5).
//
// ponytail: the inventory write and the seq update are two transactions (they live in two modules); a crash
// between them replays one batch, which only repeats observations. An exactly-once guarantee would need a
// shared transaction; the remote protocol's ack_seq (sensor-protocol 5.2) covers the cross-process case.
func (s *Service) SubmitBatch(ctx context.Context, sensorID string, seq uint64, obs []observe.Observation) (applied bool, err error) {
	if sensorID != SensorID {
		return false, ErrNotFound
	}
	if seq == 0 || len(obs) > maxSubmitBatch {
		return false, fmt.Errorf("%w: seq starts at 1 and a batch has at most %d observations", ErrInvalid, maxSubmitBatch)
	}
	for i, o := range obs {
		if o.Source != observe.Passive {
			return false, fmt.Errorf("%w: observation %d has source %q, want passive", ErrInvalid, i, o.Source)
		}
	}
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if err := s.ensureSensor(ctx); err != nil {
		return false, err
	}
	var last int64
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT coalesce((SELECT last_seq FROM sp_seq WHERE sensor_id = ? AND epoch = ?), 0)`, sensorID, localEpoch).Scan(&last); err != nil {
		return false, fmt.Errorf("sensorpassive: read seq: %w", err)
	}
	if seq <= uint64(last) { //nolint:gosec // last_seq has CHECK >= 0
		return false, nil
	}
	if len(obs) > 0 {
		if err := s.sink.Record(ctx, obs); err != nil {
			return false, err
		}
	}
	return true, s.advance(ctx, seq)
}

func (s *Service) advance(ctx context.Context, seq uint64) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sp_seq (sensor_id, epoch, last_seq) VALUES (?, ?, ?)
			ON CONFLICT (sensor_id, epoch) DO UPDATE SET last_seq = max(last_seq, excluded.last_seq)`, SensorID, localEpoch, seq)
		if err != nil {
			return fmt.Errorf("sensorpassive: save seq: %w", err)
		}
		return nil
	})
}

// nextSeq hands out the number of the next batch of this sensor.
func (s *Service) nextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq
}
