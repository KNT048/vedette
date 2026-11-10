package sensorpassive

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// SensorID is the id of the one sensor of this box (D-24: no other site). It matches the mock.
const SensorID = "sn-local"

const (
	onlineWithin   = 90 * time.Second // three heartbeats of 30 s
	spanFreshness  = 30 * time.Second // a mirror that was silent this long has "no traffic"
	seenBack       = 24 * time.Hour   // an observation older than this is out of the window (sensor-protocol.md 6.2)
	seenAhead      = 5 * time.Minute  // and one further in the future
	keptEpochs     = 2                // epochs remembered per sensor
	defaultRecheck = 5 * time.Second  // how often an open config long poll looks again at what the admin chose
)

// Errors of Service. ErrBadInterface carries the API code "bad_interface" (INV-9).
var (
	ErrNotFound     = errors.New("sensorpassive: sensor not found")
	ErrBadInterface = errors.New("sensorpassive: bad interface")
	ErrInvalid      = errors.New("sensorpassive: invalid input")
)

// Config is what New needs. DB, Audit, Sink and Host are required; Meta defaults to dropping metadata.
type Config struct {
	DB      *store.DB
	Audit   *audit.Log
	Sink    observe.Sink // the inventory (INV-5); the module never writes inv_* itself
	Meta    capture.MetadataSink
	Host    Host
	Clock   func() time.Time
	Log     *slog.Logger
	Version string // of core; the in-process capture reports it as its own
	Name    string // sensor display name; default the host name

	// ConfigRecheck is how often an open config long poll reads the settings again (5 s): a change of the SPAN filters is not
	// announced to it, a SetInterface is.
	ConfigRecheck time.Duration

	// The rest is for the capture job that still runs inside core (Run) until SP-5, and for tests: it is handed to capture.Config.
	// Open opens a Source for an interface name; default capture.OpenLive.
	Open func(iface string) (capture.Source, error)
	// FlushEvery, HeartbeatEvery and RetryEvery set the loop's pace; zero means 5 s, 30 s and 5 s. SummaryEvery is how often a
	// changed drop summary is logged, 5 min. RetryAfterCap caps what a Retry-After from the core half may ask (60 s).
	FlushEvery, HeartbeatEvery, RetryEvery, SummaryEvery, RetryAfterCap time.Duration
}

// Service is the core half of the passive sensor: it serves the passive role of the sensor protocol (Config, Observations,
// PassiveHeartbeat; see Backend), keeps what the sensor reported, and answers the API. The capture itself runs in another process
// (vedette-sensor passive, package capture) or, until SP-5, inside this one (Run). Create it with New.
type Service struct {
	db       *store.DB
	audit    *audit.Log
	sink     observe.Sink
	meta     capture.MetadataSink
	host     Host
	clock    func() time.Time
	log      *slog.Logger
	version  string
	name     string
	open     func(string) (capture.Source, error)
	instance string // the nonce of this process, in every heartbeat reply

	recheck                                                        time.Duration
	flushEvery, beatEvery, retryEvery, summaryEvery, retryAfterCap time.Duration

	submitMu sync.Mutex // one batch at a time: the seq check, the write and the seq save are one step
	budget   *capture.FloodBudget
	seqMem   map[string]uint64 // last seq applied per epoch, in case saving it failed
	budgetAt time.Time         // when "budget exhausted" was last logged

	wakeMu sync.Mutex
	wake   chan struct{} // closed and replaced when an open config long poll should look again

	hbMu sync.Mutex
	hb   *heartbeat // the last heartbeat of the sensor, nil until it has sent one

	runnerMu sync.Mutex
	runner   *capture.Runner // the in-process capture, built on the first Run
}

// heartbeat is what core remembers of the last heartbeat. The card list lives only here: after a restart of core it is empty
// until the sensor's next beat (at most 30 s).
type heartbeat struct {
	at      time.Time
	ifaces  []sensorlink.HeartbeatIface
	drops   map[string]int64
	version string
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Sink == nil || cfg.Host == nil {
		return nil, errors.New("sensorpassive: New needs DB, Audit, Sink and Host")
	}
	s := &Service{db: cfg.DB, audit: cfg.Audit, sink: cfg.Sink, meta: cfg.Meta, host: cfg.Host, clock: cfg.Clock, log: cfg.Log,
		version: cfg.Version, name: cfg.Name, open: cfg.Open, recheck: cfg.ConfigRecheck, flushEvery: cfg.FlushEvery,
		beatEvery: cfg.HeartbeatEvery, retryEvery: cfg.RetryEvery, summaryEvery: cfg.SummaryEvery, retryAfterCap: cfg.RetryAfterCap,
		budget: capture.NewFloodBudget(), seqMem: map[string]uint64{}, wake: make(chan struct{})}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.name == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			s.name = h
		} else {
			s.name = "vedette"
		}
	}
	if s.version == "" {
		s.version = "0.0.0-dev"
	}
	if s.recheck <= 0 {
		s.recheck = defaultRecheck
	}
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24)
	s.instance = hex.EncodeToString(b[:])
	return s, nil
}

// ensureSensor creates the row of this box's sensor once and refreshes its name.
func (s *Service) ensureSensor(ctx context.Context) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sp_sensor (id, name) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET name = excluded.name`, SensorID, s.name); err != nil {
			return fmt.Errorf("sensorpassive: create sensor: %w", err)
		}
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

func (s *Service) lastBeat() *heartbeat {
	s.hbMu.Lock()
	defer s.hbMu.Unlock()
	return s.hb
}

// online reports whether the sensor has sent a heartbeat in the last 90 seconds (sensor-protocol.md 6.3).
func (s *Service) online(r sensorRow) bool {
	if !r.lastSeen.Valid {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, r.lastSeen.String)
	return err == nil && s.clock().Sub(t) < onlineWithin
}

// Status lists the sensors of this box (GET /inventory/sensors): at most one. Everything about the sensor comes from its
// heartbeat (D-112 (5)): online within 90 s of the last one, its version, devices heard, the cards it reported and the SPAN
// measurement; what the admin chose (interface, SPAN) is core's own.
func (s *Service) Status(ctx context.Context) ([]Sensor, error) {
	if err := s.ensureSensor(ctx); err != nil {
		return nil, err
	}
	r, err := s.row(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	names := []string{}
	if hb := s.lastBeat(); hb != nil {
		for _, i := range hb.ifaces {
			names = append(names, i.Name)
		}
	}
	slices.Sort(names)
	st, err := s.spanStats(ctx, r)
	if err != nil {
		return nil, err
	}
	out := Sensor{ID: SensorID, Name: r.name.String, Interface: nullable(r.iface), Interfaces: names, Span: r.span,
		SpanStatus: SpanStatus{st.Verdict, st.PPS, st.OtherMACs}, Status: "offline", LastSeen: nullable(r.lastSeen),
		Version: nullable(r.version), DevicesSeen: r.devices}
	if s.online(r) {
		out.Status = "online"
	}
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
	return s.spanStats(ctx, r)
}

// spanStats: what the sensor measured and reported in its last heartbeat, never a guess (D-112 (5)). A sensor that has not
// reported for 90 seconds measured nothing: a SPAN sensor that is not listening has no traffic.
func (s *Service) spanStats(ctx context.Context, r sensorRow) (SpanStats, error) {
	if !r.span {
		return SpanStats{Verdict: VerdictOff}, nil
	}
	if !s.online(r) {
		return SpanStats{Verdict: VerdictNoTraffic}, nil
	}
	if hb := s.lastBeat(); hb != nil {
		for _, i := range hb.ifaces {
			if i.Name == r.iface.String && !i.Link {
				return SpanStats{Verdict: VerdictNoLink}, nil
			}
		}
	}
	var pps, others int
	var last sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT packets_per_s, other_macs, last_packet_at FROM sp_span_stat WHERE sensor_id = ?`, SensorID).Scan(&pps, &others, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return SpanStats{Verdict: VerdictNoTraffic}, nil
	}
	if err != nil {
		return SpanStats{}, fmt.Errorf("sensorpassive: read SPAN measurement: %w", err)
	}
	st := SpanStats{PPS: pps, OtherMACs: others}
	if last.Valid {
		st.LastPacket, _ = time.Parse(time.RFC3339Nano, last.String)
	}
	now := s.clock()
	switch {
	case st.LastPacket.IsZero() || now.Sub(st.LastPacket) > spanFreshness:
		st.Verdict, st.PPS = VerdictNoTraffic, 0
	case others == 0:
		st.Verdict = VerdictOwnOnly // INV-9: packets arrive, but only the box's own
	default:
		st.Verdict = VerdictOK
	}
	return st, nil
}

// SetInterface chooses the card the sensor listens on and whether it is a SPAN port (PRE-2, POST-2, INV-9). iface must be a card
// the sensor itself reported in its last heartbeat (a list in a heartbeat that was never sent, or a name the sensor did not
// list, steers nothing); a SPAN card has no IP address. The change is audited in the same transaction and the config long poll
// is woken, so the capture moves to the new card at once.
func (s *Service) SetInterface(ctx context.Context, actor, id, iface string, span bool) error {
	if id != SensorID {
		return ErrNotFound
	}
	var card *sensorlink.HeartbeatIface
	if hb := s.lastBeat(); hb != nil {
		for i := range hb.ifaces {
			if hb.ifaces[i].Name == iface {
				card = &hb.ifaces[i]
			}
		}
	}
	switch {
	case iface == "" && span:
		return fmt.Errorf("%w: a SPAN port needs an interface", ErrBadInterface)
	case iface != "" && card == nil:
		return fmt.Errorf("%w: %q is not an interface the sensor reported", ErrBadInterface, iface)
	case span && len(card.IPv4) > 0:
		return fmt.Errorf("%w: %q has an IP address; a SPAN port has none", ErrBadInterface, iface)
	}
	if err := s.ensureSensor(ctx); err != nil {
		return err
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE sp_sensor SET interface = ?, span = ? WHERE id = ?`, nullStr(iface), span, id); err != nil {
			return fmt.Errorf("sensorpassive: set interface: %w", err)
		}
		detail := fmt.Sprintf("interface=%q span=%t", iface, span)
		return s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "sensor.interface_set", Target: id, Detail: detail})
	})
	if err != nil {
		return err
	}
	s.ConfigChanged()
	return nil
}

// ConfigChanged wakes the open config long poll: the settings the sensor is told changed (the SPAN card here; the Box network
// page may call it when it saves filters, instead of waiting for the next look).
func (s *Service) ConfigChanged() {
	s.wakeMu.Lock()
	close(s.wake)
	s.wake = make(chan struct{})
	s.wakeMu.Unlock()
}

func (s *Service) wakeCh() <-chan struct{} {
	s.wakeMu.Lock()
	defer s.wakeMu.Unlock()
	return s.wake
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
