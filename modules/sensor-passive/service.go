package sensorpassive

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	notReadyRetry  = 5 * time.Second  // Retry-After of 503 not_ready: the box's own cards are not known yet (D-385)
)

// Errors of Service. ErrBadInterface carries the API code "bad_interface" (INV-9); ErrUseBoxNetwork "set_in_box_network" (D-387).
var (
	ErrNotFound      = errors.New("sensorpassive: sensor not found")
	ErrBadInterface  = errors.New("sensorpassive: bad interface")
	ErrInvalid       = errors.New("sensorpassive: invalid input")
	ErrUseBoxNetwork = errors.New("sensorpassive: this box has vedette-host; the card is chosen in Settings, Box network")
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
	// Name is the sensor's display name (sp_sensor.name), asked each time the row is ensured: core gives the box's name (#471, the OS
	// host name vedette-host reports). nil: core's own host name, else "vedette"; "" from it: "vedette".
	Name func(ctx context.Context) string

	// Enabled says whether the module is on; Observations asks it again under its lock before it writes (SYS-5): a batch that was
	// let in by the listener a moment before the module was turned off is not recorded. nil means on.
	Enabled func() bool
	// KnownMACs lists the devices the inventory has. The first batch seeds core's budget with them, so that devices that exist
	// do not count as new ones after a restart. nil means none.
	KnownMACs func(ctx context.Context) ([]string, error)
	// Starting says the box is still bringing the sensor container up (its start is being retried, or was confirmed moments ago):
	// a sensor not online is then "starting", not "never_connected"/"offline" (customer walk 2, W2-6). nil: never (no host to
	// start it: a container-only install, where the customer starts it, and dev).
	Starting func() bool

	// ConfigRecheck is how often an open config long poll reads the settings again (5 s): a change of the SPAN filters is not
	// announced to it, a SetInterface is.
	ConfigRecheck time.Duration

	// The rest is for Service.Run, which production no longer starts (D-141): only the test harness uses it. It is handed to capture.Config.
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
	name     func(ctx context.Context) string
	open     func(string) (capture.Source, error)
	instance string // the nonce of this process, in every heartbeat reply

	enabled                                                        func() bool
	knownMACs                                                      func(ctx context.Context) ([]string, error)
	starting                                                       func() bool
	recheck                                                        time.Duration
	flushEvery, beatEvery, retryEvery, summaryEvery, retryAfterCap time.Duration

	ensured atomic.Pointer[string] // the name the sensor row was last written with; nil: not yet

	submitMu sync.Mutex // one batch at a time: the seq check, the write and the seq save are one step
	budget   *capture.FloodBudget
	repeats  *repeatFilter
	seeded   bool      // the budget knows the devices of the inventory
	winStart time.Time // the minute the item cap counts in
	winItems int
	seqMem   map[string]uint64 // last seq applied per epoch, in case saving it failed
	budgetAt time.Time         // when "budget exhausted" was last logged

	wakeMu sync.Mutex
	wake   chan struct{} // closed and replaced when an open config long poll should look again

	hbMu    sync.Mutex
	hb      *heartbeat      // the last heartbeat of the sensor, nil until it has sent one
	unknown map[string]bool // drops keys already reported as unknown

	runnerMu sync.Mutex
	runner   *capture.Runner // the in-process capture, built on the first Run
}

// heartbeat is what core remembers of the last heartbeat. The card list lives only here: after a restart of core it is empty
// until the sensor's next beat (at most 30 s).
type heartbeat struct {
	at         time.Time
	ifaces     []sensorlink.HeartbeatIface
	drops      map[string]int64
	version    string
	captureErr string // one of sensorlink.CaptureErrors, "" while the capture runs or no card is chosen (D-399 (3))
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Sink == nil || cfg.Host == nil {
		return nil, errors.New("sensorpassive: New needs DB, Audit, Sink and Host")
	}
	s := &Service{db: cfg.DB, audit: cfg.Audit, sink: cfg.Sink, meta: cfg.Meta, host: cfg.Host, clock: cfg.Clock, log: cfg.Log,
		version: cfg.Version, name: cfg.Name, open: cfg.Open, recheck: cfg.ConfigRecheck, flushEvery: cfg.FlushEvery,
		beatEvery: cfg.HeartbeatEvery, retryEvery: cfg.RetryEvery, summaryEvery: cfg.SummaryEvery, retryAfterCap: cfg.RetryAfterCap,
		enabled: cfg.Enabled, knownMACs: cfg.KnownMACs, starting: cfg.Starting, budget: capture.NewFloodBudget(), repeats: newRepeatFilter(), unknown: map[string]bool{}, seqMem: map[string]uint64{}, wake: make(chan struct{})}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.name == nil {
		name := "vedette"
		if h, err := os.Hostname(); err == nil && h != "" {
			name = h
		}
		s.name = func(context.Context) string { return name }
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

// ensureSensor creates the row of this box's sensor once and writes its display name again when Config.Name gives another one
// (the box's name became known, or the machine was renamed). The row's key is SensorID; the name is only shown.
func (s *Service) ensureSensor(ctx context.Context) error {
	name := s.name(ctx)
	if name == "" {
		name = "vedette"
	}
	if p := s.ensured.Load(); p != nil && *p == name {
		return nil
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sp_sensor (id, name) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET name = excluded.name`, SensorID, name); err != nil {
			return fmt.Errorf("sensorpassive: create sensor: %w", err)
		}
		return nil
	})
	if err == nil {
		s.ensured.Store(&name)
	}
	return err
}

// Sensor is one card of GET /inventory/sensors (shape: web/src/features/inventory/contract.ts).
type Sensor struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Interface   *string    `json:"interface"`
	Interfaces  []string   `json:"interfaces"`
	Span        bool       `json:"span"`
	Chosen      bool       `json:"chosen"` // Interface is a stored choice, not the default card (D-380, D-393)
	SpanStatus  SpanStatus `json:"span_status"`
	Status      string     `json:"status"` // online | offline | never_connected | starting
	LastSeen    *string    `json:"last_seen"`
	Version     *string    `json:"version"`
	DevicesSeen int        `json:"devices_seen"`
	// CaptureError is why the sensor, online, does not capture on its card (sensorlink.CaptureErrors); nil while it captures, has
	// no card, or is not online (an old heartbeat says nothing about now). D-399 (3).
	CaptureError *string `json:"capture_error"`
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

// freshBeat is the last heartbeat while it is younger than 90 seconds (the rule of online), else nil. Without a host the
// cards it lists are the box's own (D-385); an older list may name cards or addresses the box no longer has.
func (s *Service) freshBeat() *heartbeat {
	hb := s.lastBeat()
	if hb == nil || s.clock().Sub(hb.at) >= onlineWithin {
		return nil
	}
	return hb
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
// measurement; what the admin chose (interface, SPAN) is core's own. Chosen says the card is a stored choice: false while it is the
// default (D-380), so the GUI of a container-only install shows "Automatic" and never saves the default by accident (D-393).
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
			if !sensorlink.VirtualIfaceName(i.Name) { // loopback, container bridges, veth, VPN: not cards to listen on (D-393)
				names = append(names, i.Name)
			}
		}
	}
	slices.Sort(names)
	st, err := s.spanStats(ctx, r)
	if err != nil {
		return nil, err
	}
	var iface *string
	if n := s.listenOn(ctx, r); n != "" {
		iface = &n
	}
	out := Sensor{ID: SensorID, Name: r.name.String, Interface: iface, Interfaces: names, Span: r.span, Chosen: r.iface.String != "",
		SpanStatus: SpanStatus{st.Verdict, st.PPS, st.OtherMACs}, Status: "offline", LastSeen: nullable(r.lastSeen),
		Version: nullable(r.version), DevicesSeen: r.devices}
	switch {
	case s.online(r):
		out.Status = "online"
		if hb := s.lastBeat(); hb != nil && hb.captureErr != "" {
			e := hb.captureErr
			out.CaptureError = &e
		}
	case s.starting != nil && s.starting(): // the host is still starting its container (W2-6): not a failure yet
		out.Status = "starting"
	case !r.lastSeen.Valid: // offline means it reported once; never heard from is not "lost contact" (D-387)
		out.Status = "never_connected"
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
// of the box as the host reports it (Host.HostCards: the authority, D-118; never a list a sensor sent, so a sensor cannot steer
// the capture onto a card it invented); a SPAN card has no IP address. Only when no host answers (container-only install,
// D-168) the authority is the latest heartbeat of the authenticated sensor, which runs on the host network: nothing else
// sees the real cards there, and the list is bounded and validated by sensorlink. That heartbeat must be younger than 90 s
// (the rule of online, D-385): an offline sensor's old list is not the box's cards now. The choice is stored whether or not the module is on and
// whether or not the sensor has sent a heartbeat: the capture uses it once it runs. The change is audited in the same transaction
// and the config long poll is woken, so the capture moves to the new card at once.
func (s *Service) SetInterface(ctx context.Context, actor, id, iface string, span bool) error {
	if id != SensorID {
		return ErrNotFound
	}
	cards, fromHost, err := s.host.HostCards(ctx)
	if err != nil {
		return fmt.Errorf("sensorpassive: list interfaces: %w", err)
	}
	if !fromHost && iface != "" { // no host (container-only, D-168): the sensor, on the host network, is the only one that sees the real cards
		hb := s.freshBeat()
		if hb == nil {
			return fmt.Errorf("%w: the sensor has not reported its network cards in the last 90 seconds; check that it runs, wait for its next heartbeat (30 s) and try again", ErrBadInterface)
		}
		if !sensorlink.ValidIfaceName(iface) {
			return fmt.Errorf("%w: %q is not an interface name", ErrBadInterface, iface)
		}
		if sensorlink.VirtualIfaceName(iface) { // the heartbeat lists every link of the machine; Box network offers only cards (D-393)
			return fmt.Errorf("%w: %q is not a network card (loopback, container, bridge or VPN link)", ErrBadInterface, iface)
		}
		cards = cardsOfHeartbeat(hb.ifaces)
	}
	var card *capture.Interface
	for i := range cards {
		if cards[i].Name == iface {
			card = &cards[i]
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
	s.ConfigChanged()
	return nil
}

// ChooseCard is SetInterface from the GUI of a container-only install (PATCH /inventory/sensors/{id}, D-387, D-393: any card of
// the fresh heartbeat, with or without an address, SPAN or not; "" goes back to the default card): only when core
// runs without vedette-host, where the sensor's fresh heartbeat is the list of cards (D-263, D-385). With a host, or a configured
// host that gives no list, it changes nothing and returns ErrUseBoxNetwork: there the host applies the SPAN card (D-56, D-118)
// through Settings, Box network, which calls SetInterface itself.
func (s *Service) ChooseCard(ctx context.Context, actor, id, iface string, span bool) error {
	if id != SensorID {
		return ErrNotFound
	}
	if _, fromHost, err := s.host.HostCards(ctx); fromHost || err != nil {
		return ErrUseBoxNetwork
	}
	return s.SetInterface(ctx, actor, id, iface, span)
}

// listenOn is the card the sensor listens on: the one chosen (the SPAN port of Settings, Box network, or any card set by
// SetInterface), else the default (D-380). The default is never stored: it follows the management card when that changes,
// and a later choice wins over it.
func (s *Service) listenOn(ctx context.Context, r sensorRow) string {
	if r.iface.String != "" {
		return r.iface.String
	}
	name, ok := s.host.ManagementCard(ctx)
	if !ok {
		name = defaultOfHeartbeat(s.lastBeat())
	}
	if !sensorlink.ValidIfaceName(name) { // what the host or the sensor says is checked at the boundary (SYS-6)
		return ""
	}
	return name
}

// defaultOfHeartbeat is the default card without vedette-host (container-only, D-168, D-380): of the cards in the sensor's last
// heartbeat that are up and have a global IPv4 address and are cards (never loopback, a container bridge such as docker0 or
// the br-… of a compose network, veth or a VPN link: sensorlink.VirtualIfaceName, the rule of Box network, D-393), the one
// wired card, else the one card. Wireless cards (wl*, ww*) are
// taken only when nothing else is there. Two candidates is not a clear answer: "" and the sensor waits for the admin.
func defaultOfHeartbeat(hb *heartbeat) string {
	if hb == nil {
		return ""
	}
	var wired, all []string
	for _, c := range hb.ifaces {
		if !c.Link || !slices.ContainsFunc(c.IPv4, globalIPv4) || sensorlink.VirtualIfaceName(c.Name) {
			continue
		}
		all = append(all, c.Name)
		if !strings.HasPrefix(c.Name, "wl") && !strings.HasPrefix(c.Name, "ww") {
			wired = append(wired, c.Name)
		}
	}
	switch {
	case len(wired) == 1:
		return wired[0]
	case len(wired) == 0 && len(all) == 1:
		return all[0]
	}
	return ""
}

func globalIPv4(p string) bool {
	pf, err := netip.ParsePrefix(p)
	a := pf.Addr()
	return err == nil && a.Is4() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsUnspecified()
}

// cardsOfHeartbeat turns the cards of a heartbeat (already bounded and validated by sensorlink: at most 32, name, MAC and
// IPv4 prefixes checked) into the shape SetInterface checks.
func cardsOfHeartbeat(in []sensorlink.HeartbeatIface) []capture.Interface {
	out := make([]capture.Interface, 0, len(in))
	for _, c := range in {
		h := capture.Interface{Name: c.Name, MAC: c.MAC, Link: c.Link}
		for _, p := range c.IPv4 {
			if pf, err := netip.ParsePrefix(p); err == nil {
				h.Addresses = append(h.Addresses, pf)
			}
		}
		out = append(out, h)
	}
	return out
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
