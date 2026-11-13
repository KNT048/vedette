package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
)

// NetHost is what the Box network screen needs of vedette-host (docs/specs/host-api.md 5 and 6.5).
// *client.Client implements it; a test gives a fake. A nil NetHost is an install without the helper
// ("container only", D-55): every /core/network route then answers 409 not_appliance.
type NetHost interface {
	StateNet(ctx context.Context) (api.NetState, error)
	NetApply(ctx context.Context, args api.NetApplyArgs, requestID, actor string) (api.Run, error)
	NetConfirm(ctx context.Context, runID, requestID, actor string) (api.Run, error)
	NetRevert(ctx context.Context, runID, requestID, actor string) (api.Run, error)
	GetRun(ctx context.Context, runID string) (api.Run, error)
	Events(ctx context.Context, runID string, after uint64) *client.Stream
}

var _ NetHost = (*client.Client)(nil)

// SpanMeasure is what the passive sensor measured on the SPAN port: the one thing the host cannot count (the
// number of other MAC addresses and the time of the last packet need a look at the traffic, D-101).
type SpanMeasure struct {
	Verdict    string // off, ok, own_only, no_traffic or no_link
	PPS        int
	OtherMACs  int
	LastPacket time.Time // zero when none yet
}

// ErrNoSensor is what a SpanSensor returns when nothing measures (the module is off): the page then shows what
// the host's counters say.
var ErrNoSensor = errors.New("core: no sensor is measuring the SPAN port")

// SpanSensor is the port to the passive sensor (module sensor-passive). Both calls are best effort: the page
// works without it.
type SpanSensor interface {
	// SpanStats returns the measured health of the mirrored traffic.
	SpanStats(ctx context.Context) (SpanMeasure, error)
	// SetSpanPort tells the sensor which card to listen on; iface "" with span false stops it.
	SetSpanPort(ctx context.Context, actor, iface string, span bool) error
}

// NetworkConfig wires NetworkHandlers. DB, Auth, Audit and Log are required; Host may be nil.
type NetworkConfig struct {
	DB    *store.DB
	Auth  *auth.Service
	Audit *audit.Log
	Log   *slog.Logger
	Host  NetHost
	// Sensor measures the SPAN port; nil: the page shows the host's counters only.
	Sensor SpanSensor
	// AddressInUse says whether a device of the inventory already has the address (409 ip_in_use); nil: not asked.
	AddressInUse func(ctx context.Context, ip netip.Addr) (bool, error)
	// AddressesChanged is called after the box's own addresses may have changed (an apply, a confirm, a revert, a
	// timeout): the caches of cmd/vedette that hold them (conn, sensor-active, honeypot) must read them again.
	AddressesChanged func()
	// AfterFunc runs f after d (nil: time.AfterFunc); the tests hold it back.
	AfterFunc func(d time.Duration, f func())
	Clock     func() time.Time // nil: time.Now
	// Gate is shut while a factory reset runs: every host write then answers 409 busy (N4). nil = never shut.
	Gate *PurgeGate
}

// NetworkHandlers implements the Box network operations of Settings (S-CORE-8, D-56: /core/network*; the routes
// belong to the host module, whose handlers these are) on top of vedette-host. Every change is one net.apply with the
// whole desired state: core merges the part the person changed into what the host reports as running, and keeps
// only what the host does not know (the SPAN switches, filters and limits, and the old address of a change that
// waits for confirmation). Nothing here runs a command itself (SYS-1).
type NetworkHandlers struct {
	gate    *PurgeGate
	db      *store.DB
	auth    *auth.Service
	audit   *audit.Log
	log     *slog.Logger
	host    NetHost
	sensor  SpanSensor
	taken   func(ctx context.Context, ip netip.Addr) (bool, error)
	changed func()
	now     func() time.Time

	mu       sync.Mutex // one change at a time, from the first read to the host's answer; never taken by a read
	settleMu sync.Mutex // one settling of a finished pending change
	cache    struct {
		sync.Mutex
		st     api.NetState
		at     time.Time
		ok     bool
		flight *stateFlight   // the one read of the host that everybody without a fresh-read need waits for
		gen    uint64         // bumped by every fresh read and every change of addresses: an older read must not fill the cache
		pps    map[string]int // packets per second of each card, from the last two readings (one sample per reading)
		prev   map[string]rxSample
	}
	cardsMu   sync.Mutex
	lastCards []Card // the last list of cards the host gave (Cards)
	lastMgmt  string // the last management card the host gave (ManagementCard)
	// ManagementLAN, for the public setup page: the last answer and when a read for it last began (one per netReadTTL).
	lanAt time.Time
	lan   netip.Prefix
	lanOK bool
	sensorMu  sync.Mutex
	sensorOn  string // the SPAN port the sensor was last told to use ("eth1/true", "/false"); "" before the first time
	after     func(d time.Duration, f func())
}

type stateFlight struct {
	done chan struct{}
	st   api.NetState
	err  error
}

type rxSample struct {
	rx uint64
	at time.Time
}

// NewNetworkHandlers returns the handlers.
func NewNetworkHandlers(c NetworkConfig) (*NetworkHandlers, error) {
	if c.DB == nil || c.Auth == nil || c.Audit == nil || c.Log == nil {
		return nil, errors.New("core: NetworkConfig needs DB, Auth, Audit and Log")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	h := &NetworkHandlers{gate: c.Gate, db: c.DB, auth: c.Auth, audit: c.Audit, log: c.Log, host: c.Host, sensor: c.Sensor, taken: c.AddressInUse, changed: c.AddressesChanged, now: c.Clock}
	h.cache.pps, h.cache.prev = map[string]int{}, map[string]rxSample{}
	h.after = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
	if c.AfterFunc != nil {
		h.after = c.AfterFunc
	}
	return h, nil
}

const (
	keyNetSpan    = "core_network_span"
	keyNetPending = "core_network_pending"

	netReadTTL      = 6 * time.Second // longer than the 5 s poll of span/status: the host allows 60 requests a minute for all of core
	netReadTimeout  = 15 * time.Second
	netApplyLimit   = 150 * time.Second // host-api 10: net.apply takes up to 120 s before it waits for the confirmation
	netConfirmLimit = 75 * time.Second  // net.confirm and net.revert: 60 s
	confirmWindow   = 300               // seconds the person has to confirm from the new address, signing in again there (S-CORE-8, D-118)
	netIfaceListMax = 64
)

func notApplianceNet() *apierr.Error {
	return apierr.New(409, CodeNotAppliance, "This install has no operating system helper (container-only install), so Vedette cannot change the box's network from here.")
}

func (h *NetworkHandlers) needHost() error {
	if h.host == nil {
		return notApplianceNet()
	}
	return nil
}

// netErr is hostErr with the sentence of this screen for a box that has no helper.
func (h *NetworkHandlers) netErr(ctx context.Context, err error) error {
	if errors.Is(err, client.ErrUnreachable) && errors.Is(err, fs.ErrNotExist) {
		return notApplianceNet()
	}
	var he *client.Error
	if errors.As(err, &he) && (he.Code == api.CodePendingConfirm || he.Code == api.CodeNetPendingConfirm) {
		return errChangePending()
	}
	return hostErr(ctx, h.log, err)
}

// ---- stored settings ----

// SpanExtract says what is read from mirrored traffic (packet contents are never stored).
type SpanExtract struct {
	DNS      bool `json:"dns"`
	TLSSNI   bool `json:"tls_sni"`
	HTTPHost bool `json:"http_host"`
	Flows    bool `json:"flows"`
}

// SpanSettings is what core keeps of the SPAN capture: the host only knows which card it is.
type SpanSettings struct {
	Enabled    bool         `json:"enabled"`
	Extract    SpanExtract  `json:"extract"`
	Filters    []SpanFilter `json:"filters"`
	CPUPercent int          `json:"cpu_percent"`
	MemoryMB   int          `json:"memory_mb"`
}

func defaultSpan() SpanSettings {
	return SpanSettings{Extract: SpanExtract{DNS: true, TLSSNI: true, HTTPHost: true, Flows: true}, Filters: []SpanFilter{}, CPUPercent: 25, MemoryMB: 512}
}

// SpanSettings returns the stored SPAN settings (the defaults before the first save). The passive sensor reads
// its extraction switches and exclusion filters from here.
func (h *NetworkHandlers) SpanSettings(ctx context.Context) (SpanSettings, error) {
	if h == nil {
		return defaultSpan(), nil
	}
	s := defaultSpan()
	if err := loadSetting(ctx, h.db, keyNetSpan, &s); err != nil {
		return SpanSettings{}, err
	}
	if s.Filters == nil {
		s.Filters = []SpanFilter{}
	}
	return s, nil
}

// pendingRecord is what core remembers of a management change that waits: the host tells that one waits and
// until when, not what the address was before.
type pendingRecord struct {
	RunID           string  `json:"run_id"`
	PreviousAddress *string `json:"previous_address"`
}

func (h *NetworkHandlers) pendingRecord(ctx context.Context) (*pendingRecord, error) {
	var r pendingRecord
	if err := loadSetting(ctx, h.db, keyNetPending, &r); err != nil {
		return nil, err
	}
	if r.RunID == "" {
		return nil, nil
	}
	return &r, nil
}

// putSettingTx stores one JSON object under a core_setting key in the caller's transaction.
func putSettingTx(ctx context.Context, tx *sql.Tx, key string, v any, at time.Time, by string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("core: encode setting %s: %w", key, err)
	}
	if err := coredb.New(tx).UpsertSetting(ctx, coredb.UpsertSettingParams{Key: key, Value: string(b), UpdatedAt: store.FormatTS(at), UpdatedBy: by}); err != nil {
		return fmt.Errorf("core: write setting %s: %w", key, err)
	}
	return nil
}

func unmarshalSetting(key, raw string, into any) error {
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return fmt.Errorf("core: setting %s is not valid: %w", key, err)
	}
	return nil
}

func loadSetting(ctx context.Context, db *store.DB, key string, into any) error {
	var raw string
	err := db.Reader().QueryRowContext(ctx, `SELECT value FROM core_setting WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("core: read setting %s: %w", key, err)
	}
	return unmarshalSetting(key, raw, into)
}

// ---- reading the host ----

// state reads state/net. The host allows 60 requests a minute for all of core, and a page polls: a read is kept for
// netReadTTL (longer than the 5 s poll) and readers that arrive during a read share it. fresh (every write, and
// the read that decides a confirm) neither uses nor joins them. Every successful reading is one sample for the
// packets-per-second of the cards.
func (h *NetworkHandlers) state(ctx context.Context, fresh bool) (api.NetState, error) {
	h.cache.Lock()
	if !fresh {
		if h.cache.ok && h.now().Sub(h.cache.at) < netReadTTL {
			st := h.cache.st
			h.cache.Unlock()
			return st, nil
		}
		if f := h.cache.flight; f != nil {
			h.cache.Unlock()
			select {
			case <-f.done:
				return f.st, f.err
			case <-ctx.Done():
				return api.NetState{}, ctx.Err()
			}
		}
	}
	f := &stateFlight{done: make(chan struct{})}
	if !fresh {
		h.cache.flight = f
	} else {
		h.cache.gen++
	}
	h.cache.ok = false
	gen := h.cache.gen
	h.cache.Unlock()

	// One call for everybody: it must not die with the first caller's context.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), netReadTimeout)
	st, err := h.host.StateNet(rctx)
	cancel()
	if err != nil {
		err = h.netErr(ctx, err)
	}

	h.cache.Lock()
	if h.cache.flight == f {
		h.cache.flight = nil
	}
	if err == nil && gen == h.cache.gen {
		h.cache.st, h.cache.at, h.cache.ok = st, h.now(), true
		h.sample(st)
	}
	h.cache.Unlock()
	f.st, f.err = st, err
	close(f.done)
	return st, err
}

// sample records the receive counters of this reading (h.cache is held): packets per second is the rise since the
// reading before, kept when the two are less than half a second apart.
func (h *NetworkHandlers) sample(st api.NetState) {
	now := h.now()
	for _, c := range st.Interfaces {
		prev, ok := h.cache.prev[c.Name]
		h.cache.prev[c.Name] = rxSample{rx: c.Counters.RxPackets, at: now}
		dt := now.Sub(prev.at).Seconds()
		switch {
		case !ok || c.Counters.RxPackets < prev.rx:
			h.cache.pps[c.Name] = 0
		case dt >= 0.5:
			h.cache.pps[c.Name] = int(float64(c.Counters.RxPackets-prev.rx)/dt + 0.5)
		}
	}
}

func (h *NetworkHandlers) packetsPerSecond(c *api.NetInterface) int {
	h.cache.Lock()
	defer h.cache.Unlock()
	return h.cache.pps[c.Name]
}

// cardsOf keeps the cards and the two roles: vedette-host lists every interface that has an address (core must know them
// all as "the box"), but a link that is not a card (sensorlink.VirtualIfaceName: container and virtual links, bridges,
// bonds, VLANs, the box's own bridge vedette0; #471) is not offered.
func cardsOf(st api.NetState) []api.NetInterface {
	var out []api.NetInterface
	for _, i := range st.Interfaces {
		if i.Role != "" || !sensorlink.VirtualIfaceName(i.Name) {
			out = append(out, i)
		}
	}
	if len(out) > netIfaceListMax {
		out = out[:netIfaceListMax]
	}
	return out
}

func cardNamed(st api.NetState, name string) *api.NetInterface {
	for i := range st.Interfaces {
		if st.Interfaces[i].Name == name {
			return &st.Interfaces[i]
		}
	}
	return nil
}

// ipv4Of returns the first global IPv4 address of a card as a prefix.
func ipv4Of(c *api.NetInterface) (netip.Prefix, bool) {
	if c == nil {
		return netip.Prefix{}, false
	}
	for _, s := range c.Addresses {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() && !p.Addr().IsLinkLocalUnicast() {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// mgmtIface is the name of the management card: the host's role, else the card of the default route.
func mgmtIface(st api.NetState) string {
	if m := st.Config.Mgmt; m != nil && m.Iface != "" {
		return m.Iface
	}
	for _, i := range st.Interfaces {
		if i.Role == api.NetRoleManagement {
			return i.Name
		}
	}
	if st.DefaultRoute != nil {
		return st.DefaultRoute.Iface
	}
	// No configuration and no default route: the one card that has an address, when there is exactly one.
	only := ""
	for _, c := range cardsOf(st) {
		if _, ok := ipv4Of(&c); ok {
			if only != "" {
				return ""
			}
			only = c.Name
		}
	}
	return only
}

func spanIface(st api.NetState) string {
	if st.Config.SPAN != nil {
		return *st.Config.SPAN
	}
	for _, i := range st.Interfaces {
		if i.Role == api.NetRoleSPAN {
			return i.Name
		}
	}
	return ""
}

// ---- views (the shape of NetworkState in web/src/features/core/contract.ts) ----

type netIfaceView struct {
	Name    string  `json:"name"`
	Role    string  `json:"role"`
	Link    bool    `json:"link"`
	Speed   *string `json:"speed"`
	MAC     string  `json:"mac"`
	Address *string `json:"address"`
}

type netMgmtView struct {
	Mode    string   `json:"mode"`
	Address *string  `json:"address"`
	Prefix  *int     `json:"prefix"`
	Gateway *string  `json:"gateway"`
	DNS     []string `json:"dns"`
}

type netSpanView struct {
	Enabled    bool         `json:"enabled"`
	Interface  *string      `json:"interface"`
	Extract    SpanExtract  `json:"extract"`
	Filters    []SpanFilter `json:"filters"`
	CPUPercent int          `json:"cpu_percent"`
	MemoryMB   int          `json:"memory_mb"`
}

type spanStatusView struct {
	Verdict      string  `json:"verdict"`
	Interface    *string `json:"interface"`
	PacketsPerS  int     `json:"packets_per_s"`
	OtherMACs    int     `json:"other_macs"`
	LastPacketAt *string `json:"last_packet_at"`
}

type netNTPView struct {
	Mode    string   `json:"mode"`
	Servers []string `json:"servers"`
}

type netPendingView struct {
	ExpiresAt       string  `json:"expires_at"`
	PreviousAddress *string `json:"previous_address"`
	WindowS         int     `json:"window_s"`
	RebootAt        *string `json:"reboot_at"`
}

type netView struct {
	Interfaces []netIfaceView  `json:"interfaces"`
	Management netMgmtView     `json:"management"`
	Span       netSpanView     `json:"span"`
	SpanStatus spanStatusView  `json:"span_status"`
	NTP        netNTPView      `json:"ntp"`
	DefaultNTP string          `json:"default_ntp"`
	DecoyIPs   []string        `json:"decoy_ips"`
	Pending    *netPendingView `json:"pending"`
}

const defaultNTPPool = "pool.ntp.org"

func refTo[T any](v T) *T { return &v }

func speedText(mbps *int) *string {
	if mbps == nil || *mbps <= 0 {
		return nil
	}
	if *mbps >= 1000 {
		g := float64(*mbps) / 1000
		return refTo(strings.TrimSuffix(strconv.FormatFloat(g, 'f', 1, 64), ".0") + " Gb/s")
	}
	return refTo(strconv.Itoa(*mbps) + " Mb/s")
}

func mgmtViewOf(st api.NetState) netMgmtView {
	card := cardNamed(st, mgmtIface(st))
	v := netMgmtView{Mode: api.NetModeStatic, DNS: []string{}}
	cfg := st.Config.Mgmt
	if cfg != nil && cfg.Mode == api.NetModeStatic {
		v.DNS = slices.Clone(cfg.DNS)
		if p, err := netip.ParsePrefix(cfg.Address); err == nil {
			v.Address, v.Prefix = refTo(p.Addr().String()), refTo(p.Bits())
		}
		if cfg.Gateway != "" {
			v.Gateway = refTo(cfg.Gateway)
		}
		return v
	}
	// DHCP, or a box the host has not configured yet: what the card has now. With no configuration of the host the mode is
	// what the kernel says of the card's address: DHCP when it has a lease (`ip address` "dynamic"), static otherwise (an
	// installer's fixed address, or a host older than D-405 that does not say).
	p, ok := ipv4Of(card)
	if cfg != nil || (ok && slices.Contains(card.Dynamic, p.String())) {
		v.Mode = api.NetModeDHCP
	}
	if ok {
		v.Address, v.Prefix = refTo(p.Addr().String()), refTo(p.Bits())
	}
	if st.DefaultRoute != nil && card != nil && st.DefaultRoute.Iface == card.Name && st.DefaultRoute.Gateway != "" {
		v.Gateway = refTo(st.DefaultRoute.Gateway)
	}
	v.DNS = dnsInUse(st)
	if len(v.DNS) == 0 && cfg != nil {
		v.DNS = slices.Clone(cfg.DNS)
	}
	if v.DNS == nil {
		v.DNS = []string{}
	}
	return v
}

// dnsInUse are the DNS servers the box's resolver uses now (a DHCP lease's or the installer's; D-405), as the static form
// takes them: IPv4 only, at most 3.
func dnsInUse(st api.NetState) []string {
	out := []string{}
	for _, s := range st.Resolvers {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() && len(out) < 3 {
			out = append(out, a.String())
		}
	}
	return out
}

func (h *NetworkHandlers) composeNet(st api.NetState, rec *pendingRecord, sp SpanSettings, status spanStatusView) netView {
	m := mgmtViewOf(st)
	mgmt := mgmtIface(st)
	span := spanIface(st)
	v := netView{Management: m, SpanStatus: status, DefaultNTP: defaultNTPPool, Interfaces: []netIfaceView{}, DecoyIPs: []string{}}
	for _, c := range cardsOf(st) {
		iv := netIfaceView{Name: c.Name, Role: "unused", Link: c.State == "up", Speed: speedText(c.SpeedMbps), MAC: c.MAC}
		switch c.Name {
		case mgmt:
			iv.Role = api.NetRoleManagement
			if m.Address != nil && m.Prefix != nil {
				iv.Address = refTo(*m.Address + "/" + strconv.Itoa(*m.Prefix))
			}
		case span:
			iv.Role = api.NetRoleSPAN
		}
		if p, ok := ipv4Of(&c); ok && iv.Address == nil { // any other card shows the address it has now (a Wi-Fi card's lease, walk 4)
			iv.Address = refTo(p.String())
		}
		v.Interfaces = append(v.Interfaces, iv)
	}
	sv := netSpanView{Enabled: sp.Enabled && span != "", Extract: sp.Extract, Filters: sp.Filters, CPUPercent: sp.CPUPercent, MemoryMB: sp.MemoryMB}
	if span != "" {
		sv.Interface = refTo(span)
	}
	v.Span = sv
	v.NTP = netNTPView{Mode: "default", Servers: []string{}}
	if len(st.Config.NTP) > 0 {
		v.NTP = netNTPView{Mode: "custom", Servers: slices.Clone(st.Config.NTP)}
	}
	for _, d := range st.Decoys {
		v.DecoyIPs = append(v.DecoyIPs, d.IP)
	}
	if p := st.Pending; p != nil {
		pv := &netPendingView{ExpiresAt: store.FormatTS(p.RevertAt.UTC()), WindowS: confirmWindow}
		if rec != nil {
			pv.PreviousAddress = rec.PreviousAddress
		}
		if p.RebootAt != nil {
			pv.RebootAt = refTo(store.FormatTS(p.RebootAt.UTC()))
		}
		v.Pending = pv
	}
	return v
}

// ---- the page ----

// view reads the host and puts core's own settings with it.
func (h *NetworkHandlers) view(ctx context.Context, fresh bool) (netView, error) {
	st, err := h.state(ctx, fresh)
	if err != nil {
		return netView{}, err
	}
	rec, _, err := h.settle(ctx, st)
	if err != nil {
		return netView{}, err
	}
	sp, err := h.SpanSettings(ctx)
	if err != nil {
		return netView{}, err
	}
	return h.composeNet(st, rec, sp, h.spanStatus(ctx, st, sp)), nil
}

// spanStatus is the health of the mirrored traffic. What only a look at the traffic can say (other MACs, the last
// packet) comes from the sensor; the host's counters give the card's link and its packets per second. With no
// sensor measuring, a SPAN card that receives packets is called ok: the card has no IP address and sends nothing,
// so what arrives is mirrored (ponytail: counters cannot tell a working mirror from a flood of the box's own frames;
// the sensor can).
func (h *NetworkHandlers) spanStatus(ctx context.Context, st api.NetState, sp SpanSettings) spanStatusView {
	iface := spanIface(st)
	out := spanStatusView{Verdict: "off"}
	if iface != "" {
		out.Interface = refTo(iface)
	}
	card := cardNamed(st, iface)
	if !sp.Enabled || card == nil {
		return out
	}
	if card.State != "up" {
		out.Verdict = "no_link"
		return out
	}
	pps := h.packetsPerSecond(card)
	if h.sensor != nil {
		// The sensor must be listening where the page says (a save may have failed to tell it, or it restarted):
		// try again at every look, and say so while it cannot be done.
		if err := h.syncSensor(ctx, "system", iface, sp, false); err != nil {
			out.Verdict = "sensor_unreachable"
			return out
		}
		m, err := h.sensor.SpanStats(ctx)
		if err == nil && m.Verdict == "off" { // it says it is not capturing although it was just told to
			if err := h.syncSensor(ctx, "system", iface, sp, true); err != nil {
				out.Verdict = "sensor_unreachable"
				return out
			}
			out.Verdict = "no_traffic" // told again: the numbers come with the next look, never "ok" from the counters
			return out
		}
		if err == nil && m.Verdict != "no_link" {
			out.Verdict, out.PacketsPerS, out.OtherMACs = m.Verdict, m.PPS, m.OtherMACs
			if !m.LastPacket.IsZero() {
				out.LastPacketAt = refTo(store.FormatTS(m.LastPacket.UTC()))
			}
			return out
		}
		if err != nil && !errors.Is(err, ErrNoSensor) {
			h.log.WarnContext(ctx, "core: the SPAN sensor did not answer; showing the host's counters", "error", err)
		}
	}
	if pps == 0 {
		out.Verdict = "no_traffic"
		return out
	}
	out.Verdict, out.PacketsPerS = "ok", pps // the host cannot tell when the last packet came: last_packet_at stays null
	return out
}

// settle ends the bookkeeping of a change that is no longer waiting at the host (confirmed from another request,
// cancelled, timed out, the box restarted): core's record is removed, the box's addresses are read again, and a
// change that went back is audited once. It returns the record of the change that still waits, if any.
func (h *NetworkHandlers) settle(ctx context.Context, st api.NetState) (rec *pendingRecord, wentBack bool, err error) {
	rec, err = h.pendingRecord(ctx)
	if err != nil {
		return nil, false, err
	}
	if st.Pending != nil {
		if rec != nil && rec.RunID != st.Pending.RunID {
			return nil, false, nil // a change core did not record (its record was lost): the old address is unknown
		}
		return rec, false, nil
	}
	if rec == nil {
		return nil, false, nil
	}
	h.settleMu.Lock()
	defer h.settleMu.Unlock()
	cur, err := h.pendingRecord(ctx)
	if err != nil || cur == nil || cur.RunID != rec.RunID {
		return nil, false, err // somebody settled it meanwhile
	}
	// Only a run that has ended settles the record. While the run is still going (a confirm is being made right
	// now), or when the host cannot be asked, nothing is written and the next read tries again: a failed read
	// is never "it went back".
	why := "the host has no record of the change any more"
	reverted := true
	run, gerr := h.host.GetRun(ctx, rec.RunID)
	var he *client.Error
	switch {
	case gerr == nil && !run.Status.Terminal():
		return nil, false, nil
	case gerr == nil && run.Status == api.StatusSucceeded:
		reverted = false
	case gerr == nil && run.Error != nil:
		why = netEnding(run.Error.Code)
	case gerr == nil:
		why = "the box went back to the old settings"
	case errors.As(gerr, &he) && he.Code == api.CodeRunNotFound: // pruned by the host: the record cannot be settled any other way
	default:
		return nil, false, nil
	}
	wctx := context.WithoutCancel(ctx)
	err = h.db.Write(wctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(wctx, `DELETE FROM core_setting WHERE key = ?`, keyNetPending); err != nil {
			return fmt.Errorf("core: drop the pending network change: %w", err)
		}
		if !reverted {
			return nil
		}
		return h.audit.Append(wctx, tx, audit.Entry{User: "system", Action: "network.management_reverted", Target: "management interface", Detail: why})
	})
	if err != nil {
		return nil, false, err
	}
	h.addressesChanged()
	return nil, reverted, nil
}

// netEnding is how an ending of the run is written in the audit log.
func netEnding(code string) string {
	switch code {
	case api.CodeNotConfirmed:
		return "not confirmed in time"
	case api.CodeCancelled:
		return "cancelled by administrator"
	case api.CodeRevertedByReboot:
		return "the box restarted before the change was confirmed"
	}
	return "the box went back to the old settings (" + code + ")"
}

func (h *NetworkHandlers) addressesChanged() {
	h.cache.Lock()
	h.cache.ok = false
	h.cache.gen++
	h.cache.Unlock()
	if h.changed != nil {
		h.changed()
	}
}

// ---- reads ----

// CoreGetCoreNetwork implements GET /core/network (viewer).
func (h *NetworkHandlers) CoreGetCoreNetwork(ctx context.Context) (*oas.CoreGetCoreNetworkOK, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	v, err := h.view(ctx, false)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CoreGetCoreNetworkOK](v)
}

// CoreGetCoreNetworkSpanStatus implements GET /core/network/span/status (viewer).
func (h *NetworkHandlers) CoreGetCoreNetworkSpanStatus(ctx context.Context) (*oas.CoreGetCoreNetworkSpanStatusOK, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	st, err := h.state(ctx, false)
	if err != nil {
		return nil, err
	}
	sp, err := h.SpanSettings(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CoreGetCoreNetworkSpanStatusOK](h.spanStatus(ctx, st, sp))
}

// ---- writing ----

// desired is the whole state net.apply takes: the part Vedette manages.
type desired struct {
	mgmt api.NetApplyMgmt
	span *string
	ntp  []string
}

// currentDesired is what the host reports as running, as a net.apply state. ok is false when the host has not
// written a configuration yet: there is then nothing to merge a SPAN or NTP change into, and the first change
// must be the management one (a static address the person has seen and confirmed).
func currentDesired(st api.NetState) (d desired, ok bool) {
	c := st.Config.Mgmt
	if c == nil {
		return desired{}, false
	}
	d.mgmt = api.NetApplyMgmt{Iface: c.Iface, Mode: c.Mode, Address: c.Address, Gateway: c.Gateway, DNS: slices.Clone(c.DNS)}
	d.span = st.Config.SPAN
	d.ntp = slices.Clone(st.Config.NTP)
	return d, true
}

func errChangePending() *apierr.Error {
	return apierr.New(409, CodeChangePending, "A change is waiting for confirmation. Confirm it from the new address or cancel it first.")
}

// errManagementUnknown is for a box that has no configuration of the host's, no default route and more than one
// card with an address: there is no telling which card the person reaches the page through.
func errManagementUnknown() *apierr.Error {
	return apierr.New(409, CodeManagementNotSet, "Vedette cannot tell which network card is the management card: several cards have an address and the box has no default route. Give the box a default route (or reinstall with the installer), then try again.")
}

func errManagementNotSet() *apierr.Error {
	return apierr.New(409, CodeManagementNotSet, "Vedette has not set up this box's network yet. Save the management address first, then change the other settings.")
}

// record writes the core_audit row of an intent, after re-checking in the same transaction that the caller is
// still an administrator with a live session (INV-7).
func (h *NetworkHandlers) record(ctx context.Context, c caller, admin bool, action, target, detail string) error {
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		if admin {
			if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
				return err
			}
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: action, Target: target, Detail: cutAtRune(detail, auditMaxDetail)})
	})
}

// act records the intent, runs fn and, when fn fails, records that too.
func (h *NetworkHandlers) act(ctx context.Context, c caller, action, target, detail string, fn func(ctx context.Context, requestID, actor string) error) error {
	leave, ok := h.gate.Enter() // held for the whole call (L1)
	if !ok {                    // a purge is running (N4)
		return errPurging()
	}
	defer leave()
	if err := h.record(ctx, c, true, action, target, detail); err != nil {
		return err
	}
	id, err := newRequestID()
	if err != nil {
		return err
	}
	// The host goes on with a command whose caller left: its end is recorded and its result stored whatever the request does.
	wctx := context.WithoutCancel(ctx)
	if err := fn(wctx, id, actorLabel(c.Email, c.ID)); err != nil {
		code := "error"
		if ae, ok := apierr.As(err); ok {
			code = ae.Code
		}
		if rerr := h.record(wctx, c, false, action+"_failed", target, code); rerr != nil {
			h.log.ErrorContext(ctx, "core: could not audit a failed network change", "action", action, "error", rerr)
		}
		return err
	}
	return nil
}

// apply sends the desired state and waits until the host is done or waits for the confirmation. A change that
// waits is remembered with the address it replaces.
func (h *NetworkHandlers) apply(ctx context.Context, requestID, actor string, d desired, previous *string) error {
	args := api.NetApplyArgs{Mgmt: d.mgmt, SPAN: api.NetApplySPAN{Iface: d.span}, NTP: nonNil(d.ntp), ConfirmTimeoutS: confirmWindow}
	run, err := h.host.NetApply(ctx, args, requestID, actor)
	if err != nil {
		return h.netErr(ctx, err)
	}
	run, err = waitRunTo(ctx, h.log, h.host, run, netApplyLimit, true)
	h.addressesChanged() // the new address is live already while the box waits for the confirmation
	if err != nil {
		return err // already an API error: the host's word, mapped
	}
	if run.Status == api.StatusAwaitingConfirm {
		h.watchWindow(run) //nolint:contextcheck // the look after the window outlives the request
		rec := pendingRecord{RunID: run.RunID, PreviousAddress: previous}
		if err := h.db.Write(ctx, func(tx *sql.Tx) error { return putSettingTx(ctx, tx, keyNetPending, rec, h.now(), "system") }); err != nil {
			h.log.ErrorContext(ctx, "core: could not store the pending network change; the page cannot show the old address", "run", run.RunID, "error", err)
		}
	}
	return nil
}

// watchWindow looks at the box again 5 seconds after the change would revert by itself, whether or not anybody
// has the page open: the addresses the other parts of the box know (conn, the sweep's protected list, the honeypot's
// box address) must not stay on the new ones, and the revert is settled and audited.
func (h *NetworkHandlers) watchWindow(run api.Run) {
	d := time.Duration(confirmWindow) * time.Second
	if run.RevertAt != nil {
		d = max(0, run.RevertAt.Sub(h.now()))
	}
	h.after(d+5*time.Second, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*netReadTimeout)
		defer cancel()
		if st, err := h.state(ctx, true); err == nil {
			_, _, _ = h.settle(ctx, st)
		}
		h.addressesChanged()
	})
}

// currentAddress is the management address now, bare, or nil.
func currentAddress(st api.NetState) *string {
	m := mgmtViewOf(st)
	return m.Address
}

// ---- PUT /core/network/management ----

// CorePutCoreNetworkManagement implements PUT /core/network/management (admin).
func (h *NetworkHandlers) CorePutCoreNetworkManagement(ctx context.Context, req *oas.CorePutCoreNetworkManagementReq) (*oas.CorePutCoreNetworkManagementOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := h.state(ctx, true)
	if err != nil {
		return nil, err
	}
	if st.Pending != nil {
		return nil, errChangePending()
	}
	iface := mgmtIface(st)
	if iface == "" {
		return nil, errManagementUnknown()
	}
	d, _ := currentDesired(st)
	d.mgmt.Iface = iface
	if d.mgmt.Mode == "" {
		d.span, d.ntp = st.Config.SPAN, slices.Clone(st.Config.NTP)
	}
	old := d.mgmt
	hadConfig := st.Config.Mgmt != nil

	var next api.NetApplyMgmt
	switch req.Mode {
	case oas.CorePutCoreNetworkManagementReqModeDhcp:
		if req.Address.Set || req.Prefix.Set || req.Gateway.Set || req.DNS != nil {
			return nil, invalid(CodeDHCPNoStatic, "With DHCP the address, gateway and DNS come from your DHCP server. Remove the static fields.")
		}
		next = api.NetApplyMgmt{Iface: iface, Mode: api.NetModeDHCP}
	case oas.CorePutCoreNetworkManagementReqModeStatic:
		var prefix *int
		if req.Prefix.Set {
			prefix = refTo(req.Prefix.Value)
		}
		s, perr := checkStatic(req.Address.Value, prefix, req.Gateway.Value, req.DNS)
		if perr != nil {
			return nil, perr
		}
		if err := h.checkFree(ctx, st, s.Addr); err != nil {
			return nil, err
		}
		next = api.NetApplyMgmt{Iface: iface, Mode: api.NetModeStatic, Address: s.CIDR(), Gateway: s.Gateway.String(), DNS: s.DNS}
	default:
		return nil, invalid("invalid_mode", "The mode must be dhcp or static.")
	}
	moves := !hadConfig || next.Mode != old.Mode || next.Address != old.Address || next.Gateway != old.Gateway
	dnsMoves := hadConfig && next.Mode == api.NetModeStatic && !slices.Equal(next.DNS, old.DNS)
	if !moves && !dnsMoves {
		return h.respond(ctx, false)
	}
	if moves && !req.Confirm.Value {
		return nil, confirmRequired(next)
	}
	d.mgmt = next
	previous := currentAddress(st)
	action, detail := "network.management", fmt.Sprintf("%s %s -> %s %s, waiting for confirmation", modeText(old.Mode), orDash(previous), next.Mode, orDash(addrOf(next)))
	if !moves {
		action, detail = "network.dns", strings.Join(next.DNS, ", ")
	}
	err = h.act(ctx, c, action, "management interface", detail, func(ctx context.Context, id, actor string) error {
		return h.apply(ctx, id, actor, d, previous)
	})
	if err != nil {
		return nil, err
	}
	return h.respond(ctx, true)
}

func modeText(m string) string {
	if m == "" {
		return "unset"
	}
	return m
}

func orDash(p *string) string {
	if p == nil || *p == "" {
		return "-"
	}
	return *p
}

func addrOf(m api.NetApplyMgmt) *string {
	if m.Address == "" {
		return nil
	}
	p, err := netip.ParsePrefix(m.Address)
	if err != nil {
		return nil
	}
	return refTo(p.Addr().String())
}

// confirmRequired is the 409 that asks for a second, explicit request: the change moves the address the person
// is using. new_ip is null with DHCP, where the server picks the address.
func confirmRequired(next api.NetApplyMgmt) *apierr.Error {
	if next.Mode == api.NetModeStatic {
		ip := ""
		if a := addrOf(next); a != nil {
			ip = *a
		}
		return apierr.New(409, CodeConfirmRequired, fmt.Sprintf("This changes the address you use to reach the box. Open https://%s:8443 within %d minutes and confirm, or the box returns to the old settings. You will need to sign in again at the new address.", ip, confirmWindow/60)).With("new_ip", ip)
	}
	return apierr.New(409, CodeConfirmRequired, fmt.Sprintf("This changes the address you use to reach the box. Find the new address your DHCP server gives the box, open it on port 8443 within %d minutes and confirm, or the box returns to the old settings. You will need to sign in again at the new address.", confirmWindow/60)).With("new_ip", nil)
}

// checkFree refuses an address that a device of the inventory or a decoy already has (the host's ARP probe, which
// runs later, finds the devices that are in neither).
func (h *NetworkHandlers) checkFree(ctx context.Context, st api.NetState, a netip.Addr) error {
	if m := mgmtViewOf(st); m.Address != nil && *m.Address == a.String() {
		return nil // the box's own address
	}
	used := false
	for _, d := range st.Decoys {
		if d.IP == a.String() {
			used = true
		}
	}
	if !used && h.taken != nil {
		var err error
		if used, err = h.taken(ctx, a); err != nil {
			return fmt.Errorf("core: look up %s in the inventory: %w", a, err)
		}
	}
	if used {
		return apierr.New(409, CodeIPInUse, fmt.Sprintf("%s is already used by a device in the inventory or by a decoy. Pick a free address.", a))
	}
	return nil
}

// respond is the answer of a change: the page as the host reports it now.
func (h *NetworkHandlers) respond(ctx context.Context, fresh bool) (*oas.CorePutCoreNetworkManagementOK, error) {
	v, err := h.view(ctx, fresh)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePutCoreNetworkManagementOK](v)
}

// ---- POST /core/network/management/confirm and /revert ----

// CorePostCoreNetworkManagementConfirm implements POST /core/network/management/confirm (admin).
func (h *NetworkHandlers) CorePostCoreNetworkManagementConfirm(ctx context.Context) (*oas.CorePostCoreNetworkManagementConfirmOK, error) {
	if err := h.settleCall(ctx, "network.management_confirmed", "confirm"); err != nil {
		return nil, err
	}
	v, err := h.view(ctx, true)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreNetworkManagementConfirmOK](v)
}

// CorePostCoreNetworkManagementRevert implements POST /core/network/management/revert (admin).
func (h *NetworkHandlers) CorePostCoreNetworkManagementRevert(ctx context.Context) (*oas.CorePostCoreNetworkManagementRevertOK, error) {
	if err := h.settleCall(ctx, "network.management_reverted", "revert"); err != nil {
		return nil, err
	}
	v, err := h.view(ctx, true)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreNetworkManagementRevertOK](v)
}

// settleCall is net.confirm or net.revert for the change that waits at the host. The run id comes from the host's
// own report, not from core's record, so a restart of core changes nothing.
func (h *NetworkHandlers) settleCall(ctx context.Context, action, what string) error {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return err
	}
	if err := h.needHost(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := h.state(ctx, true)
	if err != nil {
		return err
	}
	_, wentBack, err := h.settle(ctx, st) // a change that ended without us is settled (and audited) before we answer
	if err != nil {
		return err
	}
	if st.Pending == nil {
		if wentBack && what == "confirm" {
			return apierr.New(409, CodeNothingPending, msgRanOut)
		}
		return apierr.New(409, CodeNothingPending, msgNothingPending)
	}
	if st.Pending.RebootAt != nil {
		return apierr.New(409, CodeNothingPending, "The box could not go back to the old settings by itself and restarts in a moment, so there is nothing to confirm or cancel. It comes back on the old address.")
	}
	runID := st.Pending.RunID
	detail := "new address confirmed"
	if what == "revert" {
		detail = "cancelled by administrator"
	}
	return h.act(ctx, c, action, "management interface", detail, func(ctx context.Context, id, actor string) error {
		var run api.Run
		var err error
		if what == "confirm" {
			run, err = h.host.NetConfirm(ctx, runID, id, actor)
		} else {
			run, err = h.host.NetRevert(ctx, runID, id, actor)
		}
		if err != nil {
			return h.netErr(ctx, err)
		}
		_, err = waitRun(ctx, h.log, h.host, run, netConfirmLimit)
		if err == nil { // only a confirm or a revert that worked ends core's record; anything else is settled from the run (L2, M3)
			h.dropPending(ctx)
		}
		h.addressesChanged()
		return err
	})
}

func (h *NetworkHandlers) dropPending(ctx context.Context) {
	err := h.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM core_setting WHERE key = ?`, keyNetPending)
		return err
	})
	if err != nil {
		h.log.ErrorContext(ctx, "core: could not drop the record of the network change", "error", err)
	}
}

// ---- PUT /core/network/interfaces and /span ----

// CorePutCoreNetworkInterfaces implements PUT /core/network/interfaces (admin): which card is the management one
// (fixed: the page is reached through it), which the SPAN port, and which are unused.
func (h *NetworkHandlers) CorePutCoreNetworkInterfaces(ctx context.Context, req *oas.CorePutCoreNetworkInterfacesReq) (*oas.CorePutCoreNetworkInterfacesOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := h.state(ctx, true)
	if err != nil {
		return nil, err
	}
	cards := cardsOf(st)
	roles := map[string]string{}
	for k, v := range req.Roles {
		roles[k] = string(v)
	}
	bad := len(roles) != len(cards)
	for _, i := range cards {
		if r := roles[i.Name]; r != "management" && r != "span" && r != "unused" {
			bad = true
		}
	}
	if bad {
		return nil, invalid(CodeInvalidRoles, "Give a role (management, span or unused) for every interface.")
	}
	var mgmts, spans []string
	for _, i := range cards {
		switch roles[i.Name] {
		case "management":
			mgmts = append(mgmts, i.Name)
		case "span":
			spans = append(spans, i.Name)
		}
	}
	cur := mgmtIface(st)
	if cur == "" {
		return nil, errManagementUnknown()
	}
	switch {
	case len(mgmts) != 1:
		return nil, apierr.New(409, CodeManagementCount, fmt.Sprintf("Exactly one interface must be the management interface; you set %d. The management interface is the one you reach this page through.", len(mgmts)))
	case mgmts[0] != cur:
		return nil, apierr.New(409, CodeManagementFixed, fmt.Sprintf("%s is the management interface and you are using this page through it. It cannot be changed here; set the management address instead.", cur))
	case len(spans) > 1:
		return nil, apierr.New(409, CodeSpanCount, "Only one interface can capture mirrored traffic. Set the others to unused.")
	}
	sp, err := h.SpanSettings(ctx)
	if err != nil {
		return nil, err
	}
	name := ""
	if len(spans) == 1 {
		name = spans[0]
	}
	if name == "" {
		sp.Enabled = false
	}
	if err := h.setSpan(ctx, c, st, name, sp, "interface roles", rolesDetail(cards, roles)); err != nil {
		return nil, err
	}
	v, err := h.view(ctx, true)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePutCoreNetworkInterfacesOK](v)
}

func rolesDetail(cards []api.NetInterface, roles map[string]string) string {
	parts := make([]string, 0, len(cards))
	for _, i := range cards {
		parts = append(parts, i.Name+"="+roles[i.Name])
	}
	return strings.Join(parts, ", ")
}

// CorePutCoreNetworkSpan implements PUT /core/network/span (admin).
func (h *NetworkHandlers) CorePutCoreNetworkSpan(ctx context.Context, req *oas.CorePutCoreNetworkSpanReq) (*oas.CorePutCoreNetworkSpanOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := h.state(ctx, true)
	if err != nil {
		return nil, err
	}
	sp := SpanSettings{
		Enabled:    req.Enabled,
		Extract:    SpanExtract{DNS: req.Extract.DNS, TLSSNI: req.Extract.TLSSni, HTTPHost: req.Extract.HTTPHost, Flows: req.Extract.Flows},
		CPUPercent: req.CPUPercent, MemoryMB: req.MemoryMB, Filters: []SpanFilter{},
	}
	name := ""
	if v, ok := req.Interface.Get(); ok {
		name = v
	}
	if name != "" {
		cards := cardsOf(st)
		if !slices.ContainsFunc(cards, func(i api.NetInterface) bool { return i.Name == name }) {
			names := make([]string, len(cards))
			for i, x := range cards {
				names[i] = x.Name
			}
			return nil, invalid(CodeBadInterface, fmt.Sprintf("Network interface must be one of: %s.", strings.Join(names, ", ")))
		}
		if name == mgmtIface(st) {
			return nil, apierr.New(409, CodeSpanOnManagement, fmt.Sprintf("%s is the management interface. SPAN needs its own port: it listens with no IP address, and mirrored packets would reach your management network.", name))
		}
	}
	if sp.Enabled && name == "" {
		return nil, invalid(CodeNoInterface, "Choose the port that receives the mirrored traffic before turning SPAN on.")
	}
	if sp.Enabled && !sp.Extract.DNS && !sp.Extract.TLSSNI && !sp.Extract.HTTPHost && !sp.Extract.Flows {
		return nil, invalid(CodeNothingSelected, "Choose at least one thing to read from the mirrored traffic, or turn SPAN off.")
	}
	seen := map[string]bool{}
	for _, f := range req.Filters {
		nf, ferr := checkFilter(string(f.Type), f.Value)
		if ferr != nil {
			return nil, ferr
		}
		if seen[nf.Type+":"+nf.Value] {
			return nil, invalid(CodeBadFilter, "A filter is listed twice.")
		}
		seen[nf.Type+":"+nf.Value] = true
		sp.Filters = append(sp.Filters, nf)
	}
	if len(sp.Filters) > 50 {
		return nil, invalid(CodeBadFilter, "At most 50 filters.")
	}
	detail := fmt.Sprintf("off, %d filters", len(sp.Filters))
	if sp.Enabled {
		detail = fmt.Sprintf("on, %s, %d filters", name, len(sp.Filters))
	}
	if err := h.setSpan(ctx, c, st, name, sp, "SPAN capture", detail); err != nil {
		return nil, err
	}
	v, err := h.view(ctx, true)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePutCoreNetworkSpanOK](v)
}

// setSpan makes iface the SPAN card (net.apply, when it is not already), stores the settings and tells the sensor.
// One audit row, before the host call, with action network.span or network.interfaces by the target.
func (h *NetworkHandlers) setSpan(ctx context.Context, c caller, st api.NetState, iface string, sp SpanSettings, target, detail string) error {
	action := "network.span"
	if target == "interface roles" {
		action = "network.interfaces"
	}
	cur := spanIface(st)
	d, ok := currentDesired(st)
	if iface != cur && !ok {
		return errManagementNotSet()
	}
	if iface != cur && st.Pending != nil {
		return errChangePending()
	}
	if iface != "" {
		d.span = refTo(iface)
	} else {
		d.span = nil
	}
	return h.act(ctx, c, action, target, detail, func(ctx context.Context, id, actor string) error {
		if iface != cur {
			if err := h.apply(ctx, id, actor, d, nil); err != nil {
				return err
			}
		}
		if err := h.db.Write(ctx, func(tx *sql.Tx) error { return putSettingTx(ctx, tx, keyNetSpan, sp, h.now(), c.Email) }); err != nil {
			return err
		}
		// The settings are saved and the port is set. Telling the sensor may fail: the answer then carries the
		// verdict sensor_unreachable (span_status) and every look at the page tries again.
		if err := h.syncSensor(ctx, c.Email, iface, sp, true); err != nil {
			h.log.WarnContext(ctx, "core: could not tell the sensor about the SPAN port", "error", err)
		}
		return nil
	})
}

// syncSensor makes the passive sensor listen on the SPAN port the page says (and read the saved filters). It does
// nothing when the sensor was already told the same, unless force; a failure is returned and remembered as "not told".
func (h *NetworkHandlers) syncSensor(ctx context.Context, actor, iface string, sp SpanSettings, force bool) error {
	if h.sensor == nil {
		return nil
	}
	on := sp.Enabled && iface != ""
	want := activeSpan(iface, sp) + "/" + strconv.FormatBool(on)
	h.sensorMu.Lock()
	defer h.sensorMu.Unlock()
	if h.sensorOn == want && !force {
		return nil
	}
	if err := h.sensor.SetSpanPort(ctx, actor, activeSpan(iface, sp), on); err != nil {
		h.sensorOn = ""
		return err
	}
	h.sensorOn = want
	return nil
}

func activeSpan(iface string, sp SpanSettings) string {
	if sp.Enabled {
		return iface
	}
	return ""
}

// ---- PUT /core/network/ntp ----

// CorePutCoreNetworkNtp implements PUT /core/network/ntp (admin): the default pool or one to four servers of the
// person's own. It applies at once (D-100 (5), D-106).
func (h *NetworkHandlers) CorePutCoreNetworkNtp(ctx context.Context, req *oas.CorePutCoreNetworkNtpReq) (*oas.CorePutCoreNetworkNtpOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	var servers []string
	var detail string
	switch req.Mode {
	case oas.CorePutCoreNetworkNtpReqModeDefault:
		if len(req.Servers) > 0 {
			return nil, invalid(CodeDefaultNoServers, "The default pool takes no server list. Choose \"your own servers\" to enter some.")
		}
		detail = "default pool"
	case oas.CorePutCoreNetworkNtpReqModeCustom:
		for _, s := range req.Servers {
			servers = append(servers, strings.ToLower(strings.TrimSpace(s)))
		}
		if perr := checkNTP(servers); perr != nil {
			return nil, perr
		}
		detail = strings.Join(servers, ", ")
	default:
		return nil, invalid("invalid_mode", "The mode must be default or custom.")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := h.state(ctx, true)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(st.Config.NTP, servers) && (len(st.Config.NTP) > 0 || len(servers) > 0) {
		d, ok := currentDesired(st)
		if !ok {
			return nil, errManagementNotSet()
		}
		if st.Pending != nil {
			return nil, errChangePending()
		}
		d.ntp = servers
		err = h.act(ctx, c, "network.ntp", "NTP servers", detail, func(ctx context.Context, id, actor string) error {
			return h.apply(ctx, id, actor, d, nil)
		})
		if err != nil {
			return nil, err
		}
	} else if err := h.record(ctx, c, true, "network.ntp", "NTP servers", detail+" (no change)"); err != nil { // the mock audits every save
		return nil, err
	}
	v, err := h.view(ctx, true)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePutCoreNetworkNtpOK](v)
}

// ---- what other modules read ----

// Card is a network card of the box with its global addresses (the link-local ones do not count: a SPAN card has
// none that matters, host-api 6.5).
type Card struct {
	Name      string
	MAC       string
	Link      bool
	Addresses []netip.Addr
}

// HasHost reports whether core was started with a vedette-host socket (an appliance). False is a container-only install
// (-host-socket=""), the only case in which the passive sensor's heartbeat may decide the card (D-263).
func (h *NetworkHandlers) HasHost() bool { return h != nil && h.host != nil }

// ManagementCard is the card the passive sensor listens on when no SPAN port is chosen (D-380): the management card
// (mgmtIface: the configured one, else the card of the default route, else the one card with an address), and only
// when it is a card of the box (cardsOf: never loopback, a bridge such as vedette0, or a container link). ok is false
// when there is no host to ask (no socket, or a host that says this is no appliance): the sensor's heartbeat then
// decides. A host that does not answer right now gives the last name it gave ("" before there is one), so the
// sensor does not stop listening because the helper hiccups.
func (h *NetworkHandlers) ManagementCard(ctx context.Context) (name string, ok bool) {
	if h == nil || h.host == nil {
		return "", false
	}
	st, err := h.state(ctx, false)
	if err != nil {
		if ae, isAPI := apierr.As(err); isAPI && ae.Code == CodeNotAppliance {
			return "", false
		}
		// Unlike Cards, ok stays true before the first answer: ok=false would let the sensor's heartbeat pick the card
		// on an appliance, which D-118 forbids. "" here means "no default yet"; the next look asks the host again.
		h.cardsMu.Lock()
		defer h.cardsMu.Unlock()
		return h.lastMgmt, true
	}
	name = mgmtIface(st)
	cards := cardsOf(st)
	if !slices.ContainsFunc(cards, func(c api.NetInterface) bool { return c.Name == name }) {
		// The management card is a virtual link (default route on wg0, br0...): the one real card with an
		// IPv4 address, when there is exactly one.
		name = ""
		for _, c := range cards {
			if _, has := ipv4Of(&c); has {
				if name != "" {
					name = ""
					break
				}
				name = c.Name
			}
		}
	}
	h.cardsMu.Lock()
	h.lastMgmt = name
	h.cardsMu.Unlock()
	return name, true
}

// ManagementLAN is the network of the management card's IPv4 address (host bits cleared): the range first-run setup offers
// first (D-405). ok is false without a host, when the host has not answered (yet), or when the card has no IPv4 address. The
// caller is a public page, so a read of the host starts at most once per netReadTTL from here, whatever its outcome (anonymous
// requests cannot spend core's host budget or fill the log), and the caller waits for it at most managementLANWait; a read that
// ends later still fills the answer for the next request.
func (h *NetworkHandlers) ManagementLAN(ctx context.Context) (netip.Prefix, bool) {
	if h == nil || h.host == nil {
		return netip.Prefix{}, false
	}
	h.cardsMu.Lock()
	if !h.lanAt.IsZero() && h.now().Sub(h.lanAt) < netReadTTL {
		p, ok := h.lan, h.lanOK
		h.cardsMu.Unlock()
		return p, ok
	}
	h.lanAt = h.now()
	h.cardsMu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		st, err := h.state(context.WithoutCancel(ctx), false)
		var p netip.Prefix
		ok := false
		if err == nil {
			p, ok = ipv4Of(cardNamed(st, mgmtIface(st)))
		}
		h.cardsMu.Lock()
		h.lan, h.lanOK = p.Masked(), ok
		h.cardsMu.Unlock()
	}()
	select {
	case <-done:
	case <-time.After(managementLANWait):
	case <-ctx.Done():
	}
	h.cardsMu.Lock()
	defer h.cardsMu.Unlock()
	return h.lan, h.lanOK
}

// managementLANWait bounds how long the public setup page waits for the host (a hung host must not stall the wizard).
const managementLANWait = 2 * time.Second

// Cards lists the cards the host reports. ok is false when there is no host to ask (no socket configured, or its
// file is absent, or a host that says this is no appliance). Only "no socket configured" (HasHost false) means a
// container-only install, where sensor-passive takes the box's cards from the sensor's heartbeat (D-263, D-385);
// its HostCards turns ok=false with HasHost into an error. A host that is there but does not answer right now gives
// the last good list (or, before there is one, ok=false): the passive sensor must not fail, or go into back-off,
// because the helper hiccups.
func (h *NetworkHandlers) Cards(ctx context.Context) (cards []Card, ok bool, err error) {
	if h == nil || h.host == nil {
		return nil, false, nil
	}
	st, err := h.state(ctx, false)
	if err != nil {
		if ae, isAPI := apierr.As(err); isAPI && ae.Code == CodeNotAppliance {
			return nil, false, nil
		}
		h.cardsMu.Lock()
		last := h.lastCards
		h.cardsMu.Unlock()
		if last == nil {
			h.log.WarnContext(ctx, "core: vedette-host does not answer and no list of cards is known yet; the passive sensor's batches wait until it answers", "error", err)
		}
		return last, last != nil, nil
	}
	for _, i := range cardsOf(st) {
		c := Card{Name: i.Name, MAC: i.MAC, Link: i.State == "up"}
		for _, s := range i.Addresses {
			if p, perr := netip.ParsePrefix(s); perr == nil && !p.Addr().IsLinkLocalUnicast() {
				c.Addresses = append(c.Addresses, p.Addr())
			}
		}
		cards = append(cards, c)
	}
	h.cardsMu.Lock()
	h.lastCards = cards
	h.cardsMu.Unlock()
	return cards, true, nil
}
