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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
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
	Clock            func() time.Time // nil: time.Now
}

// NetworkHandlers implements the Box network operations of Settings (S-CORE-8, D-56: /core/network*; the routes
// belong to the host module, whose handlers these are) on top of vedette-host. Every change is one net.apply with the
// whole desired state: core merges the part the person changed into what the host reports as running, and keeps
// only what the host does not know (the SPAN switches, filters and limits, and the old address of a change that
// waits for confirmation). Nothing here runs a command itself (SYS-1).
type NetworkHandlers struct {
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
		st api.NetState
		at time.Time
		ok bool
	}
	samples struct {
		sync.Mutex
		m map[string]rxSample
	}
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
	h := &NetworkHandlers{db: c.DB, auth: c.Auth, audit: c.Audit, log: c.Log, host: c.Host, sensor: c.Sensor, taken: c.AddressInUse, changed: c.AddressesChanged, now: c.Clock}
	h.samples.m = map[string]rxSample{}
	return h, nil
}

const (
	keyNetSpan    = "core_network_span"
	keyNetPending = "core_network_pending"

	netReadTTL      = 2 * time.Second // GET /core/network and the 5 s poll of span/status may share one read of the host
	netReadTimeout  = 15 * time.Second
	netApplyLimit   = 150 * time.Second // host-api 10: net.apply takes up to 120 s before it waits for the confirmation
	netConfirmLimit = 75 * time.Second  // net.confirm and net.revert: 60 s
	confirmWindow   = 120               // seconds the person has to confirm from the new address (S-CORE-8)
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

func (h *NetworkHandlers) state(ctx context.Context, fresh bool) (api.NetState, error) {
	h.cache.Lock()
	if !fresh && h.cache.ok && h.now().Sub(h.cache.at) < netReadTTL {
		st := h.cache.st
		h.cache.Unlock()
		return st, nil
	}
	h.cache.ok = false
	h.cache.Unlock()
	rctx, cancel := context.WithTimeout(ctx, netReadTimeout)
	defer cancel()
	st, err := h.host.StateNet(rctx)
	if err != nil {
		return api.NetState{}, h.netErr(ctx, err)
	}
	h.cache.Lock()
	h.cache.st, h.cache.at, h.cache.ok = st, h.now(), true
	h.cache.Unlock()
	return st, nil
}

// virtualName is the name of a link that is not a card: container and virtual links, bridges, bonds, VLANs.
// vedette-host lists every interface that has an address (core must know them all as "the box"), so the screen
// keeps the cards and the two roles.
var virtualName = regexp.MustCompile(`^(lo|veth|podman|cni|docker|br|virbr|vdh|bond|tun|tap|wg|dummy|vnet|macvtap|ifb)|[.@]`)

func cardsOf(st api.NetState) []api.NetInterface {
	var out []api.NetInterface
	for _, i := range st.Interfaces {
		if i.Role != "" || !virtualName.MatchString(i.Name) {
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
	return ""
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
	// DHCP, or a box the host has not configured yet: what the card has now.
	if cfg != nil {
		v.Mode = api.NetModeDHCP
	}
	if p, ok := ipv4Of(card); ok {
		v.Address, v.Prefix = refTo(p.Addr().String()), refTo(p.Bits())
	}
	if st.DefaultRoute != nil && card != nil && st.DefaultRoute.Iface == card.Name && st.DefaultRoute.Gateway != "" {
		v.Gateway = refTo(st.DefaultRoute.Gateway)
	}
	if cfg != nil {
		v.DNS = slices.Clone(cfg.DNS)
	}
	if v.DNS == nil {
		v.DNS = []string{}
	}
	return v
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
		pv := &netPendingView{ExpiresAt: store.FormatTS(p.RevertAt.UTC())}
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
		m, err := h.sensor.SpanStats(ctx)
		if err == nil && m.Verdict != "off" && m.Verdict != "no_link" {
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
	out.Verdict, out.PacketsPerS = "ok", pps
	out.LastPacketAt = refTo(store.FormatTS(h.now().UTC()))
	return out
}

// packetsPerSecond is the rise of the card's receive counter since the last look, per second; 0 at the first look.
func (h *NetworkHandlers) packetsPerSecond(c *api.NetInterface) int {
	now := h.now()
	h.samples.Lock()
	defer h.samples.Unlock()
	prev, ok := h.samples.m[c.Name]
	h.samples.m[c.Name] = rxSample{rx: c.Counters.RxPackets, at: now}
	dt := now.Sub(prev.at).Seconds()
	if !ok || dt < 0.5 || c.Counters.RxPackets < prev.rx {
		return 0
	}
	return int(float64(c.Counters.RxPackets-prev.rx)/dt + 0.5)
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
	why := "the host reported no change waiting"
	reverted := true
	if run, gerr := h.host.GetRun(ctx, rec.RunID); gerr == nil {
		switch {
		case run.Status == api.StatusSucceeded:
			reverted = false
		case run.Error != nil:
			why = netEnding(run.Error.Code)
		}
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
		rec := pendingRecord{RunID: run.RunID, PreviousAddress: previous}
		if err := h.db.Write(ctx, func(tx *sql.Tx) error { return putSettingTx(ctx, tx, keyNetPending, rec, h.now(), "system") }); err != nil {
			h.log.ErrorContext(ctx, "core: could not store the pending network change; the page cannot show the old address", "run", run.RunID, "error", err)
		}
	}
	return nil
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
		return nil, errManagementNotSet()
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
		return apierr.New(409, CodeConfirmRequired, fmt.Sprintf("This changes the address you use to reach the box. Open https://%s:8443 within %d minutes and confirm, or the box returns to the old settings.", ip, confirmWindow/60)).With("new_ip", ip)
	}
	return apierr.New(409, CodeConfirmRequired, fmt.Sprintf("This changes the address you use to reach the box. Find the new address your DHCP server gives the box, open it on port 8443 within %d minutes and confirm, or the box returns to the old settings.", confirmWindow/60)).With("new_ip", nil)
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
		h.cache.Lock()
		h.cache.ok = false
		h.cache.Unlock()
		if err == nil || what == "confirm" && !isTrouble(err) {
			h.dropPending(ctx)
		}
		h.addressesChanged()
		return err
	})
}

func isTrouble(err error) bool {
	ae, ok := apierr.As(err)
	return !ok || ae.Status >= 500
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
		if h.sensor != nil {
			if err := h.sensor.SetSpanPort(ctx, c.Email, activeSpan(iface, sp), sp.Enabled && iface != ""); err != nil {
				h.log.WarnContext(ctx, "core: could not tell the sensor about the SPAN port", "error", err)
			}
		}
		return nil
	})
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

// Cards lists the cards the host reports. ok is false when this install has no host: the caller then reads the
// interfaces of the operating system it runs on.
func (h *NetworkHandlers) Cards(ctx context.Context) (cards []Card, ok bool, err error) {
	if h == nil || h.host == nil {
		return nil, false, nil
	}
	st, err := h.state(ctx, false)
	if err != nil {
		return nil, false, err
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
	return cards, true, nil
}
