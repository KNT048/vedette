package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
)

const noIP = "—" // what the API says for a device whose IP is unknown (contract.ts Asset.ip)

var assetColumns = `a.id, a.ip, a.mac, a.hostname, a.user_name, a.kind, k.source, a.origin, a.approved, a.fragile, a.regular_scan, a.first_scan_at, a.approved_at, a.suspicious, a.is_box, a.notes, a.first_seen, a.last_seen, coalesce(a.scan_source, ''), coalesce(a.snmp_source, ''), a.ignored_at,
	v.value, v.source, v.confidence, v.seen_at, m.value, m.source, m.confidence, m.seen_at, o.value, o.source, o.confidence, o.seen_at,
	h.value, h.source, h.confidence, h.seen_at, x.value, x.source, x.confidence, x.seen_at,
	(SELECT f.value FROM inv_observation f WHERE f.asset_id = a.id AND f.field = 'os' AND f.source = 'passive' AND m.source = 'passive'
		AND f.seen_at = m.seen_at ORDER BY f.id LIMIT 1),
	` + quietExpr + `, o.evidence`

const assetFrom = ` FROM inv_asset a
	LEFT JOIN inv_observation v ON v.id = a.vendor_obs_id
	LEFT JOIN inv_observation m ON m.id = a.model_obs_id
	LEFT JOIN inv_observation o ON o.id = a.os_obs_id
	LEFT JOIN inv_observation h ON h.id = a.hostname_obs_id
	LEFT JOIN inv_observation x ON x.id = a.mac_obs_id
	LEFT JOIN inv_observation k ON k.id = a.kind_obs_id`

type obsCols struct {
	value, source, seen sql.NullString
	conf                sql.NullFloat64
}

func (c obsCols) observed() *Observed {
	if !c.value.Valid {
		return nil
	}
	return &Observed{Value: c.value.String, Source: c.source.String, Confidence: c.conf.Float64, SeenAt: c.seen.String}
}

// loadDevices reads devices (with software and services) for a WHERE clause on inv_asset a; the rows
// are ordered box first, then newest first. limit 0 = no limit.
func (s *Service) loadDevices(ctx context.Context, q querier, where string, limit int, args ...any) ([]Device, error) {
	st, err := loadSettings(ctx, q) // the LAN ranges say whether a default SNMP switch reaches the device
	if err != nil {
		return nil, err
	}
	query := `SELECT ` + assetColumns + assetFrom + ` ` + where + ` ORDER BY a.is_box DESC, a.first_seen DESC, a.id`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		var d Device
		var ip, mac, host, userName, scan, approvedAt, notes, kindSrc, ignoredAt sql.NullString
		var v, m, o, h, x obsCols
		var osEvidence sql.NullString // where the stored OS came from when a declared row decided it (sourceDeclared)
		var frameOS sql.NullString    // the passive OS seen with a passive model: the same LLDP frame (modelBasis)
		var approved, fragile, suspicious, box, quiet bool
		if err := rows.Scan(&d.ID, &ip, &mac, &host, &userName, &d.Kind, &kindSrc, &d.Origin, &approved, &fragile, &d.RegularScan, &scan, &approvedAt, &suspicious, &box, &notes, &d.FirstSeen, &d.LastSeen, &d.ScanSource, &d.SNMPSource, &ignoredAt,
			&v.value, &v.source, &v.conf, &v.seen, &m.value, &m.source, &m.conf, &m.seen, &o.value, &o.source, &o.conf, &o.seen,
			&h.value, &h.source, &h.conf, &h.seen, &x.value, &x.source, &x.conf, &x.seen, &frameOS, &quiet, &osEvidence); err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		d.Site = "hq" // one site
		d.IP = noIP
		if ip.Valid {
			d.IP = ip.String
		}
		d.MAC, d.Hostname, d.UserName, d.FirstScanAt, d.ApprovedAt, d.Notes, d.KindSource = ptr(mac), ptr(host), ptr(userName), ptr(scan), ptr(approvedAt), ptr(notes), ptr(kindSrc)
		d.Vendor, d.Model, d.OS = v.observed(), m.observed(), o.observed()
		if d.OS != nil {
			d.OS.Basis = osBasis(d.OS.Value, d.OS.Source, mac.String)
			d.OS.SoftwareID = declaredRow(d.OS.Source, osEvidence.String)
		}
		if d.Model != nil {
			d.Model.Basis = modelBasis(d.Model.Source, frameOS.String, mac.String)
		}
		d.ident = []*Observed{h.observed(), x.observed()}
		d.Approved, d.Fragile, d.Suspicious, d.IsBox = approved, fragile, suspicious, box
		d.Quiet, d.PrivateMAC = quiet, mac.Valid && PrivateMAC(mac.String)
		d.IgnoredAt = ptr(ignoredAt)
		d.ScanSource, d.SNMPSource = sourceState(d.ScanSource, d.Origin), snmpState(st, d.SNMPSource, d.Origin, ip.String)
		if d.IgnoredAt != nil { // Both are off while it is ignored, as the policies apply them; the stored choice stays
			d.ScanSource, d.SNMPSource = SourceOff, SourceOff
		}
		d.Software, d.Services = []Software{}, []ServiceRow{}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	if len(out) == 0 {
		return out, nil
	}
	idx := map[string]int{}
	for i, d := range out {
		idx[d.ID] = i
	}
	sub := `(SELECT a.id FROM inv_asset a ` + where
	if limit > 0 {
		sub += fmt.Sprintf(" ORDER BY a.is_box DESC, a.first_seen DESC, a.id LIMIT %d", limit)
	}
	sub += `)`
	if err := loadSoftware(ctx, q, sub, idx, out, args); err != nil {
		return nil, err
	}
	if err := loadServices(ctx, q, sub, idx, out, args); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].observedHW = &[2]string{obsValue(out[i].Vendor), obsValue(out[i].Model)}
		fillDeclaredHardware(&out[i])
	}
	return out, nil
}

func loadServices(ctx context.Context, q querier, sub string, idx map[string]int, out []Device, args []any) error {
	rows, err := q.QueryContext(ctx, `SELECT s.asset_id, s.port, s.proto, s.name, s.product, s.version, s.detail, s.source, s.confidence, coalesce(x.ip, x.mac)
		FROM inv_service s LEFT JOIN inv_asset_address x ON x.id = s.addr_id AND s.addr_id <> ''
		WHERE s.asset_id IN `+sub+` ORDER BY s.asset_id, s.port, s.proto, s.source, s.addr_id`, args...)
	if err != nil {
		return fmt.Errorf("inventory: read services: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var asset string
		var sv ServiceRow
		var product, version, detail, addr sql.NullString
		if err := rows.Scan(&asset, &sv.Port, &sv.Proto, &sv.Name, &product, &version, &detail, &sv.Source, &sv.Confidence, &addr); err != nil {
			return fmt.Errorf("inventory: read services: %w", err)
		}
		sv.Product, sv.Version, sv.Detail, sv.Address = ptr(product), ptr(version), ptr(detail), ptr(addr)
		d := &out[idx[asset]]
		d.Services = append(d.Services, sv)
	}
	return rows.Err()
}

// summaryOf is the source of the most trusted of vendor, model, os and the confidence of the weakest. A device with
// none of them (a router seen only by ARP) takes its hostname and MAC instead, so the list still says which sensor saw
// it ("Unknown 192.168.142.1" with source "–").
func summaryOf(d *Device) *Summary {
	if d.Vendor == nil && d.Model == nil && d.OS == nil {
		return summaryOver(d.ident)
	}
	return summaryOver([]*Observed{d.Vendor, d.Model, d.OS})
}

func summaryOver(obs []*Observed) *Summary {
	var top *Observed
	weakest := 2.0
	for _, o := range obs {
		if o == nil {
			continue
		}
		if top == nil || o.Confidence > top.Confidence {
			top = o
		}
		weakest = min(weakest, o.Confidence)
	}
	if top == nil {
		return nil
	}
	return &Summary{Source: top.Source, Confidence: weakest}
}

func (s *Service) findingCounts(ctx context.Context) (map[string]int, error) {
	if s.findings == nil {
		return nil, nil
	}
	m, err := s.findings.CountByAsset(ctx)
	if err != nil {
		return nil, fmt.Errorf("inventory: finding counts: %w", err)
	}
	return m, nil
}

// riskUnavailable is the answer to a risk filter while the markers cannot be read (findings failed): 503, never the unfiltered list.
func riskUnavailable() *apierr.Error {
	return apierr.New(503, "risk_unavailable", "Vedette could not read the risk marks just now, so it cannot filter by risk. Try again in a moment, or remove the risk filter.").
		With("retry_after", 5)
}

// risks is the risk marker of every marked device, from findings through Config.Risk (one batch, cached there); clean devices
// are absent. Only the Devices page, the device page and the CSV export ask for it (#949: the honeypot, scans, reports
// and MCP read devices without it). ok is false when findings could not answer: logged, and the page shows no marker; it never fails
// the list.
func (s *Service) risks(ctx context.Context) (out map[string]*Risk, ok bool) {
	out = map[string]*Risk{}
	if s.risk == nil {
		return out, true
	}
	m, err := s.risk.DeviceStatuses(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "inventory: device risk markers not read", "error", err)
		return out, false
	}
	for id, r := range m {
		out[id] = &r
	}
	return out, true
}

// Devices lists the devices for the other modules (scan, reports, honeypot, MCP): at most MaxListed rows, the counts over all of them.
// It does not read the sources (Device.Sources nil): only the Devices page and the export need them (#855).
func (s *Service) Devices(ctx context.Context) (DeviceList, error) {
	return s.devices(ctx, DeviceFilter{}, false, false)
}

// devices is Devices narrowed by the Devices search (#849): at most MaxListed of the devices f keeps, with their sources when
// withSources and their risk markers when withRisk; the counts stay over the whole inventory (the tabs).
func (s *Service) devices(ctx context.Context, f DeviceFilter, withSources, withRisk bool) (DeviceList, error) {
	db := s.db.Reader()
	items, riskOK, err := s.filtered(ctx, db, f, MaxListed, withSources, withRisk)
	if err != nil {
		return DeviceList{}, err
	}
	out := DeviceList{Items: items, RiskUnavailable: withRisk && !riskOK}
	// An ignored device is in no count but its own: not in All, not in the To review badge.
	err = db.QueryRowContext(ctx, `SELECT ifnull(sum(ignored_at IS NULL), 0), ifnull(sum(`+toReviewSQL+` AND ignored_at IS NULL), 0), ifnull(sum(fragile AND ignored_at IS NULL), 0),
		ifnull(sum(origin = 'manual' AND ignored_at IS NULL), 0), ifnull(sum(ignored_at IS NOT NULL), 0) FROM inv_asset a`).
		Scan(&out.Counts.All, &out.Counts.Pending, &out.Counts.Fragile, &out.Counts.Manual, &out.Counts.Ignored)
	if err != nil {
		return DeviceList{}, fmt.Errorf("inventory: count devices: %w", err)
	}
	if out.NotifyNew, err = notifyNew(ctx, db); err != nil {
		return DeviceList{}, err
	}
	out.NotifyAvailable = s.modules != nil && s.modules.Enabled("notify")
	return out, nil
}

// DeviceCounts is the "All" and "To review" counts of the device list without the list (Home's device tile, findings
// GET /findings/overview): one aggregate over inv_asset. Ignored devices are in neither.
func (s *Service) DeviceCounts(ctx context.Context) (total, pending int, err error) {
	err = s.db.Reader().QueryRowContext(ctx, `SELECT count(*), ifnull(sum(`+toReviewSQL+`), 0) FROM inv_asset a WHERE a.ignored_at IS NULL`).Scan(&total, &pending)
	if err != nil {
		return 0, 0, fmt.Errorf("inventory: count devices: %w", err)
	}
	return total, pending, nil
}

// filtered reads the devices f keeps (limit 0 = all), newest first, each with its finding count, summary and, when withSources, its
// sources (a source filter reads them in any case) and, when withRisk, its risk marker (a risk filter needs withRisk); the box is
// always just seen and never marked. riskOK is false when the markers could not be read: the rows have none and a risk filter is not
// applied (DeviceList.RiskUnavailable says so); with a risk filter that is 503 risk_unavailable instead (never every device).
func (s *Service) filtered(ctx context.Context, db querier, f DeviceFilter, limit int, withSources, withRisk bool) (items []Device, riskOK bool, err error) {
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return nil, false, err
	}
	var sources map[string][]string
	if withSources || len(f.Sources) > 0 {
		if sources, err = s.deviceSources(ctx, db); err != nil {
			return nil, false, err
		}
	}
	risks, riskOK := map[string]*Risk{}, true
	if withRisk || f.HasFindings != nil { // has_findings reads the open findings from the same statuses
		risks, riskOK = s.risks(ctx)
	}
	if !riskOK && (len(f.Risks) > 0 || f.HasFindings != nil) { // never "every device" for a risk or findings filter (#949)
		return nil, false, riskUnavailable()
	}
	if !withRisk {
		f.Risks = nil
	}
	where, args := f.where(sources, risks)
	if items, err = s.loadDevices(ctx, db, where, limit, args...); err != nil {
		return nil, false, err
	}
	if f.Q != "" { // the query found the candidates; a device stays when what its row shows holds the text, or one of its other addresses (INV-57)
		other, err := otherAddressHits(ctx, db, f.Q)
		if err != nil {
			return nil, false, err
		}
		items = slices.DeleteFunc(items, func(d Device) bool { return !d.shows(f.Q) && !other[d.ID] })
	}
	if len(f.Software) > 0 {
		items = slices.DeleteFunc(items, func(d Device) bool { return len(d.matchedSoftware(f.Software)) == 0 })
	}
	if items == nil {
		items = []Device{}
	}
	now := s.now()
	for i := range items {
		d := &items[i]
		d.FindingsCount = counts[d.ID]
		if withRisk && !d.IsBox { // the box's own updates are in To fix; the box is never marked
			d.Risk = risks[d.ID]
		}
		d.Summary = summaryOf(d)
		if withSources {
			if d.Sources = sources[d.ID]; d.Sources == nil {
				d.Sources = []string{}
			}
		}
		if d.IsBox {
			d.LastSeen = now // the box is the machine running Vedette: always just seen
		}
	}
	return items, riskOK, nil
}

// Device returns one device as a list row, or ErrNotFound. findings, notify and the other modules read it.
func (s *Service) Device(ctx context.Context, id string) (Device, error) {
	items, err := s.loadDevices(ctx, s.db.Reader(), "WHERE a.id = ?", 0, id)
	if err != nil {
		return Device{}, err
	}
	if len(items) == 0 {
		return Device{}, ErrNotFound
	}
	d := items[0]
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return Device{}, err
	}
	d.FindingsCount = counts[d.ID]
	d.Summary = summaryOf(&d)
	return d, nil
}

var fieldOrder = []string{"kind", "hostname", "mac", "vendor", "model", "os"}

// Detail is GET /inventory/devices/{id}: observations (the current one of each field marked), services and software.
func (s *Service) Detail(ctx context.Context, id string) (Detail, error) {
	d, err := s.Device(ctx, id)
	if err != nil {
		return Detail{}, err
	}
	db := s.db.Reader()
	var cur [6]sql.NullString
	var kind string
	var kindSrc sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT a.kind_obs_id, a.hostname_obs_id, a.mac_obs_id, a.vendor_obs_id, a.model_obs_id, a.os_obs_id, a.kind, k.source
		FROM inv_asset a LEFT JOIN inv_observation k ON k.id = a.kind_obs_id WHERE a.id = ?`, id).
		Scan(&cur[0], &cur[1], &cur[2], &cur[3], &cur[4], &cur[5], &kind, &kindSrc); err != nil {
		return Detail{}, fmt.Errorf("inventory: read device: %w", err)
	}
	mac := ""
	if d.MAC != nil {
		mac = *d.MAC
	}
	current := map[string]bool{}
	for _, c := range cur {
		if c.Valid {
			current[c.String] = true
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ?`, id)
	if err != nil {
		return Detail{}, fmt.Errorf("inventory: read observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	list := []ObservationRow{}
	for rows.Next() {
		var o ObservationRow
		if err := rows.Scan(&o.ID, &o.Field, &o.Value, &o.Source, &o.Confidence, &o.SeenAt); err != nil {
			return Detail{}, fmt.Errorf("inventory: read observations: %w", err)
		}
		o.Current = current[o.ID]
		o.ContradictsType = o.Field == "os" && o.Source == "nmap" && guessContradicts(kind, kindSrc.String, o.Value)
		if o.Field == "os" {
			o.Basis = osBasis(o.Value, o.Source, mac)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return Detail{}, fmt.Errorf("inventory: read observations: %w", err)
	}
	for i, o := range list { // a passive model reads as stated with the OS statement of its frame (same moment, modelBasis)
		if o.Field != "model" {
			continue
		}
		for _, f := range list {
			if f.Field == "os" && f.Source == "passive" && f.SeenAt == o.SeenAt && modelBasis(o.Source, f.Value, mac) != "" {
				list[i].Basis = basisStated
				break
			}
		}
	}
	slices.SortFunc(list, func(a, b ObservationRow) int {
		if c := slices.Index(fieldOrder, a.Field) - slices.Index(fieldOrder, b.Field); c != 0 {
			return c
		}
		return -strings.Compare(a.SeenAt, b.SeenAt)
	})

	lines, err := softwareLines(ctx, db, id)
	if err != nil {
		return Detail{}, err
	}
	var cves func([]string) []string // read once for the page, when a line has keys
	for i := range lines {
		if lines[i].NotInstalled || len(lines[i].kev) == 0 {
			continue // it matches nothing
		}
		if cves == nil {
			if cves, err = s.kevIndex(ctx); err != nil {
				return Detail{}, err
			}
		}
		lines[i].KevCVEs = cves(lines[i].kev)
	}
	osc, err := osCorrection(ctx, db, id)
	if err != nil {
		return Detail{}, err
	}
	same, err := s.PossibleSameAs(ctx, id)
	if err != nil {
		return Detail{}, err
	}
	manualAt, err := manualAt(ctx, db, id)
	if err != nil {
		return Detail{}, err
	}
	differs, err := deviceDifferences(ctx, db, id)
	if err != nil {
		return Detail{}, err
	}
	if differs == nil {
		differs = []Differs{}
	}
	addrs, err := s.addresses(ctx, db, id)
	if err != nil {
		return Detail{}, err
	}
	return Detail{
		Addresses:       addrs,
		DetectedDiffers: differs,
		ManualAt:        manualAt,
		PossibleSame:    same,
		Asset:           DetailAsset{AssetCore: d.AssetCore, Software: lines, OSCorrection: osc},
		Suspicious:      d.Suspicious,
		FindingsCount:   d.FindingsCount,
		Observations:    list,
		Kinds:           devicetypes.IDs(),
	}, nil
}

// kevIndex reads the exploited lists once (KEV.CVEIndex) and returns the lookup of the CVE ids feeds knows for a set of keys: never
// nil, empty when feeds gives none. A request reads it once and looks up all of its lines or devices in it.
func (s *Service) kevIndex(ctx context.Context) (func(keys []string) []string, error) {
	if s.kev == nil {
		return func([]string) []string { return []string{} }, nil
	}
	idx, err := s.kev.CVEIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("inventory: KEV match: %w", err)
	}
	return func(keys []string) []string {
		var list []string
		if len(keys) > 0 && idx != nil {
			list = idx(keys)
		}
		if list == nil {
			list = []string{}
		}
		return list
	}, nil
}

// NoDevice ends the name of a device added by hand that has neither a name nor an IP: it is only a product someone
// declared ("Microsoft Office (no device)"), never a nameless row.
const NoDevice = " (no device)"

// NameFacts is what the naming rule (DisplayName) reads of a device.
type NameFacts struct {
	UserName string // the name a person gave the device in Vedette
	Hostname string
	// Vendor and Model are the device's current maker and model. CardVendor says the maker is only the one of its network card: the
	// IEEE prefix of its MAC, which a network scan and the passive sensor report (CardVendor). That names who made the card, not what
	// the device is: an ESXi host on an HPE server card, a firewall and a switch of one maker.
	Vendor, Model string
	CardVendor    bool
	// OS is the operating system or firmware the device states, or that an agent, SNMP or a person's correction gives (NamingOS):
	// never a network scan's fingerprint guess, never the OS row a person declared.
	OS      string
	IP      string
	Origin  string
	Product string // the first software a device added by hand runs
}

// DisplayName is the one naming rule of every page and module (web/src/features/inventory/nameOf.ts is the same): the name a person
// gave the device in Vedette whenever it is set; then the host name (a name typed when the device was added by hand is one); then a
// device added by hand is named after its first product, with NoDevice when it has no IP either; any other device after its make
// and model, unless the maker is only its network card's and no model is known; then the product of the OS or firmware it states
// (OSProduct: "VMware ESXi"); then "<card maker> device" (MakerDevice); then its IP. "" when none of these is known: the caller adds
// the kind, the IP placeholder or the id.
func DisplayName(f NameFacts) string {
	if n := strings.TrimSpace(f.UserName); n != "" {
		return n
	}
	if h := strings.TrimSpace(f.Hostname); h != "" {
		return h
	}
	hasIP := f.IP != "" && f.IP != noIP
	if p := strings.TrimSpace(f.Product); f.Origin == "manual" && p != "" {
		if hasIP {
			return p
		}
		return p + NoDevice
	}
	vendor, model := strings.TrimSpace(f.Vendor), strings.TrimSpace(f.Model)
	if model != "" || vendor != "" && !f.CardVendor {
		return strings.TrimSpace(vendor + " " + model)
	}
	if os := OSProduct(f.OS); os != "" {
		return os
	}
	if vendor != "" {
		return vendor + MakerDevice
	}
	if hasIP {
		return f.IP
	}
	return ""
}

// MakerDevice ends the name of a device known only by the maker of its network card ("Fortinet device").
const MakerDevice = " device"

// CardVendor says a vendor observation of this source names only the maker of the network card: a network scan and the passive
// sensor read it from the MAC's IEEE prefix. SNMP, an agent and a person state the device's own maker.
func CardVendor(source string) bool { return source == "nmap" || source == "passive" }

// NamingOS is the OS text the naming rule may use (NameFacts.OS): "" for a network scan's fingerprint guess (basis guess) and for the
// OS row a person declared (source declared), else value.
func NamingOS(value, source, basis string) string {
	if source == sourceDeclared || basis == basisGuess {
		return ""
	}
	return strings.TrimSpace(value)
}

// OSProduct is the product an OS or firmware text names, without its release: the words before the first one that starts with a
// digit or a bracket ("VMware ESXi 8.0 Update 3 (build 24022510)" is "VMware ESXi", "MikroTik RouterOS 7.2 - 7.5" is "MikroTik
// RouterOS", "JUNOS 15.1R7.9" is "JUNOS"). "" when the text starts with its release.
func OSProduct(os string) string {
	var words []string
	for _, w := range strings.Fields(os) {
		if c := w[0]; c >= '0' && c <= '9' || c == '(' || c == '[' || c == '-' {
			break
		}
		words = append(words, w)
	}
	return strings.Join(words, " ")
}

// nameOrHost is the name a person gave a device when set, else its host name; nil when neither is known.
func nameOrHost(user, host *string) *string {
	if user != nil && strings.TrimSpace(*user) != "" {
		return user
	}
	if host != nil && strings.TrimSpace(*host) != "" {
		return host
	}
	return nil
}

// NameOrHost is for the readers that name a device by its host name, else its address or model (response, AI, MCP, honeypot, the
// CVE page): the name a person gave it in Vedette wins, else the host name; nil when neither is known.
func (a AssetCore) NameOrHost() *string { return nameOrHost(a.UserName, a.Hostname) }

// NameOrHost is AssetCore.NameOrHost of a DeviceRef.
func (r DeviceRef) NameOrHost() *string { return nameOrHost(r.UserName, r.Hostname) }

// NameOrHost is AssetCore.NameOrHost of a KindDevice.
func (k KindDevice) NameOrHost() *string { return nameOrHost(k.UserName, k.Hostname) }

// Name is DisplayName of a listed device; its software is sorted by display name, like firstSoftware (what it runs).
func (d Device) Name() string {
	product := ""
	if run := d.Running(); len(run) > 0 {
		product = run[0].Display
	}
	vendor, model := obsValue(d.Vendor), obsValue(d.Model)
	if d.observedHW != nil {
		vendor, model = d.observedHW[0], d.observedHW[1]
	}
	card := d.Vendor != nil && d.Vendor.SoftwareID == "" && CardVendor(d.Vendor.Source)
	os := ""
	if d.OS != nil {
		os = NamingOS(d.OS.Value, d.OS.Source, d.OS.Basis)
	}
	return DisplayName(NameFacts{UserName: deref(d.UserName), Hostname: deref(d.Hostname), Vendor: vendor, Model: model, CardVendor: card, OS: os, IP: d.IP,
		Origin: d.Origin, Product: product})
}

// firstSoftware selects the display name of a device's first software, in the order the pages list it; never an nmap
// OS guess the device does not use (hiddenGuess), never a line a person said is not installed.
var firstSoftware = `(SELECT s.display FROM inv_software s WHERE s.asset_id = a.id AND s.state = 'present' AND NOT ` + hiddenGuess + ` ORDER BY s.display, s.id LIMIT 1)`

// nameColumns are the columns of inv_asset a that the naming rule reads (scanName): the vendor's and the OS's sources come from their
// observations (v, o of nameFrom).
var nameColumns = `a.user_name, a.hostname, a.vendor, v.source, a.model, a.os, o.source, a.mac, a.ip, a.origin, ` + firstSoftware

// nameFrom joins the vendor and OS observations nameColumns reads.
const nameFrom = ` FROM inv_asset a LEFT JOIN inv_observation v ON v.id = a.vendor_obs_id LEFT JOIN inv_observation o ON o.id = a.os_obs_id`

// scanName reads the nameColumns of one row (after the columns before them, extra) and gives its DisplayName.
func scanName(sc interface{ Scan(...any) error }, extra ...any) (string, error) {
	var name, host, vendor, vendorSrc, model, osName, osSrc, mac, ip, product sql.NullString
	var origin string
	if err := sc.Scan(append(extra, &name, &host, &vendor, &vendorSrc, &model, &osName, &osSrc, &mac, &ip, &origin, &product)...); err != nil {
		return "", err
	}
	os := ""
	if osName.Valid {
		os = NamingOS(osName.String, osSrc.String, osBasis(osName.String, osSrc.String, mac.String))
	}
	return DisplayName(NameFacts{UserName: name.String, Hostname: host.String, Vendor: vendor.String, Model: model.String, CardVendor: CardVendor(vendorSrc.String),
		OS: os, IP: ip.String, Origin: origin, Product: product.String}), nil
}

// Names maps device ids to the name to show (DisplayName; the id when nothing is known) for findings, notify, honeypot
// and reports.
func (s *Service) Names(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, `+nameColumns+nameFrom)
	if err != nil {
		return nil, fmt.Errorf("inventory: read names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id string
		n, err := scanName(rows, &id)
		if err != nil {
			return nil, fmt.Errorf("inventory: read names: %w", err)
		}
		if out[id] = n; n == "" {
			out[id] = id
		}
	}
	return out, rows.Err()
}

func assetExists(ctx context.Context, q querier, id string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM inv_asset WHERE id = ?`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// deviceName is how audit rows, the matcher's evidence (MatchInput) and messages name a device: as the pages do
// (DisplayName), else the id.
func deviceName(ctx context.Context, q querier, id string) string {
	n, err := scanName(q.QueryRowContext(ctx, `SELECT `+nameColumns+nameFrom+` WHERE a.id = ?`, id))
	if err != nil || n == "" {
		return id
	}
	return n
}

// DevicesPage is Devices narrowed by the Devices search (#849) with the guesses of the identification rules: GET
// /inventory/devices. Only the Devices page asks for guesses; every other reader (scan, reports, honeypot, MCP, response) reads Devices
// or Device, which never ask the host (#714 M3).
func (s *Service) DevicesPage(ctx context.Context, f DeviceFilter) (DeviceList, error) {
	l, err := s.devices(ctx, f, true, true)
	if err != nil {
		return l, err
	}
	cores := make([]*AssetCore, len(l.Items))
	for i := range l.Items {
		cores[i] = &l.Items[i].AssetCore
	}
	s.addGuesses(ctx, cores)
	return l, nil
}

// DetailPage is Detail with the guess of the identification rules and the risk marker: GET /inventory/devices/{id}.
func (s *Service) DetailPage(ctx context.Context, id string) (Detail, error) {
	d, err := s.Detail(ctx, id)
	if err != nil {
		return d, err
	}
	s.addGuesses(ctx, []*AssetCore{&d.Asset.AssetCore})
	risks, ok := s.risks(ctx) // the marker next to the title (the box never has one)
	if !d.Asset.IsBox {
		d.Risk = risks[id]
	}
	d.RiskUnavailable = !ok
	return d, nil
}

// addGuesses sets Guess on every device whose kind is still unknown and that one identification rule fits. It reads only what
// the rows already hold (make, model, OS, host name, open services) and the box's default gateway, asked once.
func (s *Service) addGuesses(ctx context.Context, items []*AssetCore) {
	var gw netip.Addr
	asked := false
	for _, d := range items {
		if d.Kind != devicetypes.Unknown || d.IsBox {
			continue
		}
		if !asked && s.gateway != nil {
			gw, asked = s.gateway(ctx), true
		}
		f := devicetypes.Facts{Gateway: gw.IsValid() && d.IP == gw.String()}
		if d.IP != noIP {
			f.IP = d.IP
		}
		if d.MAC != nil {
			f.MAC = *d.MAC
		}
		if d.Hostname != nil {
			f.Hostname = *d.Hostname
		}
		if d.Vendor != nil {
			f.Vendor = d.Vendor.Value
			f.VendorFromCard = d.Vendor.Source == string(observe.Passive) || d.Vendor.Source == string(observe.Nmap)
		}
		if d.Model != nil {
			f.Model = d.Model.Value
		}
		if d.OS != nil {
			f.OS = d.OS.Value
		}
		for _, sv := range d.Services {
			f.Services = append(f.Services, devicetypes.Service{Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: deref(sv.Product), Detail: deref(sv.Detail)})
		}
		if g, ok := devicetypes.Identify(f); ok {
			d.Guess = &g
		}
	}
}

// snmpState is the SNMP switch as the device page shows it: what SNMPPolicy does with it. Outside lan_ranges the
// default of a discovered device does not reach it (only a stored "on" does), so it shows off until a person turns it on.
func snmpState(st Settings, stored, origin, ip string) string {
	if stored == "" && origin != "manual" {
		if a, err := netip.ParseAddr(ip); err == nil && !inRanges(st, a) {
			return SourceOff
		}
	}
	return sourceState(stored, origin)
}

// inRanges reports whether ip is inside lan_ranges, exclusions aside.
func inRanges(st Settings, ip netip.Addr) bool {
	return st.InScope(ip) || st.Excluded(ip)
}

// sourceState resolves a device's stored setting of one active source: "" is the default, off for a device added by hand and on
// for one a sensor found.
func sourceState(stored, origin string) string {
	switch {
	case stored != "":
		return stored
	case origin == "manual":
		return SourceOff
	}
	return SourceOn
}
