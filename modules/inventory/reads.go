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
	"github.com/knt048/vedette/core/observe"
)

const noIP = "—" // what the API says for a device whose IP is unknown (contract.ts Asset.ip)

const assetColumns = `a.id, a.ip, a.mac, a.hostname, a.kind, k.source, a.origin, a.approved, a.fragile, a.regular_scan, a.first_scan_at, a.approved_at, a.suspicious, a.is_box, a.notes, a.first_seen, a.last_seen,
	v.value, v.source, v.confidence, v.seen_at, m.value, m.source, m.confidence, m.seen_at, o.value, o.source, o.confidence, o.seen_at,
	h.value, h.source, h.confidence, h.seen_at, x.value, x.source, x.confidence, x.seen_at`

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
		var ip, mac, host, scan, approvedAt, notes, kindSrc sql.NullString
		var v, m, o, h, x obsCols
		var approved, fragile, suspicious, box bool
		if err := rows.Scan(&d.ID, &ip, &mac, &host, &d.Kind, &kindSrc, &d.Origin, &approved, &fragile, &d.RegularScan, &scan, &approvedAt, &suspicious, &box, &notes, &d.FirstSeen, &d.LastSeen,
			&v.value, &v.source, &v.conf, &v.seen, &m.value, &m.source, &m.conf, &m.seen, &o.value, &o.source, &o.conf, &o.seen,
			&h.value, &h.source, &h.conf, &h.seen, &x.value, &x.source, &x.conf, &x.seen); err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		d.Site = "hq" // one site (D-24)
		d.IP = noIP
		if ip.Valid {
			d.IP = ip.String
		}
		d.MAC, d.Hostname, d.FirstScanAt, d.ApprovedAt, d.Notes, d.KindSource = ptr(mac), ptr(host), ptr(scan), ptr(approvedAt), ptr(notes), ptr(kindSrc)
		d.Vendor, d.Model, d.OS = v.observed(), m.observed(), o.observed()
		d.ident = []*Observed{h.observed(), x.observed()}
		d.Approved, d.Fragile, d.Suspicious, d.IsBox = approved, fragile, suspicious, box
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
	if err := s.loadSoftware(ctx, q, sub, idx, out, args); err != nil {
		return nil, err
	}
	if err := loadServices(ctx, q, sub, idx, out, args); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) loadSoftware(ctx context.Context, q querier, sub string, idx map[string]int, out []Device, args []any) error {
	rows, err := q.QueryContext(ctx, `SELECT s.asset_id, s.id, s.display, s.vendor, s.product, s.version, s.source, s.confidence, k.kev_key
		FROM inv_software s LEFT JOIN inv_software_kev k ON k.software_id = s.id
		WHERE s.asset_id IN `+sub+` ORDER BY s.asset_id, s.display, s.id, k.kev_key`, args...)
	if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var asset, key sql.NullString
		var sw Software
		var ver sql.NullString
		if err := rows.Scan(&asset, &sw.ID, &sw.Display, &sw.Vendor, &sw.Product, &ver, &sw.Source, &sw.Confidence, &key); err != nil {
			return fmt.Errorf("inventory: read software: %w", err)
		}
		d := &out[idx[asset.String]]
		if n := len(d.Software); n > 0 && d.Software[n-1].ID == sw.ID {
			d.Software[n-1].Kev = append(d.Software[n-1].Kev, key.String)
			continue
		}
		sw.Version = ptr(ver)
		sw.Kev = []string{}
		if key.Valid {
			sw.Kev = append(sw.Kev, key.String)
		}
		d.Software = append(d.Software, sw)
	}
	return rows.Err()
}

func loadServices(ctx context.Context, q querier, sub string, idx map[string]int, out []Device, args []any) error {
	rows, err := q.QueryContext(ctx, `SELECT asset_id, port, proto, name, product, version, detail, source, confidence FROM inv_service
		WHERE asset_id IN `+sub+` ORDER BY asset_id, port, proto, source`, args...)
	if err != nil {
		return fmt.Errorf("inventory: read services: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var asset string
		var sv ServiceRow
		var product, version, detail sql.NullString
		if err := rows.Scan(&asset, &sv.Port, &sv.Proto, &sv.Name, &product, &version, &detail, &sv.Source, &sv.Confidence); err != nil {
			return fmt.Errorf("inventory: read services: %w", err)
		}
		sv.Product, sv.Version, sv.Detail = ptr(product), ptr(version), ptr(detail)
		d := &out[idx[asset]]
		d.Services = append(d.Services, sv)
	}
	return rows.Err()
}

// summaryOf is the source of the most trusted of vendor, model, os and the confidence of the weakest. A device with
// none of them (a router seen only by ARP) takes its hostname and MAC instead, so the list still says which sensor saw
// it (walk 4: "Unknown 192.168.18.1" with source "–").
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

// Devices lists the devices for GET /inventory/devices: at most MaxListed rows, the counts over all of them.
func (s *Service) Devices(ctx context.Context) (DeviceList, error) {
	db := s.db.Reader()
	items, err := s.loadDevices(ctx, db, "", MaxListed)
	if err != nil {
		return DeviceList{}, err
	}
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return DeviceList{}, err
	}
	out := DeviceList{Items: items}
	if out.Items == nil {
		out.Items = []Device{}
	}
	s.addGuesses(ctx, out.Items)
	now := s.now()
	for i := range out.Items {
		d := &out.Items[i]
		d.FindingsCount = counts[d.ID]
		d.Summary = summaryOf(d)
		if d.IsBox {
			d.LastSeen = now // the box is the machine running Vedette: always just seen
		}
	}
	err = db.QueryRowContext(ctx, `SELECT count(*), ifnull(sum(approved = 0), 0), ifnull(sum(fragile), 0), ifnull(sum(origin = 'manual'), 0) FROM inv_asset`).
		Scan(&out.Counts.All, &out.Counts.Pending, &out.Counts.Fragile, &out.Counts.Manual)
	if err != nil {
		return DeviceList{}, fmt.Errorf("inventory: count devices: %w", err)
	}
	if out.NotifyNew, err = notifyNew(ctx, db); err != nil {
		return DeviceList{}, err
	}
	out.NotifyAvailable = s.modules != nil && s.modules.Enabled("notify")
	return out, nil
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
	s.addGuesses(ctx, items)
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
	if err := db.QueryRowContext(ctx, `SELECT kind_obs_id, hostname_obs_id, mac_obs_id, vendor_obs_id, model_obs_id, os_obs_id FROM inv_asset WHERE id = ?`, id).
		Scan(&cur[0], &cur[1], &cur[2], &cur[3], &cur[4], &cur[5]); err != nil {
		return Detail{}, fmt.Errorf("inventory: read device: %w", err)
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
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return Detail{}, fmt.Errorf("inventory: read observations: %w", err)
	}
	slices.SortFunc(list, func(a, b ObservationRow) int {
		if c := slices.Index(fieldOrder, a.Field) - slices.Index(fieldOrder, b.Field); c != 0 {
			return c
		}
		return -strings.Compare(a.SeenAt, b.SeenAt)
	})

	views := make([]SoftwareView, 0, len(d.Software))
	for _, sw := range d.Software {
		cves, err := s.cves(ctx, sw.Kev)
		if err != nil {
			return Detail{}, err
		}
		views = append(views, SoftwareView{ID: sw.ID, Display: sw.Display, Vendor: sw.Vendor, Product: sw.Product, Version: sw.Version, KevCVEs: cves, Source: sw.Source, Confidence: sw.Confidence})
	}
	return Detail{
		Asset:         DetailAsset{AssetCore: d.AssetCore, Software: views},
		Suspicious:    d.Suspicious,
		FindingsCount: d.FindingsCount,
		Observations:  list,
		Kinds:         devicetypes.IDs(),
	}, nil
}

// cves returns the CVE ids feeds knows for the keys; none when feeds gives none.
func (s *Service) cves(ctx context.Context, keys []string) ([]string, error) {
	if s.kev == nil || len(keys) == 0 {
		return []string{}, nil
	}
	list, err := s.kev.CVEs(ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("inventory: KEV match: %w", err)
	}
	if list == nil {
		list = []string{}
	}
	return list, nil
}

// NoDevice ends the name of a device added by hand that has neither a name nor an IP: it is only a product someone
// declared ("Microsoft Office (no device)"), never a nameless row (D-471).
const NoDevice = " (no device)"

// DisplayName is the one naming rule of every page and module (D-471; web/src/features/inventory/nameOf.ts is the same):
// the host name (a name typed by hand is one); then a device added by hand is named after its first product, with
// NoDevice when it has no IP either; any other device after its make and model, then its IP. "" when none of these is
// known: the caller adds the kind, the IP placeholder or the id.
func DisplayName(hostname, vendor, model, ip, origin, product string) string {
	if h := strings.TrimSpace(hostname); h != "" {
		return h
	}
	hasIP := ip != "" && ip != noIP
	if p := strings.TrimSpace(product); origin == "manual" && p != "" {
		if hasIP {
			return p
		}
		return p + NoDevice
	}
	if hw := strings.TrimSpace(strings.TrimSpace(vendor) + " " + strings.TrimSpace(model)); hw != "" {
		return hw
	}
	if hasIP {
		return ip
	}
	return ""
}

// Name is DisplayName of a listed device; its software is sorted by display name, like firstSoftware.
func (d Device) Name() string {
	product := ""
	if len(d.Software) > 0 {
		product = d.Software[0].Display
	}
	return DisplayName(deref(d.Hostname), obsValue(d.Vendor), obsValue(d.Model), d.IP, d.Origin, product)
}

// firstSoftware selects the display name of a device's first software, in the order the pages list it (D-471 naming).
const firstSoftware = `(SELECT display FROM inv_software WHERE asset_id = a.id ORDER BY display, id LIMIT 1)`

// Names maps device ids to the name to show (DisplayName; the id when nothing is known) for findings, notify, honeypot
// and reports.
func (s *Service) Names(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.vendor, a.model, a.ip, a.origin, `+firstSoftware+` FROM inv_asset a`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id, origin string
		var host, vendor, model, ip, product sql.NullString
		if err := rows.Scan(&id, &host, &vendor, &model, &ip, &origin, &product); err != nil {
			return nil, fmt.Errorf("inventory: read names: %w", err)
		}
		if out[id] = DisplayName(host.String, vendor.String, model.String, ip.String, origin, product.String); out[id] == "" {
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
// (DisplayName, D-471), else the id.
func deviceName(ctx context.Context, q querier, id string) string {
	var host, vendor, model, ip, product sql.NullString
	var origin string
	if err := q.QueryRowContext(ctx, `SELECT a.hostname, a.vendor, a.model, a.ip, a.origin, `+firstSoftware+` FROM inv_asset a WHERE a.id = ?`, id).
		Scan(&host, &vendor, &model, &ip, &origin, &product); err != nil {
		return id
	}
	if n := DisplayName(host.String, vendor.String, model.String, ip.String, origin, product.String); n != "" {
		return n
	}
	return id
}

// addGuesses sets Guess on every device whose kind is still unknown and that one identification rule fits (D-511). It reads only what
// the rows already hold (make, model, OS, host name, open services) and the box's default gateway, asked once.
func (s *Service) addGuesses(ctx context.Context, items []Device) {
	var gw netip.Addr
	asked := false
	for i := range items {
		d := &items[i]
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
