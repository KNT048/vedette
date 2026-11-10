package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

// This file is what other modules read and ask through their own ports (feeds.Inventory, findings.Inventory,
// mitigation.Vendors). The adapters live in cmd/vedette; they convert these neutral types to the port types,
// so no module imports another (rules/modules.md).

// DeviceRef is a device as other modules name it.
type DeviceRef struct {
	ID       string
	Hostname *string
	IP       string // "—" when unknown, like the API
	Kind     string
	Display  string // the first software's display name, else the kind
}

// DeviceRefs returns the devices with these ids; unknown ids are absent.
func (s *Service) DeviceRefs(ctx context.Context, ids []string) (map[string]DeviceRef, error) {
	out := make(map[string]DeviceRef, len(ids))
	for chunk := range slices.Chunk(ids, 400) {
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.ip, a.kind,
			(SELECT display FROM inv_software WHERE asset_id = a.id ORDER BY display, id LIMIT 1)
			FROM inv_asset a WHERE a.id IN (?`+strings.Repeat(`, ?`, len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		for rows.Next() {
			var d DeviceRef
			var host, ip, display sql.NullString
			if err := rows.Scan(&d.ID, &host, &ip, &d.Kind, &display); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("inventory: read devices: %w", err)
			}
			d.Hostname, d.IP, d.Display = ptr(host), noIP, d.Kind
			if ip.Valid {
				d.IP = ip.String
			}
			if display.Valid {
				d.Display = display.String
			}
			out[d.ID] = d
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
	}
	return out, nil
}

// MatchSoftware is one software row with the KEV keys it was matched to.
type MatchSoftware struct {
	ID, Display, Vendor, Product, Version, CPE string
	KevKeys                                    []string
}

// MatchDevice is a device with its software, for the matcher of findings.
type MatchDevice struct {
	ID       string
	Name     string // hostname, else the IP, else the id
	Software []MatchSoftware
}

// MatchInput returns the device with its software; ok is false when it does not exist.
func (s *Service) MatchInput(ctx context.Context, id string) (d MatchDevice, ok bool, err error) {
	q := s.db.Reader()
	found, err := assetExists(ctx, q, id)
	if err != nil || !found {
		return MatchDevice{}, false, err
	}
	d = MatchDevice{ID: id, Name: deviceName(ctx, q, id), Software: []MatchSoftware{}}
	rows, err := q.QueryContext(ctx, `SELECT s.id, s.display, s.vendor, s.product, ifnull(s.version, ''), ifnull(s.cpe, ''), k.kev_key
		FROM inv_software s LEFT JOIN inv_software_kev k ON k.software_id = s.id WHERE s.asset_id = ? ORDER BY s.display, s.id, k.kev_key`, id)
	if err != nil {
		return MatchDevice{}, false, fmt.Errorf("inventory: read software: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var sw MatchSoftware
		var key sql.NullString
		if err := rows.Scan(&sw.ID, &sw.Display, &sw.Vendor, &sw.Product, &sw.Version, &sw.CPE, &key); err != nil {
			return MatchDevice{}, false, fmt.Errorf("inventory: read software: %w", err)
		}
		if n := len(d.Software); n > 0 && d.Software[n-1].ID == sw.ID {
			d.Software[n-1].KevKeys = append(d.Software[n-1].KevKeys, key.String)
			continue
		}
		sw.KevKeys = []string{}
		if key.Valid {
			sw.KevKeys = append(sw.KevKeys, key.String)
		}
		d.Software = append(d.Software, sw)
	}
	if err := rows.Err(); err != nil {
		return MatchDevice{}, false, fmt.Errorf("inventory: read software: %w", err)
	}
	return d, true, nil
}

// HasDevice reports whether the inventory has a device of one of these kinds whose vendor (the device's own
// or that of one of its software rows) is the given one, compared without case.
func (s *Service) HasDevice(ctx context.Context, kinds []string, vendor string) (bool, error) {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if vendor == "" || len(kinds) == 0 {
		return false, nil
	}
	args := make([]any, 0, len(kinds)+2)
	for _, k := range kinds {
		args = append(args, k)
	}
	args = append(args, vendor, vendor)
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_asset a WHERE a.kind IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`)
		AND (lower(a.vendor) = ? OR EXISTS (SELECT 1 FROM inv_software s WHERE s.asset_id = a.id AND lower(s.vendor) = ?))`, args...).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("inventory: read vendors: %w", err)
	}
	return n > 0, nil
}

// KindDevice is a device of one of the kinds asked for in DevicesOfKind: who it is and the addresses it answers on.
type KindDevice struct {
	ID       string
	Hostname *string
	IP       string  // "—" when unknown, like the API
	MAC      *string // lower case aa:bb:cc:dd:ee:ff
	Kind     string
}

// AssetIDs returns the id of every device, with no kind filter and no row cap, ordered by id: the list a reconcile compares
// against (findings, D-144), so a device of any kind, even one added to the schema later, is never missing. Any read error is
// returned and the caller must fail closed: a short list would make the caller drop data of devices that still exist.
func (s *Service) AssetIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM inv_asset ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read device ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: read device ids: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read device ids: %w", err)
	}
	return out, nil
}

// DevicesOfKind returns every device of the given kinds, with no row cap (Devices stops at MaxListed, newest first, which is the
// wrong read for a safety list: the oldest device, usually the gateway, would be the one cut). Read-only, ordered by id. An empty
// kinds is an empty answer. Any read error is returned and the caller must fail closed: a short list is never a valid answer.
func (s *Service) DevicesOfKind(ctx context.Context, kinds []string) ([]KindDevice, error) {
	if len(kinds) == 0 {
		return nil, nil
	}
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, hostname, ip, mac, kind FROM inv_asset WHERE kind IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`) ORDER BY id`, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KindDevice
	for rows.Next() {
		var d KindDevice
		var host, ip, mac sql.NullString
		if err := rows.Scan(&d.ID, &host, &ip, &mac, &d.Kind); err != nil {
			return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
		}
		d.Hostname, d.MAC, d.IP = ptr(host), ptr(mac), noIP
		if ip.Valid {
			d.IP = ip.String
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
	}
	return out, nil
}

// ProductQuery is a vendor and product pair of KEV.
type ProductQuery struct{ Vendor, Product string }

// Key is the matching key (lower(vendor)|lower(product)) of the pair.
func (p ProductQuery) Key() string { return kevKey(p.Vendor, p.Product) }

// DeviceMatch is a device that runs a product (Exact) or may run it (a "Multiple products" entry that only
// the vendor matches).
type DeviceMatch struct {
	DeviceRef
	Exact bool
}

const multiProducts = "multiple products"

// DevicesRunning finds, for each product, the devices that run it. The map is keyed by ProductQuery.Key();
// a product with no device has no entry. A normal product matches the devices with a software row carrying
// its key. A "Multiple products" entry matches exactly only a software row declared with that product (the
// "I have it" device); a device that has any software of the vendor, or that the vendor made, matches by
// vendor only.
func (s *Service) DevicesRunning(ctx context.Context, products []ProductQuery) (map[string][]DeviceMatch, error) {
	out := map[string][]DeviceMatch{}
	for _, p := range products {
		key := p.Key()
		if _, done := out[key]; done {
			continue
		}
		vendor, product := strings.ToLower(p.Vendor), strings.ToLower(p.Product)
		multi := strings.TrimSpace(product) == multiProducts
		exact, err := s.assetIDs(ctx, `SELECT DISTINCT s.asset_id FROM inv_software_kev k JOIN inv_software s ON s.id = k.software_id
			WHERE k.kev_key = ? AND (? = 0 OR lower(s.product) = ?)`, key, boolInt(multi), product)
		if err != nil {
			return nil, err
		}
		var byVendor []string
		if multi {
			prefix := vendor + "|"
			byVendor, err = s.assetIDs(ctx, `SELECT DISTINCT s.asset_id FROM inv_software_kev k JOIN inv_software s ON s.id = k.software_id WHERE substr(k.kev_key, 1, ?) = ?
				UNION SELECT id FROM inv_asset WHERE lower(vendor) = ?`, len(prefix), prefix, vendor)
			if err != nil {
				return nil, err
			}
		}
		refs, err := s.DeviceRefs(ctx, slices.Concat(exact, byVendor))
		if err != nil {
			return nil, err
		}
		var list []DeviceMatch
		for _, id := range slices.Concat(exact, byVendor) {
			if r, ok := refs[id]; ok {
				list = append(list, DeviceMatch{DeviceRef: r, Exact: slices.Contains(exact, id)})
				delete(refs, id) // a device once, the exact answer first
			}
		}
		if len(list) > 0 {
			out[key] = list
		}
	}
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Service) assetIDs(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, query+` ORDER BY 1`, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: match products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: match products: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ManualDevice is the device "I have it" declares (feeds, S-FEED-2): one device that runs the product.
type ManualDevice struct {
	Kind    string // a hint; anything that is not a device kind is ignored
	Vendor  string
	Product string
	Display string // the name people recognise; empty keeps "vendor product"
	Key     string // lower(vendor)|lower(product), must be that of Vendor and Product
}

// AddManualDevice declares a device inside the caller's write transaction tx (INV-14): the device, its
// software, the audit row and the events are the caller's one commit. It applies every check of AddDevice (a
// product from the catalog or typed by hand, the same length and character rules). The one difference: a
// vendor and product that are an exact pair of the KEV list may be longer than 64 characters, because that is
// data from the CISA list, not something a person typed. The events are kept until the caller calls Settle.
func (s *Service) AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, in ManualDevice) error {
	if in.Key != kevKey(in.Vendor, in.Product) {
		return badRequest("bad_product", "The product key does not match the vendor and product.")
	}
	c, err := s.Catalog(ctx)
	if err != nil {
		return err
	}
	a, aerr := checkAdd(c, AddInput{Vendor: in.Vendor, Product: in.Product}, true)
	if aerr != nil && aerr.Code == "bad_product" && c.kevCount[in.Key] > 0 && cleanText(strings.TrimSpace(in.Vendor)) && cleanText(strings.TrimSpace(in.Product)) {
		a, aerr = addChecked{entry: c.custom(strings.TrimSpace(in.Vendor), strings.TrimSpace(in.Product))}, nil
	}
	if aerr != nil {
		return aerr
	}
	e := *a.entry
	if d := strings.TrimSpace(in.Display); label(d) { // a name with markup or too long is not used; the product's own name stays
		e.display = d
	}
	if r := []rune(e.display); len(r) > maxObsValue { // vendor and product of a KEV pair may add up to more than a column holds
		e.display = string(r[:maxObsValue])
	}
	a.entry = &e
	kind := ""
	if validKind(in.Kind) {
		kind = in.Kind
	}
	var o outbox
	if _, err := s.createManual(ctx, tx, &o, a, kind); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, actor, "inventory.add_manual", a.entry.display, ""); err != nil {
		return err
	}
	s.pendMu.Lock()
	if s.pending == nil {
		s.pending = map[*sql.Tx]*outbox{}
	}
	s.pending[tx] = &o
	s.pendMu.Unlock()
	return nil
}

// Settle ends AddManualDevice for tx: when the caller's transaction committed the events go out, when it rolled
// back they are dropped. The caller must call it once it knows which; a transaction with no pending events is
// a no-op.
func (s *Service) Settle(ctx context.Context, tx *sql.Tx, committed bool) {
	s.pendMu.Lock()
	o := s.pending[tx]
	delete(s.pending, tx)
	s.pendMu.Unlock()
	if o == nil || !committed {
		return
	}
	events := o.events
	for _, f := range o.after {
		events = append(events, f(ctx)...)
	}
	s.publish(ctx, events)
}

// RematchAll announces inventory.match.changed for every device and CVE that match now (D-78: after a baseline
// pull, or when matching must be recomputed from scratch). It returns how many events it published.
func (s *Service) RematchAll(ctx context.Context) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT s.asset_id, k.kev_key FROM inv_software s JOIN inv_software_kev k ON k.software_id = s.id ORDER BY s.asset_id, k.kev_key`)
	if err != nil {
		return 0, fmt.Errorf("inventory: read match keys: %w", err)
	}
	keys := map[string][]string{}
	var order []string
	for rows.Next() {
		var id, key string
		if err := rows.Scan(&id, &key); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("inventory: read match keys: %w", err)
		}
		if _, ok := keys[id]; !ok {
			order = append(order, id)
		}
		if l := keys[id]; len(l) == 0 || l[len(l)-1] != key {
			keys[id] = append(l, key)
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range order {
		cves, err := s.cves(ctx, keys[id])
		if err != nil {
			return n, err
		}
		for _, cve := range slices.Compact(slices.Sorted(slices.Values(cves))) {
			s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: cve, Basis: "product"}}})
			n++
		}
	}
	return n, nil
}

// RematchCVE announces inventory.match.changed for the devices that run the product of a CVE feeds has just
// listed (feeds.vuln.new_kev). A "Multiple products" entry matches every device with software of the vendor.
func (s *Service) RematchCVE(ctx context.Context, cve, vendor, product string) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	vendor, product = strings.ToLower(vendor), strings.ToLower(product)
	prefix := vendor + "|"
	multi := strings.TrimSpace(product) == multiProducts
	ids, err := s.assetIDs(ctx, `SELECT DISTINCT s.asset_id FROM inv_software_kev k JOIN inv_software s ON s.id = k.software_id
		WHERE k.kev_key = ? OR k.kev_key = ? OR (? = 1 AND substr(k.kev_key, 1, ?) = ?)`, prefix+product, prefix+multiProducts, boolInt(multi), len(prefix), prefix)
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: cve, Basis: "product"}}})
	}
	return len(ids), nil
}
