package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
)

// This file is what other modules read and ask through their own ports (feeds.Inventory, findings.Inventory,
// mitigation.Vendors). The adapters live in cmd/vedette; they convert these neutral types to the port types,
// so no module imports another (rules/modules.md).

// DeviceRef is a device as other modules name it.
type DeviceRef struct {
	ID       string
	Hostname *string
	IP       string // "—" when unknown, like the API
	MAC      string // "" when unknown
	Vendor   string // the current vendor value, "" when none
	Kind     string
	Display  string // the first software's display name, else the kind
	Approved bool   // a person approved it, or osquery enrolment did (sensor-active sends SNMP credentials only to approved devices, D-512)
}

// DeviceRefs returns the devices with these ids; unknown ids are absent.
func (s *Service) DeviceRefs(ctx context.Context, ids []string) (map[string]DeviceRef, error) {
	out := make(map[string]DeviceRef, len(ids))
	for chunk := range slices.Chunk(ids, 400) {
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.ip, a.mac, a.vendor, a.kind, a.approved,
			(SELECT display FROM inv_software WHERE asset_id = a.id ORDER BY display, id LIMIT 1)
			FROM inv_asset a WHERE a.id IN (?`+strings.Repeat(`, ?`, len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		for rows.Next() {
			var d DeviceRef
			var host, ip, mac, vendor, display sql.NullString
			if err := rows.Scan(&d.ID, &host, &ip, &mac, &vendor, &d.Kind, &d.Approved, &display); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("inventory: read devices: %w", err)
			}
			d.Hostname, d.IP, d.MAC, d.Vendor, d.Display = ptr(host), noIP, mac.String, vendor.String, d.Kind
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
	ID    string
	Name  string // DisplayName (D-471), else the id
	OS    string // the current operating system ("Ubuntu 26.04.1 LTS", LLDP "JUNOS 15.1R7.9"), "" when unknown (D-500, D-510)
	Model string // the current model ("EX4200-48T"), "" when unknown (D-510: the Juniper series of a Junos flaw)
	// StatedOS is the newest OS the device states itself (an LLDP or SNMP system description, source passive or snmp),
	// even when nmap's guess won OS; "" when none (D-510, review M2 of #703).
	StatedOS string
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
	var osName, model sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT os, model FROM inv_asset WHERE id = ?`, id).Scan(&osName, &model); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MatchDevice{}, false, fmt.Errorf("inventory: read device OS: %w", err)
	}
	d.OS, d.Model = osName.String, model.String
	if d.StatedOS, err = statedOS(ctx, q, id); err != nil {
		return MatchDevice{}, false, err
	}
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

// statedOS is the newest OS observation of the device from its own statement (LLDP, SNMP: sources passive and snmp).
func statedOS(ctx context.Context, q querier, id string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source IN ('passive', 'snmp')
		ORDER BY seen_at DESC, id DESC LIMIT 1`, id).Scan(&v)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("inventory: read the stated OS: %w", err)
	}
	return v, nil
}

// matchView is what the findings matcher reads of a device besides its software (D-510): folded OS, model, stated OS.
func matchView(ctx context.Context, q querier, id string) (string, error) {
	var osName, model sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT os, model FROM inv_asset WHERE id = ?`, id).Scan(&osName, &model); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("inventory: read device OS: %w", err)
	}
	stated, err := statedOS(ctx, q, id)
	return osName.String + "\x00" + model.String + "\x00" + stated, err
}

// HasDevice reports whether the inventory has a device of one of these kinds whose vendor (the device's own
// or that of one of its software rows) is the given one, compared without case.
func (s *Service) HasDevice(ctx context.Context, kinds []string, vendor string) (bool, error) {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	kinds = devicetypes.ActingAs(kinds) // every type that acts as one of the kinds (D-511)
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
	// Approved: a person approved the device. KindSource is the source of the observation the kind came from ("" when the kind
	// has none: the default unknown). Passive-only kinds (SSDP, LLDP, DHCP, mDNS) are self-announced hints (D-177): see TrustedKind.
	Approved   bool
	KindSource string
}

// TrustedKind says whether the kind may feed a safety list (the never-touch gateways, D-177): a person or an agent set it, or the
// device is approved and SNMP or nmap set it. A kind that only a passive frame claimed (SSDP, LLDP, DHCP, mDNS) is a hint any host on
// the wire can send; nmap runs in the untrusted scan container and its guess is shaped by the target (an SSDP claim earns the host an -O
// scan, and a drop box answers like a router), so an unapproved device's nmap or snmp kind is not enough either. An approved device
// whose kind is still a passive frame's claim is not trusted: the operator vouches for it by picking its kind by hand.
func (d KindDevice) TrustedKind() bool {
	switch d.KindSource {
	case "manual", "agent":
		return true
	case "snmp", "nmap":
		return d.Approved
	}
	return false
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
	kinds = devicetypes.ActingAs(kinds) // every type that acts as one of the kinds: a VPN gateway is a firewall, a modem a router (D-511)
	if len(kinds) == 0 {
		return nil, nil
	}
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.ip, a.mac, a.kind, a.approved, o.source FROM inv_asset a LEFT JOIN inv_observation o ON o.id = a.kind_obs_id WHERE a.kind IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`) ORDER BY a.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KindDevice
	for rows.Next() {
		var d KindDevice
		var host, ip, mac, src sql.NullString
		if err := rows.Scan(&d.ID, &host, &ip, &mac, &d.Kind, &d.Approved, &src); err != nil {
			return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
		}
		d.Hostname, d.MAC, d.IP, d.KindSource = ptr(host), ptr(mac), noIP, src.String
		if ip.Valid {
			d.IP = ip.String
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
	}
	return s.trustedKindUnion(ctx, kinds, out)
}

// trustedKindUnion is the union guard of the never-touch list (D-512, INV-20): a device is listed as one of the kinds while ANY trusted
// machine observation (agent, or snmp or nmap on an approved device) says so, whatever its current kind, except those older than a
// person's latest kind: a person's explicit choice wins (it is the current kind, manual ranks first), so a person can take a wrongly
// typed device off the list, and a machine observation seen after that choice puts it back (review #715 M4). A source that ranks higher can
// change the current kind (SNMP outranks nmap, DATA_MODEL 5.1), but it can only ever add a device to the list, never take one off it: an
// on-path host answering a router's SNMP read as a printer does not make the router blockable. A device whose current kind is in kinds
// but not trusted gets the trusted observation's kind and source; a device whose current kind is another one is added with them.
func (s *Service) trustedKindUnion(ctx context.Context, kinds []string, out []KindDevice) ([]KindDevice, error) {
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.ip, a.mac, a.approved, o.value, o.source FROM inv_asset a JOIN inv_observation o ON o.asset_id = a.id
		WHERE o.field = 'kind' AND o.value IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`) AND (o.source = 'agent' OR (o.source IN ('snmp', 'nmap') AND a.approved = 1))
		AND o.seen_at > coalesce((SELECT max(m.seen_at) FROM inv_observation m WHERE m.asset_id = a.id AND m.field = 'kind' AND m.source = 'manual'), '')
		ORDER BY a.id, CASE o.source WHEN 'agent' THEN 1 WHEN 'snmp' THEN 2 ELSE 3 END, o.seen_at DESC`, args...) // only "?" placeholders are concatenated; the kinds are bound
	if err != nil {
		return nil, fmt.Errorf("inventory: read trusted kinds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	at := make(map[string]int, len(out))
	for i, d := range out {
		at[d.ID] = i
	}
	added := false
	for rows.Next() {
		var d KindDevice
		var host, ip, mac sql.NullString
		if err := rows.Scan(&d.ID, &host, &ip, &mac, &d.Approved, &d.Kind, &d.KindSource); err != nil {
			return nil, fmt.Errorf("inventory: read trusted kinds: %w", err)
		}
		i, listed := at[d.ID]
		switch {
		case listed && out[i].TrustedKind():
		case listed:
			out[i].Kind, out[i].KindSource = d.Kind, d.KindSource
		default:
			d.Hostname, d.MAC, d.IP = ptr(host), ptr(mac), noIP
			if ip.Valid {
				d.IP = ip.String
			}
			at[d.ID] = len(out)
			out = append(out, d)
			added = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read trusted kinds: %w", err)
	}
	if added {
		slices.SortFunc(out, func(a, b KindDevice) int { return strings.Compare(a.ID, b.ID) })
	}
	return out, nil
}

// AddressInUse says whether a device other than the box has the address: an indexed read (inv_asset_ip_uq), with no row cap (D-178;
// Devices stops at MaxListed and would forget the oldest device). A read error is returned and the caller must fail closed.
func (s *Service) AddressInUse(ctx context.Context, ip string) (bool, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE ip = ? AND is_box = 0`, ip).Scan(&n); err != nil {
		return false, fmt.Errorf("inventory: read address: %w", err)
	}
	return n > 0, nil
}

// KnownMACs returns the MAC of every device that has one, with no row cap (D-178): the sensor's new-device budget counts a device
// absent from it as new, so a capped list would make old devices eat the budget of real new ones. Lower case, ordered; a read error is
// returned, never a short list.
func (s *Service) KnownMACs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT mac FROM inv_asset WHERE mac IS NOT NULL ORDER BY mac`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read macs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, fmt.Errorf("inventory: read macs: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read macs: %w", err)
	}
	return out, nil
}

// AddressMap returns the device id of every IP the inventory knows, with no row cap (D-178). Read error: returned, never a short map.
func (s *Service) AddressMap(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT ip, id FROM inv_asset WHERE ip IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var ip, id string
		if err := rows.Scan(&ip, &id); err != nil {
			return nil, fmt.Errorf("inventory: read addresses: %w", err)
		}
		out[ip] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read addresses: %w", err)
	}
	return out, nil
}

// BoxName returns the host name and IP of the box device ("" when it has none; ok false when there is no box row yet): a direct read of
// the one row, where Devices would load up to MaxListed devices to find it.
func (s *Service) BoxName(ctx context.Context) (hostname, ip string, ok bool, err error) {
	var h, i sql.NullString
	err = s.db.Reader().QueryRowContext(ctx, `SELECT hostname, ip FROM inv_asset WHERE is_box = 1`).Scan(&h, &i)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	} else if err != nil {
		return "", "", false, fmt.Errorf("inventory: read box: %w", err)
	}
	return h.String, i.String, true, nil
}

// AllDevices lists every device with no row cap (D-178), for readers that must see them all (the honeypot's conflict and spare-IP
// checks). Devices is the capped list of the API.
// ponytail: loads software and services of every device; fine to about 1,000 devices, about 100-300 ms per call at 10k-50k. Upgrade
// path: a narrow read (id, IP, hostname, kind, approved, is_box, OS, ports) with no software.
func (s *Service) AllDevices(ctx context.Context) ([]Device, error) {
	return s.loadDevices(ctx, s.db.Reader(), "", 0)
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
// data from the CISA list, not something a person typed. The events are kept until the caller calls Settle. It returns
// the new device's id: feeds scopes "I have this" to that one device (D-484 (4), W1-3).
func (s *Service) AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, in ManualDevice) (string, error) {
	if in.Key != kevKey(in.Vendor, in.Product) {
		return "", badRequest("bad_product", "The product key does not match the vendor and product.")
	}
	c, err := s.Catalog(ctx)
	if err != nil {
		return "", err
	}
	a, aerr := checkAdd(c, AddInput{Vendor: in.Vendor, Product: in.Product}, true)
	if aerr != nil && aerr.Code == "bad_product" && c.kevCount[in.Key] > 0 && cleanText(strings.TrimSpace(in.Vendor)) && cleanText(strings.TrimSpace(in.Product)) {
		a, aerr = addChecked{entry: c.custom(strings.TrimSpace(in.Vendor), strings.TrimSpace(in.Product))}, nil
	}
	if aerr != nil {
		return "", aerr
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
		kind = suggestedKind(in.Kind, a) // feeds' suggestion (W9-1, D-515)
	}
	var o outbox
	id, err := s.createManual(ctx, tx, &o, a, kind)
	if err != nil {
		return "", err
	}
	if err := s.auditTx(ctx, tx, actor, "inventory.add_manual", a.entry.display, ""); err != nil {
		return "", err
	}
	s.keep(tx, &o)
	return id, nil
}

// keep holds o's events until Settle(tx) (AddManualDevice, SetupScope); a second call in the same transaction adds to the first.
func (s *Service) keep(tx *sql.Tx, o *outbox) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	if s.pending == nil {
		s.pending = map[*sql.Tx]*outbox{}
	}
	if p := s.pending[tx]; p != nil {
		p.events = append(p.events, o.events...)
		p.after = append(p.after, o.after...)
		return
	}
	s.pending[tx] = o
}

// Settle ends AddManualDevice and SetupScope for tx: when the caller's transaction committed the events go out, when it rolled
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

// RematchAll announces inventory.match.changed once for every device with software keyed to a CISA entry (D-78: after
// a baseline pull, or when matching must be recomputed from scratch, e.g. the first NVD fill of D-500). The event names
// the device's first CVE; findings matches the whole device on it (review H3: one event per device, not per device and
// CVE, so a rematch of hundreds of devices fits its deadline). It returns how many events it published.
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
		if len(cves) == 0 {
			continue
		}
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: slices.Min(cves), Basis: "product"}}})
		n++
	}
	return n, nil
}

// KevRef names a CISA entry by its CVE and its vendor and product.
type KevRef struct{ CVE, Vendor, Product string }

// RematchMany announces inventory.match.changed once for every device that runs the product of one of refs (a
// "Multiple products" entry: any product of its vendor), naming the first such CVE. D-500 review H3: after an NVD
// update of a few CVEs only their devices are matched again, each once. It returns how many events it published.
func (s *Service) RematchMany(ctx context.Context, refs []KevRef) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	first := map[string]string{}
	var order []string
	for _, r := range refs {
		ids, err := s.devicesOf(ctx, r.Vendor, r.Product)
		if err != nil {
			return 0, err
		}
		for _, id := range ids {
			if c, ok := first[id]; !ok || r.CVE < c {
				if !ok {
					order = append(order, id)
				}
				first[id] = r.CVE
			}
		}
	}
	for _, id := range order {
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: first[id], Basis: "product"}}})
	}
	return len(order), nil
}

// devicesOf lists the devices with software keyed to vendor|product, or to any product of vendor for "Multiple products".
func (s *Service) devicesOf(ctx context.Context, vendor, product string) ([]string, error) {
	vendor, product = strings.ToLower(vendor), strings.ToLower(product)
	prefix := vendor + "|"
	multi := strings.TrimSpace(product) == multiProducts
	return s.assetIDs(ctx, `SELECT DISTINCT s.asset_id FROM inv_software_kev k JOIN inv_software s ON s.id = k.software_id
		WHERE k.kev_key = ? OR k.kev_key = ? OR (? = 1 AND substr(k.kev_key, 1, ?) = ?)`, prefix+product, prefix+multiProducts, boolInt(multi), len(prefix), prefix)
}

// RematchCVE announces inventory.match.changed for the devices that run the product of a CVE feeds has just
// listed (feeds.vuln.new_kev). A "Multiple products" entry matches every device with software of the vendor.
func (s *Service) RematchCVE(ctx context.Context, cve, vendor, product string) (int, error) {
	return s.RematchCVEExcept(ctx, cve, vendor, product, nil)
}

// RematchCVEExcept is RematchCVE that leaves out the devices known says already match the CVE (D-328: a CVE whose vendor or product
// changed is announced to the devices of its new product that have no finding for it, so a flag that changed on hundreds of entries does
// not announce each device once per entry).
// known returning an error is that error; nil known leaves nobody out.
func (s *Service) RematchCVEExcept(ctx context.Context, cve, vendor, product string, known func(ctx context.Context, assetID, cve string) (bool, error)) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	ids, err := s.devicesOf(ctx, vendor, product)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if known != nil {
			has, err := known(ctx, id, cve)
			if err != nil {
				return n, err
			}
			if has {
				continue
			}
		}
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: cve, Basis: "product"}}})
		n++
	}
	return n, nil
}
