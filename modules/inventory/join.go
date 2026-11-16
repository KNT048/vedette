package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/store"
)

// chassisEvidence marks the mac observation a join leaves on the device it joined into (D-515): the chassis (base) MAC an LLDP
// frame names. It never becomes the device's MAC (RecomputeAsset skips it), and an observation that names only this MAC finds
// that device again instead of making a new one (resolve).
const chassisEvidence = "chassis"

// chassisBlock is how far above the base (chassis) MAC a switch numbers the MACs of its interfaces: Juniper, Cisco and HPE give
// each interface, the management port included, a MAC from a block that starts at the base MAC (D-515).
const chassisBlock = 0x7f

// netGear are the kinds an LLDP frame gives a network device that has a base MAC (capabilities Bridge, Router, WLAN AP), and a
// firewall a person or a better source named.
var netGear = []string{"switch", "router", "ap", "firewall"}

// defaultNames are host names a device has out of the box (Junos "Amnesiac", MikroTik's own name): two devices sharing one are
// not the same device (review M1 of #722).
var defaultNames = []string{"switch", "router", "ap", "gateway", "localhost", "mikrotik", "amnesiac"}

// sameDevice finds the device a device seen without an address is part of (D-515, W1-37): a switch heard by LLDP under its chassis
// MAC is the device that answers ARP and scans on its management address under another MAC of the same chassis. From strongest:
// (b) the same host name (LLDP system name), not a default name, on a device whose MAC shares the first four bytes; (c) the chassis
// MAC is the base of a block that holds the other device's MAC: same first five bytes, within chassisBlock above. Rule (a), the LLDP
// management address, waits for the sensor protocol to carry it (D-515). Only a discovered device with a MAC, no IP and a network
// kind joins; only into a device with an IP that is not the box, whose name, model and OS (as stated, not guessed by a scan) do not
// differ from its own, and that holds no chassis mark of another MAC; and only when exactly one device fits. "" when none fits.
func sameDevice(ctx context.Context, tx *sql.Tx, id string) (into, why string, err error) {
	var ip, mac sql.NullString
	var origin string
	var isBox bool
	if err := tx.QueryRowContext(ctx, `SELECT ip, mac, origin, is_box FROM inv_asset WHERE id = ?`, id).Scan(&ip, &mac, &origin, &isBox); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("inventory: read device: %w", err)
	}
	if ip.Valid || !mac.Valid || origin != "discovered" || isBox || localMAC(mac.String) {
		return "", "", nil
	}
	own, err := facts(ctx, tx, id)
	if err != nil {
		return "", "", err
	}
	if !slices.Contains(netGear, devicetypes.ActsAs(own["kind"])) {
		return "", "", nil
	}
	// fits keeps the candidates that state nothing against this device and carry no other chassis.
	fits := func(q string, args ...any) ([]string, error) {
		ids, err := candidates(ctx, tx, q+` AND ip IS NOT NULL AND is_box = 0 AND NOT EXISTS (SELECT 1 FROM inv_observation o
			WHERE o.asset_id = inv_asset.id AND o.field = 'mac' AND o.evidence = ? AND o.value <> ?)`, append(args, chassisEvidence, mac.String)...)
		if err != nil {
			return nil, err
		}
		ids = slices.DeleteFunc(ids, func(other string) bool {
			theirs, ferr := facts(ctx, tx, other)
			if ferr != nil {
				err = ferr
			}
			return ferr != nil || differ(own, theirs)
		})
		return ids, err
	}
	if h := own["hostname"]; h != "" && !slices.Contains(defaultNames, strings.ToLower(h)) {
		ids, err := fits(`SELECT id FROM inv_asset WHERE lower(hostname) = lower(?) AND substr(mac, 1, 11) = ?`, h, mac.String[:11])
		if err != nil {
			return "", "", err
		}
		if len(ids) == 1 {
			return ids[0], "the same name " + h, nil
		}
	}
	ids, err := fits(`SELECT id FROM inv_asset WHERE substr(mac, 1, 14) = ? AND mac <> ?`, mac.String[:14], mac.String)
	if err != nil {
		return "", "", err
	}
	base := lastByte(mac.String)
	ids = slices.DeleteFunc(ids, func(other string) bool {
		var m string
		if tx.QueryRowContext(ctx, `SELECT mac FROM inv_asset WHERE id = ?`, other).Scan(&m) != nil {
			return true
		}
		d := lastByte(m) - base
		return d <= 0 || d > chassisBlock
	})
	if len(ids) == 1 {
		return ids[0], "its chassis MAC " + mac.String + " is the base of the MAC block", nil
	}
	return "", "", nil
}

// statedPassiveOS is the confidence of an OS a passive sensor read from the device's own LLDP description (sensor-passive
// ConfLLDPDesc). A lower one is the DHCP client's family guess (ConfDHCPOS, "Linux"), not something the device states.
const statedPassiveOS = 0.5

// facts is what a device says about itself: the winning kind and host name of any source, and the winning model and OS of a
// source that states them (a scan's fingerprint is a guess: the N100 switch states JUNOS 15.1R7.9 while nmap guesses JUNOS 12; so
// is the OS family a DHCP request hints at).
func facts(ctx context.Context, tx *sql.Tx, id string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ?
		AND (field IN ('kind', 'hostname') OR (field IN ('model', 'os') AND source NOT IN ('nmap', 'scan')
		AND NOT (field = 'os' AND source = 'passive' AND confidence < ?)))`, id, statedPassiveOS)
	if err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			return nil, fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	out := map[string]string{}
	for f, o := range winners(list) {
		out[f] = strings.TrimSpace(o.value)
	}
	return out, nil
}

// differ reports two devices that name, model or OS themselves differently: two switches, not one. Host names compare by their
// first label: reverse DNS says "ex4200.lan" where LLDP says "ex4200".
func differ(a, b map[string]string) bool {
	for _, f := range []string{"hostname", "model", "os"} {
		x, y := a[f], b[f]
		if f == "hostname" {
			x, _, _ = strings.Cut(x, ".")
			y, _, _ = strings.Cut(y, ".")
		}
		if x != "" && y != "" && !strings.EqualFold(x, y) {
			return true
		}
	}
	return false
}

// joinMode says what a join keeps of the row that goes: a chassis join (D-515) keeps its MAC as a mark on the other row; a join of
// one machine's rows (D-598) keeps its MACs as plain observations (the newest wins, as for any field) and its address when it is the
// newer one.
type joinMode int

const (
	joinChassis joinMode = iota
	joinMachine
)

// joinInto moves device from into device into and deletes from (D-515, D-598): its observations (the MAC as the chassis mark in a
// chassis join), software and open ports; the suspicious flag, the notes and the scan choices a person made on it when into has none;
// the agent bound to it when into has none. The approval never moves (review H1 of #722): a device that joins an approved row would
// otherwise be approved by a MAC anyone can pick, so a person approves the joined device. One audit row inventory.merge. into keeps
// its id; in a chassis join also its address and MAC; in a machine join it takes from's address when from was seen later and into is
// a discovered device (a person's address and the box's stay). The fields are folded again by the usual rules (RecomputeAsset).
func (s *Service) joinInto(ctx context.Context, tx *sql.Tx, from, into, why string, mode joinMode) error {
	fromName, intoName := deviceName(ctx, tx, from), deviceName(ctx, tx, into)
	rows, err := tx.QueryContext(ctx, `SELECT field, value, source, confidence, seen_at, evidence FROM inv_observation WHERE asset_id = ?`, from)
	if err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	type moved struct {
		obs
		evidence sql.NullString
	}
	var list []moved
	for rows.Next() {
		var m moved
		if err := rows.Scan(&m.field, &m.value, &m.source, &m.confidence, &m.seenAt, &m.evidence); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, m)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, m := range list {
		if m.field == "mac" && mode == joinChassis { // the chassis MAC becomes a mark; every other observation moves as it is, its evidence included
			m.evidence = sql.NullString{String: chassisEvidence, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (asset_id, field, source, value) DO UPDATE SET seen_at = max(seen_at, excluded.seen_at), confidence = max(confidence, excluded.confidence)`,
			store.NewID("o"), into, m.field, m.value, m.source, m.confidence, m.seenAt, m.evidence); err != nil {
			return fmt.Errorf("inventory: move an observation: %w", err)
		}
		if err := pruneObs(ctx, tx, into, m.field, m.source); err != nil {
			return err
		}
	}
	var fromIP, fromSeen, fromAgent sql.NullString
	var newer bool // from was seen after into (before the join folds their times)
	if err := tx.QueryRowContext(ctx, `SELECT f.ip, f.last_seen, f.agent_key, f.last_seen >= i.last_seen FROM inv_asset f, inv_asset i WHERE f.id = ? AND i.id = ?`,
		from, into).Scan(&fromIP, &fromSeen, &fromAgent, &newer); err != nil {
		return fmt.Errorf("inventory: read device: %w", err)
	}
	for _, q := range []string{
		`UPDATE inv_asset SET agent_key = NULL WHERE id = ?2`, // the key is unique: free it before into takes it
		`UPDATE OR IGNORE inv_software SET asset_id = ?1 WHERE asset_id = ?2`,
		`UPDATE OR IGNORE inv_service SET asset_id = ?1 WHERE asset_id = ?2`,
		`UPDATE inv_asset SET
			suspicious = max(suspicious, (SELECT suspicious FROM inv_asset WHERE id = ?2)),
			notes = coalesce(notes, (SELECT notes FROM inv_asset WHERE id = ?2)),
			regular_scan = CASE WHEN regular_scan = 'follow' THEN (SELECT regular_scan FROM inv_asset WHERE id = ?2) ELSE regular_scan END,
			fragile = CASE WHEN fragile_manual = 0 AND (SELECT fragile_manual FROM inv_asset WHERE id = ?2) = 1 THEN (SELECT fragile FROM inv_asset WHERE id = ?2) ELSE fragile END,
			fragile_manual = max(fragile_manual, (SELECT fragile_manual FROM inv_asset WHERE id = ?2)),
			first_seen = min(first_seen, (SELECT first_seen FROM inv_asset WHERE id = ?2)),
			last_seen = max(last_seen, (SELECT last_seen FROM inv_asset WHERE id = ?2))
			WHERE id = ?1`,
		`DELETE FROM inv_asset WHERE id = ?2`,
	} {
		if _, err := tx.ExecContext(ctx, q, into, from); err != nil {
			return fmt.Errorf("inventory: join devices: %w", err)
		}
	}
	if fromAgent.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET agent_key = ? WHERE id = ? AND agent_key IS NULL`, fromAgent.String, into); err != nil {
			return fmt.Errorf("inventory: move the agent: %w", err)
		}
	}
	if mode == joinMachine && fromIP.Valid { // from is deleted: its address is free
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip = ? WHERE id = ? AND origin = 'discovered' AND is_box = 0 AND (ip IS NULL OR ?)`,
			fromIP.String, into, newer); err != nil {
			return fmt.Errorf("inventory: move the address: %w", err)
		}
	}
	return s.auditTx(ctx, tx, systemActor, "inventory.merge", intoName, fromName+" is the same device: "+why)
}

// chassisOwner is the device a join left the chassis MAC mac on, when it still has an address: an observation that names only that
// MAC (an LLDP frame) is about it.
func chassisOwner(ctx context.Context, tx *sql.Tx, mac string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT o.asset_id FROM inv_observation o JOIN inv_asset a ON a.id = o.asset_id
		WHERE o.field = 'mac' AND o.value = ? AND o.evidence = ? AND a.ip IS NOT NULL ORDER BY o.asset_id LIMIT 1`, mac, chassisEvidence).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inventory: find the chassis MAC: %w", err)
	}
	return id, nil
}

func candidates(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: find the same device: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: find the same device: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// localMAC reports a locally administered MAC (a random or virtual one): its first bytes name no maker, so no block can be read.
func localMAC(mac string) bool {
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err != nil || b&0x02 != 0
}

// lastByte is the last byte of a normalised MAC.
func lastByte(mac string) int {
	b, err := strconv.ParseUint(mac[strings.LastIndexByte(mac, ':')+1:], 16, 8)
	if err != nil {
		return -1 << 10
	}
	return int(b)
}

// joinSame runs the join rules on every device a Record batch touched and joins each pair that fits: sameDevice (D-515, the touched
// row goes), agentOrphan and sameMachine (D-598, either row may go). It returns the devices that are gone and those that received
// one. A joined device created in this very batch was never announced; an older one is announced merged (findings moves its findings,
// with their status and history, to the device that received it; review H2 of #722) and then deleted (the other listeners drop it,
// notify closes its new-device incident; findings has nothing left to delete). The device that received it is matched again.
func (s *Service) joinSame(ctx context.Context, tx *sql.Tx, o *outbox, touched []string, created map[string]string, before map[string]string) (map[string]bool, []string, error) {
	gone := map[string]bool{}
	var joined []string
	for _, id := range touched {
		if gone[id] {
			continue
		}
		from, into, why, mode, err := sameAs(ctx, tx, id, s.clock())
		if err != nil {
			return nil, nil, err
		}
		if from == "" {
			continue
		}
		if _, ok := before[into]; !ok {
			if before[into], err = matchView(ctx, tx, into); err != nil {
				return nil, nil, err
			}
		}
		if err := s.joinInto(ctx, tx, from, into, why, mode); err != nil {
			return nil, nil, err
		}
		gone[from] = true
		joined = slices.DeleteFunc(joined, func(x string) bool { return x == from })
		if !slices.Contains(joined, into) {
			joined = append(joined, into)
		}
		if created[from] == "" {
			o.add(EventAssetMerged, MergeEvent{From: from, Into: into, Actor: systemActor})
			o.add(EventAssetDeleted, AssetEvent{AssetID: from})
		}
	}
	return gone, joined, nil
}

// sameAs finds the pair of rows a touched row is part of: from goes into into. "" when none fits.
func sameAs(ctx context.Context, tx *sql.Tx, id string, now time.Time) (from, into, why string, mode joinMode, err error) {
	if into, why, err = sameDevice(ctx, tx, id); into != "" || err != nil {
		return id, into, why, joinChassis, err
	}
	var orphan string
	if orphan, why, err = agentOrphan(ctx, tx, id); err != nil {
		return "", "", "", 0, err
	} else if orphan != "" {
		from, into, err = keptOrder(ctx, tx, orphan, id) // an approval the enrolment gave the orphan stays (review #831 L5)
		return from, into, why, joinMachine, err
	}
	from, into, why, err = sameMachine(ctx, tx, id, now)
	return from, into, why, joinMachine, err
}

// genericNames are host names many machines carry out of the box (D-598), with or without a number a name service added
// ("MacBook-Pro-2", Bonjour's answer to a clash): two devices that share one are not the same device.
var genericNames = regexp.MustCompile(`^(iphone|ipad|ipod|imac|mac|macbook|macbook-air|macbook-pro|mac-mini|mac-studio|mac-pro|android|galaxy|pixel|` +
	`pc|desktop|laptop|notebook|windows|ubuntu|debian|fedora|raspberrypi|host|client|device|unknown|none|localhost|esp32|esp8266|espressif|tasmota|` +
	`switch|router|ap|gateway|mikrotik|amnesiac|k8s-worker|k8s-master|node|worker|vm)(-\d+)?$`)

// defaultPrefixes are names a system makes from its model or a random suffix (Samsung "Galaxy-A52", Google "Pixel-7", Windows
// "DESKTOP-7GH2K1L", "LAPTOP-…", "WIN-…", Android "android-<hex>"): the model is shared by many devices, the suffix is not chosen
// by a person, so such a name says nothing about one machine.
var defaultPrefixes = regexp.MustCompile(`^(galaxy|pixel|redmi|oneplus|xiaomi|huawei|oppo|vivo|desktop|laptop|win|android)-`)

// ipLikeName is a name made from an address ("dhcp-192-168-1-20"): it names the lease, not the machine.
var ipLikeName = regexp.MustCompile(`\d{1,3}[-._]\d{1,3}[-._]\d{1,3}[-._]\d{1,3}`)

// machineName is the part of a host name that identifies a machine (D-598): its first label, lower case ("Kiens-MacBook-Air.local" ->
// "kiens-macbook-air"); "" for a name too short, generic or made by the system (genericNames, defaultPrefixes), made of an address,
// or only an identifier (uuidName).
func machineName(h string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(h), ".")
	l = strings.ToLower(l)
	if len(l) < 3 || genericNames.MatchString(l) || defaultPrefixes.MatchString(l) || uuidName.MatchString(l) || ipLikeName.MatchString(l) {
		return ""
	}
	return l
}

// universalMAC is the SQL test of a normalised MAC that a maker burned in: the locally administered bit (0x02 of the first byte, the
// second hex digit 2, 3, 6, 7, a, b, e or f) is clear.
const universalMAC = `substr(%s, 2, 1) IN ('0', '1', '4', '5', '8', '9', 'c', 'd')`

// macKinds reports whether a device has a MAC its maker burned in, and whether it has a locally administered (private) one: as its
// MAC, or as any MAC observation but a chassis mark.
func macKinds(ctx context.Context, tx *sql.Tx, id string) (burned, private bool, err error) {
	var b, p int
	err = tx.QueryRowContext(ctx, `SELECT coalesce(sum(`+fmt.Sprintf(universalMAC, "m")+`), 0), coalesce(sum(NOT `+fmt.Sprintf(universalMAC, "m")+`), 0)
		FROM (SELECT mac AS m FROM inv_asset WHERE id = ?1 AND mac IS NOT NULL
			UNION SELECT value FROM inv_observation WHERE asset_id = ?1 AND field = 'mac' AND evidence IS NOT ?2)`, id, chassisEvidence).Scan(&b, &p)
	if err != nil {
		return false, false, fmt.Errorf("inventory: read the MACs: %w", err)
	}
	return b > 0, p > 0, nil
}

// rotationQuiet is how long the row a private address left must have been silent before another row of its name joins it (D-598,
// review #831 M2): a rotation never shows the old and the new address at once, two machines of one name do.
const rotationQuiet = 5 * time.Minute

// sameMachine finds the other row of a machine whose Wi-Fi address is private (D-598): macOS, iOS, Android and Windows pick a locally
// administered MAC per network or per day, DHCP then gives a new address, and every new MAC made a new row. Two rows are one machine
// when **both** carry a private MAC and neither a burned-in one (a row known only by address, a declared row without a MAC, a server:
// never; review #831 H1), they carry the same host name (machineName: first label, any case; not generic or system-made) and state
// no other model or OS (facts, differ), exactly one other row carries that name, and they were not online at once: when both hold
// different addresses, the row last seen earlier must have gone silent before the other row first appeared and for rotationQuiet
// (two phones of one name, cloned VMs; review #831 M2). Never the box, never two rows a person declared. The row that stays: keptOrder.
func sameMachine(ctx context.Context, tx *sql.Tx, id string, now time.Time) (from, into, why string, err error) {
	var isBox bool
	if err := tx.QueryRowContext(ctx, `SELECT is_box FROM inv_asset WHERE id = ?`, id).Scan(&isBox); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", nil
		}
		return "", "", "", fmt.Errorf("inventory: read device: %w", err)
	}
	if isBox {
		return "", "", "", nil
	}
	own, err := facts(ctx, tx, id)
	if err != nil {
		return "", "", "", err
	}
	name := machineName(own["hostname"])
	if name == "" {
		return "", "", "", nil
	}
	if burned, private, err := macKinds(ctx, tx, id); burned || !private || err != nil {
		return "", "", "", err
	}
	ids, err := candidates(ctx, tx, `SELECT id FROM inv_asset WHERE id <> ? AND is_box = 0 AND (lower(hostname) = ? OR (lower(hostname) >= ? AND lower(hostname) < ?))`,
		id, name, name+".", name+"/")
	if err != nil {
		return "", "", "", err
	}
	var fits []string
	for _, other := range ids {
		theirs, err := facts(ctx, tx, other)
		if err != nil {
			return "", "", "", err
		}
		if machineName(theirs["hostname"]) != name || differ(own, theirs) {
			continue
		}
		b, p, err := macKinds(ctx, tx, other)
		if err != nil {
			return "", "", "", err
		}
		if !b && p {
			fits = append(fits, other)
		}
	}
	if len(fits) != 1 {
		return "", "", "", nil
	}
	if together, err := onlineTogether(ctx, tx, id, fits[0], now); together || err != nil {
		return "", "", "", err
	}
	if from, into, err = keptOrder(ctx, tx, id, fits[0]); from == "" || err != nil {
		return "", "", "", err
	}
	return from, into, "the same host name " + name + " and a private Wi-Fi address", nil
}

// onlineTogether reports whether two rows holding different addresses may be two machines online at the same time: the one last seen
// earlier was seen after the other first appeared, or less than rotationQuiet ago (it may still answer). Rows without an address, or
// with the same one, are not both online.
func onlineTogether(ctx context.Context, tx *sql.Tx, a, b string, now time.Time) (bool, error) {
	var ipA, ipB sql.NullString
	var firstA, lastA, firstB, lastB string
	if err := tx.QueryRowContext(ctx, `SELECT x.ip, x.first_seen, x.last_seen, y.ip, y.first_seen, y.last_seen FROM inv_asset x, inv_asset y WHERE x.id = ? AND y.id = ?`,
		a, b).Scan(&ipA, &firstA, &lastA, &ipB, &firstB, &lastB); err != nil {
		return false, fmt.Errorf("inventory: read devices: %w", err)
	}
	if !ipA.Valid || !ipB.Valid || ipA.String == ipB.String {
		return false, nil
	}
	if lastB < lastA { // a is the row last seen earlier
		firstB, lastA = firstA, lastB
	}
	if lastA >= firstB {
		return true, nil
	}
	t, err := time.Parse(time.RFC3339Nano, lastA)
	if err != nil {
		return true, nil // an unreadable time: do not join
	}
	return now.Sub(t) < rotationQuiet, nil
}

// keptOrder orders two rows of one machine (D-598): the row that stays is one a person declared, else an approved one, else the older
// one (first_seen, then the smaller id); so a person's approval, an enrolment's and a declared address stay where they are. "" when
// both were declared (a person keeps them apart).
func keptOrder(ctx context.Context, tx *sql.Tx, x, y string) (from, into string, err error) {
	type row struct {
		id, origin, first string
		approved          bool
	}
	read := func(id string) (row, error) {
		r := row{id: id}
		err := tx.QueryRowContext(ctx, `SELECT origin, approved, first_seen FROM inv_asset WHERE id = ?`, id).Scan(&r.origin, &r.approved, &r.first)
		if err != nil {
			err = fmt.Errorf("inventory: read device: %w", err)
		}
		return r, err
	}
	a, err := read(x)
	if err != nil {
		return "", "", err
	}
	b, err := read(y)
	if err != nil {
		return "", "", err
	}
	if a.origin == "manual" && b.origin == "manual" {
		return "", "", nil
	}
	stays := func(p, q row) bool { // p is kept over q
		switch {
		case (p.origin == "manual") != (q.origin == "manual"):
			return p.origin == "manual"
		case p.approved != q.approved:
			return p.approved
		case p.first != q.first:
			return p.first < q.first
		}
		return p.id < q.id
	}
	if stays(a, b) {
		return b.id, a.id, nil
	}
	return a.id, b.id, nil
}

// agentOrphan finds the row an agent made at an address no device held yet, which has since lost that address (D-598): the agent
// connected from the address and said its card there has MAC M (agent-intake INV-12 checks the address against the agent's own
// interfaces); M could not become the row's MAC because this device owns it; and a sensor that saw a known MAC at the address took
// the address away (claimIP: a sensor's MAC outranks an address-only row). Such a row has no address and no MAC, only the agent's
// mac observation M, and joins the device that owns M. A row that still has its address is left alone: an agent's MAC claim on its
// own never moves a report (INV-12, D-265 (4)). Exactly one such row; never the box.
func agentOrphan(ctx context.Context, tx *sql.Tx, id string) (string, string, error) {
	var mac sql.NullString
	var isBox bool
	if err := tx.QueryRowContext(ctx, `SELECT mac, is_box FROM inv_asset WHERE id = ?`, id).Scan(&mac, &isBox); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("inventory: read device: %w", err)
	}
	if !mac.Valid || isBox {
		return "", "", nil
	}
	ids, err := candidates(ctx, tx, `SELECT a.id FROM inv_asset a WHERE a.id <> ? AND a.ip IS NULL AND a.mac IS NULL AND a.is_box = 0 AND a.origin = 'discovered'
		AND EXISTS (SELECT 1 FROM inv_observation o WHERE o.asset_id = a.id AND o.field = 'mac' AND o.source = 'agent' AND o.value = ?)`, id, mac.String)
	if err != nil || len(ids) != 1 {
		return "", "", err
	}
	return ids[0], "its agent reported the MAC " + mac.String + " of this device and its address went to this device", nil
}
