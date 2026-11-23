package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// issue #829: when the join rules (join.go) cannot be sure two rows are one machine, a person decides.
// The device page says "Possibly the same device as X" with Merge and Keep separate; Merge joins the rows with the join rules' own
// primitive (joinAs), Keep separate stores the pair so it is never offered again (inv_separate).

// maxSameGroup is how many rows seen within macMemory may share a name, a model or a MAC before it says nothing about one machine (an
// office full of "iPhone"): no pair of a larger group is offered. Older rows do not count (review r1 of #871 M1): rotations and
// visitors of past months must not silence the offer for good.
const maxSameGroup = 8

// maxOffered is how many devices one device page offers, the ones seen last.
const maxOffered = 5

// PossibleSame is another device that may be the same machine as the one read: GET /inventory/devices/{id} possible_same.
type PossibleSame struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Why  string `json:"why"`
	// Reason is what the two share, as a code the page may key on: one of the Reason* constants.
	Reason   string `json:"reason"`
	Approved bool   `json:"approved"`
	// Ignored: a person ignored the other device; the Merge dialog says which watch state the kept device ends with.
	Ignored  bool   `json:"ignored"`
	LastSeen string `json:"last_seen"`
}

// SameRef is one device of a SamePair.
type SameRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Approved bool   `json:"approved"`
	LastSeen string `json:"last_seen"`
}

// SamePair is one pair of GET /inventory/possible-same.
type SamePair struct {
	A      SameRef `json:"a"`
	B      SameRef `json:"b"`
	Why    string  `json:"why"`
	Reason string  `json:"reason"`
}

// The reasons two devices are offered as possibly the same machine (PossibleSame.Reason), strongest first. An open vocabulary: the
// page shows Why, and may key an icon or a hint on the code.
const (
	ReasonSameMAC          = "same_mac"            // both were seen with one MAC, never online at once
	ReasonMACBlock         = "mac_block"           // burned-in MACs of one maker's block on network gear: the interfaces of one box (INV-57)
	ReasonSameNameCards    = "same_name_cards"     // one host name on two cards with burned-in MACs: Wi-Fi and cable, two ports (INV-57)
	ReasonRotatingName     = "rotating_name"       // one name, a private Wi-Fi address, never online at once
	ReasonRotatingModel    = "rotating_model"      // one stated model, a private Wi-Fi address, never online at once
	ReasonMACAtAddedDevice = "mac_at_added_device" // a MAC seen at the address of a device added by hand
	ReasonSameOS           = "same_os"             // a device added by hand without an address runs the OS the only found device running that release runs
)

// SamePairs is GET /inventory/possible-same.
type SamePairs struct {
	Items []SamePair `json:"items"`
}

// sameRow is what the pairing reads of a device: its identity, and the MACs any source saw on it (not a chassis mark), split into
// burned-in and private (locally administered) ones.
type sameRow struct {
	id, origin, host, model, first, last, agent, ip string
	approved, box                                   bool
	burned, private                                 []string          // sorted
	atAddr                                          []string          // a hand-added row known by its address only: the MACs seen there since (inv_hand_seen, #829)
	lastWire                                        string            // when a sensor last saw any of its MACs on the wire; last when none
	osNames                                         map[string]string // machine keys of its OS and firmware lines (machineKeys) -> the line's name
}

// lastOnline is when the row was last seen online: a sensor's MAC sighting, else any sighting. A late scan result, software list or
// open-port list for an old row moves last_seen but says nothing about the machine answering then (review r2 of #871 L2).
func (r *sameRow) lastOnline() string {
	if r.lastWire != "" {
		return r.lastWire
	}
	return r.last
}

func (r *sameRow) ref(ctx context.Context, q querier) SameRef {
	return SameRef{ID: r.id, Name: deviceName(ctx, q, r.id), Approved: r.approved, LastSeen: r.last}
}

// burnedOnly reports a row whose only MACs were burned in by a maker: a server, a printer, a switch. It never rotates its MAC, so a
// private address that carries its name is another machine (an intruder naming itself after a server).
func (r *sameRow) burnedOnly() bool { return len(r.burned) > 0 && len(r.private) == 0 }

// loadSameRows reads the rows of ids (every device but the box when ids is nil), with their MACs.
func loadSameRows(ctx context.Context, q querier, ids []string) (map[string]*sameRow, error) {
	where, macWhere, args := "WHERE is_box = 0", "", []any{}
	if ids != nil {
		in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
		where, macWhere = "WHERE id IN "+in, " AND asset_id IN "+in
		for _, id := range ids {
			args = append(args, id)
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT id, origin, approved, is_box, coalesce(hostname, ''), coalesce(model, ''), first_seen, last_seen, coalesce(agent_key, ''),
		coalesce(ip, '') FROM inv_asset `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	out := map[string]*sameRow{}
	for rows.Next() {
		r := &sameRow{}
		if err := rows.Scan(&r.id, &r.origin, &r.approved, &r.box, &r.host, &r.model, &r.first, &r.last, &r.agent, &r.ip); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		out[r.id] = r
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	macArgs := append([]any{chassisEvidence}, args...)
	macs, err := q.QueryContext(ctx, `SELECT asset_id, value FROM inv_observation WHERE field = 'mac' AND evidence IS NOT ?`+macWhere+`
		UNION SELECT id, mac FROM inv_asset `+where+` AND mac IS NOT NULL`, append(macArgs, args...)...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the MACs: %w", err)
	}
	defer func() { _ = macs.Close() }()
	for macs.Next() {
		var id, mac string
		if err := macs.Scan(&id, &mac); err != nil {
			return nil, fmt.Errorf("inventory: read the MACs: %w", err)
		}
		r := out[id]
		switch {
		case r == nil || len(mac) != 17:
		case localMAC(mac):
			r.private = append(r.private, mac)
		default:
			r.burned = append(r.burned, mac)
		}
	}
	if err := macs.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read the MACs: %w", err)
	}
	wire, err := q.QueryContext(ctx, `SELECT asset_id, max(seen_at) FROM inv_observation WHERE `+wireMAC+macWhere+` GROUP BY asset_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the MAC sightings: %w", err)
	}
	defer func() { _ = wire.Close() }()
	for wire.Next() {
		var id, at string
		if err := wire.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("inventory: read the MAC sightings: %w", err)
		}
		if r := out[id]; r != nil {
			r.lastWire = at
		}
	}
	if err := wire.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read the MAC sightings: %w", err)
	}
	seen, err := candidatePairs(ctx, q, `SELECT s.asset_id, s.mac FROM inv_hand_seen s JOIN inv_asset a ON a.id = s.asset_id
		WHERE a.origin = 'manual' AND a.mac IS NULL AND a.agent_key IS NULL AND a.ip IS NOT NULL`+strings.ReplaceAll(macWhere, "asset_id", "s.asset_id"), args...)
	if err != nil {
		return nil, err
	}
	for _, p := range seen {
		if r := out[p[0]]; r != nil {
			r.atAddr = append(r.atAddr, p[1])
		}
	}
	lines, err := osLines(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	for id, keys := range lines {
		if r := out[id]; r != nil {
			r.osNames = keys
		}
	}
	for _, r := range out {
		slices.Sort(r.burned)
		slices.Sort(r.private)
		slices.Sort(r.atAddr)
	}
	return out, nil
}

// sameCandidates is device only and the rows that share its name label, its model or one of its MACs: the only rows a pair of it
// can hold (samePairs), read through the indexes instead of the whole inventory (review r1 of #871 M3). nil when only is unknown.
func sameCandidates(ctx context.Context, q *sql.Tx, only string) ([]string, error) {
	self, err := loadSameRows(ctx, q, []string{only})
	if err != nil || self[only] == nil || self[only].box {
		return nil, err
	}
	r := self[only]
	// Name and model are compared in Go (sameLabel, strings.ToLower), as samePairs groups them: SQLite's lower() and trim() know only
	// ASCII letters and spaces (review r2 of #871 L1). inv_asset is small; the MAC observations are read through their index.
	label, model := sameLabel(r.host), strings.ToLower(strings.TrimSpace(r.model))
	rows, err := q.QueryContext(ctx, `SELECT id, coalesce(hostname, ''), coalesce(model, '') FROM inv_asset WHERE is_box = 0`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	ids := []string{only}
	for rows.Next() {
		var id, host, mod string
		if err := rows.Scan(&id, &host, &mod); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		if id != only && (label != "" && sameLabel(host) == label || model != "" && strings.ToLower(strings.TrimSpace(mod)) == model) {
			ids = append(ids, id)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	if all := slices.Concat(r.burned, r.private, r.atAddr); len(all) > 0 { // the rows carrying a MAC, and the hand-added rows it was seen at
		in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(all)), ",") + ")"
		args := []any{}
		for range 3 {
			for _, m := range all {
				args = append(args, m)
			}
		}
		byMAC, err := candidates(ctx, q, `SELECT id FROM inv_asset WHERE is_box = 0 AND (mac IN `+in+` OR id IN (SELECT asset_id FROM inv_observation WHERE field = 'mac' AND value IN `+in+`)
			OR id IN (SELECT asset_id FROM inv_hand_seen WHERE mac IN `+in+`))`, args...)
		if err != nil {
			return nil, err
		}
		for _, id := range byMAC {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	if len(r.osNames) > 0 { // the rows that run the same OS at the same release (byOS)
		all, err := osLines(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		for id, keys := range all {
			if id == only || slices.Contains(ids, id) {
				continue
			}
			for k := range keys {
				if _, ok := r.osNames[k]; ok {
					ids = append(ids, id)
					break
				}
			}
		}
	}
	for _, m := range r.burned { // the rows with a burned-in MAC of the same block (byBlock), read through the MAC indexes
		lo, hi := m[:14], m[:14]+";"
		byBlock, err := candidates(ctx, q, `SELECT id FROM inv_asset WHERE is_box = 0 AND (mac >= ?1 AND mac < ?2
			OR id IN (SELECT asset_id FROM inv_observation WHERE field = 'mac' AND value >= ?1 AND value < ?2))`, lo, hi)
		if err != nil {
			return nil, err
		}
		for _, id := range byBlock {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// keptApart reports a pair a person kept separate: no join rule and no offer takes it.
func keptApart(ctx context.Context, tx *sql.Tx, x, y string) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_separate WHERE a = ? AND b = ?`, min(x, y), max(x, y)).Scan(&n); err != nil {
		return false, fmt.Errorf("inventory: read separate devices: %w", err)
	}
	return n > 0, nil
}

// strongConflict says, in plain words, why two rows are two machines whatever else they share (the research's identity order):
// two different agents report from them, or each carries a MAC its maker burned in and they share none. "" when nothing says so.
func strongConflict(x, y *sameRow) string {
	if x.agent != "" && y.agent != "" && x.agent != y.agent {
		return "These are two machines: an agent reports from each of them. Keep them separate; delete a device only when its machine is gone."
	}
	if len(x.burned) > 0 && len(y.burned) > 0 && !slices.ContainsFunc(x.burned, func(m string) bool { return slices.Contains(y.burned, m) }) {
		return fmt.Sprintf("These are two machines: each has its own hardware MAC address (%s and %s). Keep them separate; delete a device only when its machine is gone.",
			x.burned[0], y.burned[0])
	}
	return ""
}

// sameLabel is the part of a host name two rows of one machine share (first label, lower case), generic names included ("iPhone"
// is what the person must decide on: the join rules never take it); "" for a name that names no machine: shorter than 3, a
// switch or router default, localhost, a UUID, made of an address.
func sameLabel(h string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(h), ".")
	l = strings.ToLower(l)
	if len(l) < 3 || l == "localhost" || slices.Contains(defaultNames, l) || uuidName.MatchString(l) || ipLikeName.MatchString(l) {
		return ""
	}
	return l
}

// signal is what two rows share, strongest first.
type signal int

const (
	byMAC signal = iota
	byName
	byModel
	byAddress // a MAC seen at the address of a hand-added row known by that address only (#829, n71), and a row carrying that MAC
	byBlock   // burned-in MACs from one block of a maker (the first five bytes): the interfaces of one router or firewall (INV-57)
	byOS      // a hand-added row with no address and a found device that run one OS at one release (sameos.go)
)

// samePairs lists the pairs of rows that may be one machine, only the pairs of device only when it is not "". A pair shares
// a MAC (an older MAC one row still carries, an agent's claim about its card), else a host name (sameLabel), else a model the devices
// state (not a scan's guess), else a MAC seen at the address of a hand-added row known by that address only (byAddress, addressWhy,
// #829 n71), the name or model only between rows that may rotate a private Wi-Fi address (one carries a private MAC
// and neither carries burned-in MACs only); a group larger than maxSameGroup is skipped. A pair is never offered when a person kept it
// separate, when strongConflict holds, when the rows state another name, model or OS (facts, differ), or when they were online
// together (onlineTogether: two phones of one name). The box is never in a pair.
func (s *Service) samePairs(ctx context.Context, only string) ([]samePair, error) {
	tx, err := s.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var rows map[string]*sameRow
	if only == "" {
		rows, err = loadSameRows(ctx, tx, nil)
	} else {
		var ids []string
		if ids, err = sameCandidates(ctx, tx, only); err != nil || len(ids) == 0 {
			return nil, err
		}
		rows, err = loadSameRows(ctx, tx, ids)
	}
	if err != nil {
		return nil, err
	}
	separate := map[[2]string]bool{}
	sep, err := candidatePairs(ctx, tx, `SELECT a, b FROM inv_separate`)
	if err != nil {
		return nil, err
	}
	for _, p := range sep {
		separate[p] = true
	}
	groups := [6]map[string][]*sameRow{{}, {}, {}, {}, {}, {}}
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		r := rows[id]
		for _, m := range append(slices.Clone(r.burned), r.private...) {
			if !slices.Contains(groups[byMAC][m], r) {
				groups[byMAC][m] = append(groups[byMAC][m], r)
			}
		}
		if l := sameLabel(r.host); l != "" {
			groups[byName][l] = append(groups[byName][l], r)
		}
		if m := strings.ToLower(strings.TrimSpace(r.model)); m != "" {
			groups[byModel][m] = append(groups[byModel][m], r)
		}
		for _, m := range r.atAddr {
			groups[byAddress][m] = append(groups[byAddress][m], r)
		}
		for _, m := range r.burned {
			if b := m[:14]; !slices.Contains(groups[byBlock][b], r) {
				groups[byBlock][b] = append(groups[byBlock][b], r)
			}
		}
		for k := range r.osNames {
			groups[byOS][k] = append(groups[byOS][k], r)
		}
	}
	for m, g := range groups[byAddress] { // with the rows that carry the MAC
		for _, r := range groups[byMAC][m] {
			if !slices.Contains(g, r) {
				g = append(g, r)
			}
		}
		groups[byAddress][m] = g
	}
	now := s.clock()
	recentCut := store.FormatTS(now.Add(-macMemory))
	recent := func(r *sameRow) bool { return r.last >= recentCut }
	tried, offered := map[[2]string]bool{}, map[[2]string]bool{}
	var out []samePair
	for sig, g := range groups {
		keys := make([]string, 0, len(g))
		for k := range g {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			members := g[k]
			if len(members) < 2 || len(slices.DeleteFunc(slices.Clone(members), func(r *sameRow) bool { return !recent(r) })) > maxSameGroup {
				continue
			}
			for i, x := range members {
				for _, y := range members[i+1:] {
					key := [2]string{min(x.id, y.id), max(x.id, y.id)}
					// a pair another signal tried may still share a hand-added address or a MAC block: those have rules of their own
					// (addressWhy, cardsWhy)
					if tried[key] && (signal(sig) != byAddress && signal(sig) != byBlock && signal(sig) != byOS || offered[key]) || separate[key] || only != "" && x.id != only && y.id != only || !recent(x) && !recent(y) {
						continue
					}
					tried[key] = true
					why, reason, err := pairWhy(ctx, tx, x, y, signal(sig), k, now)
					if err != nil {
						return nil, err
					}
					if why != "" {
						offered[key] = true
						out = append(out, samePair{x: x, y: y, why: why, reason: reason})
					}
				}
			}
		}
	}
	for i := range out { // names are read in the same snapshot
		out[i].a, out[i].b = out[i].x.ref(ctx, tx), out[i].y.ref(ctx, tx)
	}
	return out, nil
}

// samePair is one pair samePairs found.
type samePair struct {
	x, y        *sameRow
	a, b        SameRef
	why, reason string
}

// candidatePairs reads (a, b) rows.
func candidatePairs(ctx context.Context, q querier, query string, args ...any) ([][2]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read separate devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out [][2]string
	for rows.Next() {
		var p [2]string
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			return nil, fmt.Errorf("inventory: read separate devices: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// pairWhy is the reason to offer x and y as one machine, in plain words for the device page, and its code (Reason*); "" when they must
// not be offered (see samePairs). value is what the signal matched: the MAC, the lower-case name, the model or the MAC block.
func pairWhy(ctx context.Context, tx *sql.Tx, x, y *sameRow, sig signal, value string, now time.Time) (why, reason string, err error) {
	if sig == byBlock || sig == byName && x.burnedOnly() && y.burnedOnly() {
		return cardsWhy(ctx, tx, x, y, sig, value)
	}
	if strongConflict(x, y) != "" {
		return "", "", nil
	}
	if sig == byOS {
		why, err := osWhy(ctx, tx, x, y, value)
		return why, ReasonSameOS, err
	}
	if sig == byAddress {
		why, err := addressWhy(ctx, tx, x, y, value)
		return why, ReasonMACAtAddedDevice, err
	}
	if sig != byMAC && (x.burnedOnly() || y.burnedOnly() || len(x.private) == 0 && len(y.private) == 0) {
		return "", "", nil
	}
	fx, err := facts(ctx, tx, x.id)
	if err != nil {
		return "", "", err
	}
	fy, err := facts(ctx, tx, y.id)
	if err != nil || differ(fx, fy) {
		return "", "", err
	}
	if sig == byModel && (fx["model"] == "" || !strings.EqualFold(fx["model"], fy["model"])) {
		return "", "", nil
	}
	// "Never online at the same time" must be true for a person (review r1 of #871 H2): one row was last seen online (lastOnline)
	// before the other was first seen. The join's own test (onlineTogether) forgives a short overlap; a visitor's phone seen while the approved one was
	// online must not be offered as it.
	if x.lastOnline() >= y.first && y.lastOnline() >= x.first {
		return "", "", nil
	}
	if together, err := onlineTogether(ctx, tx, x.id, y.id, now); together || err != nil {
		return "", "", err
	}
	const rotates = ", never online at the same time, and a private Wi-Fi address (phones and laptops change it)."
	switch sig {
	case byMAC:
		return "Both were seen with the MAC address " + value + ", never online at the same time.", ReasonSameMAC, nil
	case byName:
		label, _, _ := strings.Cut(strings.TrimSpace(x.host), ".")
		return `Same name "` + label + `"` + rotates, ReasonRotatingName, nil
	default:
		return `Same model "` + fx["model"] + `"` + rotates, ReasonRotatingModel, nil
	}
}

// cardsWhy is the reason to offer two rows that each carry burned-in MACs as two network cards of one machine (INV-57), which may be
// online at the same time: the same host name (not a generic or system-made one, machineName), or MACs from one block of a maker
// (the first five bytes, at most chassisBlock apart) when one of them is network gear (a switch, router, access point or firewall) and
// the other is network gear too or of no known type. Never when two agents report from them or they state another name, model or OS.
func cardsWhy(ctx context.Context, tx *sql.Tx, x, y *sameRow, sig signal, value string) (string, string, error) {
	if twoAgents(map[string]*sameRow{x.id: x, y.id: y}, []string{x.id, y.id}) != "" {
		return "", "", nil
	}
	fx, err := facts(ctx, tx, x.id)
	if err != nil {
		return "", "", err
	}
	fy, err := facts(ctx, tx, y.id)
	if err != nil || differ(fx, fy) {
		return "", "", err
	}
	if sig == byName {
		name := machineName(x.host)
		if name == "" || machineName(y.host) != name {
			return "", "", nil
		}
		label, _, _ := strings.Cut(strings.TrimSpace(x.host), ".")
		return `Same name "` + label + `" on two network cards, each with its own hardware MAC address: one machine connected twice (Wi-Fi and cable, or two ports).`,
			ReasonSameNameCards, nil
	}
	gear := func(f map[string]string) bool { return slices.Contains(netGear, devicetypes.ActsAs(f["kind"])) }
	unknown := func(f map[string]string) bool { return f["kind"] == "" || f["kind"] == "unknown" }
	if ok := gear(fx) && (gear(fy) || unknown(fy)) || gear(fy) && unknown(fx); !ok {
		return "", "", nil
	}
	in := func(r *sameRow) string {
		for _, m := range r.burned {
			if m[:14] == value {
				return m
			}
		}
		return ""
	}
	mx, my := in(x), in(y)
	if d := lastByte(mx) - lastByte(my); mx == "" || my == "" || mx == my || d > chassisBlock || -d > chassisBlock {
		return "", "", nil
	}
	return "Their MAC addresses " + min(mx, my) + " and " + max(mx, my) + " come from one block of the same maker, as the interfaces of one router, firewall or switch do.",
		ReasonMACBlock, nil
}

// addressWhy is the reason to offer a hand-added row known by its address only and a row carrying a MAC seen at that address since
// the person added it (#829: firstAtHand refused the bind because two machines were seen there, so a person
// decides). Not offered when neither or both are such a pair, or when they state another model or OS. The person's name for the row
// is a label, not the machine's own name, and the hand-added row has no life on the wire to compare: neither is held against the pair.
func addressWhy(ctx context.Context, tx *sql.Tx, x, y *sameRow, mac string) (string, error) {
	if slices.Contains(y.atAddr, mac) {
		x, y = y, x
	}
	if !slices.Contains(x.atAddr, mac) || slices.Contains(y.atAddr, mac) || !slices.Contains(y.burned, mac) && !slices.Contains(y.private, mac) {
		return "", nil
	}
	fx, err := facts(ctx, tx, x.id)
	if err != nil {
		return "", err
	}
	fy, err := facts(ctx, tx, y.id)
	if err != nil {
		return "", err
	}
	delete(fx, "hostname")
	delete(fy, "hostname")
	if differ(fx, fy) {
		return "", nil
	}
	return "Its MAC address " + mac + " was seen at " + x.ip + ", the address " + deviceName(ctx, tx, x.id) + " was added with.", nil
}

// PossibleSameAs lists the devices that may be the same machine as device id, the one seen last first. None for the box or
// an unknown id.
func (s *Service) PossibleSameAs(ctx context.Context, id string) ([]PossibleSame, error) {
	pairs, err := s.samePairs(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]PossibleSame, 0, len(pairs))
	var ignored map[string]bool
	if len(pairs) > 0 {
		if ignored, err = s.ignoredIDs(ctx); err != nil {
			return nil, err
		}
	}
	for _, p := range pairs {
		other := p.b
		if other.ID == id {
			other = p.a
		}
		out = append(out, PossibleSame{ID: other.ID, Name: other.Name, Why: p.why, Reason: p.reason, Approved: other.Approved, Ignored: ignored[other.ID], LastSeen: other.LastSeen})
	}
	slices.SortFunc(out, func(a, b PossibleSame) int {
		if c := strings.Compare(b.LastSeen, a.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	if len(out) > maxOffered {
		out = out[:maxOffered]
	}
	return out, nil
}

// PossibleSamePairs is GET /inventory/possible-same: every pair of devices that may be one machine, the pair seen last first.
// In a pair, a is the approved device when one of them is, else the one seen first: the one a merge most likely keeps.
func (s *Service) PossibleSamePairs(ctx context.Context) (SamePairs, error) {
	pairs, err := s.samePairs(ctx, "")
	if err != nil {
		return SamePairs{}, err
	}
	out := SamePairs{Items: make([]SamePair, 0, len(pairs))}
	for _, p := range pairs {
		a, b := p.a, p.b
		if b.Approved && !a.Approved || a.Approved == b.Approved && p.y.first < p.x.first {
			a, b = b, a
		}
		out.Items = append(out.Items, SamePair{A: a, B: b, Why: p.why, Reason: p.reason})
	}
	slices.SortFunc(out.Items, func(x, y SamePair) int {
		if c := strings.Compare(max(y.A.LastSeen, y.B.LastSeen), max(x.A.LastSeen, x.B.LastSeen)); c != 0 {
			return c
		}
		return strings.Compare(x.A.ID+x.B.ID, y.A.ID+y.B.ID)
	})
	return out, nil
}

// KeepSeparate is a person's answer "two devices" (POST /inventory/devices/{id}/keep-separate): the pair is stored and never
// offered again, until either device is deleted or merged into another. Refused like Merge (the same device twice, unknown, the box).
// Saying it again changes nothing. One audit row inventory.keep_separate the first time.
func (s *Service) KeepSeparate(ctx context.Context, actor, id, other string) error {
	if id == other {
		return apierr.Invalid("A device is always itself. Pick the other device.")
	}
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		if err := pairCheck(ctx, tx, id, other, "compared with another device"); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO inv_separate (a, b, decided_by, decided_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`,
			min(id, other), max(id, other), actor, s.now())
		if err != nil {
			return fmt.Errorf("inventory: keep devices separate: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		return s.auditTx(ctx, tx, actor, "inventory.keep_separate", deviceName(ctx, tx, id), deviceName(ctx, tx, other)+" is another device")
	})
}

// pairCheck refuses a pair with an unknown device (404) or the box (409 box_device).
func pairCheck(ctx context.Context, tx *sql.Tx, x, y, what string) error {
	var n, boxes int
	if err := tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(is_box), 0) FROM inv_asset WHERE id IN (?, ?)`, x, y).Scan(&n, &boxes); err != nil {
		return fmt.Errorf("inventory: read devices: %w", err)
	}
	if n != 2 {
		return notFoundDevice()
	}
	if boxes > 0 {
		return conflict("box_device", "This is the Vedette box itself, so it cannot be "+what+". It is always its own device.")
	}
	return nil
}

// joinNotes keeps both notes of a merge, into's first, within maxNotes characters.
func joinNotes(into, from string) string {
	into, from = strings.TrimSpace(into), strings.TrimSpace(from)
	switch {
	case from == "" || from == into:
		return into
	case into == "":
		return from
	}
	out := into + "\n\n" + from
	if utf8.RuneCountInString(out) > maxNotes {
		out = string([]rune(out)[:maxNotes])
	}
	return out
}
