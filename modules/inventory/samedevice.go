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

	"github.com/knt048/vedette/core/apierr"
)

// D-599 (issue #829, J2): when the join rules (join.go, D-515, D-598) cannot be sure two rows are one machine, a person decides.
// The device page says "Possibly the same device as X" with Merge and Keep separate; Merge joins the rows with the join rules' own
// primitive (joinAs), Keep separate stores the pair so it is never offered again (inv_separate).

// maxSameGroup is how many rows may share a name, a model or a MAC before it says nothing about one machine (an office full of
// "iPhone"): no pair of a larger group is offered.
const maxSameGroup = 8

// PossibleSame is another device that may be the same machine as the one read (D-599): GET /inventory/devices/{id} possible_same.
type PossibleSame struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Why      string `json:"why"`
	Approved bool   `json:"approved"`
	LastSeen string `json:"last_seen"`
}

// SameRef is one device of a SamePair.
type SameRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Approved bool   `json:"approved"`
	LastSeen string `json:"last_seen"`
}

// SamePair is one pair of GET /inventory/possible-same (D-599).
type SamePair struct {
	A   SameRef `json:"a"`
	B   SameRef `json:"b"`
	Why string  `json:"why"`
}

// SamePairs is GET /inventory/possible-same.
type SamePairs struct {
	Items []SamePair `json:"items"`
}

// sameRow is what the pairing reads of a device: its identity, and the MACs any source saw on it (not a chassis mark), split into
// burned-in and private (locally administered) ones.
type sameRow struct {
	id, origin, host, model, first, last, agent string
	approved                                    bool
	burned, private                             []string
}

func (r *sameRow) ref(ctx context.Context, q querier) SameRef {
	return SameRef{ID: r.id, Name: deviceName(ctx, q, r.id), Approved: r.approved, LastSeen: r.last}
}

// burnedOnly reports a row whose only MACs were burned in by a maker: a server, a printer, a switch. It never rotates its MAC, so a
// private address that carries its name is another machine (D-598 review #831 H1: an intruder naming itself after a server).
func (r *sameRow) burnedOnly() bool { return len(r.burned) > 0 && len(r.private) == 0 }

// loadSameRows reads the rows of ids (every device but the box when ids is nil).
func loadSameRows(ctx context.Context, q querier, ids []string) (map[string]*sameRow, error) {
	where, args := "WHERE is_box = 0", []any{}
	if ids != nil {
		where = "WHERE id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
		for _, id := range ids {
			args = append(args, id)
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT id, origin, approved, coalesce(hostname, ''), coalesce(model, ''), first_seen, last_seen, coalesce(agent_key, '')
		FROM inv_asset `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	out := map[string]*sameRow{}
	for rows.Next() {
		r := &sameRow{}
		if err := rows.Scan(&r.id, &r.origin, &r.approved, &r.host, &r.model, &r.first, &r.last, &r.agent); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		out[r.id] = r
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	macs, err := q.QueryContext(ctx, `SELECT asset_id, value FROM inv_observation WHERE field = 'mac' AND evidence IS NOT ?
		UNION SELECT id, mac FROM inv_asset WHERE mac IS NOT NULL`, chassisEvidence)
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
	return out, macs.Err()
}

// strongConflict says, in plain words, why two rows are two machines whatever else they share (D-599, the research's identity order):
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
// is what the person must decide on: the join rules never take it, D-598); "" for a name that names no machine: shorter than 3, a
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
)

// samePairs lists the pairs of rows that may be one machine (D-599), only the pairs of device only when it is not "". A pair shares
// a MAC (an older MAC one row still carries, an agent's claim about its card), else a host name (sameLabel), else a model the devices
// state (not a scan's guess), the name or model only between rows that may rotate a private Wi-Fi address (one carries a private MAC
// and neither carries burned-in MACs only); a group larger than maxSameGroup is skipped. A pair is never offered when a person kept it
// separate, when strongConflict holds, when the rows state another name, model or OS (facts, differ), or when they were online
// together (onlineTogether: two phones of one name). The box is never in a pair.
func (s *Service) samePairs(ctx context.Context, only string) ([]samePair, error) {
	tx, err := s.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := loadSameRows(ctx, tx, nil)
	if err != nil {
		return nil, err
	}
	if only != "" && rows[only] == nil {
		return nil, nil
	}
	separate := map[[2]string]bool{}
	sep, err := candidatePairs(ctx, tx, `SELECT a, b FROM inv_separate`)
	if err != nil {
		return nil, err
	}
	for _, p := range sep {
		separate[p] = true
	}
	groups := [3]map[string][]*sameRow{{}, {}, {}}
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
	}
	now := s.clock()
	tried := map[[2]string]bool{}
	var out []samePair
	for sig, g := range groups {
		keys := make([]string, 0, len(g))
		for k := range g {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			members := g[k]
			if len(members) < 2 || len(members) > maxSameGroup {
				continue
			}
			for i, x := range members {
				for _, y := range members[i+1:] {
					key := [2]string{min(x.id, y.id), max(x.id, y.id)}
					if tried[key] || separate[key] || only != "" && x.id != only && y.id != only {
						continue
					}
					tried[key] = true
					why, err := pairWhy(ctx, tx, x, y, signal(sig), k, now)
					if err != nil {
						return nil, err
					}
					if why != "" {
						out = append(out, samePair{x: x, y: y, why: why})
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
	x, y *sameRow
	a, b SameRef
	why  string
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

// pairWhy is the reason to offer x and y as one machine, in plain words for the device page; "" when they must not be offered (see
// samePairs). value is what the signal matched: the MAC, the lower-case name or the model.
func pairWhy(ctx context.Context, tx *sql.Tx, x, y *sameRow, sig signal, value string, now time.Time) (string, error) {
	if strongConflict(x, y) != "" {
		return "", nil
	}
	if sig != byMAC && (x.burnedOnly() || y.burnedOnly() || len(x.private) == 0 && len(y.private) == 0) {
		return "", nil
	}
	fx, err := facts(ctx, tx, x.id)
	if err != nil {
		return "", err
	}
	fy, err := facts(ctx, tx, y.id)
	if err != nil || differ(fx, fy) {
		return "", err
	}
	if sig == byModel && (fx["model"] == "" || !strings.EqualFold(fx["model"], fy["model"])) {
		return "", nil
	}
	if together, err := onlineTogether(ctx, tx, x.id, y.id, now); together || err != nil {
		return "", err
	}
	const rotates = ", never online at the same time, and a private Wi-Fi address (phones and laptops change it)."
	switch sig {
	case byMAC:
		return "Both were seen with the MAC address " + value + ", never online at the same time.", nil
	case byName:
		label, _, _ := strings.Cut(strings.TrimSpace(x.host), ".")
		return `Same name "` + label + `"` + rotates, nil
	default:
		return `Same model "` + fx["model"] + `"` + rotates, nil
	}
}

// PossibleSameAs lists the devices that may be the same machine as device id (D-599), the one seen last first. None for the box or
// an unknown id.
func (s *Service) PossibleSameAs(ctx context.Context, id string) ([]PossibleSame, error) {
	pairs, err := s.samePairs(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]PossibleSame, 0, len(pairs))
	for _, p := range pairs {
		other := p.b
		if other.ID == id {
			other = p.a
		}
		out = append(out, PossibleSame{ID: other.ID, Name: other.Name, Why: p.why, Approved: other.Approved, LastSeen: other.LastSeen})
	}
	slices.SortFunc(out, func(a, b PossibleSame) int {
		if c := strings.Compare(b.LastSeen, a.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// PossibleSamePairs is GET /inventory/possible-same (D-599): every pair of devices that may be one machine, the pair seen last first.
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
		out.Items = append(out.Items, SamePair{A: a, B: b, Why: p.why})
	}
	slices.SortFunc(out.Items, func(x, y SamePair) int {
		if c := strings.Compare(max(y.A.LastSeen, y.B.LastSeen), max(x.A.LastSeen, x.B.LastSeen)); c != 0 {
			return c
		}
		return strings.Compare(x.A.ID+x.B.ID, y.A.ID+y.B.ID)
	})
	return out, nil
}

// Merge is a person's answer "the same device" (D-599, POST /inventory/devices/{into}/merge): device from joins device into with the
// join rules' own primitive (joinAs, a machine join): into keeps its id, its approval, its notes and its findings; from's MACs, address
// (when from was seen later and into is not declared), sources, software, open ports, agent binding and findings move to it; from is
// gone. A person decides, so unlike the join rules: into is approved when from was (approved_at from from), and both notes are kept.
// Refused: the same device twice (400 invalid), an unknown device (404), the box (409 box_device), two rows strongConflict says are two
// machines (409 not_same_device). Any pair may be merged, offered or not. One audit row inventory.merge by the person; events as a
// join: merged, from deleted, into updated (matched again), into approved when it was not.
func (s *Service) Merge(ctx context.Context, actor, into, from string) error {
	if into == from {
		return apierr.Invalid("A device cannot be merged with itself. Pick the other device.")
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		if err := pairCheck(ctx, tx, into, from, "merged with another device"); err != nil {
			return err
		}
		rows, err := loadSameRows(ctx, tx, []string{into, from})
		if err != nil {
			return err
		}
		if msg := strongConflict(rows[into], rows[from]); msg != "" {
			return conflict("not_same_device", msg)
		}
		var intoNotes, fromNotes, fromApprovedAt sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT i.notes, f.notes, f.approved_at FROM inv_asset i, inv_asset f WHERE i.id = ? AND f.id = ?`, into, from).
			Scan(&intoNotes, &fromNotes, &fromApprovedAt); err != nil {
			return fmt.Errorf("inventory: read devices: %w", err)
		}
		gains := rows[from].approved && !rows[into].approved
		if err := s.joinAs(ctx, tx, from, into, "a person merged them", joinMachine, actor); err != nil {
			return err
		}
		if notes := joinNotes(intoNotes.String, fromNotes.String); notes != intoNotes.String {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET notes = ? WHERE id = ?`, nullStr(notes), into); err != nil {
				return fmt.Errorf("inventory: merge notes: %w", err)
			}
		}
		if gains {
			at := fromApprovedAt.String
			if at == "" {
				at = s.now()
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET approved = 1, approved_at = ? WHERE id = ?`, at, into); err != nil {
				return fmt.Errorf("inventory: merge the approval: %w", err)
			}
		}
		if _, err := s.RecomputeAsset(ctx, tx, into); err != nil {
			return err
		}
		o.add(EventAssetMerged, MergeEvent{From: from, Into: into, Actor: actor})
		o.add(EventAssetDeleted, AssetEvent{AssetID: from, Actor: actor})
		o.add(EventAssetUpdated, AssetEvent{AssetID: into, Match: true})
		if gains {
			o.add(EventAssetApproved, AssetEvent{AssetID: into, Actor: actor})
		}
		return nil
	})
}

// KeepSeparate is a person's answer "two devices" (D-599, POST /inventory/devices/{id}/keep-separate): the pair is stored and never
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
