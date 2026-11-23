package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// maxMergeFrom is how many devices one merge takes into the kept one: the interfaces of one firewall, a laptop's two cards.
const maxMergeFrom = 8

// MergeChoice is what a person chose for the kept device where the merged devices differ (POST /inventory/devices/{id}/merge
// fields): its name in Vedette, its type and its OS. nil leaves the merge's own result. A value must be one the merge preview
// listed for that field (one of the devices' own).
type MergeChoice struct {
	Name, Kind, OS *string
}

// Merge is MergeMany with one device.
func (s *Service) Merge(ctx context.Context, actor, into, from string) error {
	return s.MergeMany(ctx, actor, into, []string{from}, MergeChoice{})
}

// mergeIDs checks the devices a merge takes: 1 to maxMergeFrom, each once, never the kept device itself (400 invalid).
func mergeIDs(into string, from []string) error {
	switch {
	case len(from) == 0:
		return apierr.Invalid("Pick at least one other device to merge into this one.")
	case len(from) > maxMergeFrom:
		return apierr.Invalid(fmt.Sprintf("One merge takes at most %d devices into this one.", maxMergeFrom))
	case slices.Contains(from, into):
		return apierr.Invalid("A device cannot be merged with itself. Pick the other device.")
	}
	seen := map[string]bool{}
	for _, f := range from {
		if seen[f] {
			return apierr.Invalid("Each device is listed once.")
		}
		seen[f] = true
	}
	return nil
}

// twoAgents names the reason two of the devices are two machines whatever a person says: two different agents report from them
// (strongConflict's first rule). Two burned-in MACs are not a reason for a person's merge: the interfaces of one firewall, router or
// server each carry one (INV-57). "" when none.
func twoAgents(rows map[string]*sameRow, ids []string) string {
	for i, x := range ids {
		for _, y := range ids[i+1:] {
			if a, b := rows[x], rows[y]; a != nil && b != nil && a.agent != "" && b.agent != "" && a.agent != b.agent {
				return "These are two machines: an agent reports from each of them. Keep them separate; delete a device only when its machine is gone."
			}
		}
	}
	return ""
}

// MergeMany is a person's answer "the same device" (POST /inventory/devices/{into}/merge): every device of from joins device into in
// one write, each with the join rules' own primitive (joinAs, a machine join that keeps the addresses, INV-57). into keeps its id, its
// main address, its approval, its notes, its name in Vedette (from's when it has none) and its findings; the addresses of from (each
// one of into's other addresses from then on, with what a scan read there), its MACs, sources, software, open ports, agent binding and
// findings move to it; from is gone. A person decides, so unlike the join rules: into is approved when a from was (approved_at from
// it, the suspicious mark cleared as Approve does), every note is kept, and an approved into keeps its own suspicious mark only.
// choice sets the name, type or OS a person picked where the devices differ, as PATCH does, in the same write.
// Refused: no device, too many, one twice or into itself (400 invalid), a choice that is none of the devices' values (400
// bad_choice), an unknown device (404), the box (409 box_device), two agents that say two machines (409 not_same_device). Any devices
// may be merged, offered or not. One audit row inventory.merge per device; events per device as a join: merged, from deleted, into
// updated (matched again), into approved when it was not.
func (s *Service) MergeMany(ctx context.Context, actor, into string, from []string, choice MergeChoice) error {
	if err := mergeIDs(into, from); err != nil {
		return err
	}
	p, err := checkChoice(choice)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		for _, f := range from {
			if err := pairCheck(ctx, tx, into, f, "merged with another device"); err != nil {
				return err
			}
		}
		ids := append([]string{into}, from...)
		rows, err := loadSameRows(ctx, tx, ids)
		if err != nil {
			return err
		}
		if msg := twoAgents(rows, ids); msg != "" {
			return conflict("not_same_device", msg)
		}
		if err := s.choiceAmong(ctx, tx, ids, choice); err != nil {
			return err
		}
		for _, f := range from {
			if err := s.mergeOne(ctx, tx, o, actor, into, f); err != nil {
				return err
			}
		}
		if p, err = choiceChanges(ctx, tx, into, p); err != nil || p == (Patch{}) {
			return err
		}
		return s.patchTx(ctx, tx, o, actor, into, p)
	})
}

// checkChoice validates the values of a choice as PATCH does and returns them as a patch.
func checkChoice(c MergeChoice) (Patch, error) {
	var p Patch
	if c.Name != nil {
		n := strings.TrimSpace(*c.Name)
		if !userName(n) || n == "" {
			return p, badRequest("bad_choice", badUserName)
		}
		p.Name = &n
	}
	if c.Kind != nil {
		if !validKind(*c.Kind) {
			return p, badRequest("bad_choice", "Device type is not one of the device types (for example router, switch, ip_phone, laptop).")
		}
		p.Kind = c.Kind
	}
	if c.OS != nil {
		v := strings.TrimSpace(*c.OS)
		if v == "" || !osText(v) {
			return p, badRequest("bad_choice", badOS)
		}
		p.OS = &v
	}
	return p, nil
}

// choiceAmong refuses a choice that is not one of the devices' own values of that field (400 bad_choice): the merge dialog offers
// only those.
func (s *Service) choiceAmong(ctx context.Context, tx *sql.Tx, ids []string, c MergeChoice) error {
	guesses := map[string]string{}
	if c.Kind != nil {
		var err error
		if guesses, err = s.kindGuesses(ctx, tx, ids); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		field string
		v     *string
	}{{"name", c.Name}, {"kind", c.Kind}, {"os", c.OS}} {
		if f.v == nil {
			continue
		}
		vals, err := fieldValues(ctx, tx, ids, f.field, guesses)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(vals, func(v MergeValue) bool { return strings.EqualFold(v.Value, strings.TrimSpace(*f.v)) }) {
			return badRequest("bad_choice", "Pick the "+fieldWords[f.field]+" of one of the devices being merged.")
		}
	}
	return nil
}

// choiceChanges keeps of p what the merged device does not have yet: picking what the merge gave anyway writes nothing.
func choiceChanges(ctx context.Context, tx *sql.Tx, into string, p Patch) (Patch, error) {
	var kind, os sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT kind, os FROM inv_asset WHERE id = ?`, into).Scan(&kind, &os); err != nil {
		return p, fmt.Errorf("inventory: read device: %w", err)
	}
	if p.Name != nil && *p.Name == deviceName(ctx, tx, into) {
		p.Name = nil
	}
	if p.Kind != nil && *p.Kind == kind.String {
		p.Kind = nil
	}
	if p.OS != nil && strings.EqualFold(*p.OS, os.String) {
		p.OS = nil
	}
	return p, nil
}

// mergeOne joins device from into device into: Merge for one device, inside the merge's write.
func (s *Service) mergeOne(ctx context.Context, tx *sql.Tx, o *outbox, actor, into, from string) error {
	rows, err := loadSameRows(ctx, tx, []string{into, from})
	if err != nil {
		return err
	}
	var intoNotes, fromNotes, fromApprovedAt sql.NullString
	var intoSuspicious bool
	if err := tx.QueryRowContext(ctx, `SELECT i.notes, f.notes, f.approved_at, i.suspicious FROM inv_asset i, inv_asset f WHERE i.id = ? AND f.id = ?`, into, from).
		Scan(&intoNotes, &fromNotes, &fromApprovedAt, &intoSuspicious); err != nil {
		return fmt.Errorf("inventory: read devices: %w", err)
	}
	gains := rows[from].approved && !rows[into].approved
	if err := rememberMerged(ctx, tx, into, from, s.now()); err != nil {
		return err
	}
	watch, err := s.joinAs(ctx, tx, o, from, into, "a person merged them", joinMachine, actor, true)
	if err != nil {
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
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET approved = 1, approved_at = ?, suspicious = 0 WHERE id = ?`, at, into); err != nil {
			return fmt.Errorf("inventory: merge the approval: %w", err)
		}
	} else if rows[into].approved { // the person says the other row is this known device: its mark is answered, this one's own stays
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET suspicious = ? WHERE id = ?`, intoSuspicious, into); err != nil {
			return fmt.Errorf("inventory: merge the mark: %w", err)
		}
	}
	if _, err := s.RecomputeAsset(ctx, tx, into); err != nil {
		return err
	}
	o.add(EventAssetDeleted, AssetEvent{AssetID: from, Actor: actor})
	if watch != "" { // The moved findings follow into's watch state
		o.add(watch, AssetEvent{AssetID: into, Actor: actor})
	}
	o.add(EventAssetUpdated, AssetEvent{AssetID: into, Match: true})
	if err := s.earnReview(ctx, tx, o, into, false); err != nil { // the merge may carry the first sighting past a day (INV-49)
		return err
	}
	if gains {
		o.add(EventAssetApproved, AssetEvent{AssetID: into, Actor: actor})
	}
	return nil
}

// kindGuesses is the type the identification rules guess (addGuesses) for each of ids whose type is unknown and that one rule fits.
func (s *Service) kindGuesses(ctx context.Context, q querier, ids []string) (map[string]string, error) {
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	devs, err := s.loadDevices(ctx, q, "WHERE a.id IN "+in, 0, args...)
	if err != nil {
		return nil, err
	}
	cores := make([]*AssetCore, len(devs))
	for i := range devs {
		cores[i] = &devs[i].AssetCore
	}
	s.addGuesses(ctx, cores)
	out := map[string]string{}
	for _, d := range cores {
		if d.Guess != nil {
			out[d.ID] = d.Guess.Type
		}
	}
	return out, nil
}

// fieldWords names the fields a merge preview compares, for messages.
var fieldWords = map[string]string{"name": "name", "kind": "type", "os": "operating system", "vendor": "maker", "model": "model", "hostname": "host name"}

// mergeFields are the fields a merge preview compares, in the order the dialog shows them; the first three a person may choose.
var mergeFields = []string{"name", "kind", "os", "vendor", "model", "hostname"}

// MergeValue is one device's value of a field.
type MergeValue struct {
	Device string `json:"device"`
	Value  string `json:"value"`
	// Guess: a type the identification rules give a device whose type is unknown (AssetCore.Guess), offered so a person can pick
	// it for the merged device; kind only.
	Guess bool `json:"guess,omitempty"`
}

// MergeField is a field the devices of a merge state differently.
type MergeField struct {
	Field  string       `json:"field"`
	Values []MergeValue `json:"values"` // the kept device's first, then the others in the order given; a device without a value is left out
	// Kept is the value the kept device has after the merge unless the person picks another: the merge's own rules (the person's
	// name of the kept device first; the strongest source's reading for the others).
	Kept      string `json:"kept"`
	Choosable bool   `json:"choosable"` // name, kind and os: the merge takes a choice (fields)
	// Missing are the devices that have no value of the field (type and OS only): a type or OS only one of the devices states is
	// listed too, so the person sees what the merged device ends with.
	Missing []string `json:"missing"`
}

// MergeSide is one device of a merge preview.
type MergeSide struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Approved  bool      `json:"approved"`
	Ignored   bool      `json:"ignored"`
	Agent     bool      `json:"agent"`
	Addresses []Address `json:"addresses"`
	Software  int       `json:"software"`   // software lines present
	OpenPorts int       `json:"open_ports"` // open port rows
	Findings  int       `json:"findings"`
	Risk      *Risk     `json:"risk"`
	LastSeen  string    `json:"last_seen"`
}

// MergeMoves is what the merge moves to the kept device, over every device taken.
type MergeMoves struct {
	Addresses      int `json:"addresses"`       // addresses that become the kept device's (each with what a scan read there)
	SoftwareNew    int `json:"software_new"`    // software lines the kept device does not have
	SoftwareShared int `json:"software_shared"` // lines it has too: one line keeps every reading of both
	Readings       int `json:"readings"`        // software readings that move (none is dropped)
	OpenPorts      int `json:"open_ports"`
	Findings       int `json:"findings"`  // findings that move, with their history and decisions (one CVE of one line is folded into one)
	Exploited      int `json:"exploited"` // distinct exploited CVEs among them (the badge of the devices taken)
}

// MergeRefusal is why the merge cannot go ahead, as the merge itself would answer (409).
type MergeRefusal struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MergePreview is GET /inventory/devices/{id}/merge-preview: what a merge of from into the device would do, so the dialog says it
// before the person confirms.
type MergePreview struct {
	Into    MergeSide     `json:"into"`
	From    []MergeSide   `json:"from"`
	Moves   MergeMoves    `json:"moves"`
	Differs []MergeField  `json:"differs"`
	Refusal *MergeRefusal `json:"refusal"`
}

// MergePreview reads what MergeMany would do with the same devices, without changing anything. Refused like MergeMany for bad input
// (400 invalid) and an unknown device (404); a merge that would be refused for the box or two agents is answered with Refusal set.
func (s *Service) MergePreview(ctx context.Context, into string, from []string) (MergePreview, error) {
	if err := mergeIDs(into, from); err != nil {
		return MergePreview{}, err
	}
	tx, err := s.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return MergePreview{}, fmt.Errorf("inventory: read devices: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ids := append([]string{into}, from...)
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var n, boxes int
	if err := tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(is_box), 0) FROM inv_asset WHERE id IN `+in, args...).Scan(&n, &boxes); err != nil {
		return MergePreview{}, fmt.Errorf("inventory: read devices: %w", err)
	}
	if n != len(ids) {
		return MergePreview{}, notFoundDevice()
	}
	var out MergePreview
	rows, err := loadSameRows(ctx, tx, ids)
	if err != nil {
		return MergePreview{}, err
	}
	switch {
	case boxes > 0:
		out.Refusal = &MergeRefusal{Code: "box_device", Message: "This is the Vedette box itself, so it cannot be merged with another device. It is always its own device."}
	default:
		if msg := twoAgents(rows, ids); msg != "" {
			out.Refusal = &MergeRefusal{Code: "not_same_device", Message: msg}
		}
	}
	ignored, err := s.ignoredIDs(ctx)
	if err != nil {
		return MergePreview{}, err
	}
	risks, _ := s.risks(ctx)
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return MergePreview{}, err
	}
	side := func(id string) (MergeSide, error) {
		r := rows[id]
		sd := MergeSide{ID: id, Name: deviceName(ctx, tx, id), Approved: r.approved, Ignored: ignored[id], Agent: r.agent != "", Findings: counts[id], Risk: risks[id], LastSeen: r.last}
		if sd.Addresses, err = s.addresses(ctx, tx, id); err != nil {
			return sd, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM inv_software WHERE asset_id = ?1 AND state = 'present'), (SELECT count(*) FROM inv_service WHERE asset_id = ?1)`, id).
			Scan(&sd.Software, &sd.OpenPorts); err != nil {
			return sd, fmt.Errorf("inventory: read device: %w", err)
		}
		return sd, nil
	}
	if out.Into, err = side(into); err != nil {
		return MergePreview{}, err
	}
	out.From = make([]MergeSide, 0, len(from))
	for _, f := range from {
		sd, err := side(f)
		if err != nil {
			return MergePreview{}, err
		}
		out.From = append(out.From, sd)
		out.Moves.Addresses += len(sd.Addresses)
		out.Moves.OpenPorts += sd.OpenPorts
		out.Moves.Findings += sd.Findings
		if sd.Risk != nil && sd.Risk.Code == RiskExploited {
			out.Moves.Exploited += sd.Risk.Count
		}
	}
	fromIn := "(" + strings.TrimSuffix(strings.Repeat("?,", len(from)), ",") + ")"
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id WHERE w.asset_id IN `+fromIn,
		args[1:]...).Scan(&out.Moves.Readings); err != nil {
		return MergePreview{}, fmt.Errorf("inventory: read software: %w", err)
	}
	// a line of a device taken is shared when the kept device, or a device taken before it, has the same product and train
	lines, err := tx.QueryContext(ctx, `SELECT asset_id, product_key, line FROM inv_software WHERE state = 'present' AND asset_id IN `+in, args...) //nolint:gosec // in is only placeholders
	if err != nil {
		return MergePreview{}, fmt.Errorf("inventory: read software: %w", err)
	}
	byDevice := map[string][][2]string{}
	for lines.Next() {
		var a, k, l string
		if err := lines.Scan(&a, &k, &l); err != nil {
			_ = lines.Close()
			return MergePreview{}, fmt.Errorf("inventory: read software: %w", err)
		}
		byDevice[a] = append(byDevice[a], [2]string{k, l})
	}
	if err := errors.Join(lines.Err(), lines.Close()); err != nil {
		return MergePreview{}, fmt.Errorf("inventory: read software: %w", err)
	}
	have := map[[2]string]bool{}
	for _, kl := range byDevice[into] {
		have[kl] = true
	}
	for _, f := range from {
		for _, kl := range byDevice[f] {
			if have[kl] {
				out.Moves.SoftwareShared++
			} else {
				out.Moves.SoftwareNew++
				have[kl] = true
			}
		}
	}
	if out.Differs, err = s.mergeDiffers(ctx, tx, ids); err != nil {
		return MergePreview{}, err
	}
	return out, nil
}

// fieldValues reads each device's value of a merge field, as the pages show it: the name every page gives it, the type (while
// unknown, the type the identification rules guess, from guesses), and the OS, maker, model and host name the device has now. A
// device without a value is left out.
func fieldValues(ctx context.Context, q querier, ids []string, field string, guesses map[string]string) ([]MergeValue, error) {
	var out []MergeValue
	for _, id := range ids {
		var v sql.NullString
		guess := false
		switch field {
		case "name":
			v = sql.NullString{String: deviceName(ctx, q, id), Valid: true}
		case "kind", "os", "vendor", "model", "hostname":
			if err := q.QueryRowContext(ctx, `SELECT `+field+` FROM inv_asset WHERE id = ?`, id).Scan(&v); err != nil {
				return nil, fmt.Errorf("inventory: read device: %w", err)
			}
			if field == "kind" && v.String == devicetypes.Unknown {
				g, ok := guesses[id]
				v, guess = sql.NullString{String: g, Valid: ok}, ok
			}
		}
		if v.Valid && strings.TrimSpace(v.String) != "" {
			out = append(out, MergeValue{Device: id, Value: v.String, Guess: guess})
		}
	}
	return out, nil
}

// mergeDiffers lists the fields the devices state differently (two values that differ in more than letter case), with the value the
// merge gives the kept device: its own name in Vedette, else the first device's that has one (joinAs), else the name the naming rule
// gives the kept device; for the other fields the winner of every device's observations together (winners, as RecomputeAsset picks).
func (s *Service) mergeDiffers(ctx context.Context, tx *sql.Tx, ids []string) ([]MergeField, error) {
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE source <> 'declared' AND field <> 'mac' AND asset_id IN ` + in //nolint:gosec // in is only placeholders
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	best := winners(list)
	guesses, err := s.kindGuesses(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	out := []MergeField{}
	for _, f := range mergeFields {
		vals, err := fieldValues(ctx, tx, ids, f, guesses)
		if err != nil {
			return nil, err
		}
		distinct := 0
		for i, v := range vals {
			if !slices.ContainsFunc(vals[:i], func(w MergeValue) bool { return strings.EqualFold(w.Value, v.Value) }) {
				distinct++
			}
		}
		missing := []string{}
		if f == "kind" || f == "os" { // the type and OS a person picks: one device's value against none is a difference too
			for _, id := range ids {
				if !slices.ContainsFunc(vals, func(v MergeValue) bool { return v.Device == id }) {
					missing = append(missing, id)
				}
			}
		}
		if distinct < 2 && (distinct == 0 || len(missing) == 0) {
			continue
		}
		kept := ""
		switch f {
		case "name":
			var named sql.NullString
			for _, id := range ids {
				if err := tx.QueryRowContext(ctx, `SELECT user_name FROM inv_asset WHERE id = ?`, id).Scan(&named); err != nil {
					return nil, fmt.Errorf("inventory: read device: %w", err)
				}
				if named.Valid {
					break
				}
			}
			kept = named.String
			if !named.Valid { // the naming rule over the merged facts (DisplayName), at the kept device's address
				var ip, origin sql.NullString
				if err := tx.QueryRowContext(ctx, `SELECT ip, origin FROM inv_asset WHERE id = ?`, ids[0]).Scan(&ip, &origin); err != nil {
					return nil, fmt.Errorf("inventory: read device: %w", err)
				}
				kept = cmpOr(DisplayName("", best["hostname"].value, best["vendor"].value, best["model"].value, ip.String, origin.String, ""), vals[0].Value)
			}
		case "kind": // a guess is never the kind: the merged device keeps a stated type, else stays unknown until a person picks one
			kept = devicetypes.Unknown
			if o, ok := best[f]; ok {
				kept = o.value
			}
		default:
			if o, ok := best[f]; ok {
				kept = o.value
			} else if len(vals) > 0 {
				kept = vals[0].Value
			}
		}
		out = append(out, MergeField{Field: f, Values: vals, Kept: kept, Choosable: f == "name" || f == "kind" || f == "os", Missing: missing})
	}
	return out, nil
}

// Split is a person's answer "this address is another device" (POST /inventory/devices/{id}/split), the undo of a merge (INV-57):
// the address (an IPv4 address or a MAC of the device; the interface row that holds it moves whole, its IP and MAC together) becomes a
// device of its own with what was read only there: the MAC's observations, and the readings and open ports a scan took at that address.
// What the device's other sources read of the whole machine (an agent's software, SNMP) stays with it. When the address was the
// device's main one, the other address seen last becomes its main one. The new device is approved when the device was, so no
// new-device alert goes out for it; the pair is kept separate (inv_separate), so it is never offered as possibly the same device and
// no join rule takes it back. Findings follow the software: matched again on both devices. Refused: an unknown device (404), an
// address that is not the device's (404 address_not_found), a text that is no IPv4 address or MAC (400 bad_address), the box (409
// box_device), the device's only address (409 only_address). One audit row inventory.split. It returns the new device's id.
func (s *Service) Split(ctx context.Context, actor, id, address string) (string, error) {
	addr := strings.ToLower(strings.TrimSpace(address))
	col := "mac"
	if ip, err := netip.ParseAddr(addr); err == nil {
		if !ip.Is4() {
			return "", badRequest("bad_address", "Give one IPv4 address or MAC address of this device.")
		}
		col = "ip"
	} else if !macRE.MatchString(addr) {
		return "", badRequest("bad_address", "Give one IPv4 address or MAC address of this device.")
	}
	wIPs, wMACs := s.wazuhSet(ctx) // read before the write: it is agent-intake's table
	var newID string
	err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var box, approved bool
		var approvedAt, mainIP, mainMAC sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT is_box, approved, approved_at, ip, mac FROM inv_asset WHERE id = ?`, id).Scan(&box, &approved, &approvedAt, &mainIP, &mainMAC)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if box {
			return conflict("box_device", "This is the Vedette box itself: its addresses are its own.")
		}
		extras, err := extrasOf(ctx, tx, id)
		if err != nil {
			return err
		}
		main := mainIP.Valid && col == "ip" && mainIP.String == addr || mainMAC.Valid && col == "mac" && mainMAC.String == addr
		var moved extraAddr // the interface that goes: main's, or the row
		if main {
			moved = extraAddr{ip: mainIP, mac: mainMAC}
		} else {
			i := slices.IndexFunc(extras, func(x extraAddr) bool {
				return col == "ip" && x.ip.Valid && x.ip.String == addr || col == "mac" && x.mac.Valid && x.mac.String == addr
			})
			if i < 0 {
				return apierr.New(404, "address_not_found", "This address is not one of this device's addresses. Reload the device page.")
			}
			moved = extras[i]
		}
		if n := len(extras); n == 0 || n == 1 && !mainIP.Valid && !mainMAC.Valid {
			return conflict("only_address", "This is the device's only address, so there is nothing to split off. Delete the device when it is not there.")
		}
		switch agent, err := agentIfaceOf(ctx, tx, id, wIPs, wMACs); {
		case err != nil:
			return err
		case agent.has(moved.ip, moved.mac):
			return conflict("agent_address", "This device's agent reports from this address, so it stays with the agent's machine. Split off the device's other addresses instead.")
		}
		name := deviceName(ctx, tx, id)
		gone, err := mergedAt(ctx, tx, id, moved.ip, moved.mac) // a merged device's interface: the split gives that device back
		if err != nil {
			return err
		}
		first, last := moved.firstSeen, moved.lastS
		if main {
			if err := tx.QueryRowContext(ctx, `SELECT first_seen, coalesce(ip_confirmed_at, last_seen) FROM inv_asset WHERE id = ?`, id).Scan(&first, &last); err != nil {
				return fmt.Errorf("inventory: read device: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip = NULL, ip_confirmed_at = NULL, mac = NULL WHERE id = ?`, id); err != nil {
				return fmt.Errorf("inventory: split an address: %w", err)
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM inv_asset_address WHERE id = ?`, moved.id); err != nil {
			return fmt.Errorf("inventory: split an address: %w", err)
		}
		if newID, err = splitID(ctx, tx, gone, store.NewID("a")); err != nil {
			return err
		}
		var at, confirmed any // the approval the device had, the address seen when the interface was
		if approved {
			at = cmpOr(approvedAt.String, s.now())
		}
		if moved.ip.Valid {
			confirmed = last
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, ip, mac, ip_confirmed_at, kind, origin, approved, approved_at, fragile, first_seen, last_seen)
			VALUES (?, ?, ?, ?, 'unknown', 'discovered', ?, ?, 0, ?, ?)`, newID, moved.ip, moved.mac, confirmed, approved, at, first, max(first, last)); err != nil {
			return fmt.Errorf("inventory: split an address: %w", err)
		}
		if err := s.moveInterface(ctx, tx, id, newID, moved.id, moved.mac); err != nil {
			return err
		}
		if err := keepMACObs(ctx, tx, newID, moved.mac, moved.source, last); err != nil {
			return err
		}
		if err := giveBack(ctx, tx, id, newID, gone); err != nil {
			return err
		}
		if main { // the other address seen last is the device's main one now
			next := extras[0]
			for _, x := range extras {
				if x.ip.Valid && !next.ip.Valid {
					next = x
					break
				}
			}
			if err := s.unbindAddress(ctx, tx, id, next.id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_asset_address WHERE id = ?`, next.id); err != nil {
				return fmt.Errorf("inventory: split an address: %w", err)
			}
			var confirmed any
			if next.ip.Valid {
				confirmed = next.lastS
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip = ?, ip_confirmed_at = ?, mac = ? WHERE id = ?`, next.ip, confirmed, next.mac, id); err != nil {
				return fmt.Errorf("inventory: split an address: %w", err)
			}
			if err := keepMACObs(ctx, tx, id, next.mac, next.source, next.lastS); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_separate (a, b, decided_by, decided_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`,
			min(id, newID), max(id, newID), actor, s.now()); err != nil {
			return fmt.Errorf("inventory: keep devices separate: %w", err)
		}
		for _, d := range []string{id, newID} {
			if _, err := s.RecomputeAsset(ctx, tx, d); err != nil {
				return err
			}
		}
		o.readdress(id)
		o.add(EventAssetDiscovered, AssetEvent{AssetID: newID, Match: true})
		if approved {
			o.add(EventAssetApproved, AssetEvent{AssetID: newID, Actor: actor})
		}
		o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: true})
		o.add(EventSoftwareChanged, AssetEvent{AssetID: id})
		o.add(EventSoftwareChanged, AssetEvent{AssetID: newID})
		return s.auditTx(ctx, tx, actor, "inventory.split", name, addr+" split off as a device of its own: "+deviceName(ctx, tx, newID))
	})
	return newID, err
}

// macRE is a normalised MAC, as the inventory stores it.
var macRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// keepMACObs makes sure device id holds a mac observation of mac, so RecomputeAsset keeps mac as its main MAC: a split gives a device a
// MAC whose observations an older merge may have pruned (INV-16). source is the address row's source when it is a sensor's.
func keepMACObs(ctx context.Context, tx *sql.Tx, id string, mac sql.NullString, source, seenAt string) error {
	if !mac.Valid {
		return nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'mac' AND value = ?`, id, mac.String).Scan(&n); err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	if n > 0 {
		return nil
	}
	if !slices.Contains([]string{"agent", "snmp", "nmap", "passive", "scan"}, source) {
		source = "passive"
	}
	return insertObs(ctx, tx, id, "mac", mac.String, source, 0.9, seenAt)
}

// moveInterface moves to device to what device from holds of one interface: its MAC's observations (copied, the table is append-only,
// then removed from from) and the readings and open ports a scan took at it (addr: the row's id, "" for from's main address). A reading
// goes to to's line of the same product and train (made when to has none); the lines of both are settled again.
func (s *Service) moveInterface(ctx context.Context, tx *sql.Tx, from, to, addr string, mac sql.NullString) error {
	if mac.Valid {
		rows, err := tx.QueryContext(ctx, `SELECT field, value, source, confidence, seen_at, evidence, ifnull(first_seen, seen_at) FROM inv_observation
			WHERE asset_id = ? AND field = 'mac' AND value = ?`, from, mac.String)
		if err != nil {
			return fmt.Errorf("inventory: read observations: %w", err)
		}
		type row struct {
			field, value, source, seen, first string
			conf                              float64
			evidence                          sql.NullString
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.field, &r.value, &r.source, &r.conf, &r.seen, &r.evidence, &r.first); err != nil {
				_ = rows.Close()
				return fmt.Errorf("inventory: read observations: %w", err)
			}
			list = append(list, r)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("inventory: read observations: %w", err)
		}
		for _, r := range list {
			if _, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (asset_id, field, source, value) DO NOTHING`, store.NewID("o"), to, r.field, r.value, r.source, r.conf, r.seen, r.evidence, r.first); err != nil {
				return fmt.Errorf("inventory: move the MAC: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = 'mac' AND value = ?`, from, mac.String); err != nil {
			return fmt.Errorf("inventory: move the MAC: %w", err)
		}
	}
	type moving struct {
		line, key, train, vendor, product string
		r                                 Reading
		ev                                itemEvidence
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+readingCols+`, w.id, w.product_key, w.line, w.vendor, w.product, `+evidenceCols+` FROM inv_software_reading r
		JOIN inv_software w ON w.id = r.software_id WHERE w.asset_id = ? AND r.addr_id = ? AND r.source IN ('nmap', 'scan')`, from, addr)
	if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	var list []moving
	for rows.Next() {
		var m moving
		evDst, ev := evidenceDest()
		if m.r, err = scanReading(rows, append([]any{&m.line, &m.key, &m.train, &m.vendor, &m.product}, evDst...)...); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read software: %w", err)
		}
		m.ev = ev()
		list = append(list, m)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	now := s.now()
	touched := map[string]bool{}
	for _, m := range list {
		r := m.r
		r.Addr = ""
		target, err := s.lineOf(ctx, tx, to, lineIdentity{productKey: m.key, line: m.train, vendor: m.vendor, product: m.product}, r)
		if err != nil {
			return err
		}
		if err := putReading(ctx, tx, target, r, m.ev); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = ? AND instance = ? AND addr_id = ?`, m.line, m.r.Source, m.r.Instance, addr); err != nil {
			return fmt.Errorf("inventory: move a reading: %w", err)
		}
		touched[m.line], touched[target] = true, true
	}
	for _, l := range slices.Sorted(maps.Keys(touched)) {
		if _, err := s.settleLine(ctx, tx, l, now, nil); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_service SET asset_id = ?, addr_id = '' WHERE asset_id = ? AND addr_id = ? AND source IN ('nmap', 'scan')`, to, from, addr); err != nil {
		return fmt.Errorf("inventory: move the open ports: %w", err)
	}
	return nil
}
