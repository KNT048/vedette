package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"sync"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
)

// Identifying the stored software lines again after an update of the product catalogue (INV-58).
//
// A reading lands on the line of its product and release train as the catalogue that shipped with the build identified it
// (identify). The catalogue ships inside the binary and changes between releases: a new product, a new train rule, a corrected name.
// Each reading keeps what its source sent (itemEvidence), and the catalogue the stored lines were last identified under is stored
// (inv_catalogue_pass). When a start finds another catalogue, a job identifies every reading again from what it keeps, as the
// write path would identify it now, and moves what moved through the write path's own steps: a reading goes to its line (lineOf,
// putReading, first seen kept), every line it touched is settled (settleLine: the resolver, the history), and the device is announced
// as on a source's read (inventory.software.changed and the match events), so findings match it again. A line whose readings all
// belong to another product or train is renamed in place: its id, history and the findings that point at it stay.
//
// What does not keep its item follows its line: a reading of an earlier build, a person's edit of a line, a stated OS. It goes to
// its line's train of its version (the self-check's rule, trainOf), on its line's product. A line held only by a person's entries is
// identified again by its names when the catalogue knows them as a product and the line's product is no product of the catalogue
// (a product the catalogue learnt).
//
// The pass runs in the background (health does not wait), a page of devices at a time; a device is read without holding the write
// lock and written only when something of it moves, in one transaction. It is resumable (the last device done is stored) and
// idempotent (a device identified again is no change); the revision is stored when every device is done.

// identifier is the line of an item a source sends and the version it reads (identify).
type identifier func(it SoftwareItem, source string) (lineIdentity, string)

// identifyRules is the generation of the identification code (identify and core/productid's rules). Raise it with a change of that
// code that can give a stored reading another product or train: the next start identifies the stored lines again, as after a change
// of the catalogue's data. TestIdentifyRulesFollowTheIdentificationCode fails on any change of that code until the change is weighed.
const identifyRules = "2"

// catalogueRevision is the revision of the product catalogue this build identifies with: a hash of the identification rules'
// generation and of the catalogue files core/productid loads (products/*.json, curated.json, kev-products.json).
var catalogueRevision = sync.OnceValue(func() string {
	h := sha256.New()
	put := func(name string, b []byte) {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", name, len(b))
		_, _ = h.Write(b)
	}
	put("rules", []byte(identifyRules))
	names, err := fs.Glob(catalogdata.Products, "products/*.json")
	if err != nil {
		panic("inventory: the embedded catalogue: " + err.Error()) // a constant pattern over embedded files
	}
	slices.Sort(names)
	for _, n := range names {
		b, err := fs.ReadFile(catalogdata.Products, n)
		if err != nil {
			panic("inventory: the embedded catalogue: " + err.Error())
		}
		put(n, b)
	}
	put("curated.json", catalogdata.Curated)
	put("kev-products.json", catalogdata.KEVProducts)
	return hex.EncodeToString(h.Sum(nil))[:32]
})

// reidentifyPage is how many devices one step of the pass reads.
const reidentifyPage = 200

// ReidentifyLines brings the stored software lines to the product catalogue of this build, when they were identified under another
// one (INV-58). The job runs it at start and every day after; with the lines up to date it reads one row. A device that cannot be
// identified again is logged and skipped: the devices after it still are, and the pass stays open, so the next run walks every
// device again (a device already done is only read).
func (s *Service) ReidentifyLines(ctx context.Context) error {
	if err := s.settleStaleLines(ctx); err != nil {
		return err
	}
	run := &passRun{}
	for {
		done, err := s.reidentifyStep(ctx, reidentifyPage, run)
		if err != nil || done {
			return err
		}
	}
}

// settleStaleLines settles again every line whose stored value is not what the resolver says of its readings now (the self-check
// inventory.line_value_is_the_resolvers): a line settled by an earlier release under another rule (a person's entry that a later
// agent report now outgrows) would otherwise keep its old value until its source reports again. Each device's lines are settled in
// one write, announced as a software change (the findings match it again); most runs find none and write nothing.
func (s *Service) settleStaleLines(ctx context.Context) error {
	stale := map[string][]string{}
	if err := eachStoredLine(ctx, s.db.Reader(), func(l storedLine) {
		if l.resolveBreak() != "" {
			stale[l.asset] = append(stale[l.asset], l.id)
		}
	}); err != nil {
		return err
	}
	for _, asset := range slices.Sorted(maps.Keys(stale)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
			before, err := deviceKeys(ctx, tx, asset)
			if err != nil {
				return err
			}
			now := s.now()
			for _, id := range stale[asset] {
				st, err := s.settleLine(ctx, tx, id, now, nil)
				if err != nil {
					return err
				}
				if st.lapsed != "" {
					if err := s.auditTx(ctx, tx, systemActor, "inventory.software_correction_lapsed", deviceName(ctx, tx, asset), st.lapsed); err != nil {
						return err
					}
				}
				if st.kept != "" {
					if err := s.auditTx(ctx, tx, systemActor, "inventory.software_correction_kept", deviceName(ctx, tx, asset), st.kept); err != nil {
						return err
					}
				}
			}
			return s.announceSoftware(ctx, tx, o, asset, before, true)
		})
		if err != nil {
			s.log.ErrorContext(ctx, "inventory: a device's software lines could not be settled again", "asset", asset, "error", err)
		}
	}
	return nil
}

// passRun is what one run of the pass knows besides the stored state: whether it walked every device from the first, and how many
// devices failed. The revision is stored only after a walk from the first device with no failure.
type passRun struct {
	started, fromStart bool
	failed             int
}

// passState is the row of inv_catalogue_pass.
type passState struct {
	revision, target, after string
	found                   bool
}

func readPass(ctx context.Context, q querier) (passState, error) {
	var p passState
	err := q.QueryRowContext(ctx, `SELECT revision, target, after FROM inv_catalogue_pass WHERE id = 1`).Scan(&p.revision, &p.target, &p.after)
	if errors.Is(err, sql.ErrNoRows) {
		return passState{}, nil
	} else if err != nil {
		return p, fmt.Errorf("inventory: read the catalogue pass: %w", err)
	}
	p.found = true
	return p, nil
}

func (s *Service) savePass(ctx context.Context, tx *sql.Tx, p passState) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_catalogue_pass (id, revision, target, after, updated_at) VALUES (1, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET revision = excluded.revision, target = excluded.target, after = excluded.after, updated_at = excluded.updated_at`,
		p.revision, p.target, p.after, s.now()); err != nil {
		return fmt.Errorf("inventory: store the catalogue pass: %w", err)
	}
	return nil
}

// reidentifyStep identifies the lines of the next page of at most page devices; done when every device is up to date, or when the
// run reached the last device after a failure (the next run tries again).
func (s *Service) reidentifyStep(ctx context.Context, page int, run *passRun) (done bool, err error) {
	st, err := readPass(ctx, s.db.Reader())
	if err != nil || st.found && st.revision == s.catRev {
		return err == nil, err
	}
	if st.target != s.catRev { // a new pass (or one for a catalogue this build does not have: it starts again)
		st.target, st.after = s.catRev, ""
		if err := s.db.Write(ctx, func(tx *sql.Tx) error { return s.savePass(ctx, tx, st) }); err != nil {
			return false, err
		}
		s.log.InfoContext(ctx, "inventory: the product catalogue changed; identifying the stored software lines again", "from", st.revision, "to", s.catRev)
	}
	if !run.started {
		run.started, run.fromStart = true, st.after == ""
	}
	ids, err := devicesWithSoftware(ctx, s.db.Reader(), st.after, page)
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		if run.failed > 0 || !run.fromStart { // walk every device again: now from the first (a resumed run), or at the next run
			st.after = ""
			if err := s.db.Write(ctx, func(tx *sql.Tx) error { return s.savePass(ctx, tx, st) }); err != nil {
				return false, err
			}
			if run.failed > 0 {
				s.log.WarnContext(ctx, "inventory: some devices' software lines could not be identified again; the next run tries again", "failed", run.failed)
				return true, nil
			}
			run.fromStart = true
			return false, nil
		}
		st.revision, st.target, st.after = s.catRev, "", ""
		return true, s.db.Write(ctx, func(tx *sql.Tx) error { return s.savePass(ctx, tx, st) })
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if err := s.reidentifyDevice(ctx, id, st); err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			run.failed++
			s.log.ErrorContext(ctx, "inventory: a device's software lines could not be identified again", "asset", id, "error", err)
		}
	}
	st.after = ids[len(ids)-1]
	return false, s.db.Write(ctx, func(tx *sql.Tx) error { return s.savePass(ctx, tx, st) })
}

// reidentifyDevice identifies one device's lines again when something of it moves, and stores the pass as done up to it.
func (s *Service) reidentifyDevice(ctx context.Context, id string, st passState) error {
	sw, err := deviceSoftware(ctx, s.db.Reader(), id)
	if err != nil {
		return err
	}
	if !s.planIdentities(sw).changes() { // most devices: read, nothing to write
		return nil
	}
	st.after = id
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		if err := s.reidentifyDeviceTx(ctx, tx, o, id); err != nil {
			return err
		}
		return s.savePass(ctx, tx, st)
	})
}

// devicesWithSoftware lists, in id order, at most n devices after id after that hold a software line.
func devicesWithSoftware(ctx context.Context, q querier, after string, n int) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT asset_id FROM inv_software WHERE asset_id > ? ORDER BY asset_id LIMIT ?`, after, n)
	if err != nil {
		return nil, fmt.Errorf("inventory: list devices with software: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: list devices with software: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// heldLine is a stored line of a device with its readings, as the pass reads it.
type heldLine struct {
	id, key, train, vendor, product, display, state, marked string
	readings                                                []heldReading
}

type heldReading struct {
	r  Reading
	ev itemEvidence
}

// deviceSoftware reads every line of a device with its readings and what they keep, in id order.
func deviceSoftware(ctx context.Context, q querier, assetID string) ([]heldLine, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, product_key, line, vendor, product, display, state, ifnull(not_installed_at, '') FROM inv_software WHERE asset_id = ? ORDER BY id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software lines: %w", err)
	}
	var lines []heldLine
	at := map[string]int{}
	for rows.Next() {
		var l heldLine
		if err := rows.Scan(&l.id, &l.key, &l.train, &l.vendor, &l.product, &l.display, &l.state, &l.marked); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read software lines: %w", err)
		}
		at[l.id] = len(lines)
		lines = append(lines, l)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read software lines: %w", err)
	}
	rows, err = q.QueryContext(ctx, `SELECT `+readingCols+`, r.software_id, `+evidenceCols+` FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id
		WHERE w.asset_id = ? ORDER BY r.software_id, r.source, r.instance, r.addr_id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software readings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var line string
		evDst, ev := evidenceDest()
		r, err := scanReading(rows, append([]any{&line}, evDst...)...)
		if err != nil {
			return nil, fmt.Errorf("inventory: read software readings: %w", err)
		}
		if i, ok := at[line]; ok {
			lines[i].readings = append(lines[i].readings, heldReading{r: r, ev: ev()})
		}
	}
	return lines, rows.Err()
}

// placed is where a reading of a device belongs under this build's catalogue.
type placed struct {
	from      string       // the line it is on
	old       Reading      // as stored
	r         Reading      // as it is to be stored: the version identify reads, the instance of its install
	ev        itemEvidence // what it keeps (moves with it)
	to        lineIdentity // the line it belongs to, with the names it gives a line
	drop      bool         // another reading of the same source, install and address on the same line is newer: it goes
	following bool         // it keeps no item: it follows its line
}

// identPlan is what the pass does to one device: lines renamed in place, and readings that move or change.
type identPlan struct {
	renames map[string]lineIdentity // line id -> the product and train it takes
	moves   []placed                // readings whose line, instance or version changes, or that go
	all     []placed
}

func (p identPlan) changes() bool { return len(p.renames) > 0 || len(p.moves) > 0 }

type identityKey struct{ key, train string }

func keyOf(id lineIdentity) identityKey { return identityKey{id.productKey, id.line} }

// planIdentities is where every reading of a device belongs now (the rules at the top of this file). It only reads its input.
func (s *Service) planIdentities(lines []heldLine) identPlan {
	plan := identPlan{renames: map[string]lineIdentity{}}
	held := heldIdentities(lines, nil) // the identities the device's lines hold, as the plan renames them
	type home struct {
		line string
		from identityKey
		to   lineIdentity
	}
	var homes []home // the lines none of whose readings stays: the identity of what each shows
	for _, l := range lines {
		if len(l.readings) == 0 {
			continue
		}
		var mine []placed
		keys := map[string]bool{}
		for _, hr := range l.readings {
			p := placed{from: l.id, old: hr.r, r: hr.r, ev: hr.ev}
			if hr.ev.ok {
				id, v := s.ident(hr.ev.item(hr.r), hr.r.Source)
				p.to, p.r.Version, p.r.Instance = id, v, hr.ev.instance
				keys[id.productKey] = true
			} else {
				p.following = true
			}
			mine = append(mine, p)
		}
		key, names := l.key, lineIdentity{vendor: l.vendor, product: l.product}
		switch {
		case len(keys) == 1:
			key = slices.Collect(maps.Keys(keys))[0]
		case len(keys) == 0 && entriesOnly(l):
			key = s.entriesKey(l)
		}
		for i := range mine {
			p := &mine[i]
			if !p.following {
				continue
			}
			p.to = lineIdentity{productKey: key, line: l.train, vendor: names.vendor, product: names.product}
			if p.r.Version != "" {
				p.to.line = trainOf(key, p.r.Version)
			} else if key != l.key {
				p.to.line = ""
			}
		}
		for i := range mine { // a version written as its product's scheme reads it ("8.0 U3" is ESXi 8.0.3 with its build), as a new read would
			p := &mine[i]
			p.r.Version, p.r.Display = statedRelease(p.to.productKey, p.r.Version, p.r.Display)
		}
		// the line keeps its id on the identity of what it shows (the resolver's reading) when none of its readings stays where it is
		cur := identityKey{l.key, l.train}
		if !slices.ContainsFunc(mine, func(p placed) bool { return keyOf(p.to) == cur }) {
			eff := Resolve(LineState{State: l.state, NotInstalledAt: l.marked}, l.readingList()).Effective
			if i := slices.IndexFunc(mine, func(p placed) bool {
				return p.old.Source == eff.Source && p.old.Instance == eff.Instance && p.old.Addr == eff.Addr
			}); i >= 0 {
				homes = append(homes, home{line: l.id, from: cur, to: mine[i].to})
			}
		}
		plan.all = append(plan.all, mine...)
	}
	// a line is renamed when no line holds its new identity, which another line may leave first: until none moves
	for moved := true; moved; {
		moved = false
		for _, h := range homes {
			if _, done := plan.renames[h.line]; done || held[keyOf(h.to)] != "" {
				continue
			}
			plan.renames[h.line] = h.to
			delete(held, h.from)
			held[keyOf(h.to)] = h.line
			moved = true
		}
	}
	// two installs of one line that one source reads at different releases are told apart by their release (readingsOfList)
	type slot struct {
		to                 identityKey
		source, inst, addr string
	}
	releases := map[slot]map[string]bool{}
	for _, p := range plan.all {
		if p.following {
			continue
		}
		k := slot{keyOf(p.to), p.r.Source, p.r.Instance, p.r.Addr}
		if releases[k] == nil {
			releases[k] = map[string]bool{}
		}
		releases[k][p.r.Version+"\x00"+p.r.PkgVersion] = true
	}
	for i := range plan.all {
		p := &plan.all[i]
		if !p.following && len(releases[slot{keyOf(p.to), p.r.Source, p.r.Instance, p.r.Addr}]) > 1 {
			p.r.Instance = installInstance(p.r.Instance, p.r)
		}
	}
	// one reading per line, source, instance and address: the newer one stays (as when two devices' lines fold)
	type pk struct {
		to                 identityKey
		source, inst, addr string
	}
	newest := map[pk]int{}
	for i, p := range plan.all {
		k := pk{keyOf(p.to), p.r.Source, p.r.Instance, p.r.Addr}
		if j, ok := newest[k]; !ok || p.r.SeenAt > plan.all[j].r.SeenAt {
			newest[k] = i
		}
	}
	for i := range plan.all {
		p := &plan.all[i]
		p.drop = newest[pk{keyOf(p.to), p.r.Source, p.r.Instance, p.r.Addr}] != i
		line := held[keyOf(p.to)] // "": a line the device does not have yet
		if p.drop || line != p.from || p.r.Instance != p.old.Instance || p.r.Version != p.old.Version || p.r.Display != p.old.Display {
			plan.moves = append(plan.moves, *p)
		}
	}
	return plan
}

// heldIdentities maps the product and train of every line of a device to its id, after renames.
func heldIdentities(lines []heldLine, renames map[string]lineIdentity) map[identityKey]string {
	held := map[identityKey]string{}
	for _, l := range lines {
		if to, ok := renames[l.id]; ok {
			held[keyOf(to)] = l.id
			continue
		}
		held[identityKey{l.key, l.train}] = l.id
	}
	return held
}

// readingList is the readings of a line as the resolver reads them.
func (l heldLine) readingList() []Reading {
	out := make([]Reading, len(l.readings))
	for i, hr := range l.readings {
		out[i] = hr.r
	}
	return out
}

// entriesOnly says whether only a person's entries hold the line.
func entriesOnly(l heldLine) bool {
	return !slices.ContainsFunc(l.readings, func(hr heldReading) bool { return !hr.r.entry() })
}

// entriesKey is the product of a line only a person's entries hold: when the line's own product is no product of the catalogue, the
// catalogue's product that its names and its key (as the exploited-list name a person's pick carries) identify, as a person adding
// it now would get (a product the catalogue learnt); else the line's.
func (s *Service) entriesKey(l heldLine) string {
	if p, ok := productid.ByKey(l.key); ok && p.ID != "" {
		return l.key
	}
	id, _ := s.ident(SoftwareItem{Display: l.display, Vendor: l.vendor, Product: l.product, Version: l.readings[0].r.Version, KevKeys: []string{l.key}}, sourceManual)
	if p, ok := productid.ByKey(id.productKey); ok && p.ID != "" {
		return id.productKey
	}
	return l.key
}

// reidentifyDeviceTx identifies the readings of one device again and moves what moved, inside the write transaction.
func (s *Service) reidentifyDeviceTx(ctx context.Context, tx *sql.Tx, o *outbox, assetID string) error {
	lines, err := deviceSoftware(ctx, tx, assetID)
	if err != nil {
		return err
	}
	plan := s.planIdentities(lines)
	if !plan.changes() {
		return nil
	}
	before, err := deviceKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	n, err := s.applyIdentities(ctx, tx, assetID, lines, plan)
	if err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, systemActor, "inventory.software_sync", deviceName(ctx, tx, assetID),
		fmt.Sprintf("product catalogue update: %d software lines identified again", n)); err != nil {
		return err
	}
	return s.announceSoftware(ctx, tx, o, assetID, before, false) // as a source's read: a match event per CVE gained, or one when the keys stay
}

// applyIdentities writes a device's plan through the write path's steps and settles every line it touched; it returns how many.
func (s *Service) applyIdentities(ctx context.Context, tx *sql.Tx, assetID string, lines []heldLine, plan identPlan) (int, error) {
	now := s.now()
	touched := map[string]bool{}
	byID := map[string]heldLine{}
	for _, l := range lines {
		byID[l.id] = l
	}
	held := heldIdentities(lines, plan.renames)
	renamed := slices.Sorted(maps.Keys(plan.renames))
	// a line may take the identity another renamed line leaves: every renamed line first leaves its own (a key no product has)
	for _, id := range renamed {
		if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET product_key = ?, line = '' WHERE id = ?`, "#identifying "+id, id); err != nil {
			return 0, fmt.Errorf("inventory: identify a software line again: %w", err)
		}
	}
	for _, id := range renamed {
		to, l := plan.renames[id], byID[id]
		if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET product_key = ?, line = ? WHERE id = ?`, to.productKey, to.line, id); err != nil {
			return 0, fmt.Errorf("inventory: identify a software line again: %w", err)
		}
		if err := softwareEvent(ctx, tx, assetID, id, to.productKey, l.display, now, "identified_again", clip(identityText(l.key, l.train), maxSwVer),
			clip(identityText(to.productKey, to.line), maxSwVer), "", ""); err != nil {
			return 0, err
		}
		touched[id] = true
	}
	// every reading that moves leaves first, so none takes the place of one that has not left yet
	for _, p := range plan.moves {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = ? AND instance = ? AND addr_id = ?`,
			p.from, p.old.Source, p.old.Instance, p.old.Addr); err != nil {
			return 0, fmt.Errorf("inventory: move a software reading: %w", err)
		}
		touched[p.from] = true
	}
	names := map[string]map[[2]string][2]string{}
	for _, p := range plan.moves {
		if p.drop {
			continue
		}
		lineID, err := s.lineOf(ctx, tx, assetID, p.to, p.r)
		if err != nil {
			return 0, err
		}
		held[keyOf(p.to)] = lineID
		if err := putReading(ctx, tx, lineID, p.r, p.ev); err != nil {
			return 0, err
		}
		touched[lineID] = true
	}
	for _, p := range plan.all { // the names a line takes are its readings' own, as on a source's read
		if p.drop || p.following {
			continue
		}
		if id := held[keyOf(p.to)]; touched[id] {
			if names[id] == nil {
				names[id] = map[[2]string][2]string{}
			}
			names[id][[2]string{p.r.Source, p.r.Instance}] = [2]string{p.to.vendor, p.to.product}
		}
	}
	ids := slices.Sorted(maps.Keys(touched))
	for _, id := range ids {
		if _, err := s.settleLine(ctx, tx, id, now, names[id]); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// identityText is a line's product and train as its history keeps an identification ("oracle|java se 21").
func identityText(key, train string) string {
	if train == "" {
		return key
	}
	return key + " " + train
}
