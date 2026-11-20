package exposure

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	corerun "github.com/knt048/vedette/core/run"
)

// Domain targets form a tree. Where a target sits (its parent) and which target scans each name found under a domain (the owner) are
// derived from the targets' values, scopes and switches; settleTree is their one writer and runs in the write transaction of every
// change to them (a target added, removed or edited, a scan's rows), so the stored tree and the names a scan reaches never disagree.
//
//   - The parent of a domain target is the nearest other domain target whose value contains it (proofat.Within: never across a public
//     suffix). A subdomain added under a target sits under it; a target added above existing ones takes them under it; a target removed
//     hands its children to its own parent.
//   - Every name under a domain is scanned by at most one enabled target: its owner, the deepest enabled target that contains the name
//     and whose scope takes it (its own name always; with scope all every name under it; with scope selected the names chosen on its own
//     rows; with scope self none other). A name nobody's scope takes is scanned by nobody. A target's scan skips every name it does not
//     own: the names of its enabled children are theirs.
//   - A name a target no longer scans keeps its row (found, first and last seen) and loses the addresses it had there; a service of that
//     target on an address no name of it points at any more is closed at once, its issues gone with it (as for an address that left the
//     domain). The owner's own scan watches them from now on.

// scopeNode is one domain target as the ownership rule reads it.
type scopeNode struct {
	id, value string
	mode      ScopeMode
	enabled   bool
	chosen    map[string]bool // the names chosen on its own rows (scope selected)
}

// takes says the node's scope takes name: its own name, or a name under it its scope mode lets it scan.
func (n scopeNode) takes(name string) bool {
	switch {
	case name == n.value:
		return true
	case !Covers(n.value, name):
		return false
	case n.mode == ScopeAll:
		return true
	case n.mode == ScopeSelected:
		return n.chosen[name]
	}
	return false
}

// ownerOf is the id of the target that scans name: of the enabled nodes that contain it, the deepest whose scope takes it; "" when none
// does. Two nodes that both contain a name are nested, so the deeper is the one with the longer value.
func ownerOf(name string, nodes []scopeNode) string {
	var in []scopeNode
	for _, n := range nodes {
		if n.enabled && Covers(n.value, name) {
			in = append(in, n)
		}
	}
	slices.SortFunc(in, func(a, b scopeNode) int { return cmp.Compare(len(b.value), len(a.value)) })
	for _, n := range in {
		if n.takes(name) {
			return n.id
		}
	}
	return ""
}

// NamePlan is which names under a domain target its scan may reach (ScanTarget.Names), read from the stored tree when the scan starts:
// the target's own scope and the scopes of the enabled targets under it, which scan their own names. A change to the tree applies from
// the next scan.
type NamePlan struct {
	id    string
	nodes []scopeNode // the target (taken as enabled: it is the one scanning) and the enabled domain targets under it
}

// Scans says the scan of the plan's target reaches name: the target owns it. A nil plan (an IP target, or a caller that builds a
// ScanTarget by hand) scans every name it is handed.
func (p *NamePlan) Scans(name string) bool {
	if p == nil {
		return true
	}
	return ownerOf(name, p.nodes) == p.id
}

// planOf is the plan of the domain target t among all, with the chosen names of each target (chosen by target id).
func planOf(t Target, all []Target, chosen map[string]map[string]bool) *NamePlan {
	p := &NamePlan{id: t.ID}
	for _, o := range all {
		if o.Kind != KindDomain || (o.ID != t.ID && (!o.Enabled || !Covers(t.Value, o.Value))) {
			continue
		}
		n := nodeOf(o, chosen)
		if o.ID == t.ID {
			n.enabled = true
		}
		p.nodes = append(p.nodes, n)
	}
	return p
}

func nodeOf(t Target, chosen map[string]map[string]bool) scopeNode {
	return scopeNode{id: t.ID, value: t.Value, mode: cmp.Or(t.ScopeMode, ScopeAll), enabled: t.Enabled, chosen: chosen[t.ID]}
}

// namePlan reads the plan of the domain target t now.
func namePlan(ctx context.Context, q querier, t Target) (*NamePlan, error) {
	all, err := listTargets(ctx, q)
	if err != nil {
		return nil, err
	}
	chosen, err := chosenNames(ctx, q)
	if err != nil {
		return nil, err
	}
	return planOf(t, all, chosen), nil
}

// chosenNames is, for each domain target, the names chosen on its rows (exp_host.selected).
func chosenNames(ctx context.Context, q querier) (map[string]map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT target_id, name FROM exp_host WHERE selected = 1`)
	if err != nil {
		return nil, fmt.Errorf("chosen names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]bool{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("chosen names: %w", err)
		}
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][name] = true
	}
	return out, rows.Err()
}

// parentOf is the id of the nearest other domain target that contains the domain target t; "" when none (an IP has none).
func parentOf(t Target, all []Target) string {
	if t.Kind != KindDomain {
		return ""
	}
	best := Target{}
	for _, o := range all {
		if o.Kind == KindDomain && o.ID != t.ID && o.Value != t.Value && Covers(o.Value, t.Value) && len(o.Value) > len(best.Value) {
			best = o
		}
	}
	return best.ID
}

// ancestors is the chain of parents of t, nearest first, as stored (a loop, which settleTree never writes, ends the chain).
func ancestors(t Target, byID map[string]Target) []Target {
	var out []Target
	seen := map[string]bool{t.ID: true}
	for p := t.ParentID; p != "" && !seen[p]; {
		o, ok := byID[p]
		if !ok {
			break
		}
		seen[p] = true
		out = append(out, o)
		p = o.ParentID
	}
	return out
}

// settleTree writes, in tx, the parent of every domain target and the owner of every name found under one (exp_host.child_target_id:
// the other target that scans the name; NULL when the row's own target scans it or nobody does), and drops the addresses of the names a
// target does not scan; the services of a target left on no address of it are closed and their issues gone. It returns the ids of the
// services it closed, by target.
func settleTree(ctx context.Context, tx *sql.Tx) (map[string][]string, error) {
	all, err := listTargets(ctx, tx)
	if err != nil {
		return nil, err
	}
	for _, t := range all {
		if p := parentOf(t, all); p != t.ParentID {
			if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET parent_id = ? WHERE id = ?`, nullString(p), t.ID); err != nil {
				return nil, fmt.Errorf("placing target %s: %w", t.Value, err)
			}
		}
	}
	chosen, err := chosenNames(ctx, tx)
	if err != nil {
		return nil, err
	}
	nodes := map[string]scopeNode{}
	var list []scopeNode
	for _, t := range all {
		if t.Kind == KindDomain {
			n := nodeOf(t, chosen)
			nodes[t.ID] = n
			list = append(list, n)
		}
	}
	type hostRow struct{ id, target, name, child string }
	var hosts []hostRow
	err = func() error {
		rows, err := tx.QueryContext(ctx, `SELECT id, target_id, name, coalesce(child_target_id, '') FROM exp_host`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var h hostRow
			if err := rows.Scan(&h.id, &h.target, &h.name, &h.child); err != nil {
				return err
			}
			hosts = append(hosts, h)
		}
		return rows.Err()
	}()
	if err != nil {
		return nil, fmt.Errorf("reading names: %w", err)
	}
	left := map[string]bool{}               // the targets that dropped an address
	dropped := map[string]map[string]bool{} // the names each target does not scan
	for _, h := range hosts {
		own, ok := nodes[h.target]
		if !ok {
			continue // a row of an IP target: none is written
		}
		// The row's own target is taken as enabled: a target that is switched off keeps its rows as its last scan left them, and an
		// enabled one under it is still the owner of its names.
		scope := slices.Clone(list)
		for i := range scope {
			if scope[i].id == own.id {
				scope[i].enabled = true
			}
		}
		owner := ownerOf(h.name, scope)
		child := owner
		if owner == h.target {
			child = ""
		}
		if child != h.child {
			if _, err := tx.ExecContext(ctx, `UPDATE exp_host SET child_target_id = ? WHERE id = ?`, nullString(child), h.id); err != nil {
				return nil, fmt.Errorf("writing the owner of %s: %w", h.name, err)
			}
		}
		if owner == h.target {
			continue
		}
		if dropped[h.target] == nil {
			dropped[h.target] = map[string]bool{}
		}
		dropped[h.target][h.name] = true
		res, err := tx.ExecContext(ctx, `DELETE FROM exp_address WHERE host_id = ?`, h.id)
		if err != nil {
			return nil, fmt.Errorf("dropping the addresses of %s: %w", h.name, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			left[h.target] = true
		}
	}
	closed := map[string][]string{}
	for target := range left {
		ids, err := closeUnaddressed(ctx, tx, target)
		if err != nil {
			return nil, err
		}
		if err := goneWithService(ctx, tx, ids); err != nil {
			return nil, err
		}
		closed[target] = ids
	}
	for target, names := range dropped {
		if err := goneWithName(ctx, tx, target, names); err != nil {
			return nil, err
		}
	}
	return closed, nil
}

// goneWithName marks gone the open issues of target about a name it does not scan any more (a certificate, a web site or an admin page
// by that name): its scans no longer look there, so they would never say it is fixed; the scan that owns the name reports it there.
func goneWithName(ctx context.Context, tx *sql.Tx, target string, names map[string]bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, engine, key FROM exp_issue WHERE target_id = ? AND state = 'open'`, target)
	if err != nil {
		return fmt.Errorf("issues by name: %w", err)
	}
	var gone []string
	for rows.Next() {
		var id, engine, key string
		if err := rows.Scan(&id, &engine, &key); err != nil {
			_ = rows.Close()
			return fmt.Errorf("issues by name: %w", err)
		}
		if n := issueName(IssueEngine(engine), key); n != "" && names[n] {
			gone = append(gone, id)
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("issues by name: %w", err)
	}
	for _, id := range gone {
		if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET state = 'gone' WHERE id = ?`, id); err != nil {
			return fmt.Errorf("issue %s gone: %w", id, err)
		}
	}
	return nil
}

// issueName is the host name an issue's key is about: a certificate's name, the host of an admin page's address or of a ZAP site;
// "" when the key names no host name (an address, a template on a port, an OpenVAS result).
func issueName(e IssueEngine, key string) string {
	var host string
	switch {
	case e == EngineSurface && strings.HasPrefix(key, keyCertExpiry):
		host = strings.TrimPrefix(key, keyCertExpiry)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	case e == EngineSurface && strings.HasPrefix(key, keyAdminPage):
		host = urlHost(strings.TrimPrefix(key, keyAdminPage))
	case e == EngineZAP:
		if _, site, ok := strings.Cut(key, "@"); ok {
			host = urlHost(site)
		}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return strings.ToLower(host)
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// closeUnaddressed closes the open services of target on addresses no row of it has any more and returns their ids.
func closeUnaddressed(ctx context.Context, tx *sql.Tx, target string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT s.id FROM exp_service s WHERE s.target_id = ? AND s.state = 'open'
		AND NOT EXISTS (SELECT 1 FROM exp_address a WHERE a.target_id = s.target_id AND a.ip = s.ip)`, target)
	if err != nil {
		return nil, fmt.Errorf("services left without an address: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("services left without an address: %w", err)
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("services left without an address: %w", err)
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE exp_service SET state = 'closed' WHERE id = ?`, id); err != nil {
			return nil, fmt.Errorf("closing service %s: %w", id, err)
		}
	}
	return ids, nil
}

// NodeEdit is a change to a target (PATCH /exposure/tree/{id}); a nil field is left as it is.
type NodeEdit struct {
	Scope   *ScopeMode // domains only
	Enabled *bool
	// Selected are the ids of the target's names to scan, replacing the choice; only with the scope selected (the one asked for in the
	// same edit, or the stored one).
	Selected *[]string
}

// MaxSelected bounds the names one edit chooses.
const MaxSelected = 1000

// The refusals of an edit.
var (
	ErrSelectedScope = apiErr(400, "bad_value", "Names are chosen only when the scope is \"the names I choose\".")
	ErrSelectedMany  = apiErr(400, "bad_value", "Choose at most %d names at once.", MaxSelected)
)

func errNotAName(id string) *APIError {
	return apiErr(400, "bad_value", "%s is not a name found under this target.", clipText(id, 96))
}

// EditNode changes the scope, the switch or the chosen names of a target, audited, and settles the tree in the same write: the names it
// no longer scans keep their rows and lose their addresses, the names a child gave back are scanned by it again from its next scan.
// Switching a target off stops its scan that is queued or runs.
func (s *Service) EditNode(ctx context.Context, user, id string, e NodeEdit) (TargetView, error) {
	off := false
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		scope, enabled := t.ScopeMode, t.Enabled
		var what []string
		if e.Scope != nil {
			switch {
			case t.Kind != KindDomain:
				return ErrScopeIP
			case !e.Scope.Valid():
				return ErrScope
			}
			if *e.Scope != scope {
				what = append(what, "scope "+string(*e.Scope))
			}
			scope = *e.Scope
		}
		if e.Enabled != nil && *e.Enabled != enabled {
			enabled = *e.Enabled
			what = append(what, map[bool]string{true: "switched on", false: "switched off"}[enabled])
		}
		var chosen map[string]bool
		if e.Selected != nil {
			if t.Kind != KindDomain || scope != ScopeSelected {
				return ErrSelectedScope
			}
			if len(*e.Selected) > MaxSelected {
				return ErrSelectedMany
			}
			names, err := hostIDs(ctx, tx, id)
			if err != nil {
				return err
			}
			chosen = map[string]bool{}
			for _, h := range *e.Selected {
				if !names[h] {
					return errNotAName(h)
				}
				chosen[h] = true
			}
			what = append(what, plural(len(chosen), "name")+" chosen")
		}
		var sc any
		if t.Kind == KindDomain {
			sc = string(cmp.Or(scope, ScopeAll))
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET scope_mode = ?, enabled = ? WHERE id = ?`, sc, boolInt(enabled), id); err != nil {
			return fmt.Errorf("editing target %s: %w", t.Value, err)
		}
		if chosen != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE exp_host SET selected = 0 WHERE target_id = ? AND selected = 1`, id); err != nil {
				return fmt.Errorf("choosing names: %w", err)
			}
			for h := range chosen {
				if _, err := tx.ExecContext(ctx, `UPDATE exp_host SET selected = 1 WHERE id = ?`, h); err != nil {
					return fmt.Errorf("choosing names: %w", err)
				}
			}
		}
		if _, err := settleTree(ctx, tx); err != nil {
			return err
		}
		off = t.Enabled && !enabled
		if len(what) == 0 {
			return nil
		}
		return s.audit(ctx, tx, user, "exposure.target_edit", t.Value, strings.Join(what, ", "))
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: editing target: %w", err)
	}
	if runID, ok := s.activeRun(ctx, id); off && ok && s.cfg.Runs != nil {
		if err := s.cfg.Runs.Stop(ctx, runID, user, "the target was switched off"); err != nil && !errors.Is(err, corerun.ErrEnded) {
			s.cfg.Log.WarnContext(ctx, "exposure: stopping the scan of a target switched off", "error", err)
		}
	}
	return s.Target(ctx, id)
}

// hostIDs is the set of the ids of the names of target.
func hostIDs(ctx context.Context, q querier, target string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT id FROM exp_host WHERE target_id = ?`, target)
	if err != nil {
		return nil, fmt.Errorf("names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("names: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ---- the rules of the tree, counted (selfcheck) ----

// treeTarget is a target as the counts read it.
type treeTarget struct {
	id, kind, value, parent string
	enabled                 bool
}

func treeTargets(ctx context.Context, q querier) ([]treeTarget, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, kind, value, coalesce(parent_id, ''), enabled FROM exp_target ORDER BY value`)
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []treeTarget
	for rows.Next() {
		var t treeTarget
		var on int
		if err := rows.Scan(&t.id, &t.kind, &t.value, &t.parent, &on); err != nil {
			return nil, fmt.Errorf("targets: %w", err)
		}
		t.enabled = on == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// unplacedPairs counts the pairs of domain targets where one is a name under the other and the other is not among its stored
// ancestors: a subdomain stored as a target unrelated to its parent.
func unplacedPairs(ctx context.Context, q querier) (int64, error) {
	ts, err := treeTargets(ctx, q)
	if err != nil {
		return 0, err
	}
	byID := map[string]treeTarget{}
	for _, t := range ts {
		byID[t.id] = t
	}
	var n int64
	for _, c := range ts {
		if c.kind != string(KindDomain) {
			continue
		}
		anc := map[string]bool{}
		for p := c.parent; p != "" && !anc[p]; p = byID[p].parent {
			anc[p] = true
		}
		for _, p := range ts {
			if p.kind == string(KindDomain) && p.id != c.id && p.value != c.value && Covers(p.value, c.value) && !anc[p.id] {
				n++
			}
		}
	}
	return n, nil
}

// doubleScanned counts the names scanned by two or more enabled targets: a target scans its own name, and a name under it whose row
// carries addresses (a scan of that target resolved and probed it; a name it does not scan keeps its row without addresses).
func doubleScanned(ctx context.Context, q querier) (int64, error) {
	ts, err := treeTargets(ctx, q)
	if err != nil {
		return 0, err
	}
	by := map[string]map[string]bool{} // name: the enabled targets that scan it
	add := func(name, target string) {
		if by[name] == nil {
			by[name] = map[string]bool{}
		}
		by[name][target] = true
	}
	for _, t := range ts {
		if t.enabled && t.kind == string(KindDomain) {
			add(t.value, t.id)
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT h.name, h.target_id FROM exp_host h JOIN exp_target t ON t.id = h.target_id
		WHERE t.enabled = 1 AND EXISTS (SELECT 1 FROM exp_address a WHERE a.host_id = h.id)`)
	if err != nil {
		return 0, fmt.Errorf("scanned names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name, target string
		if err := rows.Scan(&name, &target); err != nil {
			return 0, fmt.Errorf("scanned names: %w", err)
		}
		add(name, target)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("scanned names: %w", err)
	}
	var n int64
	for _, ts := range by {
		if len(ts) > 1 {
			n++
		}
	}
	return n, nil
}
