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
	"github.com/knt048/vedette/core/store"
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
//     own: an enabled child's own name, and the names under the child that the child's scope takes. A name under a child that scans only
//     itself (or did not choose it) stays its parent's when the parent's scope takes it.
//   - The rows of a name live with the target that scans it. When that changes (a child added, removed, switched off or narrowed), the
//     old target hands them over in the same write (handOver): the name keeps a row in both, its addresses, services and issues move,
//     merged with what the new owner holds; nothing is closed, reopened or made new, so the change raises no alert. A name nobody
//     scans keeps its rows where they are, as the last scan left them.

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

// own is the plan's target as a node.
func (p *NamePlan) own() (scopeNode, bool) {
	if p == nil {
		return scopeNode{}, false
	}
	for _, n := range p.nodes {
		if n.id == p.id {
			return n, true
		}
	}
	return scopeNode{}, false
}

// Find says the scan looks for names under the target (scope all or selected); with scope self it looks up the target's name only.
// A nil plan finds every name.
func (p *NamePlan) Find() bool {
	n, ok := p.own()
	return !ok || n.mode != ScopeSelf
}

// Choose says the target's scope is the names chosen: on a domain with too many names to list, its scan falls back to Chosen.
func (p *NamePlan) Choose() bool {
	n, ok := p.own()
	return ok && n.mode == ScopeSelected
}

// Chosen are the names chosen for the target's scan (scope selected) that it scans, sorted.
func (p *NamePlan) Chosen() []string {
	n, ok := p.own()
	if !ok || n.mode != ScopeSelected {
		return nil
	}
	var out []string
	for name := range n.chosen {
		if name != n.value && p.Scans(name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
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

// settleTree writes, in tx, the parent of every domain target and the link of every name that is its own target
// (exp_host.child_target_id), and hands the rows of each name over to the target that scans it now (handOver), so ownership moves
// without anything being closed or opened. gone is a target removed in the same write ("" for none): it scans nothing, and its names go
// to whoever scans them before its rows are deleted.
func settleTree(ctx context.Context, tx *sql.Tx, gone string) (*handLog, error) {
	log := &handLog{made: map[string]bool{}, merged: map[string]bool{}}
	all, err := listTargets(ctx, tx)
	if err != nil {
		return nil, err
	}
	live := slices.DeleteFunc(slices.Clone(all), func(t Target) bool { return t.ID == gone })
	for _, t := range live {
		if p := parentOf(t, live); p != t.ParentID {
			if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET parent_id = ? WHERE id = ?`, nullString(p), t.ID); err != nil {
				return nil, fmt.Errorf("placing target %s: %w", t.Value, err)
			}
		}
	}
	chosen, err := chosenNames(ctx, tx)
	if err != nil {
		return nil, err
	}
	var nodes []scopeNode
	byValue := map[string]string{}
	for _, t := range live {
		if t.Kind == KindDomain {
			nodes = append(nodes, nodeOf(t, chosen))
			byValue[t.Value] = t.ID
		}
	}
	hosts, err := hostRows(ctx, tx)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		child := byValue[h.name] // the name is its own target: that target scans it
		if child == h.target {
			child = ""
		}
		if child != h.child {
			if _, err := tx.ExecContext(ctx, `UPDATE exp_host SET child_target_id = ? WHERE id = ?`, nullString(child), h.id); err != nil {
				return nil, fmt.Errorf("linking the name %s: %w", h.name, err)
			}
		}
		if owner := ownerOf(h.name, nodes); owner != "" && owner != h.target {
			if err := handOver(ctx, tx, log, h, owner); err != nil {
				return nil, err
			}
		}
	}
	return log, nil
}

// handLog is what one settle did with rows: the rows it made (copies), and the rows it folded into a row the receiver held before.
// A service or issue new in a scan's write stays new when the settle moves it to another target; folded into an older one, it was not new.
type handLog struct{ made, merged map[string]bool }

// hostRow is a name of a target as settleTree reads it.
type hostRow struct{ id, target, name, child string }

func hostRows(ctx context.Context, q querier) ([]hostRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, target_id, name, coalesce(child_target_id, '') FROM exp_host ORDER BY target_id, name`)
	if err != nil {
		return nil, fmt.Errorf("reading names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []hostRow
	for rows.Next() {
		var h hostRow
		if err := rows.Scan(&h.id, &h.target, &h.name, &h.child); err != nil {
			return nil, fmt.Errorf("reading names: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// handOver moves what the target of h holds about its name to the target that scans the name now (to), merged with what to holds
// already: the name (to gets a row of it, first and last seen kept), its addresses, the services on an address no other name of the
// old target points at with their issues, the issues about that name or that address. A service on an address the old target still
// reaches through another of its names is copied, not moved: both scan that address now, and neither reads its ports as new. Nothing
// is closed, reopened or made new: states, first seen and a person's decisions travel with the rows, so a name that comes back
// later is not reported as newly open.
func handOver(ctx context.Context, tx *sql.Tx, log *handLog, h hostRow, to string) error {
	var oh string
	err := tx.QueryRowContext(ctx, `SELECT id FROM exp_host WHERE target_id = ? AND name = ?`, to, h.name).Scan(&oh)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		oh = store.NewID("xh")
		_, err = tx.ExecContext(ctx, `INSERT INTO exp_host (id, target_id, name, source, cname, first_seen, last_seen)
			SELECT ?, ?, name, source, cname, first_seen, last_seen FROM exp_host WHERE id = ?`, oh, to, h.id)
	case err == nil:
		_, err = tx.ExecContext(ctx, `UPDATE exp_host SET first_seen = min(exp_host.first_seen, f.first_seen), last_seen = max(exp_host.last_seen, f.last_seen)
			FROM (SELECT first_seen, last_seen FROM exp_host WHERE id = ?) AS f WHERE exp_host.id = ?`, h.id, oh)
	}
	if err != nil {
		return fmt.Errorf("handing over the name %s: %w", h.name, err)
	}
	ips, err := moveAddresses(ctx, tx, h, to, oh)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		var still int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM exp_address WHERE target_id = ? AND ip = ?)`, h.target, ip).Scan(&still); err != nil {
			return fmt.Errorf("handing over %s: %w", ip, err)
		}
		svcs, err := idsOf(ctx, tx, `SELECT id FROM exp_service WHERE target_id = ? AND ip = ?`, h.target, ip)
		if err != nil {
			return err
		}
		for _, sid := range svcs {
			if err := handOverService(ctx, tx, log, sid, to, h.name, still == 1); err != nil {
				return err
			}
		}
		if err := handOverIssues(ctx, tx, log, h.target, to, func(e IssueEngine, key string) bool { return keyAddr(e, key) == ip }, still == 1); err != nil {
			return err
		}
	}
	return handOverIssues(ctx, tx, log, h.target, to, func(e IssueEngine, key string) bool { return issueName(e, key) == h.name }, false)
}

// moveAddresses moves the addresses of h to the row oh of target to and returns them.
func moveAddresses(ctx context.Context, tx *sql.Tx, h hostRow, to, oh string) ([]string, error) {
	type addr struct{ ip, family, class, first, last string }
	var as []addr
	err := func() error {
		rows, err := tx.QueryContext(ctx, `SELECT ip, family, class, first_seen, last_seen FROM exp_address WHERE host_id = ?`, h.id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a addr
			if err := rows.Scan(&a.ip, &a.family, &a.class, &a.first, &a.last); err != nil {
				return err
			}
			as = append(as, a)
		}
		return rows.Err()
	}()
	if err != nil {
		return nil, fmt.Errorf("the addresses of %s: %w", h.name, err)
	}
	var ips []string
	for _, a := range as {
		res, err := tx.ExecContext(ctx, `UPDATE exp_address SET first_seen = min(first_seen, ?3), family = CASE WHEN ?4 > last_seen THEN ?5 ELSE family END,
			class = CASE WHEN ?4 > last_seen THEN ?6 ELSE class END, last_seen = max(last_seen, ?4) WHERE target_id = ?1 AND host_id = ?2 AND ip = ?7`,
			to, oh, a.first, a.last, a.family, a.class, a.ip)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 0 {
				_, err = tx.ExecContext(ctx, `INSERT INTO exp_address (host_id, target_id, ip, family, class, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					oh, to, a.ip, a.family, a.class, a.first, a.last)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("handing over the address %s: %w", a.ip, err)
		}
		if !slices.Contains(ips, a.ip) {
			ips = append(ips, a.ip)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_address WHERE host_id = ?`, h.id); err != nil {
		return nil, fmt.Errorf("handing over the addresses of %s: %w", h.name, err)
	}
	return ips, nil
}

// handOverService gives the service sid to target to: moved (merged into to's own row of the same port when it has one), or copied when
// keep (the old target still reaches the address). Its issues follow: with a copy, those about the name go and the others are copied.
func handOverService(ctx context.Context, tx *sql.Tx, log *handLog, sid, to, name string, keep bool) error {
	var oid string
	err := tx.QueryRowContext(ctx, `SELECT o.id FROM exp_service o JOIN exp_service s ON s.ip = o.ip AND s.port = o.port AND s.proto = o.proto
		WHERE s.id = ? AND o.target_id = ?`, sid, to).Scan(&oid)
	switch {
	case errors.Is(err, sql.ErrNoRows) && !keep: // the row itself moves, with its issues
		if _, err := tx.ExecContext(ctx, `UPDATE exp_service SET target_id = ? WHERE id = ?`, to, sid); err != nil {
			return fmt.Errorf("handing over service %s: %w", sid, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET target_id = ? WHERE service_id = ?`, to, sid); err != nil {
			return fmt.Errorf("handing over the issues of service %s: %w", sid, err)
		}
		return nil
	case errors.Is(err, sql.ErrNoRows): // a copy
		oid = store.NewID("xs")
		log.made[oid] = true
		_, err = tx.ExecContext(ctx, `INSERT INTO exp_service (id, target_id, ip, port, proto, name, product, version, cpe, title, cert, is_web, ident, state, first_seen, last_seen, last_run_id)
			SELECT ?, ?, ip, port, proto, name, product, version, cpe, title, cert, is_web, ident, state, first_seen, last_seen, last_run_id FROM exp_service WHERE id = ?`, oid, to, sid)
	case err == nil: // merged: the later reading wins, first seen is the earlier
		if !keep && !log.made[oid] {
			log.merged[sid] = true // folded into a row the receiver held already: not new there
		}
		_, err = tx.ExecContext(ctx, `UPDATE exp_service SET first_seen = min(exp_service.first_seen, s.first_seen),
			state = CASE WHEN s.last_seen > exp_service.last_seen THEN s.state ELSE exp_service.state END,
			name = CASE WHEN s.last_seen > exp_service.last_seen THEN s.name ELSE exp_service.name END,
			product = CASE WHEN s.last_seen > exp_service.last_seen THEN s.product ELSE exp_service.product END,
			version = CASE WHEN s.last_seen > exp_service.last_seen THEN s.version ELSE exp_service.version END,
			cpe = CASE WHEN s.last_seen > exp_service.last_seen THEN s.cpe ELSE exp_service.cpe END,
			title = CASE WHEN s.last_seen > exp_service.last_seen THEN s.title ELSE exp_service.title END,
			cert = CASE WHEN s.last_seen > exp_service.last_seen THEN s.cert ELSE exp_service.cert END,
			is_web = CASE WHEN s.last_seen > exp_service.last_seen THEN s.is_web ELSE exp_service.is_web END,
			ident = CASE WHEN s.last_seen > exp_service.last_seen THEN s.ident ELSE exp_service.ident END,
			last_run_id = CASE WHEN s.last_seen > exp_service.last_seen THEN s.last_run_id ELSE exp_service.last_run_id END,
			last_seen = max(exp_service.last_seen, s.last_seen)
			FROM (SELECT * FROM exp_service WHERE id = ?) AS s WHERE exp_service.id = ?`, sid, oid)
	}
	if err != nil {
		return fmt.Errorf("handing over service %s: %w", sid, err)
	}
	issues, err := issuesOf(ctx, tx, `SELECT id, engine, key FROM exp_issue WHERE service_id = ?`, sid)
	if err != nil {
		return err
	}
	for _, i := range issues {
		n := issueName(i.engine, i.key)
		switch {
		case !keep || n == name:
			err = moveIssue(ctx, tx, log, i, to, oid)
		case n == "":
			err = copyIssue(ctx, tx, log, i, to, oid)
		}
		if err != nil {
			return err
		}
	}
	if !keep {
		if _, err := tx.ExecContext(ctx, `DELETE FROM exp_service WHERE id = ?`, sid); err != nil {
			return fmt.Errorf("handing over service %s: %w", sid, err)
		}
	}
	return nil
}

// handOverIssues gives the issues of from that are about no service and that about picks to target to: copied when keep, else moved.
func handOverIssues(ctx context.Context, tx *sql.Tx, log *handLog, from, to string, about func(IssueEngine, string) bool, keep bool) error {
	issues, err := issuesOf(ctx, tx, `SELECT id, engine, key FROM exp_issue WHERE target_id = ? AND service_id IS NULL`, from)
	if err != nil {
		return err
	}
	for _, i := range issues {
		if !about(i.engine, i.key) {
			continue
		}
		if keep {
			err = copyIssue(ctx, tx, log, i, to, "")
		} else {
			err = moveIssue(ctx, tx, log, i, to, "")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type issueRef struct {
	id     string
	engine IssueEngine
	key    string
}

func issuesOf(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]issueRef, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("issues: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []issueRef
	for rows.Next() {
		var i issueRef
		var e string
		if err := rows.Scan(&i.id, &e, &i.key); err != nil {
			return nil, fmt.Errorf("issues: %w", err)
		}
		i.engine = IssueEngine(e)
		out = append(out, i)
	}
	return out, rows.Err()
}

func idsOf(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("reading ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reading ids: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// twinOf is the issue of target to with the engine and key of i on service svc ("": none), or "".
func twinOf(ctx context.Context, tx *sql.Tx, i issueRef, to, svc string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM exp_issue WHERE target_id = ? AND engine = ? AND key = ? AND ifnull(service_id, '') = ?`, to, string(i.engine), i.key, svc).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// moveIssue gives issue i to target to, on service svc ("": none): its row moves, or is merged into to's own issue of the same engine and
// key (first seen the earlier, the later reading wins, a person's decision is kept from either).
func moveIssue(ctx context.Context, tx *sql.Tx, log *handLog, i issueRef, to, svc string) error {
	twin, err := twinOf(ctx, tx, i, to, svc)
	if err != nil {
		return fmt.Errorf("handing over issue %s: %w", i.id, err)
	}
	if !log.made[twin] && twin != "" {
		log.merged[i.id] = true // folded into an issue the receiver held already: not new there
	}
	if twin == "" {
		if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET target_id = ?, service_id = ? WHERE id = ?`, to, nullString(svc), i.id); err != nil {
			return fmt.Errorf("handing over issue %s: %w", i.id, err)
		}
		return nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE exp_issue SET first_seen = min(exp_issue.first_seen, i.first_seen),
		title = CASE WHEN i.last_seen > exp_issue.last_seen THEN i.title ELSE exp_issue.title END,
		severity = CASE WHEN i.last_seen > exp_issue.last_seen THEN i.severity ELSE exp_issue.severity END,
		cves = CASE WHEN i.last_seen > exp_issue.last_seen THEN i.cves ELSE exp_issue.cves END,
		detail = CASE WHEN i.last_seen > exp_issue.last_seen THEN i.detail ELSE exp_issue.detail END,
		state = CASE WHEN exp_issue.state = 'handled' OR i.state = 'handled' THEN 'handled' WHEN i.last_seen > exp_issue.last_seen THEN i.state ELSE exp_issue.state END,
		resolution = CASE WHEN exp_issue.state = 'handled' THEN exp_issue.resolution ELSE i.resolution END,
		resolved_by = CASE WHEN exp_issue.state = 'handled' THEN exp_issue.resolved_by ELSE i.resolved_by END,
		resolved_at = CASE WHEN exp_issue.state = 'handled' THEN exp_issue.resolved_at ELSE i.resolved_at END,
		note = CASE WHEN exp_issue.state = 'handled' THEN exp_issue.note ELSE coalesce(i.note, exp_issue.note) END,
		accepted_until = CASE WHEN exp_issue.state = 'handled' THEN exp_issue.accepted_until ELSE i.accepted_until END,
		last_run_id = CASE WHEN i.last_seen > exp_issue.last_seen THEN i.last_run_id ELSE exp_issue.last_run_id END,
		last_seen = max(exp_issue.last_seen, i.last_seen)
		FROM (SELECT * FROM exp_issue WHERE id = ?) AS i WHERE exp_issue.id = ?`, i.id, twin)
	if err == nil {
		_, err = tx.ExecContext(ctx, `DELETE FROM exp_issue WHERE id = ?`, i.id)
	}
	if err != nil {
		return fmt.Errorf("merging issue %s: %w", i.id, err)
	}
	return nil
}

// copyIssue gives target to a copy of issue i on service svc ("": none), unless it has that issue already.
func copyIssue(ctx context.Context, tx *sql.Tx, log *handLog, i issueRef, to, svc string) error {
	twin, err := twinOf(ctx, tx, i, to, svc)
	if err != nil || twin != "" {
		return err
	}
	id := store.NewID("xi")
	log.made[id] = true
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_issue (id, target_id, service_id, engine, key, title, severity, cves, detail, state, resolution, resolved_by, resolved_at,
		note, accepted_until, first_seen, last_seen, last_run_id) SELECT ?, ?, ?, engine, key, title, severity, cves, detail, state, resolution, resolved_by, resolved_at,
		note, accepted_until, first_seen, last_seen, last_run_id FROM exp_issue WHERE id = ?`, id, to, nullString(svc), i.id)
	if err != nil {
		return fmt.Errorf("copying issue %s: %w", i.id, err)
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

// NodeEdit is a change to a target (PATCH /exposure/tree/{id}); a nil field is left as it is.
type NodeEdit struct {
	Scope   *ScopeMode // domains only
	Enabled *bool
	// Selected are the ids of the target's names to scan, replacing the choice; only with the scope selected (the one asked for in the
	// same edit, or the stored one).
	Selected *[]string
}

// MaxSelected bounds the names one target chooses: with its own name, the most one scan reads (300 names).
const MaxSelected = 299

// The refusals of an edit.
var (
	ErrSelectedScope = apiErr(400, "bad_value", "Names are chosen only when the scope is \"the names I choose\".")
	ErrSelectedMany  = apiErr(400, "bad_value", "Choose at most %d names: one scan reads at most 300 names, this one included. For more, add a subdomain as its own target.", MaxSelected)
)

func errNotAName(id string) *APIError {
	return apiErr(400, "bad_value", "%s is not a name found under this target.", clipText(id, 96))
}

// EditNode changes the scope, the switch or the chosen names of a target, audited, and settles the tree in the same write: the rows of the
// names whose scanner changed go to the target that scans them now. Switching a target off stops its scan that is queued or runs.
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
		if _, err := settleTree(ctx, tx, ""); err != nil {
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

// doubleScanned counts the names that two enabled targets each probed in their newest scan that wrote its rows, both scans started after
// both targets existed and after the last change of a target that contains the name (added, edited, removed: a change of who scans it):
// a name scanned twice in the same round (a parent that probed a child's name). It reads what the scans recorded (run items of kind
// name), not the rows the tree keeps in order.
func doubleScanned(ctx context.Context, q querier) (int64, error) {
	rows, err := q.QueryContext(ctx, `WITH last AS (
			SELECT t.id AS target, t.created_at AS created, r.id AS run, r.started_at AS started FROM exp_target t
			JOIN core_run r ON r.id = (SELECT r2.id FROM exp_scan x JOIN core_run r2 ON r2.id = x.run_id
				WHERE x.target_id = t.id AND r2.status IN ('done', 'partial', 'stopped') AND r2.started_at IS NOT NULL
				AND EXISTS (SELECT 1 FROM core_run_item i WHERE i.run_id = r2.id AND i.subject_kind = 'name')
				ORDER BY r2.started_at DESC, r2.id DESC LIMIT 1)
			WHERE t.enabled = 1)
		SELECT l.target, l.created, l.started, i.label, coalesce(h.name, i.label) FROM last l
		JOIN core_run_item i ON i.run_id = l.run AND i.subject_kind = 'name' LEFT JOIN exp_host h ON h.id = i.subject_id`)
	if err != nil {
		return 0, fmt.Errorf("probed names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type scanOf struct{ created, started string }
	scans := map[string]scanOf{}
	by := map[string][]string{} // name: the targets whose newest scan probed it
	for rows.Next() {
		var target, created, started, label, name string
		if err := rows.Scan(&target, &created, &started, &label, &name); err != nil {
			return 0, fmt.Errorf("probed names: %w", err)
		}
		scans[target] = scanOf{created, started}
		if !slices.Contains(by[name], target) {
			by[name] = append(by[name], target)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("probed names: %w", err)
	}
	changes, err := treeChanges(ctx, q)
	if err != nil {
		return 0, err
	}
	var n int64
	for name, ts := range by {
		changed := ""
		for _, c := range changes {
			if c.at > changed && Covers(c.value, name) {
				changed = c.at
			}
		}
	pairs:
		for i, a := range ts {
			for _, b := range ts[i+1:] {
				sa, sb := scans[a], scans[b]
				if sa.started >= sb.created && sb.started >= sa.created && sa.started > changed && sb.started > changed { // the same round
					n++
					break pairs
				}
			}
		}
	}
	return n, nil
}

// treeChange is a change of a domain target that can change who scans the names under it.
type treeChange struct{ at, value string }

// treeChanges reads the targets added, edited and removed (the audit rows of the module, which outlive a removed target).
func treeChanges(ctx context.Context, q querier) ([]treeChange, error) {
	rows, err := q.QueryContext(ctx, `SELECT ts, target FROM core_audit WHERE action IN ('exposure.target_add', 'exposure.target_edit', 'exposure.target_delete')`)
	if err != nil {
		return nil, fmt.Errorf("changes of the targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []treeChange
	for rows.Next() {
		var c treeChange
		if err := rows.Scan(&c.at, &c.value); err != nil {
			return nil, fmt.Errorf("changes of the targets: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
