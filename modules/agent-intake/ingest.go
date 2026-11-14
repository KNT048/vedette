package agentintake

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// Log takes the results of one log request from an enrolled node (INV-7, INV-12). errNodeInvalid for a key that is not a node's;
// a 429 apierr over the node's rate; nil otherwise, even when nothing was written (an unmatched node, an empty list): the answer to
// osquery is the same, what it did not write is in the server log.
func (s *Service) Log(ctx context.Context, src netip.Addr, in logIn) error {
	n, err := s.authNode(ctx, "log", src, in.nodeKey, "log", logPerMin)
	if err != nil {
		return err
	}
	// One machine is one address: the nodes bound to one source share a log bucket with the numbers of a single node (D-265 (2b)).
	if ok, wait := s.node.allow(srcKey(src), "src", logPerMin); !ok {
		return rateLimited(wait)
	}
	if !in.result {
		return s.touch(ctx, n, touchEvery)
	}
	ip, mac, update := binding(n, src, in)
	if err := s.markResult(ctx, n, ip, mac, update); err != nil {
		return err
	}
	if !ip.IsValid() {
		s.warnUnmatched(ctx, n.id,
			"node", n.id, "src", src.String(), "declared_interfaces", len(in.snaps["interfaces"]))
		return nil
	}
	// The hint is the TCP address only. The MAC is the node's own claim, and the inventory resolves a device by MAC first: with it in
	// the hint a node could write onto any device whose MAC it names. It goes in as a 0.9 observation only, which the inventory
	// refuses when another device owns that MAC (D-265 (4)).
	hint := observe.AssetHint{IP: ip}
	kernel, err := s.nodeKernel(ctx, n, in)
	if err != nil {
		return err
	}
	win, err := s.nodeWindows(ctx, n, in)
	if err != nil {
		return err
	}
	in.snaps = withWindows(withKernel(in.snaps, kernel), win)
	taken, err := s.deliver(ctx, src.Unmap().WithZone(""), hint, mac, n.id, in)
	if err != nil {
		return err
	}
	return s.firstReport(ctx, n, hint, mac, taken)
}

// nodeKernel is the running kernel release of the node (D-516): the one this request's kernel_info snapshot gives, stored on the node
// when it changed, else the one stored. "" when the node never gave a usable one.
func (s *Service) nodeKernel(ctx context.Context, n nodeRow, in logIn) (string, error) {
	rows := in.snaps["kernel_info"]
	if len(rows) == 0 {
		return n.kernel, nil
	}
	k := strings.ToLower(rows[0]["version"])
	if !kernelReleaseRE.MatchString(k) {
		return n.kernel, nil
	}
	if k == n.kernel {
		return k, nil
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET kernel = ? WHERE id = ?`, k, n.id)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("agentintake: store the kernel: %w", err)
	}
	return k, nil
}

// nodeWindows is the Windows release and update revision of the node (D-524): the one this request's os_revision snapshot gives,
// stored on the node when it changed, else the one stored. Zero when the node never gave a usable one (Linux, an osquery older than
// 5.12, a revision that is not a positive integer). A request whose os_version row is of another build than the stored one and that
// gives no usable revision clears the stored one (D-546, review M2): the machine took a feature update, and its old release must
// not stay its operating-system row until the next revision report; the device then has no Windows row for that while.
func (s *Service) nodeWindows(ctx context.Context, n nodeRow, in logIn) (winOS, error) {
	w, ok := parseWinOS(in.snaps["os_revision"])
	if !ok && n.win.version != "" && !sameWinBuild(in.snaps, n.win) {
		w, ok = winOS{}, true
	}
	if !ok || w == n.win {
		return n.win, nil
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET win_name = ?, win_version = ?, win_target = ? WHERE id = ?`, w.name, w.version, w.target, n.id)
		return err
	})
	if err != nil {
		return winOS{}, fmt.Errorf("agentintake: store the windows release: %w", err)
	}
	return w, nil
}

// withKernel puts the running kernel release on every deb_packages row (column "kernel", as the Wazuh path does), on a copy: the
// mapper reads it to give the Kernel row the running kernel's image. "" leaves the snapshots as they are.
func withKernel(snaps map[string][]row, kernel string) map[string][]row {
	debs := snaps["deb_packages"]
	if kernel == "" || len(debs) == 0 {
		return snaps
	}
	out := make(map[string][]row, len(snaps))
	for k, v := range snaps {
		out[k] = v
	}
	rows := make([]row, len(debs))
	for i, r := range debs {
		c := make(row, len(r)+1)
		for k, v := range r {
			c[k] = v
		}
		c["kernel"] = kernel
		rows[i] = c
	}
	out["deb_packages"] = rows
	return out
}

// answers is the fixed order of the first report's answers (schedule.go firstReport), so the stored list is canonical.
var answers = []string{"os_version", "system_info", "interfaces", "packages", "os_revision"}

// firstReport records which answers of the first report the inventory took from this node (the config stops asking for them every
// minute), and approves the device in the name of the token's maker once per node, as soon as the inventory has it (D-503). mac is the
// node's card on the hint's address: the inventory approves the row only when it was never seen with another MAC (DHCP reuse).
func (s *Service) firstReport(ctx context.Context, n nodeRow, hint observe.AssetHint, mac string, taken []string) error {
	var list []string
	for _, a := range answers {
		if hasAnswer(n.reported, a) || slices.Contains(taken, a) {
			list = append(list, a)
		}
	}
	reported := strings.Join(list, ",")
	approved := false
	if !n.approved && len(taken) > 0 {
		var err error
		if approved, err = s.approve(ctx, n.id, hint, mac, "", false); err != nil {
			return err
		}
	}
	if reported == n.reported && !approved {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET reported = ?, approved_at = CASE WHEN ? THEN coalesce(approved_at, ?) ELSE approved_at END WHERE id = ?`,
			reported, approved, store.FormatTS(s.now()), n.id); err != nil {
			return fmt.Errorf("agentintake: mark first report: %w", err)
		}
		return nil
	})
}

// approve asks the inventory to approve the device of node (hint: its bound address, mac: the card on it) and says whether the node is
// done (approved_at is set): the inventory found the device, or refused the request at its boundary. A transient error is returned.
// note ends the audit detail ("" on the log path); agentSaw is observe.Approver's (true off the log path: no live report backs the address).
func (s *Service) approve(ctx context.Context, node string, hint observe.AssetHint, mac, note string, agentSaw bool) (bool, error) {
	reason, err := s.enrolment(ctx, node)
	if err != nil {
		return false, err
	}
	found, err := s.cfg.Approver.ApproveEnrolled(ctx, hint, mac, reason+note, agentSaw)
	switch {
	case err != nil && transient(err):
		return false, fmt.Errorf("agentintake: approve: %w", err)
	case err != nil: // refused at the inventory's boundary: it would refuse it again; do not try at every report
		s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused the enrolment's approval", "node", node, "error", err.Error())
		return true, nil
	}
	// no device yet (only the interfaces arrived): the next report tries again. A row seen with another MAC (DHCP gave this address to a
	// new machine and no sensor saw the move yet) is found and left for a person: done once, like a suspicious one.
	return found, nil
}

// approveRecent is how recent a node's last result must be for approve-enrolled to approve from its binding: a binding is the node's
// address when it last reported, and an address it left may since belong to another machine (review #673 H1).
const approveRecent = 7 * 24 * time.Hour

// ApproveBound is the job approve-enrolled (D-503, the upgrade path): it runs at start, when the module is turned on, and daily after.
// A node enrolled before Vedette approved and typed devices from the enrolment has a binding (bound_ip, bound_mac) from its reports but
// no approved_at, and its next report that the inventory takes may be an hour away (an old install has no --config_refresh, so it never
// gets the first-report schedule). Each such node goes through the same approve as the log path, with its bound address and MAC: every
// guard of the inventory holds (the box's addresses, a row seen with another MAC, a suspicious device, once per node), and the inventory
// types the device from the OS its agent already reported. No live connection backs a stored address, so two more conditions stand
// in for it: the node delivered a result within approveRecent (last_result_at; last_seen moves with config calls and node-prune's gap),
// and the inventory counts the row as found only when the agent itself reported this MAC on it (agentSaw). Only nodes with approved_at
// NULL are read, so a second run does nothing. An error on one node does not stop the run: the next nodes are tried and the first error
// is returned at the end (the job runs again tomorrow; the log path covers a live node in the meantime).
func (s *Service) ApproveBound(ctx context.Context) error {
	type bound struct{ id, ip, mac string }
	var list []bound
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, bound_ip, bound_mac FROM intake_osquery_nodes
		WHERE approved_at IS NULL AND bound_ip IS NOT NULL AND coalesce(bound_mac, '') <> '' AND last_result_at >= ? ORDER BY id`,
		store.FormatTS(s.now().Add(-approveRecent)))
	if err != nil {
		return fmt.Errorf("agentintake: read bound nodes: %w", err)
	}
	for rows.Next() {
		var b bound
		if err := rows.Scan(&b.id, &b.ip, &b.mac); err != nil {
			_ = rows.Close()
			return fmt.Errorf("agentintake: read bound nodes: %w", err)
		}
		list = append(list, b)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("agentintake: read bound nodes: %w", err)
	}
	approved := 0
	var first error
	for _, b := range list {
		if ctx.Err() != nil { // the module was turned off or the box stops
			return ctx.Err()
		}
		ip, err := netip.ParseAddr(b.ip)
		if err != nil {
			continue // not written by markResult; nothing to approve
		}
		done, err := s.approve(ctx, b.id, observe.AssetHint{IP: ip}, b.mac, ", approved from its earlier reports after an upgrade", true)
		switch {
		case errors.Is(err, errNodeInvalid): // revoked since the list was read
			continue
		case err != nil:
			first = cmp.Or(first, err)
			continue
		case !done:
			continue
		}
		err = s.db.Write(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET approved_at = coalesce(approved_at, ?) WHERE id = ?`, store.FormatTS(s.now()), b.id); err != nil {
				return fmt.Errorf("agentintake: mark approved: %w", err)
			}
			return nil
		})
		if err != nil {
			first = cmp.Or(first, err)
			continue
		}
		approved++
	}
	if approved > 0 {
		s.cfg.Log.InfoContext(ctx, "agent-intake: enrolled machines approved from their earlier reports", "nodes", approved)
	}
	return first
}

// enrolment is the audit detail of the enrolment's approval: the machine, the token and who made the token.
func (s *Service) enrolment(ctx context.Context, node string) (string, error) {
	var host, token string
	var by sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT n.host_identifier, t.name, t.created_by FROM intake_osquery_nodes n JOIN intake_agent_tokens t ON t.id = n.token_id WHERE n.id = ?`, node).Scan(&host, &token, &by)
	switch {
	case errors.Is(err, sql.ErrNoRows): // revoked since the key was read
		return "", errNodeInvalid
	case err != nil:
		return "", fmt.Errorf("agentintake: read enrolment: %w", err)
	}
	maker := "made before Vedette recorded who makes tokens"
	if by.Valid {
		maker = "made by " + by.String
	}
	return fmt.Sprintf("osquery on %q enrolled with the token %q, %s", host, token, maker), nil
}

// sourceWindow is how often one source address may replace a software list (D-265 (2b)): one machine is one bound IPv4, so a
// hundred nodes enrolled by one host cannot multiply the writer's work. Later lists in the window are dropped, not queued.
const sourceWindow = 5 * time.Minute

type replaceState struct {
	last   time.Time
	warned bool
}

// allowReplace says whether the source may replace a software list now; the first drop of a window is logged once.
func (s *Service) allowReplace(ctx context.Context, src netip.Addr, node string) bool {
	now := s.now()
	key := srcKey(src)
	s.warnMu.Lock()
	if len(s.replaced) > limiterKeys {
		clear(s.replaced)
	}
	st := s.replaced[key]
	if st == nil || now.Sub(st.last) >= sourceWindow {
		s.replaced[key] = &replaceState{last: now}
		s.warnMu.Unlock()
		return true
	}
	warn := !st.warned
	st.warned = true
	s.warnMu.Unlock()
	if warn {
		s.cfg.Log.WarnContext(ctx, "agent-intake: a second software list from one source address within 5 minutes was dropped", "src", key, "node", node)
	}
	return false
}

// binding is the anti-spoofing rule of D-169 (5): the inventory is written only for the device whose address is the one this connection
// came from, and the MAC is the one of that very card. The address is the TCP peer, which the client cannot forge and no proxy hides;
// it must be among the IPv4 the node declared in its interfaces result of this request, or in the last one that matched. No match,
// an IPv6 or a NAT'd peer: nothing is written (fail closed). update says the request carried an interfaces result, so the stored
// binding is replaced by the answer (also by "none").
func binding(n nodeRow, src netip.Addr, in logIn) (ip netip.Addr, mac string, update bool) {
	src = src.Unmap().WithZone("")
	rows, declared := in.snaps["interfaces"]
	if declared {
		if src.Is4() {
			for _, i := range parseInterfaces(rows) {
				if i.ip == src {
					return src, i.mac, true
				}
			}
		}
		return netip.Addr{}, "", true
	}
	if src.Is4() && n.boundIP == src && n.boundMAC != "" {
		return src, n.boundMAC, false
	}
	return netip.Addr{}, "", false
}

// markResult stores that the node delivered a result log, and its new binding when the request had an interfaces result.
func (s *Service) markResult(ctx context.Context, n nodeRow, ip netip.Addr, mac string, update bool) error {
	ts := store.FormatTS(s.now())
	gone := false
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET last_seen = ?, last_result_at = ? WHERE id = ?`, ts, ts, n.id)
		if err != nil {
			return fmt.Errorf("agentintake: mark node: %w", err)
		}
		if c, _ := r.RowsAffected(); c == 0 { // revoked or pruned since the key was read: this result is not taken
			gone = true
			return nil
		}
		if update {
			var bip, bmac any
			if ip.IsValid() {
				bip, bmac = ip.String(), mac
			}
			if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET bound_ip = ?, bound_mac = ? WHERE id = ?`, bip, bmac, n.id); err != nil {
				return fmt.Errorf("agentintake: bind node: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE intake_agent_tokens SET last_received = ? WHERE id = ?`, ts, n.tokenID); err != nil {
			return fmt.Errorf("agentintake: mark token: %w", err)
		}
		return nil
	})
	if err == nil && gone {
		return errNodeInvalid
	}
	return err
}

// deliver hands the device facts and the package list to the inventory. An empty package list never replaces the stored one
// (POST-2 of the plan): a node whose package table failed or is empty must not wipe what was known. taken is the answers of the first
// report this request gave (schedule.go firstReport): the interfaces matched (deliver runs only then), os_version or system_info
// with a row, a package list that was not empty and that the 5-minute window let through (the window is per source address, not per
// node: a list it dropped was not taken from this node, so the first hour keeps asking for it).
func (s *Service) deliver(ctx context.Context, src netip.Addr, hint observe.AssetHint, mac, node string, in logIn) (taken []string, err error) {
	if _, ok := in.snaps["interfaces"]; ok {
		taken = append(taken, "interfaces")
	}
	if _, ok := parseWinOS(in.snaps["os_revision"]); ok { // stored on the node before deliver (nodeWindows); only a usable one counts
		taken = append(taken, "os_revision")
	}
	if obs := observations(hint, in.snaps, mac); len(obs) > 0 {
		if err := s.record(ctx, obs); err != nil {
			return nil, err
		}
		for _, q := range []string{"os_version", "system_info"} {
			if len(in.snaps[q]) > 0 {
				taken = append(taken, q)
			}
		}
	}
	items, dropped := mapPackages(in.snaps, maxRows)
	if dropped > 0 || len(in.truncated) > 0 || in.dropped > 0 {
		s.cfg.Log.InfoContext(ctx, "agent-intake: rows dropped", "node", node, "rows_not_fitting", dropped, "events_or_rows_refused", in.dropped, "truncated", len(in.truncated))
	}
	if len(items) == 0 {
		if hasPackageQuery(in) {
			s.cfg.Log.InfoContext(ctx, "agent-intake: an empty package list kept the stored one", "node", node)
		}
		return taken, nil
	}
	if !s.allowReplace(ctx, src, node) {
		return taken, nil
	}
	// A Windows list without the operating system's row (its revision not reported yet) is not the first report's package answer:
	// the first hour keeps asking for it, so the row comes within minutes, not with the next hourly list (D-546, review M3).
	if len(in.snaps["programs"]) == 0 || in.snaps["windows_os"] != nil {
		taken = append(taken, "packages")
	}
	if err := s.cfg.Software.ReplaceSoftware(ctx, hint, observe.Agent, items); err != nil {
		if transient(err) {
			return nil, fmt.Errorf("agentintake: software: %w", err)
		}
		// The inventory refused this list. osquery would resend it for ever; the next snapshot is a whole new list, so drop it here.
		s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused a software list", "node", node, "error", err.Error())
	}
	return taken, nil
}

func hasPackageQuery(in logIn) bool {
	for _, q := range []string{"deb_packages", "rpm_packages", "programs"} {
		if _, ok := in.snaps[q]; ok {
			return true
		}
	}
	return false
}

// transient says the error is the store being busy or the request going away: the caller retries, osquery resends the log.
func transient(err error) bool {
	return errors.Is(err, store.ErrBusy) || errors.Is(err, store.ErrFrozen) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// record sends observations, dropping the one the inventory rejects at its boundary and sending the rest (observe.ErrRejected).
func (s *Service) record(ctx context.Context, obs []observe.Observation) error {
	for range len(obs) + 1 {
		err := s.cfg.Sink.Record(ctx, obs)
		if err == nil {
			return nil
		}
		var rej *observe.ErrRejected
		if !errors.As(err, &rej) || rej.Index < 0 || rej.Index >= len(obs) {
			if transient(err) {
				return fmt.Errorf("agentintake: observations: %w", err)
			}
			s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused observations", "error", err.Error())
			return nil
		}
		obs = slices.Delete(obs, rej.Index, rej.Index+1)
		if len(obs) == 0 {
			return nil
		}
	}
	return nil
}
