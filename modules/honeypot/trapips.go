package honeypot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/store"
)

// Trap IPs (D-466): one list of profiles replaces the secondary IP and the decoy personalities. Each has a name (its host
// name), an address, a preset, a vendor for its MAC prefix and its own services; the host lets the address answer only those.

// checkIP applies INV-5 and FORBID-1 to an address the owner typed: IPv4 without leading zeros, inside the network of the
// box, not its network or broadcast address, not the box, not a device of the inventory.
func checkIP(w *world, raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, bad("bad_ip", "Enter an address for the Trap IP, for example 192.168.10.240. Pick an address no device uses.")
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || ip.IsUnspecified() {
		return netip.Addr{}, bad("bad_ip", "The address is not valid. Use the form 192.168.10.240, each number 0 to 255, no leading zeros.")
	}
	if !w.lan.IsValid() {
		return netip.Addr{}, bad("no_lan", "Add your LAN range first (Devices, Scope and sensors), so Vedette knows which network the Trap IPs go on.")
	}
	if !usable(w.lan, ip) {
		return netip.Addr{}, bad("ip_outside_lan", fmt.Sprintf("The Trap IP must be inside the box's network (%s), not the network or broadcast address.", w.lan))
	}
	if ip == w.box.IP {
		return netip.Addr{}, bad("ip_is_box", "This is the Vedette box's own IP. Pick an unused IP.")
	}
	if d := w.deviceAt(ip); d != nil {
		return netip.Addr{}, conflictErr("ip_in_use", fmt.Sprintf("IP %s belongs to device %s in the inventory. Pick an unused IP.", ip, d.Name))
	}
	return ip, nil
}

// cleanInput checks a Trap IP in the order the form shows its fields (preset, vendor, name, address, services; the mock
// checks the same order). self is the id being changed, "" for a new one. The checks against other Trap IPs that the
// stored state decides run again in the writing transaction (writeChecks).
func cleanInput(w *world, in TrapIPInput, self string) (trapIPRow, error) {
	if !validPreset(in.Preset) {
		return trapIPRow{}, bad("bad_preset", "Choose what the Trap IP looks like.")
	}
	var vendor *string
	if in.Vendor != nil && *in.Vendor != "" {
		if _, ok := vendorOUI(*in.Vendor); !ok {
			return trapIPRow{}, bad("bad_vendor", "Choose a vendor from the list, or none.")
		}
		vendor = ptr(*in.Vendor)
	}
	example := presetExample(in.Preset)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return trapIPRow{}, bad("bad_name", "Enter a name for the Trap IP, for example "+example+".")
	}
	if !validHostname(name) {
		return trapIPRow{}, bad("bad_name", "The name may only contain letters, digits and hyphens, up to 15 characters, not all digits, and must not start or end with a hyphen. Example "+example+".")
	}
	if nameTaken(w, name, self) {
		return trapIPRow{}, conflictErr("name_in_use", fmt.Sprintf("The name %s is already used by a device or another Trap IP. Pick another name.", name))
	}
	ip, err := checkIP(w, in.IP)
	if err != nil {
		return trapIPRow{}, err
	}
	if len(in.Services) == 0 {
		return trapIPRow{}, bad("bad_services", "Pick at least one service for the Trap IP to answer on.")
	}
	seen := map[ServiceName]bool{}
	for _, s := range in.Services {
		if !s.Valid() || seen[s] {
			return trapIPRow{}, bad("bad_services", "Pick services from the list, each once.")
		}
		seen[s] = true
	}
	return trapIPRow{TrapIP: TrapIP{Name: name, IP: ip.String(), Preset: in.Preset, Vendor: vendor, Services: inOrder(in.Services)}, ip: ip}, nil
}

func nameTaken(w *world, name, self string) bool {
	for _, d := range w.devices {
		if d.Hostname != "" && strings.EqualFold(d.Hostname, name) {
			return true
		}
	}
	return slices.ContainsFunc(w.trapIPs, func(d trapIPRow) bool { return d.ID != self && strings.EqualFold(d.Name, name) })
}

// writeChecks are the checks that depend on the stored Trap IPs, run in the transaction that writes, so two requests
// cannot both pass: the address and the name are not another Trap IP's, and a new one stays within the host's 32.
func writeChecks(ctx context.Context, tx *sql.Tx, d trapIPRow, self string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hp_trap_ips WHERE ip = ? AND id != ?`, d.IP, self).Scan(&n); err != nil {
		return fmt.Errorf("honeypot: check trap IPs: %w", err)
	}
	if n > 0 {
		return conflictErr("ip_in_use", fmt.Sprintf("IP %s is already another Trap IP.", d.IP))
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hp_trap_ips WHERE lower(name) = lower(?) AND id != ?`, d.Name, self).Scan(&n); err != nil {
		return fmt.Errorf("honeypot: check trap IPs: %w", err)
	}
	if n > 0 {
		return conflictErr("name_in_use", fmt.Sprintf("The name %s is already used by a device or another Trap IP. Pick another name.", d.Name))
	}
	if self != "" {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hp_trap_ips`).Scan(&n); err != nil {
		return fmt.Errorf("honeypot: count trap IPs: %w", err)
	}
	if n >= maxHostIPs {
		return conflictErr("limit_reached", fmt.Sprintf("The box can hold %d Trap IPs. Delete one before adding another.", maxHostIPs))
	}
	return nil
}

func servicesJSON(l []ServiceName) (string, error) {
	if l == nil {
		l = []ServiceName{}
	}
	return jsonMarshal(l)
}

func auditDetail(d trapIPRow) string {
	names := make([]string, len(d.Services))
	for i, s := range d.Services {
		names[i] = string(s)
	}
	return fmt.Sprintf("%s %s: %s", d.Preset, d.Name, strings.Join(names, ", "))
}

// TrapIPs is GET /honeypot/trap-ips.
func (s *Service) TrapIPs(ctx context.Context) (TrapIPsResponse, error) {
	w, err := s.load(ctx)
	if err != nil {
		return TrapIPsResponse{}, err
	}
	out := TrapIPsResponse{Items: make([]TrapIP, 0, len(w.trapIPs)), Suggestions: suggestions(w.devices), SpareIPs: spareIPs(w), SpareChecked: w.discovered()}
	hv := s.hostView()
	for _, d := range w.trapIPs {
		out.Items = append(out.Items, w.withState(d, hv))
	}
	return out, nil
}

// AddTrapIP is POST /honeypot/trap-ips (INV-5, INV-13, D-466). A new Trap IP is on.
func (s *Service) AddTrapIP(ctx context.Context, actor string, in TrapIPInput) (TrapIP, error) {
	w, err := s.load(ctx)
	if err != nil {
		return TrapIP{}, err
	}
	d, err := cleanInput(w, in, "")
	if err != nil {
		return TrapIP{}, err
	}
	d.ID, d.Enabled, d.CreatedAt = store.NewID("tip"), true, store.FormatTS(s.now())
	svc, err := servicesJSON(d.Services)
	if err != nil {
		return TrapIP{}, err
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if err := writeChecks(ctx, tx, d, ""); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hp_trap_ips (`+trapIPCols+`) VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
			d.ID, d.Name, d.IP, string(d.Preset), d.Vendor, svc, d.CreatedAt); err != nil {
			if store.IsUniqueViolation(err) {
				return conflictErr("ip_in_use", fmt.Sprintf("IP %s is already another Trap IP.", d.IP))
			}
			return fmt.Errorf("honeypot: add trap IP: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "honeypot.trap_ip_add", d.IP, auditDetail(d))
	})
	if err != nil {
		return TrapIP{}, err
	}
	s.Kick()
	return s.trapIP(ctx, d.ID)
}

// EditTrapIP is PUT /honeypot/trap-ips/{id}: the same checks as AddTrapIP; the switch is left as it is.
func (s *Service) EditTrapIP(ctx context.Context, actor, id string, in TrapIPInput) (TrapIP, error) {
	w, err := s.load(ctx)
	if err != nil {
		return TrapIP{}, err
	}
	if !slices.ContainsFunc(w.trapIPs, func(d trapIPRow) bool { return d.ID == id }) {
		return TrapIP{}, notFound("No such Trap IP.")
	}
	d, err := cleanInput(w, in, id)
	if err != nil {
		return TrapIP{}, err
	}
	svc, err := servicesJSON(d.Services)
	if err != nil {
		return TrapIP{}, err
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if err := writeChecks(ctx, tx, d, id); err != nil {
			return err
		}
		r, err := tx.ExecContext(ctx, `UPDATE hp_trap_ips SET name = ?, ip = ?, preset = ?, vendor = ?, services = ? WHERE id = ?`,
			d.Name, d.IP, string(d.Preset), d.Vendor, svc, id)
		if err != nil {
			if store.IsUniqueViolation(err) {
				return conflictErr("ip_in_use", fmt.Sprintf("IP %s is already another Trap IP.", d.IP))
			}
			return fmt.Errorf("honeypot: change trap IP: %w", err)
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return notFound("No such Trap IP.")
		}
		return s.auditTx(ctx, tx, actor, "honeypot.trap_ip_edit", d.IP, auditDetail(d))
	})
	if err != nil {
		return TrapIP{}, err
	}
	s.Kick()
	return s.trapIP(ctx, id)
}

// SetTrapIPEnabled is PATCH /honeypot/trap-ips/{id}. Turning one on whose address a device, the box or another network
// has taken since is refused (INV-6): it could not listen.
func (s *Service) SetTrapIPEnabled(ctx context.Context, actor, id string, enabled bool) (TrapIP, error) {
	if enabled {
		w, err := s.load(ctx)
		if err != nil {
			return TrapIP{}, err
		}
		i := slices.IndexFunc(w.trapIPs, func(d trapIPRow) bool { return d.ID == id })
		if i < 0 {
			return TrapIP{}, notFound("No such Trap IP.")
		}
		if _, err := checkIP(w, w.trapIPs[i].IP); err != nil {
			return TrapIP{}, err
		}
	}
	action := "honeypot.trap_ip_disable"
	if enabled {
		action = "honeypot.trap_ip_enable"
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var ip, name string
		err := tx.QueryRowContext(ctx, `UPDATE hp_trap_ips SET enabled = ? WHERE id = ? RETURNING ip, name`, enabled, id).Scan(&ip, &name)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound("No such Trap IP.")
		}
		if err != nil {
			return fmt.Errorf("honeypot: switch trap IP: %w", err)
		}
		return s.auditTx(ctx, tx, actor, action, ip, name)
	})
	if err != nil {
		return TrapIP{}, err
	}
	s.Kick()
	return s.trapIP(ctx, id)
}

// DeleteTrapIP is DELETE /honeypot/trap-ips/{id}: the address stops answering (POST-5), old hits stay.
func (s *Service) DeleteTrapIP(ctx context.Context, actor, id string) error {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var ip, name string
		err := tx.QueryRowContext(ctx, `DELETE FROM hp_trap_ips WHERE id = ? RETURNING ip, name`, id).Scan(&ip, &name)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound("No such Trap IP.")
		}
		if err != nil {
			return fmt.Errorf("honeypot: delete trap IP: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "honeypot.trap_ip_delete", ip, name)
	})
	if err == nil {
		s.Kick()
	}
	return err
}

// trapIP reads one Trap IP with its state.
func (s *Service) trapIP(ctx context.Context, id string) (TrapIP, error) {
	w, err := s.load(ctx)
	if err != nil {
		return TrapIP{}, err
	}
	hv := s.hostView()
	for _, d := range w.trapIPs {
		if d.ID == id {
			return w.withState(d, hv), nil
		}
	}
	return TrapIP{}, notFound("No such Trap IP.")
}

// withState puts what the host says on a Trap IP: listening only when the container runs and the host holds the address,
// not because the switch is on (INV-7). Reasons are plain sentences for the screen.
func (w *world) withState(d trapIPRow, hv hostView) TrapIP {
	out := d.TrapIP
	out.Services = slices.Clone(d.Services)
	set := func(state, reason string) TrapIP {
		out.State = state
		if reason != "" {
			out.Reason = ptr(reason)
		}
		return out
	}
	if m := hv.macs[d.ip]; m != "" && hv.placed[d.ip] {
		out.MAC = ptr(m)
	}
	switch why, hostFault := hv.conflicts[d.ip], hv.hostFailed[d.ip]; {
	case !d.Enabled:
		if hv.pending && hv.placed[d.ip] {
			return set(StateStopping, "")
		}
		return set(StateOff, "")
	case w.ipProblem(d.ip) != "":
		return set(StateConflict, w.ipProblem(d.ip))
	case why != "" && hostFault:
		return set(StateFailed, why)
	case why != "":
		return set(StateConflict, why)
	case hv.available && hv.running && hv.placed[d.ip]:
		if hv.openPorts {
			return set(StateListening, openPortsNote)
		}
		return set(StateListening, "")
	case hv.pending:
		return set(StateStarting, "")
	case hv.available && hv.running: // the container runs, but the host did not confirm this address (no answer, busy)
		return set(StateFailed, notConfirmed)
	default:
		return set(StateFailed, reasonOrDefault(hv.reason))
	}
}
