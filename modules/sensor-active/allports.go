package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The weekly scan of every TCP port of each LAN device (D-592, kf-scan item 1, review r1). The normal scan reads nmap's top 1000 and
// nmapargv.ExtraPorts (the surface list and the reviewed admin ports); a service on any other port is found by this run: once a week
// per device, inside the window, after the queue and the SNMP round, one device at a time, only while the window has room for a
// whole run (nmapargv.AllPortsHostTimeout), at min(the settings' rate, the policy's rate, nmapargv.AllPortsMaxRate) and never below
// nmapargv.AllPortsMinRate. The run is port discovery only (-sS -p-); the open ports the normal scan does not cover then get one
// PortVersions run (-sV and the four scripts, at most nmapargv.MaxPortVersions ports, the normal LAN rate). A device that is
// fragile, of unknown kind, set to never, past nothing but its gentle scan, the box or declared by hand never gets it
// (allPortsPlan), checked when it is picked, again under the run lock right before nmap (scanDevice), and while it runs
// (checkRun, on a change of the device or of the settings). A Scan now identification or an exposure scan stops it and goes
// first (lockWithin); it stays due. The run only adds ports and their services: never the software list (no -O, so no OS guess).

// allPortsEvery is how often a device gets its scan of every port; allPortsKeep is how long the ports such a run found outside the
// normal scan's lists are carried by the normal scans when no later weekly run replaces them (review r1 M4).
const (
	allPortsEvery = 7 * 24 * time.Hour
	allPortsKeep  = 14 * 24 * time.Hour
)

// Outcomes of sa_all_ports.
const (
	allPortsDone        = "done"
	allPortsNotEligible = "not_eligible"
)

// allPortsPlan is the rate of a device's weekly scan of every port, or why it gets none: only a device the policy lets discovery
// scan normally (allowed, past its gentle scan, neither fragile nor of unknown kind nor set to never; FORBID-5), at the lower of
// the settings' and the policy's rate, capped at AllPortsMaxRate, and not below AllPortsMinRate (the run would not fit its host
// timeout).
func allPortsPlan(dec Decision, st Settings) (rate int, why string) {
	switch {
	case !dec.Allowed:
		return 0, dec.Reason
	case dec.Never:
		return 0, reasonNever
	case dec.Fragile:
		return 0, "fragile"
	case dec.Unclassified:
		return 0, "unclassified"
	case dec.FirstGentle:
		return 0, "first_gentle_scan"
	}
	rate = min(st.Rate, nmapargv.AllPortsMaxRate)
	if dec.Rate > 0 {
		rate = min(rate, dec.Rate)
	}
	if rate < nmapargv.AllPortsMinRate {
		return 0, "rate_too_low"
	}
	return rate, ""
}

// allPortsRound runs the weekly scans that are due while the window has room for one (Tick, after the queue and SNMP), one device at
// a time: the run lock is let go between devices, and no device starts while a Scan now identification or an exposure scan waits
// for it. A run stopped (window, settings, a person's scan) leaves its device due: a later tick of the window, or the next window,
// tries again. A run that failed otherwise, or whose end could not be recorded, waits for the next window (held in memory), never a
// tight loop.
func (s *Service) allPortsRound(ctx context.Context) error {
	for ctx.Err() == nil && s.urgent.Load() == 0 {
		st, err := s.permit(ctx)
		if err != nil {
			return nil // outside the window, scanning off, nmap missing: nothing now
		}
		start, _, _ := st.window(s.local())
		end, ok := s.windowNow(st)
		if !ok || end.Sub(s.clock()) < nmapargv.AllPortsHostTimeout || st.Rate < nmapargv.AllPortsMinRate {
			return nil // not enough window left for a whole run, or a rate too low (Health says so)
		}
		id, err := s.nextAllPorts(ctx, st, start)
		if err != nil || id == "" {
			return err
		}
		err = s.scanDevice(ctx, id, "all_ports", true)
		switch {
		case err == nil:
			err = s.markAllPorts(ctx, id, allPortsDone)
		case errors.Is(err, ErrBlocked), errors.Is(err, ErrNotFound):
			err = s.markAllPorts(ctx, id, allPortsNotEligible)
		case errors.Is(err, ErrStopped), errors.Is(err, ErrOutsideWindow), errors.Is(err, ErrUnavailable),
			errors.Is(err, ErrScanningOff), errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
			return nil // still due: a later tick or the next window tries again
		}
		if err != nil {
			s.log.WarnContext(ctx, "sensoractive: a weekly scan of every port failed; the device waits for the next window", "asset", id, "error", err)
			s.holdAllPorts(id, start)
		}
	}
	return nil
}

// holdAllPorts keeps a device out of the weekly round until the next window (the window that starts at start is skipped).
func (s *Service) holdAllPorts(id string, start time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.allPortsHeld == nil || !s.allPortsHeldIn.Equal(start) {
		s.allPortsHeld, s.allPortsHeldIn = map[string]bool{}, start
	}
	s.allPortsHeld[id] = true
}

func (s *Service) heldAllPorts(id string, start time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allPortsHeldIn.Equal(start) && s.allPortsHeld[id]
}

// nextAllPorts is the device whose weekly scan is due first (never scanned so first, then the oldest), among the known devices;
// "" when none is due. A device the policy does not allow it is marked not_eligible on the way, so its policy is read again only a
// week later, not at every tick. Rows of devices the inventory no longer has are removed (review r1 L4).
func (s *Service) nextAllPorts(ctx context.Context, st Settings, start time.Time) (string, error) {
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return "", err
	}
	known := map[string]bool{}
	for _, id := range addrs {
		known[id] = true
	}
	last := map[string]string{} // "" when the device never had a weekly run
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT asset_id, coalesce(last_at, '') FROM sa_all_ports`)
	if err != nil {
		return "", fmt.Errorf("sensoractive: read the weekly scans: %w", err)
	}
	var gone []string
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err != nil {
			_ = rows.Close()
			return "", err
		}
		if !known[id] {
			gone = append(gone, id)
			continue
		}
		last[id] = at
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return "", err
	}
	if len(gone) > 0 {
		if err := s.db.Write(ctx, func(tx *sql.Tx) error {
			for _, id := range gone {
				if _, err := tx.ExecContext(ctx, `DELETE FROM sa_all_ports WHERE asset_id = ?`, id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return "", fmt.Errorf("sensoractive: remove the weekly scans of deleted devices: %w", err)
		}
	}
	due := store.FormatTS(s.clock().Add(-allPortsEvery))
	var ids []string
	for id := range known {
		if at := last[id]; at == "" || at <= due {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b string) int { // never first ("" sorts first), then the oldest, then by id
		if c := cmpStr(last[a], last[b]); c != 0 {
			return c
		}
		return cmpStr(a, b)
	})
	for _, id := range ids {
		if ctx.Err() != nil {
			return "", nil
		}
		if s.heldAllPorts(id, start) {
			continue
		}
		dec, err := s.inv.ScanPolicy(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, why := allPortsPlan(dec, st); why != "" {
			if err := s.markAllPorts(ctx, id, allPortsNotEligible); err != nil {
				return "", err
			}
			continue
		}
		return id, nil
	}
	return "", nil
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// markAllPorts records the end of a device's weekly scan (or that it was not eligible): it is due again allPortsEvery later. The
// ports of a done run were written by recordDevice (keepAllPortsExtra) and are kept.
func (s *Service) markAllPorts(ctx context.Context, id, outcome string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, last_at, outcome) VALUES (?, ?, ?)
ON CONFLICT (asset_id) DO UPDATE SET last_at = excluded.last_at, outcome = excluded.outcome`, id, s.now(), outcome)
		return err
	})
	if err != nil {
		return fmt.Errorf("sensoractive: recording a weekly scan: %w", err)
	}
	return nil
}

// probeAllPorts is the nmap work of a weekly run (review r1 H2): the port discovery over every port, then, on the open ports that
// are neither in nmapargv.ExtraPorts nor among the ports the device's last normal scan found open (that scan read nmap's top 1000
// and the extra ports with -sV), at most nmapargv.MaxPortVersions of them, one PortVersions run at the normal LAN rate. A device
// that answers on more than commonports.MaxBelievableOpen ports (a SYN proxy, a tarpit) gets no follow-up and nothing is recorded.
// A stop drops the whole result (the device stays due); a follow-up that fails otherwise (an older worker) leaves the open ports
// without their versions.
func (s *Service) probeAllPorts(ctx context.Context, jobID, assetID string, ip netip.Addr, rate, normalRate int) ([]host, error) {
	hosts, err := s.probe(ctx, jobID, nmapargv.AllPorts, rate, []netip.Addr{ip})
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if i < 0 || hosts[i].timedOut {
		return hosts, nil
	}
	h := &hosts[i]
	if len(h.ports) > commonports.MaxBelievableOpen {
		s.log.WarnContext(ctx, "sensoractive: the device answers on too many ports to believe; its weekly scan records nothing", "ip", ip.String(), "open", len(h.ports))
		return nil, nil
	}
	seen := s.normalPorts(ctx, assetID)
	var want []int
	for _, p := range h.ports {
		_, inExtra := slices.BinarySearch(nmapargv.ExtraPortNumbers, p.number)
		if p.proto == "tcp" && !inExtra && !slices.Contains(seen, p.number) {
			want = append(want, p.number)
		}
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if len(want) == 0 {
		return hosts, nil
	}
	if len(want) > nmapargv.MaxPortVersions {
		want = want[:nmapargv.MaxPortVersions]
	}
	x, err := s.probe(ctx, jobID, nmapargv.PortVersions, normalRate, []netip.Addr{ip}, want...)
	switch {
	case errors.Is(err, ErrStopped):
		return nil, err
	case err != nil:
		s.log.WarnContext(ctx, "sensoractive: the version scan after a weekly scan did not run; its open ports are recorded without versions", "ip", ip.String(), "error", err)
		return hosts, nil
	}
	if j := slices.IndexFunc(x, func(v host) bool { return v.addr == ip }); j >= 0 && !x[j].timedOut {
		for k, p := range h.ports {
			if q := slices.IndexFunc(x[j].ports, func(v portInfo) bool { return v.number == p.number && v.proto == p.proto }); q >= 0 {
				h.ports[k] = x[j].ports[q]
			}
		}
		for _, sc := range x[j].scripts {
			if slices.Contains(want, sc.port) {
				h.scripts = append(h.scripts, sc)
			}
		}
	}
	return hosts, nil
}

// keepNormalPorts stores the open ports a normal or versions scan found, which the weekly run's follow-up does not read again.
func (s *Service) keepNormalPorts(ctx context.Context, id string, list []observe.Service) error {
	ports := []int{}
	for _, sv := range list {
		if sv.Proto == "tcp" {
			ports = append(ports, sv.Port)
		}
	}
	b, err := json.Marshal(ports)
	if err != nil {
		return err
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, normal_ports) VALUES (?, ?)
ON CONFLICT (asset_id) DO UPDATE SET normal_ports = excluded.normal_ports`, id, string(b))
		return err
	})
	if err != nil {
		return fmt.Errorf("sensoractive: keeping the ports of a normal scan: %w", err)
	}
	return nil
}

// normalPorts is what keepNormalPorts stored (none when the device had no normal scan since D-592, or on a read error: then the
// follow-up reads every open port outside the extra list, still at most MaxPortVersions).
func (s *Service) normalPorts(ctx context.Context, id string) []int {
	var raw string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT normal_ports FROM sa_all_ports WHERE asset_id = ?`, id).Scan(&raw); err != nil {
		return nil
	}
	var out []int
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// keepAllPortsExtra stores the open ports of a weekly run outside nmapargv.ExtraPorts with the time of the run, so the normal scans
// until the next weekly run keep the ones they do not find themselves (allPortsExtra, withExtra). The next done weekly run replaces
// them; they are carried at most allPortsKeep after the run that saw them (review r1 M4), never for ever.
func (s *Service) keepAllPortsExtra(ctx context.Context, id string, list []observe.Service) error {
	extra := []observe.Service{}
	for _, sv := range list {
		if _, in := slices.BinarySearch(nmapargv.ExtraPortNumbers, sv.Port); !in || sv.Proto != "tcp" {
			extra = append(extra, sv)
		}
	}
	b, err := json.Marshal(extra)
	if err == nil && len(b) > 262144 {
		err = errors.New("over the column's size")
	}
	if err == nil {
		err = s.db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, extra, extra_at) VALUES (?, ?, ?)
ON CONFLICT (asset_id) DO UPDATE SET extra = excluded.extra, extra_at = excluded.extra_at`, id, string(b), s.now())
			return err
		})
	}
	if err != nil {
		return fmt.Errorf("sensoractive: keeping the ports of a weekly scan: %w", err)
	}
	return nil
}

// allPortsExtra is what keepAllPortsExtra stored for the device, while it is at most allPortsKeep old (none when the device never
// had a weekly run, after that, or on a read error).
func (s *Service) allPortsExtra(ctx context.Context, id string) []observe.Service {
	var raw string
	keep := store.FormatTS(s.clock().Add(-allPortsKeep))
	err := s.db.Reader().QueryRowContext(ctx, `SELECT extra FROM sa_all_ports WHERE asset_id = ? AND extra_at >= ?`, id, keep).Scan(&raw)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.log.WarnContext(ctx, "sensoractive: reading the ports of a weekly scan failed", "asset", id, "error", err)
		}
		return nil
	}
	var out []observe.Service
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// withExtra adds to a normal scan's list the extra ports it does not hold itself, up to maxServices.
func withExtra(list, extra []observe.Service) []observe.Service {
	for _, e := range extra {
		if len(list) >= maxServices {
			break
		}
		if !slices.ContainsFunc(list, func(x observe.Service) bool { return x.Port == e.Port && x.Proto == e.Proto }) {
			list = append(list, e)
		}
	}
	return list
}
