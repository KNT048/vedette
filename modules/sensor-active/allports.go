package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The weekly scan of every TCP port of each LAN device (D-592, kf-scan item 1). The normal scan reads nmap's top 1000 and
// nmapargv.ExtraPorts (the surface list and the reviewed admin ports); a service on any other port is found by this run: once a week per device,
// inside the window, after the queue and the SNMP round, one device at a time, only while the window has room for a whole run
// (nmapargv.AllPortsHostTimeout), at min(the settings' rate, the policy's rate, nmapargv.AllPortsMaxRate) and never below
// nmapargv.AllPortsMinRate. A device that is fragile, of unknown kind, set to never, past nothing but its gentle scan, the box or
// declared by hand never gets it (allPortsPlan), and the check is made again under the run lock right before nmap (scanDevice).

// allPortsEvery is how often a device gets its scan of every port.
const allPortsEvery = 7 * 24 * time.Hour

// Outcomes of sa_all_ports.
const (
	allPortsDone        = "done"
	allPortsFailed      = "failed"
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

// allPortsRound runs the weekly scans that are due while the window has room for one (Tick, after the queue and SNMP). A run cut by
// the window or a change of settings leaves its device due, so it is tried in the next window.
func (s *Service) allPortsRound(ctx context.Context) error {
	for ctx.Err() == nil {
		st, err := s.permit(ctx)
		if err != nil {
			return nil // outside the window, scanning off, nmap missing: nothing now
		}
		end, ok := s.windowNow(st)
		if !ok || end.Sub(s.clock()) < nmapargv.AllPortsHostTimeout || st.Rate < nmapargv.AllPortsMinRate {
			return nil // not enough window left for a whole run, or a rate too low (Health says so)
		}
		id, err := s.nextAllPorts(ctx, st)
		if err != nil || id == "" {
			return err
		}
		err = s.scanDevice(ctx, id, "all_ports", true)
		switch {
		case err == nil:
			s.markAllPorts(ctx, id, allPortsDone)
		case errors.Is(err, ErrBlocked), errors.Is(err, ErrNotFound):
			s.markAllPorts(ctx, id, allPortsNotEligible)
		case errors.Is(err, ErrStopped), errors.Is(err, ErrOutsideWindow), errors.Is(err, ErrUnavailable),
			errors.Is(err, ErrScanningOff), errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
			return nil // still due: the next window tries again
		default:
			s.log.WarnContext(ctx, "sensoractive: a weekly scan of every port failed", "asset", id, "error", err)
			s.markAllPorts(ctx, id, allPortsFailed) // tried again a week later, not every minute
		}
	}
	return nil
}

// nextAllPorts is the device whose weekly scan is due first (never scanned so first, then the oldest), among the known devices;
// "" when none is due. A device the policy does not allow it is marked not_eligible on the way, so its policy is read again only a
// week later, not at every tick.
func (s *Service) nextAllPorts(ctx context.Context, st Settings) (string, error) {
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return "", err
	}
	last := map[string]string{}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT asset_id, last_at FROM sa_all_ports`)
	if err != nil {
		return "", fmt.Errorf("sensoractive: read the weekly scans: %w", err)
	}
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err != nil {
			_ = rows.Close()
			return "", err
		}
		last[id] = at
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return "", err
	}
	due := store.FormatTS(s.clock().Add(-allPortsEvery))
	var ids []string
	seen := map[string]bool{}
	for _, id := range addrs { // a device with several addresses is listed once
		if at, ok := last[id]; (!ok || at <= due) && !seen[id] {
			seen[id] = true
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
		dec, err := s.inv.ScanPolicy(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, why := allPortsPlan(dec, st); why != "" {
			s.markAllPorts(ctx, id, allPortsNotEligible)
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
// extra ports of a done run were written by recordDevice (keepAllPortsExtra) and are kept.
func (s *Service) markAllPorts(ctx context.Context, id, outcome string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, last_at, outcome) VALUES (?, ?, ?)
ON CONFLICT (asset_id) DO UPDATE SET last_at = excluded.last_at, outcome = excluded.outcome`, id, s.now(), outcome)
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: recording a weekly scan failed", "asset", id, "error", err)
	}
}

// keepAllPortsExtra stores the open ports of a weekly scan that the normal scan's own Extra list does not hold, so the normal scans
// until the next weekly one keep the ones they did not find themselves (allPortsExtra, withExtra). nmap's top 1000 is not known
// here (D-592: nmap-services is not copied), so a port of the top 1000 that closed after the weekly run stays listed until the next
// one. ponytail: at most a week stale; the upgrade is reading nmap's <scaninfo services> of the normal run.
func (s *Service) keepAllPortsExtra(ctx context.Context, id string, list []observe.Service) {
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
			_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, last_at, outcome, extra) VALUES (?, ?, ?, ?)
ON CONFLICT (asset_id) DO UPDATE SET extra = excluded.extra`, id, s.now(), allPortsDone, string(b))
			return err
		})
	}
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: keeping the ports of a weekly scan failed", "asset", id, "error", err)
	}
}

// allPortsExtra is what keepAllPortsExtra stored for the device (none when it never had a weekly scan, or on a read error).
func (s *Service) allPortsExtra(ctx context.Context, id string) []observe.Service {
	var raw string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT extra FROM sa_all_ports WHERE asset_id = ?`, id).Scan(&raw)
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
