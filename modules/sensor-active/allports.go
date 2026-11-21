package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The weekly scan of every TCP port of each LAN device (kf-scan item 1). The normal scan reads nmap's top 1000 and
// nmapargv.ExtraPorts (the surface list and the reviewed admin ports); a service on any other port is found by this run: once a week
// per device, inside the window, after the queue and the SNMP round, one device at a time, only while the window has room for a
// whole run (nmapargv.AllPortsHostTimeout), at min(the settings' rate, the policy's rate, nmapargv.AllPortsMaxRate) and never below
// nmapargv.AllPortsMinRate. The run is port discovery only (-sS -p-); the open ports the normal scan does not cover then get one
// PortVersions run (-sV and the four scripts, at most nmapargv.MaxPortVersions ports, the normal LAN rate). A device that is
// fragile, of unknown kind, set to never, past nothing but its gentle scan, the box or declared by hand never gets it
// (allPortsPlan), checked when it is picked, again under the run lock right before nmap (scanDevice), and while it runs
// (checkRun, on a change of the device or of the settings). A Scan now identification or an exposure scan stops it and goes
// first (lockWithin); it stays due. The run writes straight into the inventory, scoped to what it looked at: the ports found open or closed (every port, no versions), and the products the follow-up read (per port, observe.PortInstance); never the rest of the software list (no -O, so no OS guess).

// allPortsEvery is how often a device gets its scan of every port; allPortsKeep is how long the ports such a run found outside the
// normal scan's lists stay when no later weekly run sees them again (a normal scan removes them after that, review r1 M4).
const (
	allPortsEvery = 7 * 24 * time.Hour
	allPortsKeep  = 14 * 24 * time.Hour
)

// Outcomes of sa_all_ports. done, not_eligible, answers_everywhere and failed make the device due a week later; retry (a first
// failure) keeps it due, held out of the rest of the window (review r2 M1: one retry in the next window, then a week, never daily).
const (
	allPortsDone        = "done"
	allPortsNotEligible = "not_eligible"
	allPortsEverywhere  = "answers_everywhere"
	allPortsRetry       = "retry"
	allPortsFailed      = "failed"
)

// errAnswersEverywhere: the device answered the weekly discovery on more than commonports.MaxBelievableOpen ports, or on so many
// that nmap's output went over the parser's limits (a firewall or SYN proxy, a tarpit): the weekly scan learns nothing from it.
var errAnswersEverywhere = errors.New("sensoractive: the device answers on every port (a firewall or SYN proxy); the weekly scan learns nothing")

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
// tries again. A device that answers on every port counts as done for the week. A run that failed otherwise, or whose end could not
// be recorded, is tried once more in the next window (held for the rest of this one), then waits for the next week (review r2 M1).
func (s *Service) allPortsRound(ctx context.Context) error {
	for ctx.Err() == nil {
		if other, _, err := s.laneBusy(ctx, ""); err != nil || other != "" {
			return err // a person's check or a scan for exposure waits for the lane: it goes first, the round goes on at the next tick
		}
		st, err := s.permit(ctx)
		if err != nil {
			return nil // outside the window, scanning off, nmap missing: nothing now
		}
		start, _, _ := st.window(s.local())
		end, ok := s.windowNow(ctx, st)
		if !ok || end.Sub(s.clock()) < nmapargv.AllPortsWindowRoom || st.Rate < nmapargv.AllPortsMinRate {
			return nil // not enough window left for a whole run and its follow-up (review r2 L2), or a rate too low (Health says so)
		}
		id, err := s.nextAllPorts(ctx, st, start)
		if err != nil || id == "" {
			return err
		}
		lbl := s.deviceLabel(ctx, id)
		err = s.doWork(ctx, run.Spec{Kind: RunAllPorts, Title: "Scan of every port of " + lbl, Trigger: run.Schedule,
			Subject: &run.Subject{Kind: "device", ID: id, Label: lbl}, Steps: []run.StepPlan{{Name: lbl, Total: 1}}},
			func(ctx context.Context) error { return s.scanDevice(ctx, id, "all_ports", true) }, s.allPortsResult, 0, "")
		switch {
		case err == nil:
			err = s.markAllPorts(ctx, id, allPortsDone)
		case errors.Is(err, errAnswersEverywhere):
			s.log.WarnContext(ctx, "sensoractive: the device answers on every port (a firewall or SYN proxy); the weekly scan learns nothing", "asset", id)
			err = s.markAllPorts(ctx, id, allPortsEverywhere)
		case errors.Is(err, ErrBlocked), errors.Is(err, ErrNotFound):
			err = s.markAllPorts(ctx, id, allPortsNotEligible)
		case errors.Is(err, ErrStopped), errors.Is(err, ErrOutsideWindow), errors.Is(err, ErrUnavailable),
			errors.Is(err, ErrScanningOff), errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
			return nil // still due: a later tick or the next window tries again
		}
		if err != nil {
			s.failAllPorts(ctx, id, start, err)
		}
	}
	return nil
}

// allPortsResult is how an all_ports run ends, from scanDevice's error.
func (s *Service) allPortsResult(ctx context.Context, err error) run.Result {
	switch {
	case errors.Is(err, errAnswersEverywhere):
		return run.Result{Status: run.Partial, Error: "The device answers on every port (a firewall or a SYN proxy): this scan learns nothing"}
	case errors.Is(err, ErrStopped) && ctx.Err() == nil:
		return run.Result{Status: run.Partial, Error: "It gave way to other work; it stays due"}
	}
	r := s.scanResult(ctx, err)
	if r.Status == run.Waiting { // the round asks for it again when it is due: this run does not wait
		return run.Result{Status: run.Partial, Error: "Not done: it waits for " + r.WaitingFor + "; it stays due"}
	}
	return r
}

// failAllPorts handles a weekly run that failed (not a stop, not a refusal): the first failure is held out of this window and tried
// again in the next (outcome retry, still due); a second one in a row waits for the next week (failed). A write that fails leaves the
// hold only (the next window tries again).
func (s *Service) failAllPorts(ctx context.Context, id string, start time.Time, cause error) {
	s.holdAllPorts(id, start)
	var outcome string
	_ = s.db.Reader().QueryRowContext(ctx, `SELECT coalesce(outcome, '') FROM sa_all_ports WHERE asset_id = ?`, id).Scan(&outcome)
	if outcome == allPortsRetry {
		s.log.WarnContext(ctx, "sensoractive: a weekly scan of every port failed again; the device waits for the next week", "asset", id, "error", cause)
		if err := s.markAllPorts(ctx, id, allPortsFailed); err != nil {
			s.log.WarnContext(ctx, "sensoractive: recording a weekly scan failed", "asset", id, "error", err)
		}
		return
	}
	s.log.WarnContext(ctx, "sensoractive: a weekly scan of every port failed; the device is tried once more in the next window", "asset", id, "error", cause)
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, outcome) VALUES (?, ?) ON CONFLICT (asset_id) DO UPDATE SET outcome = excluded.outcome`, id, allPortsRetry)
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: recording a weekly scan failed", "asset", id, "error", err)
	}
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
			gone = append(gone, id) // no address now: removed below only if the inventory no longer has the device (review r2 L4)
			continue
		}
		last[id] = at
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return "", err
	}
	gone = slices.DeleteFunc(gone, func(id string) bool {
		_, err := s.inv.Asset(ctx, id)
		return !errors.Is(err, ErrNotFound) // the device is still there (it only has no address now), or the read failed: kept
	})
	if len(gone) > 0 {
		if err := s.db.Write(ctx, func(tx *sql.Tx) error {
			for _, id := range gone {
				for _, q := range []string{`DELETE FROM sa_all_ports WHERE asset_id = ?`, `DELETE FROM sa_port_read WHERE asset_id = ?`} {
					if _, err := tx.ExecContext(ctx, q, id); err != nil {
						return err
					}
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
// ports of a done run were written to the inventory by recordDevice.
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

// probeAllPorts is the nmap work of a weekly run (review r1 H2, r2): the port discovery over every port, then one PortVersions run
// at the normal LAN rate on at most nmapargv.MaxPortVersions of the open ports the normal scan does not cover (neither in
// nmapargv.ExtraPorts nor among the ports the device's last normal scan found open): the ports never read with -sV first, then the
// ones read longest ago (review r2 L3), so every port gets its version over the weeks. A device that answers on more than
// commonports.MaxBelievableOpen ports, or on so many that nmap's output goes over the parser's limits (a SYN proxy, a tarpit), is
// errAnswersEverywhere. A cancel (a person's scan, a change of the device or the settings) is ErrStopped whatever the error: the
// partial result is dropped and the device stays due (review r2 L1). A follow-up that fails otherwise (an older worker) leaves the
// open ports without their versions. The host's read lists the ports the follow-up read.
func (s *Service) probeAllPorts(ctx context.Context, jobID, assetID string, ip netip.Addr, rate, normalRate int) ([]host, error) {
	hosts, err := s.probe(ctx, jobID, nmapargv.AllPorts, rate, []netip.Addr{ip})
	switch {
	case ctx.Err() != nil:
		return nil, ErrStopped
	case errors.Is(err, errTooManyPorts), errors.Is(err, errXMLTooBig):
		return nil, errAnswersEverywhere
	case err != nil:
		return nil, err
	}
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if i < 0 || hosts[i].timedOut {
		return hosts, nil
	}
	h := &hosts[i]
	if len(h.ports) > commonports.MaxBelievableOpen {
		return nil, errAnswersEverywhere
	}
	read := s.readTimes(ctx, assetID)
	recent := store.FormatTS(s.clock().Add(-readFresh))
	var want []int
	for _, p := range h.ports {
		_, inExtra := slices.BinarySearch(nmapargv.ExtraPortNumbers, p.number)
		if p.proto == "tcp" && !inExtra && read[p.number] <= recent { // a port read this week (by a normal scan too) is left alone
			want = append(want, p.number)
		}
	}
	slices.SortFunc(want, func(a, b int) int { // never read first ("" sorts first), then read longest ago, then by port
		if c := cmpStr(read[a], read[b]); c != 0 {
			return c
		}
		return a - b
	})
	want = slices.Compact(want)
	if len(want) == 0 {
		return hosts, nil
	}
	if len(want) > nmapargv.MaxPortVersions {
		want = want[:nmapargv.MaxPortVersions]
	}
	slices.Sort(want) // the -p list is ascending
	x, err := s.probe(ctx, jobID, nmapargv.PortVersions, normalRate, []netip.Addr{ip}, want...)
	switch {
	case ctx.Err() != nil, errors.Is(err, ErrStopped):
		return nil, ErrStopped
	case err != nil:
		s.log.WarnContext(ctx, "sensoractive: the version scan after a weekly scan did not run; its open ports are recorded without versions", "ip", ip.String(), "error", err)
		return hosts, nil
	}
	if j := slices.IndexFunc(x, func(v host) bool { return v.addr == ip }); j >= 0 && !x[j].timedOut {
		h.read = want
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

// readFresh is how recent a port's -sV read must be for the weekly follow-up to leave the port alone: a normal scan reads every
// port it finds open, so the ports it found this week are not read again; a port the follow-up read last week is read again.
const readFresh = allPortsEvery - 24*time.Hour

// readTimes are the times each port of a device was last read with -sV (sa_port_read), by port.
func (s *Service) readTimes(ctx context.Context, id string) map[int]string {
	out := map[int]string{}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT port, read_at FROM sa_port_read WHERE asset_id = ?`, id)
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: reading the ports read with versions failed", "asset", id, "error", err)
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p int
		var at string
		if err := rows.Scan(&p, &at); err == nil {
			out[p] = at
		}
	}
	return out
}

// noteRead records that the read ports were read with -sV now, and forgets the ports inside what the scan looked at (scanned) that
// are no longer open: a port that closes is read from scratch when it opens again. A failed write is logged only: the follow-up
// then picks its ports without that record, which costs a read of a port twice, never a missed one.
func (s *Service) noteRead(ctx context.Context, id string, read []int, scanned []observe.PortRange, open []int) {
	now := s.now()
	gone := []int{}
	for p := range s.readTimes(ctx, id) {
		if !slices.Contains(open, p) && slices.ContainsFunc(scanned, func(r observe.PortRange) bool { return p >= r.From && p <= r.To }) {
			gone = append(gone, p)
		}
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		for _, p := range read {
			if _, err := tx.ExecContext(ctx, `INSERT INTO sa_port_read (asset_id, port, read_at) VALUES (?, ?, ?)
ON CONFLICT (asset_id, port) DO UPDATE SET read_at = excluded.read_at`, id, p, now); err != nil {
				return err
			}
		}
		for _, p := range gone {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sa_port_read WHERE asset_id = ? AND port = ?`, id, p); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: recording the ports read with versions failed", "asset", id, "error", err)
	}
}

// recordFollowUp writes the software the weekly follow-up read: each read port's products replace what was read on that port
// before (instance observe.PortInstance), and the software of every other port stays. A port the follow-up read that no longer
// answers has no product, so its old reading goes.
func (s *Service) recordFollowUp(ctx context.Context, hint observe.AssetHint, h host) error {
	var sw []observe.Software
	scope := make([]string, 0, len(h.read))
	for _, p := range h.read {
		scope = append(scope, observe.PortInstance(p))
		k := slices.IndexFunc(h.ports, func(q portInfo) bool { return q.number == p && q.proto == "tcp" })
		if k < 0 {
			continue
		}
		for _, x := range softwareOf(host{addr: h.addr, ports: []portInfo{h.ports[k]}}) {
			if !x.Guess {
				x.Instance = observe.PortInstance(p)
				sw = append(sw, x)
			}
		}
	}
	if err := s.sw.ReplaceSoftware(ctx, hint, observe.Nmap, scope, sw); err != nil {
		return fmt.Errorf("sensoractive: recording software: %w", err)
	}
	return nil
}
