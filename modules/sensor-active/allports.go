package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
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
// first (lockWithin); it stays due. The run only adds ports and their services: never the software list (no -O, so no OS guess).

// allPortsEvery is how often a device gets its scan of every port; allPortsKeep is how long the ports such a run found outside the
// normal scan's lists are carried by the normal scans when no later weekly run replaces them (review r1 M4).
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
	st := s.allPortsState(ctx, assetID)
	var want []int
	for _, p := range h.ports {
		_, inExtra := slices.BinarySearch(nmapargv.ExtraPortNumbers, p.number)
		if p.proto == "tcp" && !inExtra && !slices.Contains(st.NormalPorts, p.number) {
			want = append(want, p.number)
		}
	}
	slices.SortFunc(want, func(a, b int) int { // never read first ("" sorts first), then read longest ago, then by port
		if c := cmpStr(st.Versioned[strconv.Itoa(a)], st.Versioned[strconv.Itoa(b)]); c != 0 {
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

// portSoftware is a software row a weekly follow-up read on one port (review r2 M2): kept by port and product, carried into the
// device's nmap software list by the weekly run and by the normal scans, as the extra ports are.
type portSoftware struct {
	Port     int              `json:"port"`
	Software observe.Software `json:"software"`
}

// allPortsRow is what sa_all_ports holds for a device besides its schedule.
type allPortsRow struct {
	NormalPorts []int
	NormalSW    []observe.Software // nil: no normal scan recorded since the upgrade
	Extra       []observe.Service
	ExtraSW     []portSoftware
	ExtraAt     string
	Versioned   map[string]string // port -> when the follow-up last read it
}

// allPortsState reads the row (empty on none or a read error).
func (s *Service) allPortsState(ctx context.Context, id string) allPortsRow {
	var np, ex, exsw, ver string
	var nsw, at sql.NullString
	r := allPortsRow{Versioned: map[string]string{}}
	err := s.db.Reader().QueryRowContext(ctx, `SELECT normal_ports, normal_sw, extra, extra_sw, coalesce(extra_at, ''), versioned FROM sa_all_ports WHERE asset_id = ?`, id).
		Scan(&np, &nsw, &ex, &exsw, &at, &ver)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.log.WarnContext(ctx, "sensoractive: reading the weekly scan of a device failed", "asset", id, "error", err)
		}
		return r
	}
	_ = json.Unmarshal([]byte(np), &r.NormalPorts)
	if nsw.Valid {
		r.NormalSW = []observe.Software{}
		_ = json.Unmarshal([]byte(nsw.String), &r.NormalSW)
	}
	_ = json.Unmarshal([]byte(ex), &r.Extra)
	_ = json.Unmarshal([]byte(exsw), &r.ExtraSW)
	_ = json.Unmarshal([]byte(ver), &r.Versioned)
	r.ExtraAt = at.String
	return r
}

// fresh says the carry of the last weekly run is at most allPortsKeep old (review r1 M4).
func (s *Service) fresh(r allPortsRow) bool {
	return r.ExtraAt != "" && r.ExtraAt >= store.FormatTS(s.clock().Add(-allPortsKeep))
}

// keepNormal stores what a normal or versions scan found: its open ports (the weekly follow-up does not read them again) and its
// software (the weekly run writes the device's nmap software as this plus its own, review r2 M2). It returns the weekly run's
// software to carry, while fresh.
func (s *Service) keepNormal(ctx context.Context, id string, list []observe.Service, sw []observe.Software) ([]observe.Software, error) {
	ports := []int{}
	for _, sv := range list {
		if sv.Proto == "tcp" {
			ports = append(ports, sv.Port)
		}
	}
	if sw == nil {
		sw = []observe.Software{}
	}
	bp, err := json.Marshal(ports)
	if err != nil {
		return nil, err
	}
	bs, err := json.Marshal(sw)
	if err != nil {
		return nil, err
	}
	if len(bs) > 262144 {
		bs = []byte("[]")
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, normal_ports, normal_sw) VALUES (?, ?, ?)
ON CONFLICT (asset_id) DO UPDATE SET normal_ports = excluded.normal_ports, normal_sw = excluded.normal_sw`, id, string(bp), string(bs))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sensoractive: keeping the ports of a normal scan: %w", err)
	}
	r := s.allPortsState(ctx, id)
	if !s.fresh(r) {
		return nil, nil
	}
	out := make([]observe.Software, len(r.ExtraSW))
	for i, e := range r.ExtraSW {
		out[i] = e.Software
	}
	return out, nil
}

// keepAllPorts stores what a done weekly run found and returns the device's nmap software list to write, or nil when none should be
// written (no normal scan recorded since the upgrade: the device is queued for one instead, which writes both). Open ports outside
// nmapargv.ExtraPorts are carried with the run's time (a port the follow-up did not read keeps what an earlier run read on it);
// the software of the ports the follow-up read replaces what was kept for them (a version that changed, review r2 M2), the rest is
// kept while the port is open; ports no longer open drop out; the versioned times move for the ports read.
func (s *Service) keepAllPorts(ctx context.Context, id string, h host) ([]observe.Software, error) {
	prev := s.allPortsState(ctx, id)
	now := s.now()
	open := map[int]bool{}
	for _, p := range h.ports {
		if p.proto == "tcp" {
			open[p.number] = true
		}
	}
	extra := []observe.Service{}
	for _, sv := range servicesOf(h) {
		if _, in := slices.BinarySearch(nmapargv.ExtraPortNumbers, sv.Port); in && sv.Proto == "tcp" {
			continue
		}
		if !slices.Contains(h.read, sv.Port) && sv.Product == "" {
			if j := slices.IndexFunc(prev.Extra, func(e observe.Service) bool { return e.Port == sv.Port && e.Proto == sv.Proto }); j >= 0 {
				sv = prev.Extra[j] // what an earlier run read on a port this one did not read
			}
		}
		extra = append(extra, sv)
	}
	var extraSW []portSoftware
	for _, e := range prev.ExtraSW {
		if open[e.Port] && !slices.Contains(h.read, e.Port) {
			extraSW = append(extraSW, e)
		}
	}
	for _, p := range h.read {
		k := slices.IndexFunc(h.ports, func(q portInfo) bool { return q.number == p && q.proto == "tcp" })
		if k < 0 {
			continue
		}
		for _, sw := range softwareOf(host{addr: h.addr, ports: []portInfo{h.ports[k]}}) {
			if !sw.Guess && !slices.ContainsFunc(extraSW, func(e portSoftware) bool {
				return e.Port == p && e.Software.Vendor == sw.Vendor && e.Software.Product == sw.Product
			}) {
				extraSW = append(extraSW, portSoftware{Port: p, Software: sw})
			}
		}
	}
	versioned := map[string]string{}
	for k, v := range prev.Versioned {
		if n, err := strconv.Atoi(k); err == nil && open[n] {
			versioned[k] = v
		}
	}
	for _, p := range h.read {
		versioned[strconv.Itoa(p)] = now
	}
	be, err1 := json.Marshal(extra)
	bs, err2 := json.Marshal(extraSW)
	bv, err3 := json.Marshal(versioned)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, err
	}
	if extraSW == nil {
		bs = []byte("[]")
	}
	if len(be) > 262144 || len(bs) > 262144 || len(bv) > 65536 {
		return nil, errors.New("sensoractive: the ports of a weekly scan are over the column's size")
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_all_ports (asset_id, extra, extra_sw, extra_at, versioned) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (asset_id) DO UPDATE SET extra = excluded.extra, extra_sw = excluded.extra_sw, extra_at = excluded.extra_at, versioned = excluded.versioned`,
			id, string(be), string(bs), now, string(bv))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sensoractive: keeping the ports of a weekly scan: %w", err)
	}
	if prev.NormalSW == nil {
		if len(extraSW) > 0 {
			if err := s.Enqueue(ctx, id, "all_ports"); err != nil { // its normal scan writes the software, with these carried
				return nil, err
			}
		}
		return nil, nil
	}
	out := slices.Clone(prev.NormalSW)
	for _, e := range extraSW {
		out = append(out, e.Software)
	}
	return out, nil
}

// allPortsExtra is the weekly run's carried ports while fresh (none when the device never had a weekly run, after allPortsKeep, or
// on a read error).
func (s *Service) allPortsExtra(ctx context.Context, id string) []observe.Service {
	r := s.allPortsState(ctx, id)
	if !s.fresh(r) {
		return nil
	}
	return r.Extra
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
