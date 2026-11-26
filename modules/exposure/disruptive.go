package exposure

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

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// nmap's disruptive scripts (password guessing, denial of service and the login and crash checks) are the last step of a deep scan
// whose run allows the disruptive checks (runMode: a person's scan, the terms include them, the box's own IP not behind carrier-grade
// NAT). They used to run inside the deep scan's first nmap run, before every other engine: a firewall that bans the box, or that the
// brute-force load overwhelms, then made the templates, ZAP and OpenVAS talk to nothing. Now the first nmap run is the sweep of every
// port with service identification and the safe scripts, and the disruptive scripts run after OpenVAS, on the open ports the scan
// found, so such a ban costs only this step.

// DisruptiveScanner is implemented by a ServiceScanner that runs nmap's disruptive scripts on the open ports of the box's own verified
// public IP (cmd/vedette: sensor-active's ScanDisruptive). The implementation keeps its fences: the own-IP check and the terms (they
// must still allow the disruptive checks) right before the job leaves, the probe row, the worker's own fence. A step that could not run
// for a reason the page may show returns *Unavailable. ServiceScan.Scripts holds the script results.
type DisruptiveScanner interface {
	ScanDisruptive(ctx context.Context, t ScanTarget, ip netip.Addr, ports []int) (ServiceScan, error)
}

// DisruptiveTimeout bounds the step: nmap's own host timeout of the run (nmapargv.DisruptiveHostTimeout, 30 minutes) plus the wait for
// the box's one nmap slot and the checks around the job. cmd/vedette holds them together in a test.
const DisruptiveTimeout = 40 * time.Minute

// keyScriptDisruptive is the key space of a finding the disruptive scripts confirmed: an issue of the surface engine like keyScript,
// apart from it, so the deep scan's first nmap run (which does not run these scripts) never takes it for fixed. Only a later run of
// the disruptive scripts that finished on the address does.
const keyScriptDisruptive = "nse-disruptive:"

// The notes of the step.
const (
	notDisruptiveScheduled  = "Scheduled scans never run the disruptive checks; they run when a person presses Scan now."
	notDisruptiveOff        = "The disruptive checks are not part of this scan: they run only on the box's own public IP, when its testing terms include them and the box is not behind carrier-grade NAT."
	notDisruptiveNoScanner  = "nmap's disruptive scripts are not set up on this box."
	notDisruptiveNoAddress  = "No address of this scan is the box's own public IP with the disruptive checks allowed, so nmap's disruptive scripts did not run."
	notDisruptiveNoPorts    = "No open port was found for nmap's disruptive scripts to check."
	notDisruptiveEverywhere = "More than 40 ports answered, more than a normal box exposes (a router or firewall that answers for every port looks like this), so nmap's disruptive scripts were not sent over them."
	notDisruptiveFail       = "nmap's disruptive scripts failed, so they checked nothing. The box log has the error."
	notDisruptiveSlow       = "nmap's disruptive scripts did not finish within %d minutes, so what they found is not shown."
)

// disruptiveStep is the last step of a deep scan: nmap's disruptive scripts on the open ports this scan found on the box's own public IP
// (an IP target, or the box's own address among a domain's deep-scanned ones), each address re-checked right before (the gate or the
// domain's deep gate), then the liveness check. What they confirm is written as issues of the surface engine (keyScriptDisruptive).
// A stop of the run leaves the step to the run's end (close).
func (s *Service) disruptiveStep(ctx context.Context, x *corerun.Exec, ex *scanExec, user string, t Target, c Content, deep []deepAddr) {
	rs := runStepsOf(ctx)
	mode := ex.mode
	if !mode.Full {
		return
	}
	lt := liveTarget(t, user)
	if s.skipIfGone(ctx, lt, c, stepKeyDisruptive) {
		return
	}
	ds, _ := s.cfg.Services.(DisruptiveScanner)
	switch {
	case user == SystemUser:
		rs.skip(ctx, stepKeyDisruptive, notDisruptiveScheduled)
		return
	case !mode.Disruptive:
		rs.skip(ctx, stepKeyDisruptive, notDisruptiveOff)
		return
	case ds == nil:
		rs.skip(ctx, stepKeyDisruptive, notDisruptiveNoScanner)
		return
	}
	type addr struct {
		st ScanTarget
		ip netip.Addr
	}
	var addrs []addr
	if t.Kind == KindIP {
		ip, err := netip.ParseAddr(t.Value)
		if err != nil {
			return
		}
		st := s.scanTarget(ctx, t, user, mode)
		if _, reason, gerr := s.gate(ctx, user, t.ID); gerr != nil || reason != "" { // the gate of the run is an hour old by now
			if ctx.Err() != nil {
				return
			}
			rs.skip(ctx, stepKeyDisruptive, "nmap's disruptive scripts did not run: this IP can no longer be scanned (it was removed, paused, no longer verified or needs the scan confirmed again), so nothing was sent.")
			return
		}
		addrs = append(addrs, addr{st, ip})
	} else {
		st := s.scanTarget(ctx, t, user, mode)
		for _, a := range deep {
			if !a.box || !a.inZone {
				continue
			}
			stD, line, err := s.deepGate(ctx, deepMode(st, a), a.ip, a.names)
			if err != nil {
				return
			}
			if line == "" && stD.Mode.Disruptive && stD.Domain == nil { // the box's own IP, reached through a name of the domain
				addrs = append(addrs, addr{stD, a.ip})
			}
		}
	}
	if len(addrs) == 0 {
		rs.skip(ctx, stepKeyDisruptive, notDisruptiveNoAddress)
		return
	}
	open := openPorts(c)
	if !slices.ContainsFunc(addrs, func(a addr) bool { return len(open[a.ip.String()]) > 0 }) {
		rs.skip(ctx, stepKeyDisruptive, notDisruptiveNoPorts)
		return
	}
	if slices.ContainsFunc(addrs, func(a addr) bool { return len(open[a.ip.String()]) > commonports.MaxBelievableOpen }) {
		rs.skip(ctx, stepKeyDisruptive, notDisruptiveEverywhere) // a router or SYN proxy answering for every port: nothing real to check
		return
	}
	if !s.beforeEngine(ctx, lt, &c, stepKeyDisruptive, stepNameDisruptive, "scripts") {
		return
	}
	rs.start(ctx, stepKeyDisruptive)
	rs.reportTo(stepKeyDisruptive)
	defer rs.reportTo("")
	var notes []string
	var rows []ScriptRow
	finished := map[string]bool{}
	failed, ran := false, false
	for _, a := range addrs {
		k := a.ip.String()
		ports := slices.DeleteFunc(slices.Clone(open[k]), func(p int) bool { return s.lostPort(ctx, k, p) })
		if len(ports) == 0 { // every open port of it stopped answering earlier in the run: the note says so
			if len(open[k]) > 0 {
				notes = append(notes, clipText("Not run on "+k+". "+s.lostText(ctx, lt, map[string][]int{k: s.observerOf(ctx).lostOf()[k]}), maxLineText))
			}
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, DisruptiveTimeout)
		res, err := ds.ScanDisruptive(dctx, a.st, a.ip, ports)
		slow := dctx.Err() != nil
		cancel()
		var un *Unavailable
		switch {
		case ctx.Err() != nil: // stopped: the run's end says so
			return
		case err == nil:
			ran, finished[k] = true, true
			got, vuln := 0, 0
			for _, r := range sanitizeScripts(res.Scripts) {
				if r.IP == k {
					rows = append(rows, r)
					got++
					if r.vulnerable() {
						vuln++
					}
				}
			}
			notes = append(notes, fmt.Sprintf("Ran on %s of %s: %s, %d saying VULNERABLE.", plural(len(ports), "open port"), k, plural(got, "result"), vuln))
		case errors.As(err, &un):
			notes = append(notes, clipText("Did not run on "+k+": "+un.Reason, maxLineText))
		case slow || errors.Is(err, ErrServicesTimedOut):
			failed = true
			notes = append(notes, fmt.Sprintf(notDisruptiveSlow, int(DisruptiveTimeout/time.Minute)))
		default:
			failed = true
			s.cfg.Log.ErrorContext(ctx, "exposure: nmap's disruptive scripts failed", "target", t.Value, "ip", k, "error", err)
			notes = append(notes, notDisruptiveFail)
		}
	}
	note := strings.Join(notes, " ")
	if len(rows) > 0 || len(finished) > 0 {
		fresh, err := s.writeDisruptive(ctx, t, x.ID(), rows, finished)
		if err != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: storing what nmap's disruptive scripts found failed", "target", t.Value, "error", err)
			rs.end(ctx, stepKeyDisruptive, corerun.Failed, "What nmap's disruptive scripts found could not be stored.")
			return
		}
		s.alertNews(ctx, t, x.ID(), stepKeyDisruptive, ex.first, nil, fresh)
	}
	switch {
	case failed && !ran:
		rs.end(ctx, stepKeyDisruptive, corerun.Failed, note)
	case failed:
		rs.end(ctx, stepKeyDisruptive, corerun.Partial, note)
	case !ran:
		rs.skip(ctx, stepKeyDisruptive, cmp.Or(note, notDisruptiveNoPorts))
	default:
		rs.end(ctx, stepKeyDisruptive, corerun.Done, note)
	}
}

// writeDisruptive writes the issues of the disruptive scripts of a scan whose other rows are written: what they confirmed, and, on the
// addresses where they finished, the earlier findings of these scripts they no longer confirm are gone.
func (s *Service) writeDisruptive(ctx context.Context, t Target, runID string, rows []ScriptRow, finished map[string]bool) ([]NewIssue, error) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	issues := scriptIssues(rows, keyScriptDisruptive)
	covered := func(x issueWhere) bool {
		return strings.HasPrefix(x.key, keyScriptDisruptive) && finished[ipKey(x.ip)] && (!x.service || x.seen)
	}
	var out []NewIssue
	err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		if _, err := loadTarget(wctx, tx, t.ID); err != nil {
			return err
		}
		hosts, err := storedHostAddrs(wctx, tx, t)
		if err != nil {
			return err
		}
		fresh, reopened, err := writeIssues(wctx, tx, t.ID, runID, store.FormatTS(s.clock()), hosts, issues, engineSet{EngineSurface: len(finished) > 0},
			map[IssueEngine]coverFunc{EngineSurface: covered})
		if err != nil {
			return err
		}
		again, err := s.auditAgain(wctx, tx, reopened)
		if err != nil {
			return err
		}
		var countErr error
		if err := updateSummary(wctx, tx, runID, func(sum *scanSummary) {
			if sum.Counts != nil {
				sum.Counts.NewIssues += len(fresh)
				countErr = rowCounts(wctx, tx, t.ID, sum.Counts)
			}
		}); err != nil {
			return err
		}
		if countErr != nil {
			return countErr
		}
		out, err = issueHolders(wctx, tx, fresh, again)
		return err
	})
	return out, err
}
