package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// ---- the sweep: one run per pass, across windows ----
//
// A pass over the confirmed ranges is one lan_sweep run. Its steps are the blocks it sweeps, in order: first the /24 blocks of a
// wider range where devices were seen before (so the known segments stay fresh even when the whole pass takes many nights), then the
// rest of each range. A step's done count is the number of its addresses walked: the cursor a resumed run continues from, after a
// closed window, a person's check that went first, or a restart. The run waits (core/run waiting) while the window is closed and the
// window's driver resumes it when the window opens, so a /16 that takes nine nights is one run with true progress.

// knownBlocksMax bounds the known /24 blocks a pass sweeps first (the rest of them are swept in address order).
const knownBlocksMax = 64

// sweepStep is a planned step: a block of addresses and the configured range it belongs to (its network and broadcast addresses are
// the range's, not the block's).
type sweepStep struct {
	block, rng netip.Prefix
}

// planSweep is the steps of a new pass: the known /24 blocks of ranges wider than /24 first, then what is left of every range, each
// as the fewest CIDR blocks. known is the addresses of the inventory's devices.
func planSweep(ranges []netip.Prefix, known []netip.Addr) []sweepStep {
	ranges = mergePrefixes(ranges)
	var first, rest []sweepStep
	for _, r := range ranges {
		if r.Bits() >= 24 {
			rest = append(rest, sweepStep{block: r, rng: r})
			continue
		}
		var blocks []netip.Prefix
		for _, a := range known {
			if a = a.Unmap(); a.Is4() && r.Contains(a) {
				b := netip.PrefixFrom(a, 24).Masked()
				if !slices.Contains(blocks, b) {
					blocks = append(blocks, b)
				}
			}
		}
		slices.SortFunc(blocks, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		if room := knownBlocksMax - len(first); len(blocks) > room {
			blocks = blocks[:max(room, 0)]
		}
		for _, b := range blocks {
			first = append(first, sweepStep{block: b, rng: r})
		}
		for _, p := range without(r, blocks) {
			rest = append(rest, sweepStep{block: p, rng: r})
		}
	}
	return append(first, rest...)
}

// without is r minus the blocks inside it, as the fewest CIDR blocks in address order.
func without(r netip.Prefix, blocks []netip.Prefix) []netip.Prefix {
	in := func(p netip.Prefix) bool {
		return slices.ContainsFunc(blocks, func(b netip.Prefix) bool { return p.Contains(b.Addr()) || b.Contains(p.Addr()) })
	}
	if !in(r) {
		return []netip.Prefix{r}
	}
	if slices.ContainsFunc(blocks, func(b netip.Prefix) bool { return b.Bits() <= r.Bits() && b.Contains(r.Addr()) }) {
		return nil // r is one of the blocks (or inside one)
	}
	lo := netip.PrefixFrom(r.Addr(), r.Bits()+1)
	hiAddr := r.Addr().As4()
	bit := 31 - r.Bits()
	hiAddr[3-bit/8] |= 1 << (bit % 8)
	hi := netip.PrefixFrom(netip.AddrFrom4(hiAddr), r.Bits()+1)
	return append(without(lo, blocks), without(hi, blocks)...)
}

// stepCursor walks the addresses a step sweeps, in order: every address of its block but the network and broadcast address of the
// range it belongs to (for ranges wider than /31). It holds no list, so a /8 costs no memory.
type stepCursor struct {
	st  sweepStep
	cur netip.Addr
}

// newCursor is a cursor past the first skip addresses of st (the step's done count).
func newCursor(st sweepStep, skip int) *stepCursor {
	c := &stepCursor{st: st, cur: st.block.Addr()}
	for range skip {
		if _, ok := c.next(); !ok {
			break
		}
	}
	return c
}

func (c *stepCursor) next() (netip.Addr, bool) {
	netAddr, bcast := c.st.rng.Addr(), lastAddr(c.st.rng)
	for c.cur.IsValid() && c.st.block.Contains(c.cur) {
		a := c.cur
		c.cur = a.Next()
		if c.st.rng.Bits() <= 30 && (a == netAddr || a == bcast) {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// stepSize is how many addresses a stepCursor yields for a step.
func stepSize(st sweepStep) int {
	n := prefixSize(st.block)
	if st.rng.Bits() <= 30 {
		if st.block.Contains(st.rng.Addr()) {
			n--
		}
		if st.block.Contains(lastAddr(st.rng)) {
			n--
		}
	}
	return max(n, 0)
}

// stepOf reads a stored step back: its name is its block; the range is the configured one that holds it now (false when none does:
// the range left the scope since the pass began).
func stepOf(name string, ranges []netip.Prefix) (sweepStep, bool) {
	b, err := netip.ParsePrefix(name)
	if err != nil || !b.Addr().Is4() {
		return sweepStep{}, false
	}
	for _, r := range mergePrefixes(ranges) {
		if r.Contains(b.Addr()) && r.Bits() <= b.Bits() {
			return sweepStep{block: b.Masked(), rng: r}, true
		}
	}
	return sweepStep{}, false
}

// sweepTitle is the title of a pass over ranges.
func sweepTitle(ranges []string) string {
	t := "LAN sweep of " + strings.Join(ranges, ", ")
	if r := []rune(t); len(r) > 200 {
		t = string(r[:199]) + "…"
	}
	return t
}

// newSweep queues a pass over the confirmed ranges now (Spec.Trigger and the rest from base), its steps planned from the
// inventory's addresses. inTx runs in the same transaction (the audit row of a person's start).
func (s *Service) newSweep(ctx context.Context, st Settings, base run.Spec, inTx func(tx *sql.Tx, id string) error) (string, error) {
	spec, err := s.sweepSpec(ctx, st, base)
	if err != nil {
		return "", err
	}
	return s.submit(ctx, spec, nil, inTx)
}

// sweepSpec is the run of one pass of the ranges: a step per block of the plan, in order.
func (s *Service) sweepSpec(ctx context.Context, st Settings, base run.Spec) (run.Spec, error) {
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return run.Spec{}, err
	}
	known := make([]netip.Addr, 0, len(addrs))
	for a := range addrs {
		known = append(known, a)
	}
	plan := planSweep(prefixes(st.LANRanges), known)
	base.Kind, base.Title = RunSweep, sweepTitle(st.LANRanges)
	base.Subject = &run.Subject{Kind: "scope", ID: "lan", Label: strings.Join(st.LANRanges, ", ")}
	for _, p := range plan {
		base.Steps = append(base.Steps, run.StepPlan{Name: p.block.String(), Total: stepSize(p)})
	}
	return base, nil
}

// runSweep is the work of a lan_sweep run: every step not done, from its cursor, in batches of MaxBatch addresses that the settings
// put in scope and the inventory does not protect (INV-1). The settings are read again before every batch (and inside probe); the
// run waits when the window closes, when scanning is off or the scope unconfirmed, and between two batches when another run asked
// for the nmap lane (a person's check goes first, then the sweep goes on from its cursor). Hosts found are recorded in the inventory
// by MAC; devices that are new there reach the queue through inventory.asset.discovered.
func (s *Service) runSweep(ctx context.Context, x *run.Exec) (run.Result, error) {
	s.lockRun(ctx)
	defer s.runMu.Unlock()
	d, err := x.Run(ctx)
	if err != nil {
		return run.Result{}, err
	}
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// a person's pass runs outside the window for its hour; a stop of the work in progress stops one batch (batchCtx), none before the first
	cur := &running{cancel: func() {}, runID: x.ID(), until: s.sweepUntil(ctx, d.Run)}
	jctx = withManualUntil(jctx, cur.until)
	s.setCur(cur)
	defer s.setCur(nil)
	macs, err := s.knownMACs(jctx)
	if err != nil {
		return run.Result{}, err
	}
	if _, err := s.startJob(jctx, KindSweep, "", d.Total); err != nil {
		return run.Result{}, err
	}
	sink := progress.SinkFrom(ctx) // a person's Scan the LAN now reports how far it is
	newDevices, failed, retries, firstErr := 0, 0, 0, ""
	sent := false // a batch was sent since this start: only then does the pass give way to other work
	finish := func(r run.Result) (run.Result, error) {
		status := StatusDone
		switch r.Status {
		case run.Waiting, run.Partial:
			status = StatusStopped
		case run.Failed:
			status = StatusFailed
		}
		done := d.Done
		if cur, err := x.Run(context.WithoutCancel(ctx)); err == nil {
			done = cur.Done
		}
		// a pass that waits before it walked any address (the window closed, the worker away) has not started: core/run keeps it so
		r.NotBegun = r.Status == run.Waiting && d.Done == 0 && done == 0
		s.finishJob(ctx, x.ID(), status, done, newDevices, r.Error)
		return r, nil
	}
	steps := d.Steps
	for round := 0; len(steps) > 0 && round < 8; round++ {
		for _, step := range steps {
			if step.Status == run.Done {
				continue
			}
			st, err := s.inv.Settings(jctx)
			if err != nil {
				return finish(run.Result{Status: run.Partial, Error: "reading the settings failed"})
			}
			sp, ok := stepOf(step.Name, prefixes(st.LANRanges))
			if !ok {
				s.stepEnd(jctx, x, step.Seq, run.Stopped, "This range is no longer in the scope")
				continue
			}
			s.stepStart(jctx, x, step.Seq)
			walked := step.Done
			cursor := newCursor(sp, walked)
			for {
				if r, wait := s.sweepMayGoOn(jctx, x, sent); wait {
					return finish(r)
				}
				st, err = s.inv.Settings(jctx)
				if err != nil {
					return finish(run.Result{Status: run.Partial, Error: "reading the settings failed"})
				}
				batch, n, err := s.stepBatch(jctx, st, cursor.next)
				if err != nil {
					if jctx.Err() != nil {
						return finish(run.Result{Status: run.Partial, Error: "stopped"})
					}
					return finish(run.Result{Status: run.Partial, Error: "reading the scope failed"})
				}
				if n == 0 {
					break
				}
				if len(batch) > 0 {
					bctx, bcancel := s.batchCtx(jctx, cur)
					hosts, err := s.probe(progress.WithSink(bctx, nil), x.ID(), nmapargv.Sweep, st.Rate, batch)
					bcancel()
					sent = true
					switch {
					case errors.Is(err, ErrStopped):
						if jctx.Err() != nil { // the run itself was stopped (a person, Vedette stopping): core/run records why
							return finish(run.Result{Status: run.Partial, Error: "stopped"})
						}
						if s.off.Load() {
							return finish(run.Result{Status: run.Partial, Error: run.ModuleOffReason})
						}
						// The batch was stopped for a reason of its own (a device of it may no longer be scanned, the settings or the
						// window changed under it): the pass reads the rules again and sweeps the batch again from the cursor, or waits
						// for what no longer allows it. It never ends on a bare "stopped".
						why := s.whyStopped(cur)
						if why == nil {
							why = err
						}
						if r := s.sweepWait(jctx); r.Status == run.Waiting {
							return finish(r)
						}
						if retries++; retries > 3 {
							return finish(run.Result{Status: run.Waiting, WaitingFor: "the next window (every try of a batch was stopped: " + stopWords(why) + ")"})
						}
						s.runWrite(ctx, "log", x.Log(context.WithoutCancel(ctx), run.Warn, "A batch was stopped because "+stopWords(why)+"; it is swept again"))
						cursor = newCursor(sp, walked)
						continue
					case errors.Is(err, ErrUnavailable):
						return finish(run.Result{Status: run.Waiting, WaitingFor: "the scan worker to be available"})
					case err == nil:
						var fresh map[netip.Addr]bool
						if fresh, err = s.recordSweep(jctx, hosts, batch, macs); err == nil {
							newDevices += len(fresh)
							s.sweepItems(jctx, hosts, batch, fresh)
							break
						}
						fallthrough
					default:
						failed++
						if firstErr == "" {
							firstErr = err.Error()
						}
						s.log.WarnContext(ctx, "sensoractive: a sweep batch failed", "run", x.ID(), "error", err)
					}
				}
				walked, retries = walked+n, 0
				s.stepProgress(jctx, x, step.Seq, walked, step.Total)
				if sink != nil {
					if r, err := x.Run(jctx); err == nil {
						sink.Report(progress.Update{Phase: progress.PhaseDiscovery, Percent: -1, Done: int64(r.Done), Total: int64(r.Total), Unit: progress.UnitHosts})
					}
				}
			}
			s.stepEnd(jctx, x, step.Seq, run.Done, "")
		}
		// a range added to the scope while the pass went on is swept in this pass, not a week later
		if steps, err = s.addNewRanges(jctx, x); err != nil {
			return finish(run.Result{Status: run.Partial, Error: "reading the settings failed"})
		}
	}
	s.resumeChildren(context.WithoutCancel(ctx), x.ID())
	if failed > 0 {
		return finish(run.Result{Status: run.Failed, Error: fmt.Sprintf("%d batches failed; first: %s", failed, firstErr)})
	}
	return finish(run.Result{})
}

// batchCtx is the context of one batch of pass cur: a stop of the work in progress (stopCur) cancels this batch only, so the pass can
// read the rules again and go on from its cursor, and the reason it was stopped for is the batch's own (cur.why starts empty).
func (s *Service) batchCtx(parent context.Context, cur *running) (context.Context, context.CancelFunc) {
	bctx, bcancel := context.WithCancel(parent)
	s.mu.Lock()
	cur.cancel, cur.why = bcancel, nil
	s.mu.Unlock()
	return bctx, bcancel
}

// addNewRanges adds to pass x the steps of what the scope holds now that none of its steps covers (a range added, or widened, while
// the pass went on) and returns them; none when the pass covers the whole scope.
func (s *Service) addNewRanges(ctx context.Context, x *run.Exec) ([]run.Step, error) {
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return nil, err
	}
	d, err := x.Run(ctx)
	if err != nil {
		return nil, err
	}
	var have []netip.Prefix
	for _, step := range d.Steps {
		if p, err := netip.ParsePrefix(step.Name); err == nil {
			have = append(have, p.Masked())
		}
	}
	var added []run.Step
	for _, r := range mergePrefixes(prefixes(st.LANRanges)) {
		for _, p := range without(r, have) {
			sp := sweepStep{block: p, rng: r}
			seq, err := x.AddStep(context.WithoutCancel(ctx), p.String(), stepSize(sp))
			if err != nil {
				return nil, err
			}
			added = append(added, run.Step{Seq: seq, Name: p.String(), Status: run.Queued, Total: stepSize(sp)})
		}
	}
	return added, nil
}

// sweepMayGoOn says whether the sweep waits now instead of sending its next batch, and for what: the settings no longer allow it,
// the window closed, or another run asked for the nmap lane.
// sent: the pass sent a batch since it last started; it gives way only then, so it always moves between two turns of other work.
func (s *Service) sweepMayGoOn(ctx context.Context, x *run.Exec, sent bool) (run.Result, bool) {
	if ctx.Err() != nil {
		return run.Result{Status: run.Partial, Error: "stopped"}, true
	}
	if r := s.sweepWait(ctx); r.Status == run.Waiting {
		return r, true
	}
	if !sent {
		return run.Result{}, false
	}
	if _, title, err := s.laneBusy(ctx, x.ID()); err == nil && title != "" {
		s.setYielded(x.ID(), true)
		return run.Result{Status: run.Waiting, WaitingFor: "“" + title + "” to finish (it goes first; the sweep then goes on)"}, true
	}
	return run.Result{}, false
}

// sweepWait is what a sweep waits for now, or a zero Result when it may go on.
func (s *Service) sweepWait(ctx context.Context) run.Result {
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return run.Result{Status: run.Waiting, WaitingFor: "the settings to be readable"}
	}
	switch err := st.allowed(); {
	case errors.Is(err, ErrScanningOff):
		return run.Result{Status: run.Waiting, WaitingFor: "active scanning to be turned on"}
	case errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
		return run.Result{Status: run.Waiting, WaitingFor: "the scan scope to be confirmed"}
	case err != nil:
		return run.Result{Status: run.Waiting, WaitingFor: "the scan settings to allow it"}
	}
	if _, ok := s.windowNow(ctx, st); !ok {
		return run.Result{Status: run.Waiting, WaitingFor: s.windowWait(st)}
	}
	return run.Result{}
}

// stepBatch takes from next up to MaxBatch addresses the settings snapshot st puts in scope and the inventory does not protect;
// walked is how many addresses it took from next (the step's cursor moves by it), 0 when the step is used up.
func (s *Service) stepBatch(ctx context.Context, st Settings, next func() (netip.Addr, bool)) (batch []netip.Addr, walked int, err error) {
	prot, err := s.inv.ProtectedIPs(ctx)
	if err != nil {
		return nil, 0, err
	}
	skip := make(map[netip.Addr]bool, len(prot))
	for _, a := range prot {
		skip[a.Unmap()] = true
	}
	sc := newScope(st)
	for len(batch) < MaxBatch && walked < 16*MaxBatch { // a run of excluded addresses still moves the cursor in bounded steps
		a, ok := next()
		if !ok {
			break
		}
		walked++
		if sc.contains(a) && !skip[a] {
			batch = append(batch, a)
		}
	}
	return batch, walked, nil
}

// sweepItems records the hosts a batch found as items of the run: the device the inventory has at the address, or the address.
func (s *Service) sweepItems(ctx context.Context, hosts []host, batch []netip.Addr, fresh map[netip.Addr]bool) {
	up := onlyTargets(hosts, batch)
	if len(up) == 0 {
		return
	}
	addrs, _ := s.inv.Addresses(ctx) // a failed read leaves the items without a link
	x := execOf(ctx)
	if x == nil {
		return
	}
	seen := map[netip.Addr]bool{}
	var its []run.Item
	for _, h := range up {
		if seen[h.addr] {
			continue
		}
		seen[h.addr] = true
		outcome := "found"
		if fresh[h.addr] {
			outcome = "new"
		}
		its = append(its, hostItem(h.addr, addrs[h.addr], outcome))
	}
	if err := x.AddItems(context.WithoutCancel(ctx), its...); err != nil && !errors.Is(err, run.ErrNotLive) {
		s.log.WarnContext(ctx, "sensoractive: recording the hosts a sweep found failed", "run", x.ID(), "error", err)
	}
}

// resumeChildren queues again the device checks that wait under a run (the devices a person's sweep found: they are checked
// right after it, within its hour).
func (s *Service) resumeChildren(ctx context.Context, parent string) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM core_run WHERE parent_id = ? AND status = 'waiting' ORDER BY queued_at, rowid`, parent)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		if err := s.resumeWaiting(ctx, id); err != nil && !errors.Is(err, run.ErrNotResumable) {
			s.log.WarnContext(ctx, "sensoractive: queueing a device check after a sweep failed", "run", id, "error", err)
		}
	}
}

func (s *Service) stepStart(ctx context.Context, x *run.Exec, seq int) {
	s.runWrite(ctx, "start a step", x.StartStep(context.WithoutCancel(ctx), seq))
}

func (s *Service) stepProgress(ctx context.Context, x *run.Exec, seq, done, total int) {
	s.runWrite(ctx, "progress", x.Progress(context.WithoutCancel(ctx), seq, min(done, total), total))
}

func (s *Service) stepEnd(ctx context.Context, x *run.Exec, seq int, st run.Status, note string) {
	s.runWrite(ctx, "end a step", x.EndStep(context.WithoutCancel(ctx), seq, st, note))
}

// runWrite logs a failed write of a run's progress: the work goes on, its probes are the record.
func (s *Service) runWrite(ctx context.Context, what string, err error) {
	if err != nil && !errors.Is(err, run.ErrNotLive) {
		s.log.WarnContext(ctx, "sensoractive: recording the progress of a run failed", "what", what, "error", err)
	}
}

// ---- the estimate ----

// SweepCost is what one pass over a scope costs at a rate: the addresses it walks, the time one pass takes (a floor: an address
// behind a router costs nmapargv.SweepProbes packets, one on the box's own networks one ARP request), and the windows it needs.
type SweepCost struct {
	Addresses int           // in the ranges, outside the exclusions
	Pass      time.Duration // one pass at the rate
	Window    time.Duration // one window (0: no window is set)
	Windows   int           // windows one pass needs (1 when it fits one; 0 without a window)
}

// Cost is SweepCost of st.
func (st Settings) Cost(local []netip.Prefix) SweepCost {
	sc := newScope(st)
	n, near := sc.count(), sc.within(local).count()
	c := SweepCost{Addresses: n, Window: st.windowLength()}
	if st.Rate < 1 {
		return c
	}
	c.Pass = time.Duration(near+(n-near)*nmapargv.SweepProbes) * time.Second / time.Duration(st.Rate)
	if c.Window > 0 {
		c.Windows = max(1, int(math.Ceil(float64(c.Pass)/float64(c.Window))))
	}
	return c
}

// sweepEstimate is the time a waiting or running pass has left, in words: "about 9 more nights at 50 packets/s" (run.Kind.Estimate).
func (s *Service) sweepEstimate(ctx context.Context, r run.Run) string {
	if r.Total <= 0 || r.Done >= r.Total || r.Status != run.Running { // a waiting pass says what it waits for, not a time left
		return ""
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.Rate < 1 {
		return ""
	}
	need := s.sweepTime(ctx, st, r.Total-r.Done)
	win := st.windowLength()
	switch {
	case need < time.Minute:
		return "less than a minute left"
	case win <= 0 || need <= win:
		return fmt.Sprintf("about %s left at %d packets/s", roundWords(need), st.Rate)
	}
	nights := int(math.Ceil(float64(need) / float64(win)))
	return fmt.Sprintf("about %d more windows at %d packets/s", nights, st.Rate)
}

// sweepTime is how long a sweep of n addresses of the scope takes at the settings' rate (st.Rate at least 1): an address on one of the
// box's own segments costs one ARP request, one behind a router nmapargv.SweepProbes packets.
func (s *Service) sweepTime(ctx context.Context, st Settings, n int) time.Duration {
	sc := newScope(st)
	near, all := sc.within(s.localPrefixes(ctx)).count(), sc.count()
	perAddr := float64(nmapargv.SweepProbes)
	if all > 0 {
		perAddr = (float64(near) + float64((all-near)*nmapargv.SweepProbes)) / float64(all)
	}
	return time.Duration(float64(n) * perAddr * float64(time.Second) / float64(st.Rate))
}

// sweepHold is how long a pass keeps the nmap lane from a run queued behind it (run.Kind.Hold): it gives way after its current batch
// (sweepMayGoOn), and a queued pass after the first batch it sends, so one batch of at most MaxBatch addresses.
func (s *Service) sweepHold(ctx context.Context, r run.Run) (time.Duration, bool) {
	if r.Status != run.Running && r.Status != run.Queued {
		return 0, false
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.Rate < 1 {
		return 0, false
	}
	return s.sweepTime(ctx, st, min(MaxBatch, max(r.Total-r.Done, 0))), true
}

// roundWords writes d for an "about": "40 minutes" (rounded up) or "3 hours" (rounded to the nearest: 3 hours and 10 minutes is not
// "about 4 hours").
func roundWords(d time.Duration) string {
	if d < 90*time.Minute {
		return countWords(int(math.Ceil(d.Minutes())), "minute")
	}
	return countWords(int(math.Round(d.Hours())), "hour")
}

// countWords writes n of a unit with its plural: "1 minute", "3 minutes".
func countWords(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// boundWords writes d for an "at most": rounded up, in minutes or hours, so the bound is never below the time it stands for.
func boundWords(d time.Duration) string {
	if d < 90*time.Minute {
		return countWords(int(math.Ceil(d.Minutes())), "minute")
	}
	return countWords(int(math.Ceil(d.Hours())), "hour")
}
