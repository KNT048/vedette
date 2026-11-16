package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/core/sensorlink"
)

// SNMP "Read now" (#849, S-INV-1): an administrator adds a credential with a range in the Add dialog, presses Read now, and every
// approved device of the inventory inside the credential's scope is read at once, outside the window, as a Test reads one. D-512
// holds: nothing is sent to a device that is not approved (those wait under To review), to a device the scan policy refuses (never,
// added manually, the box or its decoys, outside the scan scope), or to an address with no device: a read never discovers anything.
// One read at a time on the box; the read of each credential is kept in memory (the last one since the box started).

const (
	snmpReasonRead = "snmp_read"
	// snmpReadBatch bounds one batch of a read: 64 devices, one after another, each with a v3 discovery and a GET of 2 s sent twice.
	snmpReadBatch = 10 * time.Minute
)

// SNMPRead is one Read now (SnmpRead in contract.ts).
type SNMPRead struct {
	ID, CredentialID, By string
	StartedAt            time.Time
	FinishedAt           time.Time // zero while running
	Status               string    // running, done, stopped, failed
	Message              string    // why it stopped or failed
	Total, Done          int
	Answered, Skipped    int
	Results              []SNMPReadResult
}

// SNMPReadResult is what one device answered, as a Test says it.
type SNMPReadResult struct {
	IP string
	SNMPTestResult
}

// snmpReadState is the read of each credential and whether one runs (under Service.mu).
type snmpReadState struct {
	last    map[string]*SNMPRead // by credential id
	running bool
	done    map[string]chan struct{} // closed when the read of that id ends (tests wait on it)
}

func (r *SNMPRead) clone() SNMPRead {
	out := *r
	out.Results = slices.Clone(r.Results)
	return out
}

// ReadSNMP starts a Read now of credential id (POST /inventory/snmp/{id}/read) and answers at once with the run. 409 when nothing can
// be sent (scanning off, the scope not confirmed, SNMP unavailable, a saved secret this box cannot open: secret_lost, #868) or another
// SNMP job runs (busy).
func (s *Service) ReadSNMP(ctx context.Context, actor, id string) (SNMPRead, error) {
	// The module's stop generation before anything else, and the sticky off flag: a module turned off before or while the read is
	// prepared answers 409 stopped, and one turned off later stops the next batch (snmpBatch checks off once registered; #855 r1 M2,
	// r2 L1, SYS-5).
	stops := s.stops.Load()
	if s.off.Load() {
		return SNMPRead{}, stoppedRead()
	}
	if s.secrets == nil {
		return SNMPRead{}, snmpOff()
	}
	cred, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return SNMPRead{}, err
	}
	// Only a lost secret is refused here; any other failure to open one is reported where the job is built, as before.
	if lost, _ := s.snmpLost(ctx, s.db.Reader(), *cred); lost {
		return SNMPRead{}, snmpSecretLost()
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return SNMPRead{}, err
	}
	switch {
	case errors.Is(st.allowed(), ErrScanningOff):
		return SNMPRead{}, apierr.New(409, reasonScanningOff, snmpMessage(reasonScanningOff, netip.Addr{}, "", ""))
	case st.allowed() != nil:
		return SNMPRead{}, apierr.New(409, reasonScopeNotConfirmed, "The scan scope is not set up and confirmed under Scope and sensors, so nothing is sent.")
	}
	if ready, msg := s.SNMPStatus(); !ready {
		return SNMPRead{}, apierr.New(409, SNMPUnavailable, snmpMessage(SNMPUnavailable, netip.Addr{}, "", msg))
	}
	busy := apierr.New(409, SNMPBusy, "Another SNMP read is running (a Test, a Read now or the scan window's round). Try again in a minute.")
	s.mu.Lock()
	if s.reads.running {
		s.mu.Unlock()
		return SNMPRead{}, busy
	}
	s.reads.running = true
	s.mu.Unlock()
	release := func() {
		s.mu.Lock()
		s.reads.running = false
		s.mu.Unlock()
	}
	if !s.snmpMu.TryLock() {
		release()
		return SNMPRead{}, busy
	}
	targets, skipped, err := s.snmpReadTargets(ctx, *cred)
	if err == nil { // every Read now is audited, one that finds no approved device too (S-INV-1, #855 r1 L1)
		err = s.db.Write(ctx, func(tx *sql.Tx) error {
			return s.auditTx(ctx, tx, actor, "inventory.snmp_read", cred.Name, fmt.Sprintf("%d approved devices, %d skipped", len(targets), skipped))
		})
	}
	jobID := ""
	if err == nil {
		jobID, err = s.startJob(ctx, KindSNMP, snmpReasonRead, len(targets))
	}
	if err == nil && (s.stops.Load() != stops || s.off.Load()) {
		s.closeSNMPJob(ctx, jobID, 0, ErrStopped)
		err = stoppedRead()
	}
	if err != nil {
		s.snmpMu.Unlock()
		release()
		return SNMPRead{}, err
	}
	run := &SNMPRead{ID: jobID, CredentialID: id, By: actor, StartedAt: s.clock(), Status: StatusRunning, Total: len(targets), Skipped: skipped, Results: []SNMPReadResult{}}
	// A device that answered this credential and moved out of its scope is not read (D-512): it is a skipped row that says so
	// (#829 C4), so a read of nothing says why.
	for _, m := range s.snmpMovedOut(ctx, []snmpRow{*cred})[id] {
		run.Skipped++
		run.Results = append(run.Results, SNMPReadResult{IP: m.IP, SNMPTestResult: SNMPTestResult{Reason: SNMPNotForThisCredential, Message: m.Message, DeviceID: m.DeviceID}})
	}
	done := make(chan struct{})
	s.mu.Lock()
	if s.reads.last == nil {
		s.reads.last, s.reads.done = map[string]*SNMPRead{}, map[string]chan struct{}{}
	}
	s.reads.last[id], s.reads.done[id] = run, done
	out := run.clone()
	s.mu.Unlock()
	// The read outlives the request; the module turned off (Stop) stops its batch, and the read before the next one.
	go s.runSNMPRead(context.WithoutCancel(ctx), run, *cred, targets, stops, done)
	return out, nil
}

func stoppedRead() *apierr.Error {
	return apierr.New(409, "stopped", "The read was stopped before anything was sent: active discovery was turned off.")
}

// SNMPReadOf is the read of credential id that runs now or the last one since the box started (GET /inventory/snmp/{id}/read); nil
// when none. 404 when the credential does not exist.
func (s *Service) SNMPReadOf(ctx context.Context, id string) (*SNMPRead, error) {
	if s.secrets == nil {
		return nil, snmpOff()
	}
	if _, err := s.snmpRow(ctx, s.db.Reader(), id); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reads.last[id]
	if !ok {
		return nil, nil
	}
	out := r.clone()
	return &out, nil
}

// SNMPReadDone is closed when the read of credential id ends (nil when none was started): for a caller that waits on the state.
func (s *Service) SNMPReadDone(id string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads.done[id]
}

// snmpReadTargets lists the devices of the inventory inside the credential's scope that a read may reach (the rules of the window's
// round, snmpPolicy) and counts the ones it may not.
func (s *Service) snmpReadTargets(ctx context.Context, cred snmpRow) ([]snmpTarget, int, error) {
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return nil, 0, err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return nil, 0, err
	}
	ips := make([]netip.Addr, 0, len(addrs))
	for ip := range addrs {
		if cred.covers(ip) {
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	var out []snmpTarget
	skipped := 0
	for _, ip := range ips {
		if !localnet.Addr(ip) {
			skipped++
			continue
		}
		a, why, err := s.snmpPolicy(ctx, addrs[ip], box)
		switch {
		case errors.Is(err, ErrNotFound):
			continue // deleted since the addresses were read: not a device any more
		case err != nil:
			return nil, 0, err
		case why != "" || a.IP != ip:
			skipped++
			continue
		}
		out = append(out, snmpTarget{asset: addrs[ip], ip: ip, creds: []int{0}})
	}
	return out, skipped, nil
}

// runSNMPRead reads the targets in batches of 64 (each with every check of a batch: snmpBatch reads the policy and the credential
// again), records what they said and keeps the run up to date. It starts holding snmpMu and releases it between batches, so a Test or
// the window's round can take turns.
func (s *Service) runSNMPRead(ctx context.Context, run *SNMPRead, cred snmpRow, targets []snmpTarget, stops uint64, done chan struct{}) {
	defer close(done)
	held := true
	var err error
	n := 0
	for batch := range slices.Chunk(targets, sensorlink.MaxSNMPTargets) {
		if !held {
			s.snmpMu.Lock()
		}
		held = false
		if s.stops.Load() != stops || s.off.Load() {
			s.snmpMu.Unlock()
			err = ErrStopped
			break
		}
		bctx, cancel := context.WithTimeout(ctx, snmpReadBatch)
		var answers []sensorlink.SNMPAnswer
		answers, err = s.snmpBatch(bctx, run.ID, []snmpRow{cred}, batch, true)
		cancel()
		s.snmpMu.Unlock()
		if err != nil {
			break
		}
		s.addReadResults(run, cred, batch, answers)
		n += len(batch)
	}
	if held {
		s.snmpMu.Unlock() // no target: the lock taken by ReadSNMP is still held
	}
	s.closeSNMPJob(ctx, run.ID, n, err)
	s.mu.Lock()
	defer s.mu.Unlock()
	run.FinishedAt = s.clock()
	switch {
	case err == nil:
		run.Status = StatusDone
	case errors.Is(err, ErrStopped):
		run.Status, run.Message = StatusStopped, "The read was stopped: the scan settings, a device or the credential changed, or the module was turned off."
	case errors.Is(err, errSNMPSecretLost):
		run.Status, run.Message = StatusFailed, snmpLostText+" Nothing more was sent."
	case errors.Is(err, ErrSNMPUnavailable), errors.Is(err, ErrWorkerLost), errors.Is(err, context.DeadlineExceeded):
		_, msg := s.SNMPStatus()
		run.Status, run.Message = StatusFailed, "SNMP reads cannot run now: "+cmpOr(msg, "the scan worker did not finish the read in time")+"."
	default:
		run.Status, run.Message = StatusFailed, "The read did not finish. The details are in the box log."
		s.log.ErrorContext(ctx, "sensoractive: snmp read failed", "job", run.ID, "error", err)
	}
	s.reads.running = false
}

// addReadResults puts a batch's answers on the run: one row per device as Test answers; a device the batch's last check dropped
// (no longer approved, set to never, moved) got nothing and counts as skipped.
func (s *Service) addReadResults(run *SNMPRead, cred snmpRow, batch []snmpTarget, answers []sensorlink.SNMPAnswer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range batch {
		i := slices.IndexFunc(answers, func(a sensorlink.SNMPAnswer) bool { return a.Target == t.ip.String() })
		run.Done++
		if i < 0 {
			run.Skipped++
			continue
		}
		a := answers[i]
		r := SNMPReadResult{IP: t.ip.String(), SNMPTestResult: SNMPTestResult{Reason: a.Status, DeviceID: t.asset}}
		if a.Status == sensorlink.SNMPStatusOK {
			f := identifySNMP(a.Values)
			r.Answer = &f
			run.Answered++
		}
		r.OK = r.Reason == SNMPOK
		r.Message = snmpMessage(r.Reason, t.ip, cred.Version, "")
		run.Results = append(run.Results, r)
	}
}
