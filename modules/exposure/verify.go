package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

const (
	dnsTimeout   = 5 * time.Second
	notFoundHint = "DNS usually updates within minutes and can take up to 72 hours, and a resolver may keep an older answer until the record's TTL runs out (often an hour). Check again later. If it still fails, make sure the Name field is the host shown (some providers append the domain automatically) and the value is exactly the one shown."
)

func txtRecord(token string) string { return "vedette-verify=" + token }

// proveDomain looks for the record proving t among the box's targets (prove). A failed lookup is "not confirmed" with the
// names asked and what came back (fail closed), never an error: the answer is a normal result.
func (s *Service) proveDomain(ctx context.Context, t Target) (proof, error) {
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err != nil {
		return proof{}, fmt.Errorf("reading the targets: %w", err)
	}
	return s.prove(ctx, t, all), nil
}

// retryWait is the minutes (1 or more, rounded up) until the oldest of the attempts of the last hour leaves the hour.
func retryWait(recent []time.Time, now time.Time) int {
	return max(1, int((recent[0].Add(time.Hour).Sub(now)+time.Minute-1)/time.Minute))
}

// attempt counts one verification attempt of a person (INV-5) and refuses the eleventh in an hour.
func (s *Service) attempt(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		now := s.clock()
		recent, err := recentAttempts(ctx, tx, now)
		if err != nil {
			return err
		}
		if len(recent) >= MaxAttemptsPerHour {
			return rateLimited(retryWait(recent, now))
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO exp_attempt (ts) VALUES (?)`, store.FormatTS(now)); err != nil {
			return fmt.Errorf("recording attempt: %w", err)
		}
		return nil
	})
}

// domainCheckAllowed lets a person check one domain target once every DomainCheckEvery: a check is DNS lookups only, so the limit is
// per target and short, and says in seconds when the next check is allowed. perTarget false (the box's own check of a name just
// added) skips the per-target slot. Every check counts against the box-wide bound too (DomainCheckBurst, one more every
// DomainCheckRefill), so a loop over many targets, or adding and deleting names, cannot make the resolver and the audit log work without limit.
func (s *Service) domainCheckAllowed(id string, perTarget bool) error {
	now := s.clock()
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	for k, at := range s.lastCheck { // bounded by the targets: forget what no longer limits anything
		if d := now.Sub(at); d >= DomainCheckEvery || d < 0 {
			delete(s.lastCheck, k)
		}
	}
	if perTarget {
		if at, ok := s.lastCheck[id]; ok {
			return checkedTooSoon(int((DomainCheckEvery - now.Sub(at) + time.Second - 1) / time.Second))
		}
	}
	// The bucket in integer time: each check adds DomainCheckRefill to the moment it would be full again, and it holds at most
	// DomainCheckBurst checks, so a check is allowed while that moment is no more than (burst-1) refills ahead.
	full := s.bucketFull
	if full.Before(now) || full.After(now.Add(DomainCheckBurst*DomainCheckRefill)) { // empty, or a clock set back
		full = now
	}
	if wait := full.Add(DomainCheckRefill).Sub(now) - DomainCheckBurst*DomainCheckRefill; wait > 0 {
		return checksTooBusy(max(1, int((wait+time.Second-1)/time.Second)))
	}
	s.bucketFull = full.Add(DomainCheckRefill)
	if perTarget {
		s.lastCheck[id] = now
	}
	return nil
}

// Verify re-checks ownership of one target (POST …/verify, PRE-2). A domain: its TXT record, at most once every DomainCheckEvery per
// target. An IP: the box must leave the Internet through it now, and the check counts among the MaxAttemptsPerHour of the box. A pass
// renews the proof for ValidDays (INV-4). "Not found" is verified:false, not an error, and inside those days a warning only.
func (s *Service) Verify(ctx context.Context, user, id string) (VerifyResult, error) {
	return s.verify(ctx, user, id, true)
}

// verify is Verify; limited false is the box's own check of a name a proof already covers (right after it is added), which is no
// attempt of a person.
func (s *Service) verify(ctx context.Context, user, id string, limited bool) (VerifyResult, error) {
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
	}
	if t.Typed {
		return s.verifyTyped(ctx, user, t, limited)
	}
	if t.Kind == KindIP {
		// Like a detection, this probes the network and writes the sighting of an IP, so the two never run side by side (L4).
		s.detectMu.Lock()
		defer s.detectMu.Unlock()
	}
	switch {
	case !limited && t.Kind == KindDomain: // the box's own check of a name just added: counted by the box-wide bound only
		err = s.domainCheckAllowed(id, false)
	case !limited:
	case t.Kind == KindDomain:
		err = s.domainCheckAllowed(id, true)
	default:
		err = s.attempt(ctx)
	}
	if err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
	}
	var ok bool
	var failure string // why nothing could be checked, when that was the case
	var observed []string
	var pr proof
	bound := "" // the box-bound value the executors check, when the stored token is an older one
	if t.Kind == KindDomain {
		if pr, err = s.proveDomain(ctx, t); err != nil {
			return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
		}
		ok, failure = pr.found, pr.failure
		if ok {
			bound = s.boundTokenNote(ctx, t, pr)
		}
	} else {
		addrs, _, perr := s.observe(ctx, DeepRounds)
		if perr != nil {
			failure = probeFailure(perr)
		}
		for _, a := range addrs {
			observed = append(observed, a.String())
		}
		ok = slices.Contains(observed, t.Value)
	}
	err = s.write(ctx, func(tx *sql.Tx, emit func(string, any)) error {
		cur, err := loadTarget(ctx, tx, id) // the target may have been deleted or changed meanwhile
		if err != nil {
			return err
		}
		if cur.Kind == KindDomain {
			if pr, err = stillOwner(ctx, tx, id, pr); err != nil {
				return err
			}
			ok, failure = pr.found, pr.failure
		}
		now := s.clock()
		wasOK := !cur.VerifiedAt.IsZero() && cur.LastCheck != nil && cur.LastCheck.OK && cur.validity(now) != validityExpired
		method, message := methodDNS, ""
		var verifiedAt time.Time
		if cur.Kind == KindIP {
			method = methodBoxEgress
		}
		switch {
		case ok && cur.Kind == KindIP:
			message, verifiedAt = fmt.Sprintf("The box reaches the Internet via %s. Verified until %s.", cur.Value, s.dayText(now.Add(ValidDays*24*time.Hour))), now
		case ok:
			message, verifiedAt = proofMessage(cur, pr, s.momentText(now))+bound, now
		case failure != "" && cur.Kind == KindDomain:
			message = failure + s.stillValid(cur, now) + " " + notFoundHint
		case failure != "":
			message = failure + s.stillValid(cur, now)
		case cur.Kind == KindIP:
			message = fmt.Sprintf("This box currently reaches the Internet via %s, not %s.%s Ask your admin to route the box through %s (for example switch WAN), then verify again.", noneIfEmpty(observed), cur.Value, s.stillValid(cur, now), cur.Value)
		default:
			message = fmt.Sprintf("The TXT record %s was not found on %s.%s %s", txtRecord(cur.Token), cur.Value, s.stillValid(cur, now), notFoundHint)
		}
		var setMethod string
		if ok {
			setMethod = method
		}
		if err := updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: ok, Message: message, Covers: ok && pr.coversBelow(cur.Value), Via: keptVia(cur, pr)}, verifiedAt, setMethod); err != nil {
			return err
		}
		if cur.Kind == KindDomain {
			if err := settleMethod(ctx, tx, id, pr); err != nil {
				return err
			}
		}
		action := "exposure.verify_fail"
		if ok {
			action = "exposure.verify_ok"
		}
		quiet := user == SystemUser && !ok && cur.LastCheck != nil && !cur.LastCheck.OK // the box's own failing re-check is no row every time
		if !quiet {
			if err := s.audit(ctx, tx, user, action, cur.Value, method); err != nil {
				return err
			}
		}
		if ok && !wasOK {
			emit(EventTargetVerified, TargetVerifiedEvent{TargetID: id})
		}
		if ok && cur.Kind == KindDomain {
			return s.coverOthers(ctx, tx, user, cur, pr, now, emit)
		}
		return nil
	})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
	}
	v, err := s.Target(ctx, id)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Verified: ok, Message: v.LastCheck.Message, Target: v}, nil
}

// boundTokenNote says, after a passed check of t's own record, which value the executors check when it is not t's stored token.
// A domain's token is the one vedette-host binds to the box for it (HMAC of the domain), and the
// scan worker (deep nmap, nuclei), OpenVAS and ZAP through a parent name check that value; a target added by an older release, or while the
// host gave no token (a logged fallback), keeps a random one. Check keeps passing on the stored token (nothing that works breaks); the
// note names the record to add next to it so those steps pass too. "" when the two are the same, there is no fence, or it gave none.
func (s *Service) boundTokenNote(ctx context.Context, t Target, p proof) string {
	if s.cfg.DomainFence == nil {
		return ""
	}
	dom, stored, _ := p.gate(t) // the domain whose token it is, and that token
	tok, err := s.cfg.DomainFence.Token(ctx, dom)
	if err != nil || !fenceTokenRE.MatchString(tok) || tok == stored {
		return ""
	}
	if !p.own { // a name covered by another target's record: that target's older token is what the executors cannot use
		return fmt.Sprintf(" The record is %s's, whose token is older than the value this box binds to it, which deep scans of addresses that are not this box's and web pages check: add the TXT record %s on %s too, keeping the current one.", dom, txtRecord(tok), p.proven)
	}
	return fmt.Sprintf(" This target's token is older than the value this box binds to %s, which deep scans of addresses that are not this box's (and web pages, when the record is on a parent name) check: add the TXT record %s on %s too, keeping the current one.", t.Value, txtRecord(tok), p.proven)
}

// coverOthers verifies, in the transaction of t's verification, the box's other domain targets the record just found proves too:
// a target added before its parent was verified is covered from now, with no second record. Each one gets its own check
// message and audit row; one already verified and passing is left as it is. The record is checked again for each of them right
// before each of their scans (INV-1 (c)), so a record removed, or the parent target removed with its token, covers them no more.
func (s *Service) coverOthers(ctx context.Context, tx *sql.Tx, user string, t Target, p proof, now time.Time, emit func(string, any)) error {
	if !p.own && !p.reused && p.proven != p.via { // a parent target's record counts only on that target's own name
		return nil
	}
	all, err := listTargets(ctx, tx)
	if err != nil {
		return err
	}
	byID := map[string]Target{}
	for _, o := range all {
		byID[o.ID] = o
	}
	for _, o := range all {
		if o.Kind != KindDomain || o.ID == t.ID || !Covers(p.proven, o.Value) || !o.VerifiedAt.IsZero() && o.LastCheck != nil && o.LastCheck.OK {
			continue
		}
		verifiedAt := now // a pass renews the proof (INV-4)
		msg := fmt.Sprintf("Covered by the TXT record on %s, found when %s was checked: it proves %s and every name under it.", p.at, t.Value, p.proven)
		if p.own && p.proven != t.Value || p.reused { // a record on a parent name: the zone's, so it proves every name under that name
			msg = reusedMessage(p.proven, s.momentText(now))
		}
		via := p.via // the target whose token proved o: t itself when its own token sits on a parent name
		if p.own {
			via = t.Value
		}
		if err := updateCheck(ctx, tx, o.ID, Check{At: store.FormatTS(now), OK: true, Message: msg, Via: via}, verifiedAt, methodDNS); err != nil {
			return err
		}
		// t's own record on its own name covers o under it in the tree: o keeps no method of its own
		covered := p.own && p.proven == t.Value && slices.ContainsFunc(ancestors(o, byID), func(a Target) bool { return a.ID == t.ID })
		if err := recordDomainMethod(ctx, tx, o.ID, covered); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, user, "exposure.verify_ok", o.Value, methodDNS+", covered by "+p.proven); err != nil {
			return err
		}
		emit(EventTargetVerified, TargetVerifiedEvent{TargetID: o.ID})
	}
	return nil
}

func noneIfEmpty(ips []string) string {
	if len(ips) == 0 {
		return "no public IP"
	}
	return strings.Join(ips, ", ")
}

// verifyTyped checks the proof of a public IP a person typed in (INV-35): the token file, then reverse DNS. A person's check is
// allowed once every DomainCheckEvery per target and counts against the box-wide bound, like a domain's; the box's own re-check
// (limited false) counts against the bound only. A pass renews the ValidDays from now. "Not found" is verified:false with what was asked,
// and inside those days a warning only (INV-4).
func (s *Service) verifyTyped(ctx context.Context, user string, t Target, limited bool) (VerifyResult, error) {
	if limited { // a person's check takes the per-target pause and the box-wide bound; the box's own re-check has its own schedule
		if err := s.domainCheckAllowed(t.ID, true); err != nil {
			return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
		}
	}
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: reading the targets: %w", err)
	}
	pr := s.proveIP(ctx, t, all)
	s.rememberLive(t.ID, pr)
	err = s.write(ctx, func(tx *sql.Tx, emit func(string, any)) error {
		cur, err := loadTarget(ctx, tx, t.ID) // the target may have been deleted, or seen as the box's own, meanwhile
		if err != nil {
			return err
		}
		if !cur.Typed {
			return nil
		}
		now := s.clock()
		wasOK := !cur.VerifiedAt.IsZero() && cur.LastCheck != nil && cur.LastCheck.OK && cur.validity(now) != validityExpired
		msg, action, method := pr.message+s.stillValid(cur, now), "exposure.verify_fail", ""
		var verifiedAt time.Time
		if pr.ok {
			msg = fmt.Sprintf("%s Verified until %s.", pr.message, s.dayText(now.Add(ValidDays*24*time.Hour)))
			action, method, verifiedAt = "exposure.verify_ok", pr.method, now
		}
		if err := recordIPProof(ctx, tx, cur.ID, Check{At: store.FormatTS(now), OK: pr.ok, Message: msg}, verifiedAt, method); err != nil {
			return err
		}
		if user == SystemUser && cur.LastCheck != nil && cur.LastCheck.OK == pr.ok && !pr.ok { // the box's own failing re-check is no row every time
			return nil
		}
		if err := s.audit(ctx, tx, user, action, cur.Value, orDefault(method, "ip proof")); err != nil {
			return err
		}
		if pr.ok && !wasOK {
			emit(EventTargetVerified, TargetVerifiedEvent{TargetID: cur.ID})
		}
		return nil
	})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
	}
	v, err := s.Target(ctx, t.ID)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Verified: pr.ok, Message: v.LastCheck.Message, Target: v}, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// liveFor is how long a live result of a typed IP's proof is reused (never past the proof's own expiry); a failure only lives liveFailFor,
// so a person who fixed the file is not refused for minutes.
const (
	liveFor     = 5 * time.Minute
	liveFailFor = DomainCheckEvery
)

type liveEntry struct {
	at time.Time
	pr ipProof
}

func (s *Service) rememberLive(id string, pr ipProof) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	s.live[id] = liveEntry{at: s.clock(), pr: pr}
}

// liveResult is the live result of the last liveFor (liveFailFor for a failure) for a target, or false.
func (s *Service) liveResult(t Target) (ipProof, bool) {
	now := s.clock()
	s.liveMu.Lock()
	e, ok := s.live[t.ID]
	s.liveMu.Unlock()
	if !ok || e.at.After(now) {
		return ipProof{}, false
	}
	window := liveFor
	if !e.pr.ok {
		window = liveFailFor
	}
	if exp := t.expiresAt(now); exp.IsZero() || !now.Before(exp) {
		return ipProof{}, false
	}
	return e.pr, now.Sub(e.at) < window
}

// liveProof is the live proof of a typed IP that is not older than liveFor: what the steps of a scan hand the executors, which check the
// same proof again.
func (s *Service) liveProof(t Target) (ipProof, bool) {
	pr, ok := s.liveResult(t)
	return pr, ok && pr.ok
}

// liveTypedProof is the proof of a typed IP right before something is sent to it (a scan, a step of it, a question to Shodan, OpenVAS):
// one live result per target is looked for and reused for liveFor, so the gate, ScannableIP, every step and the terms of one scan ask the
// third party once. A look that is not cached takes the per-target pause and the box-wide bound of a person's check; when they are used up
// the last check stands. A pass renews the ValidDays; a proof not found is recorded as a warning (INV-4). The target is read again afterwards.
func (s *Service) liveTypedProof(ctx context.Context, actor string, t Target) (Target, error) {
	reload := func() (Target, error) { return loadTarget(ctx, s.cfg.DB.Reader(), t.ID) }
	if _, ok := s.liveResult(t); ok {
		return reload()
	}
	if err := s.domainCheckAllowed(t.ID, true); err != nil {
		return reload() // the last check stands
	}
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err != nil {
		return Target{}, fmt.Errorf("reading the targets: %w", err)
	}
	pr := s.proveIP(ctx, t, all)
	s.rememberLive(t.ID, pr)
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		cur, err := loadTarget(ctx, tx, t.ID)
		if err != nil || !cur.Typed {
			return err
		}
		now := s.clock()
		c, action, method := Check{At: store.FormatTS(now), OK: pr.ok, Message: pr.message + s.stillValid(cur, now)}, "exposure.verify_fail", ""
		var verifiedAt time.Time
		if pr.ok {
			c.Message = fmt.Sprintf("%s Verified until %s.", pr.message, s.dayText(now.Add(ValidDays*24*time.Hour)))
			action, method, verifiedAt = "exposure.verify_ok", pr.method, now
		}
		if err := recordIPProof(ctx, tx, cur.ID, c, verifiedAt, method); err != nil {
			return err
		}
		if cur.LastCheck != nil && cur.LastCheck.OK == pr.ok { // nothing changed: the check is not a row of its own
			return nil
		}
		return s.audit(ctx, tx, actor, action, cur.Value, orDefault(method, "ip proof")+", right before use")
	})
	if err != nil {
		return Target{}, fmt.Errorf("recording the proof check: %w", err)
	}
	return reload()
}

// RunProofRecheck is the body of the ip-proof job (INV-4, INV-35): every proof the box can check by itself that is within IPRecheckLeft of
// running out is checked again (not found: tried again every IPRecheckRetry). A typed IP whose proof is still valid: its file or reverse
// DNS name; an expired one is proved again by a person. A domain that was proved and is switched on: its TXT record (DNS only), expired
// or not, since a record found is a new proof.
func (s *Service) RunProofRecheck(ctx context.Context) error {
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err != nil {
		return fmt.Errorf("exposure: listing targets: %w", err)
	}
	now := s.clock()
	for _, t := range all {
		due := !t.proofNext(now).IsZero() && !t.proofNext(now).After(now)
		var err error
		switch {
		case !due:
			continue
		case t.Typed && t.validity(now) != validityExpired:
			_, err = s.verifyTyped(ctx, SystemUser, t, false)
		case t.Kind == KindDomain && t.Enabled:
			_, err = s.verify(ctx, SystemUser, t.ID, false)
		default:
			continue
		}
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.HTTP == 429 { // the box's bound of checks is used up: the next tick goes on
				return nil
			}
			if ctx.Err() != nil {
				return fmt.Errorf("exposure: re-checking proofs: %w", ctx.Err())
			}
			s.cfg.Log.WarnContext(ctx, "exposure: re-checking a proof failed", "target", t.Value, "error", err)
		}
	}
	return nil
}
