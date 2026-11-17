package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

const (
	dnsTimeout   = 5 * time.Second
	notFoundHint = "DNS usually updates within minutes and can take up to 72 hours. Check again later, and make sure the value was pasted without extra quotes and that the Name field is the host shown (some providers append the domain automatically)."
)

func txtRecord(token string) string { return "vedette-verify=" + token }

// proveDomain looks for the record proving t among the box's targets (D-628, prove). A failed lookup is "not confirmed" with the
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

// Verify re-checks ownership of one target (POST …/verify, PRE-2). A domain: its TXT record. An IP:
// the box must leave the Internet through it now; seeing it renews it for 30 days (INV-4). "Not found"
// is verified:false, not an error.
func (s *Service) Verify(ctx context.Context, user, id string) (VerifyResult, error) {
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
	}
	if t.Kind == KindIP {
		// Like a detection, this probes the network and writes the sighting of an IP, so the two never run side by side (L4).
		s.detectMu.Lock()
		defer s.detectMu.Unlock()
	}
	if err := s.attempt(ctx); err != nil {
		return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
	}
	var ok bool
	var failure string // why nothing could be checked, when that was the case
	var observed []string
	var pr proof
	if t.Kind == KindDomain {
		if pr, err = s.proveDomain(ctx, t); err != nil {
			return VerifyResult{}, fmt.Errorf("exposure: verifying: %w", err)
		}
		ok, failure = pr.found, pr.failure
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
			message = proofMessage(cur, pr)
			if cur.VerifiedAt.IsZero() {
				verifiedAt = now
			}
		case failure != "" && cur.Kind == KindDomain:
			message = failure + " " + notFoundHint
		case failure != "":
			message = failure
		case cur.Kind == KindIP:
			message = fmt.Sprintf("This box currently reaches the Internet via %s, not %s. Ask your admin to route the box through %s (for example switch WAN), then verify again.", noneIfEmpty(observed), cur.Value, cur.Value)
		default:
			message = fmt.Sprintf("The TXT record %s was not found on %s. %s", txtRecord(cur.Token), cur.Value, notFoundHint)
		}
		var setMethod string
		if ok {
			setMethod = method
		}
		if err := updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: ok, Message: message}, verifiedAt, setMethod); err != nil {
			return err
		}
		action := "exposure.verify_fail"
		if ok {
			action = "exposure.verify_ok"
		}
		if err := s.audit(ctx, tx, user, action, cur.Value, method); err != nil {
			return err
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

// coverOthers verifies, in the transaction of t's verification, the box's other domain targets the record just found proves too
// (D-628): a target added before its parent was verified is covered from now, with no second record. Each one gets its own check
// message and audit row; one already verified and passing is left as it is. The record is checked again for each of them right
// before each of their scans (INV-1 (c)), so a record removed, or the parent target removed with its token, covers them no more.
func (s *Service) coverOthers(ctx context.Context, tx *sql.Tx, user string, t Target, p proof, now time.Time, emit func(string, any)) error {
	all, err := listTargets(ctx, tx)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.Kind != KindDomain || o.ID == t.ID || !Covers(p.proven, o.Value) || !o.VerifiedAt.IsZero() && o.LastCheck != nil && o.LastCheck.OK {
			continue
		}
		var verifiedAt time.Time
		if o.VerifiedAt.IsZero() {
			verifiedAt = now
		}
		msg := fmt.Sprintf("Covered by the TXT record on %s, found when %s was checked: it proves %s and every name under it.", p.at, t.Value, p.proven)
		if err := updateCheck(ctx, tx, o.ID, Check{At: store.FormatTS(now), OK: true, Message: msg}, verifiedAt, methodDNS); err != nil {
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
