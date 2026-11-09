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
	notFoundHint = "DNS usually updates within minutes and can take up to 72 hours. Check again later, and make sure the value was pasted without extra quotes and that the Name field is just @ (some providers append the domain automatically)."
)

func txtRecord(token string) string { return "vedette-verify=" + token }

// lookupTXT reports whether the domain has the TXT record of the target. A failed lookup is "not
// confirmed" with a reason (fail closed), never an error: the answer is a normal result.
func (s *Service) lookupTXT(ctx context.Context, t Target) (found bool, failure string) {
	lctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	vals, err := s.cfg.Resolver.LookupTXT(lctx, t.Value)
	if err != nil {
		var de interface{ NotFound() bool }
		if errors.As(err, &de) && de.NotFound() {
			return false, ""
		}
		return false, fmt.Sprintf("The DNS lookup for %s failed, so the record could not be checked. Try again in a few minutes.", t.Value)
	}
	want := txtRecord(t.Token)
	for _, v := range vals {
		if strings.TrimSpace(v) == want {
			return true, ""
		}
	}
	return false, ""
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
			wait := int((recent[0].Add(time.Hour).Sub(now) + time.Minute - 1) / time.Minute)
			return rateLimited(max(1, wait))
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
	if t.Kind == KindDomain {
		ok, failure = s.lookupTXT(ctx, t)
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
			message, verifiedAt = fmt.Sprintf("The box reaches the Internet via %s. Verified until %s.", cur.Value, ymd(now.Add(ValidDays*24*time.Hour))), now
		case ok:
			message = fmt.Sprintf("Found the TXT record %s on %s.", txtRecord(cur.Token), cur.Value)
			if cur.VerifiedAt.IsZero() {
				verifiedAt = now
			}
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

func noneIfEmpty(ips []string) string {
	if len(ips) == 0 {
		return "no public IP"
	}
	return strings.Join(ips, ", ")
}
