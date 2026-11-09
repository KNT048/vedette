package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// observe runs rounds rounds of the probe (INV-2, D-81). A round asks the three public services once each and
// accepts an address only when at least two of them agree (EgressProber.Round). The rule over rounds: every
// address that was accepted in at least one round is seen, in the order it was first accepted; a round without
// agreement adds nothing. So a load balancer in front of several uplinks, which gives a new connection a new
// address, shows all of them over a few rounds, while one wrong service can never add an address. Public
// addresses come back in public, refused ones (private, CGNAT, reserved) in refused. It fails only when no round
// accepted anything: ErrNoAgreement when some services answered without agreeing in any round, ErrServicesDown
// when none ever answered.
func (s *Service) observe(ctx context.Context, rounds int) (public []netip.Addr, refused []string, err error) {
	seen := map[netip.Addr]bool{}
	disagreed := false
	for range rounds {
		a, err := s.cfg.Prober.Round(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			disagreed = disagreed || errors.Is(err, ErrNoAgreement)
			continue
		}
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if IsPublicIPv4(a) {
			public = append(public, a)
		} else {
			refused = append(refused, a.String())
		}
	}
	if len(seen) == 0 {
		if disagreed {
			return nil, nil, fmt.Errorf("exposure: probing the public IP services: %w", ErrNoAgreement)
		}
		return nil, nil, fmt.Errorf("exposure: probing the public IP services: %w", ErrServicesDown)
	}
	return public, refused, nil
}

// probeFailure is the sentence that says why an observation found nothing.
func probeFailure(err error) string {
	if errors.Is(err, ErrNoAgreement) {
		return msgDisagree
	}
	return msgOffline
}

// Settings returns the auto-detect state of the box (GET /exposure/targets, box_ip).
func (s *Service) Settings(ctx context.Context) (BoxIP, error) {
	b, err := loadBoxIP(ctx, s.cfg.DB.Reader())
	if err != nil {
		return BoxIP{}, fmt.Errorf("exposure: reading auto-detect settings: %w", err)
	}
	return b, nil
}

// deepDue says whether a full check (DeepRounds rounds) may run now: none ran yet, or the last one is at least
// DeepEvery old. At a short interval the automatic checks are light (LightRounds), so each service is asked once
// per check and a full check, with its many connections, runs at most once an hour: polite to free services.
func (s *Service) deepDue(ctx context.Context) (bool, error) {
	last, err := loadLastDeep(ctx, s.cfg.DB.Reader())
	if err != nil {
		return false, err
	}
	now := s.clock()
	return last.IsZero() || last.After(now.Add(clockSlack)) || now.Sub(last) >= DeepEvery, nil
}

// SaveSettings turns auto-detect on or off and sets its interval (PUT /exposure/box-ip/settings, INV-11).
// Turning it on checks at once, unless the box checked within the last EnableGap (so toggling cannot be used to
// probe over and over). The list of IPs is not touched.
func (s *Service) SaveSettings(ctx context.Context, user string, auto bool, interval int) (BoxIP, error) {
	if interval < MinIntervalMin || interval > MaxIntervalMin {
		return BoxIP{}, ErrBadInterval
	}
	var before BoxIP
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		var err error
		if before, err = loadBoxIP(ctx, tx); err != nil {
			return err
		}
		if err := saveSettings(ctx, tx, auto, interval); err != nil {
			return err
		}
		state := "off"
		if auto {
			state = "on"
		}
		return s.audit(ctx, tx, user, "exposure.box_ip_settings", "box", fmt.Sprintf("auto-detect %s, every %d minutes", state, interval))
	})
	if err != nil {
		return BoxIP{}, fmt.Errorf("exposure: saving auto-detect settings: %w", err)
	}
	if auto && !before.Auto && s.sinceLastRun(before, s.clock()) >= EnableGap {
		deep, err := s.deepDue(ctx)
		if err != nil {
			return BoxIP{}, err
		}
		if _, err := s.Detect(ctx, user, deep); err != nil && !isOutcome(err) {
			return BoxIP{}, err
		}
	}
	return s.Settings(ctx)
}

// sinceLastRun is the time since the last detection, or a very long time when there was none.
func (s *Service) sinceLastRun(b BoxIP, now time.Time) time.Duration {
	if b.LastRun == nil {
		return time.Duration(1<<63 - 1)
	}
	at, err := parseTS(b.LastRun.At)
	if err != nil || at.After(now.Add(clockSlack)) {
		return time.Duration(1<<63 - 1)
	}
	return now.Sub(at)
}

// isOutcome reports whether err is an expected result of a detection (already recorded in last_run and the
// audit log) and not a failure of the box itself.
func isOutcome(err error) bool {
	var ae *APIError
	return errors.As(err, &ae)
}

// Detect is the check of the box's public IPs (POST /exposure/box-ip/verify, PRE-5, INV-2, INV-4, INV-11). It asks
// the public services (DeepRounds rounds when deep, else LightRounds), then adds every distinct public IP that
// passed the two-of-three rule as a new target or renews it for 30 days from now. user is the person who asked, or
// SystemUser when the box runs it by itself; the audit trail says which. Private, reserved and CGNAT addresses are
// never stored. The outcome is also written to last_run, whether it worked or not. Expected failures come back as an
// *APIError (not_public, too_many, unreachable). Audit: a person's click is always audited; a run of the box is
// audited only when something changed (an IP added, an expired IP seen again, a switch between working and failing,
// a refused address that is new), because last_run already says what the routine runs did (INV-11).
func (s *Service) Detect(ctx context.Context, user string, deep bool) (DetectResult, error) {
	s.detectMu.Lock()
	defer s.detectMu.Unlock()
	return s.detectLocked(ctx, user, deep)
}

// detectLocked is Detect for a caller that holds detectMu (the scan-time check, INV-13).
func (s *Service) detectLocked(ctx context.Context, user string, deep bool) (DetectResult, error) {
	rounds := LightRounds
	if deep {
		rounds = DeepRounds
	}
	public, refused, perr := s.observe(ctx, rounds)
	if perr != nil && ctx.Err() != nil {
		return DetectResult{}, fmt.Errorf("exposure: detecting public IPs: %w", ctx.Err())
	}
	auto := user == SystemUser
	var ids []string
	var message string
	var outcome error
	err := s.write(ctx, func(tx *sql.Tx, emit func(string, any)) error {
		ids, message, outcome = nil, "", nil
		now := s.clock()
		prev, err := loadBoxIP(ctx, tx)
		if err != nil {
			return err
		}
		log := func(action, target, detail string) error { return s.audit(ctx, tx, user, action, target, detail) }
		// The run of the box says nothing new when the last run already told this about the address (L3).
		logRefused := func(ip string) error {
			if auto && prev.LastRun != nil && strings.Contains(prev.LastRun.Message, ip) {
				return nil
			}
			return log("exposure.verify_fail", ip, "box_egress: not a public address")
		}
		// A run of the box is audited when it switches between working and failing; the first run counts as coming from "working".
		switched := func(nowOK bool) bool { return prev.LastRun == nil || prev.LastRun.OK != nowOK }
		run := func(ok bool, text string) error { return saveRun(ctx, tx, now, ok, text, deep) }
		fail := func(err *APIError, summary string) error {
			outcome = err
			if e := run(false, err.Message); e != nil {
				return e
			}
			if auto && switched(false) {
				return log("exposure.auto_detect", "box", summary)
			}
			return nil
		}
		switch {
		case perr != nil:
			summary := "failed: the public IP services are not reachable"
			e := ErrUnreachable
			if errors.Is(perr, ErrNoAgreement) {
				e, summary = ErrDisagree, "failed: the public IP services did not agree"
			}
			if !auto {
				if err := log("exposure.verify_fail", "box", "box_egress: "+summary); err != nil {
					return err
				}
			}
			return fail(e, summary)
		case len(public) == 0:
			for _, ip := range refused {
				if err := logRefused(ip); err != nil {
					return err
				}
			}
			return fail(notPublic(refused), "refused: "+strings.Join(refused, ", ")+" (not public)")
		}
		for _, ip := range refused {
			if err := logRefused(ip); err != nil {
				return err
			}
		}
		until := ymd(now.Add(ValidDays * 24 * time.Hour))
		n, err := countTargets(ctx, tx)
		if err != nil {
			return err
		}
		blocked, err := ignoredSet(ctx, tx) // the Ignored list only blocks (INV-14)
		if err != nil {
			return err
		}
		var seen, added, skipped, onIgnored []string
		changed := false // something the audit trail of a run of the box must show
		for _, a := range public {
			ip := a.String()
			if blocked[ip] {
				onIgnored = append(onIgnored, ip)
				continue
			}
			msg := fmt.Sprintf("The box reaches the Internet via %s. Verified until %s.", ip, until)
			t, exists, err := loadTargetByValue(ctx, tx, ip)
			if err != nil {
				return err
			}
			switch {
			case exists:
				was := t.validity(now)
				if err := renewIP(ctx, tx, t.ID, now, msg); err != nil {
					return err
				}
				if !auto || was == validityExpired {
					if err := log("exposure.verify_renew", ip, "box_egress"); err != nil {
						return err
					}
				}
				if was == validityExpired {
					changed = true
					emit(EventTargetVerified, TargetVerifiedEvent{TargetID: t.ID})
				}
				ids, seen = append(ids, t.ID), append(seen, ip)
			case n >= MaxTargets:
				skipped = append(skipped, ip)
			default:
				id := store.NewID("xt")
				nt := Target{ID: id, Kind: KindIP, Value: ip, Method: methodBoxEgress, VerifiedAt: now, CreatedAt: now,
					LastCheck: &Check{At: store.FormatTS(now), OK: true, Message: msg}}
				if err := insertTarget(ctx, tx, nt); err != nil {
					return err
				}
				detail := "box_egress"
				if auto {
					detail = "box_egress, auto-detect"
				}
				if err := log("exposure.verify_ok", ip, detail); err != nil {
					return err
				}
				emit(EventTargetVerified, TargetVerifiedEvent{TargetID: id})
				n++
				changed = true
				ids, seen, added = append(ids, id), append(seen, ip), append(added, ip)
			}
		}
		if len(seen) == 0 && len(skipped) == 0 {
			// Every address the box uses is on the Ignored list: nothing to add, and that is a normal result, not a failure.
			is := "is"
			if len(onIgnored) > 1 {
				is = "are"
			}
			message = fmt.Sprintf("The box reaches the Internet via %s, which %s on your Ignored list, so nothing was added.", strings.Join(onIgnored, ", "), is)
			if err := run(true, message); err != nil {
				return err
			}
			if auto && switched(true) {
				return log("exposure.auto_detect", "box", "seen: "+strings.Join(onIgnored, ", ")+"; not added (Ignored list)")
			}
			return nil
		}
		if len(seen) == 0 {
			return fail(ErrTooMany, "not added: "+strings.Join(skipped, ", ")+fmt.Sprintf(" (limit of %d targets)", MaxTargets))
		}
		via := seen[0]
		each := "Verified"
		if len(seen) > 1 {
			via, each = fmt.Sprintf("%d public IPs: %s", len(seen), strings.Join(seen, ", ")), "Each is verified"
		}
		message = fmt.Sprintf("The box reaches the Internet via %s. %s until %s.", via, each, until)
		if len(refused) > 0 {
			message += fmt.Sprintf(" Ignored, not public: %s.", strings.Join(refused, ", "))
		}
		if len(skipped) > 0 {
			message += fmt.Sprintf(" Not added, the list holds at most %d targets: %s.", MaxTargets, strings.Join(skipped, ", "))
		}
		if len(onIgnored) > 0 {
			message += fmt.Sprintf(" Not added, on your Ignored list: %s.", strings.Join(onIgnored, ", "))
		}
		nowOK := len(skipped) == 0
		if err := run(nowOK, message); err != nil {
			return err
		}
		if !auto || !(changed || switched(nowOK)) {
			return nil
		}
		summary := "seen: " + strings.Join(seen, ", ")
		if len(added) > 0 {
			summary += "; added: " + strings.Join(added, ", ")
		}
		if len(skipped) > 0 {
			summary += "; not added: " + strings.Join(skipped, ", ")
		}
		return log("exposure.auto_detect", "box", summary)
	})
	if err != nil {
		return DetectResult{}, fmt.Errorf("exposure: detecting public IPs: %w", err)
	}
	if outcome != nil {
		return DetectResult{}, fmt.Errorf("exposure: detecting public IPs: %w", outcome)
	}
	items := make([]TargetView, 0, len(ids))
	for _, id := range ids {
		v, err := s.Target(ctx, id)
		if err != nil {
			return DetectResult{}, err
		}
		items = append(items, v)
	}
	return DetectResult{Items: items, Message: message}, nil
}
