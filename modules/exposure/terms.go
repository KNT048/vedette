package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
)

// The testing terms of a verified target (FULL-1, D-566; kien 2026-11-14: "say it clearly in the terms, then use the tools to their
// full capability", and finally: deep by default after the disclosure, disruptive checks only with their own tick). One acceptance
// per target, by an administrator with two-step sign-in, makes every scan of that target a deep scan (ScanMode.Full); the one extra
// tick, off by default, adds the disruptive checks (ScanMode.Disruptive). Without an acceptance a target keeps the K-4 scope of the
// Scan now sentence (D-559): passive web scan, read-only nuclei (D-520), no Greenbone. It can be withdrawn at any time; a new
// TermsVersion asks again. The texts are the only copy: the API sends them with the target in it and the page shows what it got;
// the mock's copy (contract.ts TERMS_TEMPLATE, TERMS_TEMPLATE_DOMAIN, TERMS_DISRUPTIVE) is held equal by a test, and each version's text is pinned.
const (
	TermsVersion = "2026-11-14c"
	// termsTemplate is the text of an IP target, unchanged since 2026-11-14b; termsTemplateDomain is a domain's (D-571, FULL-5 slice 3,
	// LEGAL-2): the "yours alone" sentence becomes what reaches every address a name under the domain resolves to and who answers for
	// a provider's permission. Both share the head and the tail, so the list of tools is the same.
	termsTemplate       = termsHead + termsOwnIP + termsTail
	termsTemplateDomain = termsHead + termsDomain + termsTail
	termsHead           = "I confirm that my company owns {value} and that I am authorized to test it in depth. Once I accept, every scan of {value} is a deep scan, and Vedette's tools may send it:\n" +
		"All ports: every TCP port, and the service and version behind each one.\n" +
		"Version and exploit-confirming checks: tests for known vulnerabilities, some of which confirm a flaw by sending the exploit request itself (for example reading a file or running a harmless command).\n" +
		"An active web scan that submits forms: a spider and an active scan that fill in and send forms and send attack payloads such as SQL injection and cross-site scripting probes. It can create records, send e-mails from forms or change data.\n" +
		"Authentication checks: whether login pages, admin interfaces and services let anyone in without a password or with weak settings. Passwords are not guessed unless the disruptive checks below are ticked.\n"
	termsOwnIP = "Accept only if {value} is yours alone: not an address shared through your Internet provider (carrier-grade NAT), a hosting provider's NAT or proxy, or a CDN or hosted service that serves your names. Their servers are not yours to test. "
	// termsDomain: plan 2026-11-14 §3.5 word for word, then kien's LEGAL-2 (2026-11-14 18:4x): the IP-level tools by name, then
	// TERMS.md's own sentences (D-544, #783) on what verifying a name proves, third-party hosting, CDN and proxies, the customer's
	// responsibility, and that Vedette does not check who owns the addresses, so the two texts never disagree.
	termsDomain = "Every name under {value} that resolves to a public address is scanned at this depth, whatever serves it: your own server, a hosting provider or a CDN. " +
		"If a provider serves a name, its testing policy applies to you (for example, Cloudflare and AWS forbid denial-of-service tests); leave the disruptive checks off unless that provider allows them. " +
		"Vedette sends all ports, OpenVAS, nuclei and the active web scan (ZAP) to each address a name under {value} resolves to. " +
		"Verifying a name proves you control its DNS, not that you own the machines behind it or may test them. " +
		"With shared or cloud hosting, a CDN or a proxy, that address can also serve other people's systems: you are responsible for having the provider's permission. " +
		"Vedette does not check who owns those addresses. "
	termsTail = "The deep scan can load or slow the services on {value} and may create, change or delete data. Run scans when you can accept that, and keep a backup. " +
		"An administrator can withdraw this acceptance at any time. Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it."
	// termsDisruptive is the one extra tick, off by default: what it adds to the deep scan.
	termsDisruptive = "Include disruptive checks (denial of service, brute-force and default-password logins): these can crash your service or lock accounts."
)

// Terms is who accepted the testing terms of a target, when, and the exact text of the version they saw (FULL-1). UserID and Method
// (how two-step was met) are kept in the row and the audit line, not in the API.
type Terms struct {
	Version    string `json:"version"`
	By         string `json:"by"`
	At         string `json:"at"`
	Text       string `json:"text"`
	Disruptive bool   `json:"disruptive"` // the extra tick: the disruptive checks too (its sentence is then part of Text)
	UserID     string `json:"-"`
	Method     string `json:"-"`
}

// current says the acceptance is of the terms in force: one of an older version counts as not accepted.
func (t *Terms) current() bool { return t != nil && t.Version == TermsVersion }

// ScanMode is what a scan of a target may do, read by every scanner seam from ScanTarget (FULL-1): Full once the target's testing
// terms of the current version are accepted (else the K-4 scope), Disruptive when the extra tick was accepted with them.
type ScanMode struct {
	Full       bool
	Disruptive bool
}

func (t Target) mode() ScanMode {
	full := t.Terms.current()
	return ScanMode{Full: full, Disruptive: full && t.Terms.Disruptive}
}

// ModeNow is the scan mode of target id right before a deep job leaves core (FULL-4, D-526/D-527; added by Trưởng for the scanner
// adapters in cmd/vedette, flagged for Mlee): exposure's gate again with actor, then the terms as stored now. A target the gate
// refuses, or whose terms were withdrawn or are of an older version meanwhile, is the zero ScanMode (the K-4 scope); the tick taken
// back keeps Full without Disruptive. The ScanTarget.Mode of the run is minutes old by then, like the gate of the run.
func (s *Service) ModeNow(ctx context.Context, actor, id string) (ScanMode, error) {
	t, reason, err := s.gate(ctx, actor, id)
	if err != nil || reason != "" {
		return ScanMode{}, err
	}
	return t.mode(), nil
}

// TermsNotice is the terms as the page shows them (contract.ts TermsNotice): the version, the text with the target in it (one
// paragraph per line) and the sentence of the extra tick.
type TermsNotice struct {
	Version    string `json:"version"`
	Text       string `json:"text"`
	Disruptive string `json:"disruptive"`
}

// termsFor is the current terms for one target: a domain's text or an IP's (D-571); a domain or an IP has no braces, so the value
// cannot substitute again.
func termsFor(k Kind, value string) TermsNotice {
	tmpl := termsTemplate
	if k == KindDomain {
		tmpl = termsTemplateDomain
	}
	return TermsNotice{Version: TermsVersion, Text: strings.ReplaceAll(tmpl, "{value}", value), Disruptive: termsDisruptive}
}

// cgnat is the shared address space of carrier-grade NAT (RFC 6598).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// sharedAddress is the warning of the terms step of an IP target when the box's default gateway is in 100.64.0.0/10 (D-566 review r1
// M2): the box then reaches the Internet through carrier-grade NAT, so its public IP is the provider's, shared with other customers,
// and its open ports are the provider's. The disruptive tick is refused while it shows. ponytail: only the box's own gateway is
// known here (a home router whose WAN side is CGNAT is not seen); upgrade: the host reports the router's WAN address (UPnP or the
// second hop of a traceroute). "" when not known to be shared (no Gateway wired, or the lookup failed).
func (s *Service) sharedAddress(ctx context.Context, t Target) string {
	if t.Kind != KindIP || s.cfg.Gateway == nil {
		return ""
	}
	g, err := s.cfg.Gateway.Gateway(ctx)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the gateway for the testing terms", "err", err)
		return ""
	}
	if !g.IP.IsValid() || !cgnat.Contains(g.IP.Unmap()) {
		return ""
	}
	return fmt.Sprintf("This box reaches the Internet through carrier-grade NAT (its gateway %s is in 100.64.0.0/10), so %s is probably shared with your provider's other customers and its open ports are the provider's. "+
		"The disruptive checks cannot be accepted for it; accept the deep scan only if your provider confirms the address is yours alone.", g.IP, t.Value)
}

func errTermsChanged() *APIError {
	return apiErr(409, "notice_changed", "The testing terms changed since this page loaded. Read them again, then accept them again.")
}

// AcceptTerms is PUT /exposure/targets/{id}/terms (admin with two-step sign-in, FULL-1): the target must be verified and the request
// must carry the version the page showed and whether the disruptive tick is on. It stores who, when, the version, the flag and the
// exact text (with the tick's sentence when ticked) with an exposure.terms_accept audit row naming the flag, in one transaction. The
// terms include the ownership and authorization sentence, so a target without a commitment of the current Scan now sentence gets that
// one too (its own exposure.commitment row). Accepting what is already accepted changes nothing; changing only the tick is a new
// acceptance.
func (s *Service) AcceptTerms(ctx context.Context, who Actor, id, version string, disruptive bool) (TargetView, error) {
	if !who.Admin {
		return TargetView{}, apiErr(403, "forbidden", "Only an administrator can accept the testing terms.")
	}
	if s.cfg.TwoStep == nil {
		return TargetView{}, errNeedTwoStep()
	}
	method, err := s.cfg.TwoStep(ctx, who.ID)
	if err != nil {
		return TargetView{}, fmt.Errorf("checking two-step sign-in: %w", err)
	}
	if method == "" {
		return TargetView{}, errNeedTwoStep()
	}
	if version != TermsVersion {
		return TargetView{}, errTermsChanged()
	}
	if disruptive {
		t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
		if err != nil {
			return TargetView{}, err
		}
		if w := s.sharedAddress(ctx, t); w != "" {
			return TargetView{}, apiErr(409, "shared_address", "%s", w)
		}
	}
	newMode := ScanMode{Full: true, Disruptive: disruptive}
	value := ""
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock()
		switch t.status(now) {
		case statusUnverified:
			return apiErr(409, "not_verified", "Verify ownership first; only then can the testing terms be accepted.")
		case statusExpired:
			return apiErr(409, "expired", "Verification of %s has expired. Verify it again first.", t.Value)
		}
		if t.Kind == KindIP { // paused: the box no longer goes out through it, so it is not shown to be the box's own now (review r1 L2)
			c, err := s.loadChecks(ctx, tx)
			if err != nil {
				return err
			}
			if c.paused(t) {
				return apiErr(409, "ip_not_current", "This box no longer reaches the Internet through %s; it was last seen %s. Its testing terms can be accepted once the box uses it again.", t.Value, s.momentText(t.VerifiedAt))
			}
		}
		if t.Terms.current() && t.Terms.Disruptive == disruptive {
			return nil
		}
		if !t.Commitment.current() {
			n := noticeFor(t.Value)
			if err := setCommitment(ctx, tx, id, who.Email, now, n, who.ID, method); err != nil {
				return err
			}
			if err := s.audit(ctx, tx, who.Email, "exposure.commitment", t.Value, "confirmed by accepting the testing terms (user "+who.ID+", two-step: "+method+", notice "+n.Version+"): "+n.Text); err != nil {
				return err
			}
		}
		n := termsFor(t.Kind, t.Value)
		text, flag := n.Text, "disruptive checks: no"
		if disruptive {
			text, flag = n.Text+"\n"+n.Disruptive, "disruptive checks: yes"
		}
		what := "accepted"
		if t.Terms != nil {
			what = "accepted again (replaces terms " + t.Terms.Version + ", accepted by " + t.Terms.By + " at " + t.Terms.At + ", disruptive checks: " + yesNo(t.Terms.Disruptive) + ")"
		}
		if err := setTerms(ctx, tx, id, &Terms{Version: n.Version, By: who.Email, At: store.FormatTS(now), Text: text, Disruptive: disruptive, UserID: who.ID, Method: method}); err != nil {
			return err
		}
		value = t.Value
		return s.audit(ctx, tx, who.Email, "exposure.terms_accept", t.Value, auditClip(what+" ("+flag+", user "+who.ID+", two-step: "+method+", terms "+n.Version+"): "+text))
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: accepting the testing terms: %w", err)
	}
	if value != "" { // the terms changed: the tick taken back stops a disruptive scan that runs (review r1 M1)
		s.stopRunAbove(ctx, id, value, newMode, who.Email, "exposure.terms_accept", "the disruptive checks were taken out of this target's testing terms")
	}
	return s.Target(ctx, id)
}

// auditDetailMax is core/audit's limit on a detail, in characters.
const auditDetailMax = 2000

// termsClipNote ends an audit detail whose terms text was cut (D-571: a domain's text with a long name, and the tick's sentence, can pass
// auditDetailMax). The whole text stays in the target's row (terms_text) and each version's text is pinned in code.
const termsClipNote = " … (cut here; the whole text is stored with the acceptance and pinned to its version)"

// auditClip keeps an audit detail within auditDetailMax characters, cutting its end and saying so.
func auditClip(d string) string {
	if utf8.RuneCountInString(d) <= auditDetailMax {
		return d
	}
	return clipText(d, auditDetailMax-utf8.RuneCountInString(termsClipNote)) + termsClipNote
}

// above says whether mode a may do more than mode b (D-566 review r1 M1).
func (a ScanMode) above(b ScanMode) bool {
	return (a.Full && !b.Full) || (a.Disruptive && !b.Disruptive)
}

// stopRunAbove cancels the run of target id when its mode is above m (D-566 review r1 M1): withdrawing or lowering the terms must
// reach a scan that runs now, the case where the service is being hurt. Every step reads the run's context: the Greenbone step stops
// gvmd's task (stop_task) and keeps the snapshot of the earlier steps, as a Stop does. The run is found and cancelled under runMu in
// one step, and only a run really cancelled gets its own audit row (review r2 L1), on the action of the terms change, after its row.
func (s *Service) stopRunAbove(ctx context.Context, id, value string, m ScanMode, user, action, why string) {
	s.runMu.Lock()
	r := s.run
	stop := r != nil && r.view.Status == RunRunning && r.view.TargetID == id && r.mode.above(m)
	if stop {
		r.cancel(&stoppedBy{by: user + " (" + why + ")", why: why})
	}
	s.runMu.Unlock()
	if !stop {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	if err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		return s.audit(wctx, tx, user, action, value, stoppedNote+" ("+why+")")
	}); err != nil {
		s.cfg.Log.ErrorContext(wctx, "exposure: auditing the stop of a scan by a terms change failed", "target", value, "error", err)
	}
}

// stoppedNote is the audit row written when a terms change really stopped the running scan.
const stoppedNote = "the scan of this target that was running was stopped"

// RevokeTerms is DELETE /exposure/targets/{id}/terms (admin, FULL-1): always possible; the next scan runs in the K-4 scope again, and
// a scan of this target that runs now at full depth is stopped (review r1 M1).
func (s *Service) RevokeTerms(ctx context.Context, user, id string) (TargetView, error) {
	value := ""
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		if t.Terms == nil {
			return nil
		}
		if err := setTerms(ctx, tx, id, nil); err != nil {
			return err
		}
		value = t.Value
		return s.audit(ctx, tx, user, "exposure.terms_revoke", t.Value, "withdrawn (terms "+t.Terms.Version+", disruptive checks: "+yesNo(t.Terms.Disruptive)+", accepted by "+t.Terms.By+" at "+t.Terms.At+")")
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: withdrawing the testing terms: %w", err)
	}
	if value != "" {
		s.stopRunAbove(ctx, id, value, ScanMode{}, user, "exposure.terms_revoke", "the testing terms of this target were withdrawn")
	}
	return s.Target(ctx, id)
}

// setTerms stores an acceptance, or clears it (nil).
func setTerms(ctx context.Context, tx *sql.Tx, id string, t *Terms) error {
	var v, by, at, text, uid, method any
	disruptive := 0
	if t != nil {
		v, by, at, text, uid, method = t.Version, t.By, t.At, t.Text, nullIf(t.UserID), nullIf(t.Method)
		if t.Disruptive {
			disruptive = 1
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET terms_version = ?, terms_by = ?, terms_at = ?, terms_text = ?, terms_user_id = ?, terms_method = ?, terms_disruptive = ? WHERE id = ?`,
		v, by, at, text, uid, method, disruptive, id); err != nil {
		return fmt.Errorf("recording the testing terms of %s: %w", id, err)
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
