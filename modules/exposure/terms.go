package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/store"
)

// The testing terms of a verified target (FULL-1, D-566; kien 2026-11-14: "say it clearly in the terms, then use the tools to their
// full capability", and finally: deep by default after the disclosure, disruptive checks only with their own tick). One acceptance
// per target, by an administrator with two-step sign-in, makes every scan of that target a deep scan (ScanMode.Full); the one extra
// tick, off by default, adds the disruptive checks (ScanMode.Disruptive). Without an acceptance a target keeps the K-4 scope of the
// Scan now sentence (D-559): passive web scan, read-only nuclei (D-520), no Greenbone. It can be withdrawn at any time; a new
// TermsVersion asks again. The texts are the only copy: the API sends them with the target in it and the page shows what it got;
// the mock's copy (contract.ts TERMS_TEMPLATE, TERMS_DISRUPTIVE) is held equal by a test, and each version's text is pinned.
const (
	TermsVersion  = "2026-11-14"
	termsTemplate = "I confirm that my company owns {value} and that I am authorized to test it in depth. Once I accept, every scan of {value} is a deep scan, and Vedette's tools may send it:\n" +
		"All ports: every TCP port, and the service and version behind each one.\n" +
		"Version and exploit-confirming checks: tests for known vulnerabilities, some of which confirm a flaw by sending the exploit request itself (for example reading a file or running a harmless command).\n" +
		"An active web scan that submits forms: a spider and an active scan that fill in and send forms and send attack payloads such as SQL injection and cross-site scripting probes. It can create records, send e-mails from forms or change data.\n" +
		"Authentication checks: whether login pages, admin interfaces and services let anyone in without a password or with weak settings. Passwords are not guessed unless the disruptive checks below are ticked.\n" +
		"The deep scan can load or slow the services on {value} and may create, change or delete data. Run scans when you can accept that, and keep a backup. " +
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

// TermsNotice is the terms as the page shows them (contract.ts TermsNotice): the version, the text with the target in it (one
// paragraph per line) and the sentence of the extra tick.
type TermsNotice struct {
	Version    string `json:"version"`
	Text       string `json:"text"`
	Disruptive string `json:"disruptive"`
}

// termsFor is the current terms for one target (a domain or an IP has no braces, so the value cannot substitute again).
func termsFor(value string) TermsNotice {
	return TermsNotice{Version: TermsVersion, Text: strings.ReplaceAll(termsTemplate, "{value}", value), Disruptive: termsDisruptive}
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
		n := termsFor(t.Value)
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
		return s.audit(ctx, tx, who.Email, "exposure.terms_accept", t.Value, what+" ("+flag+", user "+who.ID+", two-step: "+method+", terms "+n.Version+"): "+text)
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: accepting the testing terms: %w", err)
	}
	return s.Target(ctx, id)
}

// RevokeTerms is DELETE /exposure/targets/{id}/terms (admin, FULL-1): always possible; the next scan runs in the K-4 scope again.
// A scan that runs now keeps the mode it started with, except Greenbone, whose step checks the terms again right before it starts.
func (s *Service) RevokeTerms(ctx context.Context, user, id string) (TargetView, error) {
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
		return s.audit(ctx, tx, user, "exposure.terms_revoke", t.Value, "withdrawn (terms "+t.Terms.Version+", disruptive checks: "+yesNo(t.Terms.Disruptive)+", accepted by "+t.Terms.By+" at "+t.Terms.At+")")
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: withdrawing the testing terms: %w", err)
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
