package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// The sentence an administrator's first Scan now confirms (D-473, amending D-26; widened by D-559: a commitment of an older
// version is asked again once, by the first Scan now after the upgrade). It is the only copy: the API sends it with the
// target's name filled in, the page shows what the API sent, the scan request echoes the version, and the commitment stores the
// sentence of that version. Changing the text means a new version, so a page that shows the old one is refused (409 notice_changed)
// instead of recording words nobody read. The mock's copy (web/src/features/exposure/contract.ts) is held equal by a test.
const (
	NoticeVersion  = "2026-11-14"
	noticeTemplate = "By choosing Scan now I confirm that my company owns {value} and that I am authorized to scan it, including identifying its services and versions, " +
		"safe checks for known exploited vulnerabilities and a passive web scan. " +
		"Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it."
)

// Notice is the sentence with its version (contract.ts Notice).
type Notice struct {
	Version string `json:"version"`
	Text    string `json:"text"`
}

// noticeFor is the current sentence for one target. A domain name or an IP has no braces, so the value cannot make a second
// substitution; the text is plain.
func noticeFor(value string) Notice {
	return Notice{Version: NoticeVersion, Text: strings.ReplaceAll(noticeTemplate, "{value}", value)}
}

// Actor is who presses Scan now: the signed-in person, as the server knows them. A zero Actor with only Email is a caller that is
// not a person at a button (tests, a schedule): it can scan what is confirmed and confirm nothing.
type Actor struct {
	ID    string
	Email string
	Admin bool
}

// TwoStep says how a user meets two-step sign-in: "app" or "email" (Vedette's own), "sso" (the identity provider owns MFA, D-473), or "" for none
// (core/auth, wired in cmd/vedette). nil in Config means "none": the first scan
// of a target, which records a legal confirmation, is refused.
type TwoStep func(ctx context.Context, userID string) (method string, err error)

func errNeedAdminFirstScan(value string) *APIError {
	return apiErr(400, "commitment_required", "%s has not been confirmed yet. An administrator must run the first scan: it records that your company owns %s and that the scan is authorized.", value, value)
}

func errNeedAdminReconfirm(value string) *APIError {
	return apiErr(400, "commitment_required", "The confirmation text changed, so %s must be confirmed again. An administrator confirms once with the next Scan now.", value)
}

func errNeedTwoStep() *APIError {
	return apiErr(403, "twofa_required", "Turn on two-step sign-in for your account first (My account), then run the first scan again. The first scan records your confirmation that your company owns the target and that you are authorized to scan it.")
}

func errNoticeMissing(value string) *APIError {
	return apiErr(400, "commitment_required", "The first scan of %s records a confirmation, so the request must carry notice_version of the sentence shown next to Scan now.", value)
}

func errNoticeChanged() *APIError {
	return apiErr(409, "notice_changed", "The confirmation text changed since this page loaded. Read it again, then press Scan now again.")
}

// confirmByScan records the D-26 commitment for the first Scan now of an administrator with two-step sign-in (D-473): who, when,
// which target, and the exact sentence of the version they saw, in the same transaction as the audit row (SYS-3). A target that
// already has a commitment of this version is left alone, so a second click or a second administrator never rewrites the record;
// one of an older version is replaced (D-559), with an audit row naming the old version.
func (s *Service) confirmByScan(ctx context.Context, who Actor, t Target, version string) error {
	if s.cfg.TwoStep == nil {
		return errNeedTwoStep()
	}
	method, err := s.cfg.TwoStep(ctx, who.ID)
	if err != nil {
		return fmt.Errorf("checking two-step sign-in: %w", err)
	}
	if method == "" {
		return errNeedTwoStep()
	}
	switch {
	case version == "" && t.Commitment != nil: // a page loaded before the sentence changed sends none: it is stale, not a missing first scan
		return errNoticeChanged()
	case version == "":
		return errNoticeMissing(t.Value)
	case version != NoticeVersion:
		return errNoticeChanged()
	}
	return s.commit(ctx, who, method, t.ID, noticeFor(t.Value))
}

// commit stores the commitment of a verified target with the sentence it was given (INV-7). It is a no-op when one of the same
// version exists; one of an older version (or none recorded) is replaced (D-559).
func (s *Service) commit(ctx context.Context, who Actor, method, id string, n Notice) error {
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock()
		switch t.status(now) {
		case statusUnverified:
			return apiErr(409, "not_verified", "Verify ownership first; only then can this target be scanned.")
		case statusExpired:
			return apiErr(409, "expired", "Verification of %s has expired. Verify it again first.", t.Value)
		}
		if t.Commitment.current() {
			return nil
		}
		what := "confirmed by the first Scan now"
		if t.Commitment != nil {
			old := "recorded before versions"
			if t.Commitment.Version != nil {
				old = *t.Commitment.Version
			}
			what = "re-confirmed under the new sentence (replaces notice " + old + ", confirmed by " + t.Commitment.By + " at " + t.Commitment.At + ")"
		}
		if err := setCommitment(ctx, tx, id, who.Email, now, n, who.ID, method); err != nil {
			return err
		}
		return s.audit(ctx, tx, who.Email, "exposure.commitment", t.Value, what+" (user "+who.ID+", two-step: "+method+", notice "+n.Version+"): "+n.Text)
	})
	if err != nil {
		return fmt.Errorf("exposure: recording commitment: %w", err)
	}
	return nil
}
