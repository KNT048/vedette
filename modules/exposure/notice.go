package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// The sentence an administrator's first Scan now confirms (D-473, amending D-26). It is the only copy: the API sends it with the
// target's name filled in, the page shows what the API sent, the scan request echoes the version, and the commitment stores the
// sentence of that version. Changing the text means a new version, so a page that shows the old one is refused (409 notice_changed)
// instead of recording words nobody read. The mock's copy (web/src/features/exposure/contract.ts) is held equal by a test.
const (
	NoticeVersion  = "2026-11-13"
	noticeTemplate = "By choosing Scan now I confirm that my company owns {value} and that I am authorized to scan it. " +
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

// TwoStep says whether a user has two-step sign-in on (core/auth, wired in cmd/vedette). nil in Config means "no": the first scan
// of a target, which records a legal confirmation, is refused.
type TwoStep func(ctx context.Context, userID string) (bool, error)

func errNeedAdminFirstScan(value string) *APIError {
	return apiErr(400, "commitment_required", "%s has not been confirmed yet. An administrator must run the first scan: it records that your company owns %s and that the scan is authorized.", value, value)
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
// already has a commitment is left alone, so a second click or a second administrator never rewrites the first record.
func (s *Service) confirmByScan(ctx context.Context, who Actor, t Target, version string) error {
	if s.cfg.TwoStep == nil {
		return errNeedTwoStep()
	}
	on, err := s.cfg.TwoStep(ctx, who.ID)
	if err != nil {
		return fmt.Errorf("checking two-step sign-in: %w", err)
	}
	if !on {
		return errNeedTwoStep()
	}
	switch {
	case version == "":
		return errNoticeMissing(t.Value)
	case version != NoticeVersion:
		return errNoticeChanged()
	}
	return s.commit(ctx, who.Email, t.ID, noticeFor(t.Value))
}

// commit stores the commitment of a verified target with the sentence it was given (INV-7). It is a no-op when one exists.
func (s *Service) commit(ctx context.Context, user, id string, n Notice) error {
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
		if t.Commitment != nil {
			return nil
		}
		if err := setCommitment(ctx, tx, id, user, now, n); err != nil {
			return err
		}
		return s.audit(ctx, tx, user, "exposure.commitment", t.Value, "confirmed by the first Scan now (notice "+n.Version+"): "+n.Text)
	})
	if err != nil {
		return fmt.Errorf("exposure: recording commitment: %w", err)
	}
	return nil
}
