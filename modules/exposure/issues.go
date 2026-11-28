package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
)

// A person handles an issue the way a finding is handled (the shared status vocabulary): patched, mitigated, accepted until a last
// day, not relevant or a false positive, with a note that says why for the three that leave the flaw in place. The scan writer keeps a
// handled issue handled (writeIssues); an accepted one opens again by itself after its last day (RunAcceptExpiry).

// Resolution is how a person handled an issue (exp_issue.resolution): the findings vocabulary, same values and order.
type Resolution string

// The resolutions.
const (
	ResolvedPatched       Resolution = "patched"
	ResolvedMitigated     Resolution = "mitigated"
	ResolvedAccepted      Resolution = "accepted"
	ResolvedNotRelevant   Resolution = "not_relevant"
	ResolvedFalsePositive Resolution = "false_positive"
)

// Resolutions lists every resolution.
var Resolutions = []Resolution{ResolvedPatched, ResolvedMitigated, ResolvedAccepted, ResolvedNotRelevant, ResolvedFalsePositive}

// Valid reports whether r is one of Resolutions.
func (r Resolution) Valid() bool { return slices.Contains(Resolutions, r) }

// needsNote says the flaw stays where it is, so the next person must read why.
func (r Resolution) needsNote() bool {
	return r == ResolvedAccepted || r == ResolvedNotRelevant || r == ResolvedFalsePositive
}

// Limits of handling issues.
const (
	MaxIssueIDs   = 500 // issues one request handles or reopens
	MinIssueNote  = 3   // characters of the note a resolution that leaves the flaw needs
	MaxIssueNote  = 500 // characters of a note
	MaxAcceptDays = 365 // the last day of an accepted risk is at most this many days ahead
)

// The refusals of handling issues (the texts of the mock and of findings).
var (
	ErrIssueIDs     = apiErr(400, "bad_value", "Choose between 1 and %d issues.", MaxIssueIDs)
	ErrResolution   = apiErr(400, "bad_value", "Choose how the issues were handled.")
	ErrIssueNote    = apiErr(400, "bad_value", "The note is at most %d characters.", MaxIssueNote)
	ErrNoteRequired = apiErr(400, "note_required", "Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.")
	ErrBadUntil     = apiErr(400, "bad_until", "Accept the risk until a date from tomorrow up to one year from today.")
	ErrUntilOnly    = apiErr(400, "bad_until", "A last day is set only when the risk is accepted.")
)

// HandleResult is the answer of POST /exposure/issues/handle.
type HandleResult struct {
	Handled int `json:"handled"`
	Skipped int `json:"skipped"`
}

// ReopenResult is the answer of POST /exposure/issues/reopen.
type ReopenResult struct {
	Reopened int `json:"reopened"`
	Skipped  int `json:"skipped"`
}

// uniqueIDs checks a list of issue ids and drops repeats.
func uniqueIDs(ids []string) ([]string, error) {
	out := slices.Compact(slices.Sorted(slices.Values(ids)))
	if len(out) == 0 || len(ids) > MaxIssueIDs || slices.Contains(out, "") {
		return nil, ErrIssueIDs
	}
	return out, nil
}

// acceptUntil checks the last day of an accepted risk: a calendar day from tomorrow to MaxAcceptDays ahead (UTC days, as findings and
// the page count them).
func acceptUntil(raw string, now time.Time) (string, error) {
	d, err := time.Parse(time.DateOnly, raw)
	if err != nil || d.Format(time.DateOnly) != raw {
		return "", ErrBadUntil
	}
	y, m, day := now.UTC().Date()
	today := time.Date(y, m, day, 0, 0, 0, 0, time.UTC)
	if !d.After(today) || d.After(today.AddDate(0, 0, MaxAcceptDays)) {
		return "", ErrBadUntil
	}
	return raw, nil
}

// HandleIssues marks the open issues among ids as handled with one resolution and note (POST /exposure/issues/handle), one audit row
// per issue, in one write. Issues that are not open (gone, handled, or no such issue) are skipped and counted.
func (s *Service) HandleIssues(ctx context.Context, user string, ids []string, res Resolution, note, until string) (HandleResult, error) {
	ids, err := uniqueIDs(ids)
	if err != nil {
		return HandleResult{}, err
	}
	if !res.Valid() {
		return HandleResult{}, ErrResolution
	}
	note = strings.TrimSpace(note)
	switch n := utf8.RuneCountInString(note); {
	case n > MaxIssueNote:
		return HandleResult{}, ErrIssueNote
	case res.needsNote() && n < MinIssueNote:
		return HandleResult{}, ErrNoteRequired
	}
	now := s.clock()
	switch {
	case res == ResolvedAccepted:
		if until, err = acceptUntil(until, now); err != nil {
			return HandleResult{}, err
		}
	case until != "":
		return HandleResult{}, ErrUntilOnly
	}
	out := HandleResult{}
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		out = HandleResult{}
		for _, id := range ids {
			what, err := issueLabel(ctx, tx, id, IssueOpen)
			if errors.Is(err, sql.ErrNoRows) {
				out.Skipped++
				continue
			}
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET state = 'handled', resolution = ?, resolved_by = ?, resolved_at = ?, note = ?, accepted_until = ?
				WHERE id = ? AND state = 'open'`, string(res), clipText(user, 320), store.FormatTS(now), nullString(note), nullString(until), id); err != nil {
				return fmt.Errorf("handling issue %s: %w", id, err)
			}
			detail := string(res)
			if until != "" {
				detail += " until " + until
			}
			if note != "" {
				detail += ": " + note
			}
			if err := s.audit(ctx, tx, user, "exposure.issue_handle", what, detail); err != nil {
				return err
			}
			out.Handled++
		}
		return nil
	})
	if err != nil {
		return HandleResult{}, fmt.Errorf("exposure: handling issues: %w", err)
	}
	return out, nil
}

// ReopenIssues opens the handled issues among ids again (POST /exposure/issues/reopen), one audit row per issue; the others are skipped.
func (s *Service) ReopenIssues(ctx context.Context, user string, ids []string) (ReopenResult, error) {
	ids, err := uniqueIDs(ids)
	if err != nil {
		return ReopenResult{}, err
	}
	out := ReopenResult{}
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		out = ReopenResult{}
		for _, id := range ids {
			was, what, err := reopenIssue(ctx, tx, id)
			if errors.Is(err, sql.ErrNoRows) {
				out.Skipped++
				continue
			}
			if err != nil {
				return err
			}
			if err := s.audit(ctx, tx, user, "exposure.issue_reopen", what, "was "+was); err != nil {
				return err
			}
			out.Reopened++
		}
		return nil
	})
	if err != nil {
		return ReopenResult{}, fmt.Errorf("exposure: reopening issues: %w", err)
	}
	return out, nil
}

// issueLabel names issue id in the state given for the audit trail ("acme.example: Expired certificate"); sql.ErrNoRows when there is
// no such issue in that state.
func issueLabel(ctx context.Context, tx *sql.Tx, id, state string) (string, error) {
	var value, title string
	err := tx.QueryRowContext(ctx, `SELECT t.value, i.title FROM exp_issue i JOIN exp_target t ON t.id = i.target_id WHERE i.id = ? AND i.state = ?`, id, state).
		Scan(&value, &title)
	if err != nil {
		return "", err
	}
	return clipText(value+": "+title, 500), nil
}

// reopenIssue opens the handled issue id again and returns how it was handled and its label; sql.ErrNoRows when it is not handled.
func reopenIssue(ctx context.Context, tx *sql.Tx, id string) (was, what string, err error) {
	if what, err = issueLabel(ctx, tx, id, IssueHandled); err != nil {
		return "", "", err
	}
	if err := tx.QueryRowContext(ctx, `SELECT resolution FROM exp_issue WHERE id = ?`, id).Scan(&was); err != nil {
		return "", "", fmt.Errorf("reopening issue %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET state = 'open', resolution = NULL, resolved_by = NULL, resolved_at = NULL, note = NULL,
		accepted_until = NULL WHERE id = ?`, id); err != nil {
		return "", "", fmt.Errorf("reopening issue %s: %w", id, err)
	}
	return was, what, nil
}

// acceptanceEnds is when an acceptance with last day until has ended everywhere: noon UTC of the next day (the last day is over in every
// time zone), as findings counts it.
func acceptanceEnds(until time.Time) time.Time { return until.AddDate(0, 0, 1).Add(12 * time.Hour) }

// AcceptTick is how often the accept-expiry job looks for accepted risks whose last day is over.
const AcceptTick = time.Hour

// RunAcceptExpiry opens again every accepted issue whose last day is over everywhere, as the system user, with an audit row that names
// who accepted it and until when. The job accept-expiry runs it.
func (s *Service) RunAcceptExpiry(ctx context.Context) error {
	now := s.clock()
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, accepted_until, resolved_by FROM exp_issue WHERE state = 'handled' AND resolution = 'accepted'
			AND accepted_until <= ? ORDER BY id`, now.Format(time.DateOnly))
		if err != nil {
			return fmt.Errorf("accepted issues: %w", err)
		}
		type due struct{ id, until, by string }
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.id, &d.until, &d.by); err != nil {
				_ = rows.Close()
				return fmt.Errorf("accepted issues: %w", err)
			}
			list = append(list, d)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("accepted issues: %w", err)
		}
		for _, d := range list {
			last, err := time.Parse(time.DateOnly, d.until)
			if err != nil || now.Before(acceptanceEnds(last)) {
				continue
			}
			_, what, err := reopenIssue(ctx, tx, d.id)
			if err != nil {
				return err
			}
			// open again: news of the daily summary's span, and told again if its CVE is exploited (the exploited-check job), as an
			// ended risk acceptance of a finding is
			oa, err := openedAt(store.FormatTS(now))
			if err != nil {
				return err
			}
			checked, err := exploitedMark(markChecked)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET opened_at = ?, exploited = ? WHERE id = ?`, oa, checked, d.id); err != nil {
				return fmt.Errorf("reopening issue %s: %w", d.id, err)
			}
			if err := s.audit(ctx, tx, SystemUser, "exposure.issue_reopen", what, "risk acceptance expired (accepted by "+d.by+" until "+d.until+")"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("exposure: reopening accepted issues: %w", err)
	}
	return nil
}

// auditAgain writes, in tx, one audit row by the system for each issue a scan opened again after a person marked it patched or
// mitigated, and returns how each had been marked, by id.
func (s *Service) auditAgain(ctx context.Context, tx *sql.Tx, again []reopenedIssue) (map[string]string, error) {
	out := make(map[string]string, len(again))
	for _, a := range again {
		what, err := issueLabel(ctx, tx, a.id, IssueOpen)
		if err != nil {
			return nil, fmt.Errorf("the issue opened again: %w", err)
		}
		if err := s.audit(ctx, tx, SystemUser, "exposure.issue_reopen", what, "found again by a scan (was "+a.was+" by "+a.by+")"); err != nil {
			return nil, err
		}
		out[a.id] = a.was
	}
	return out, nil
}
