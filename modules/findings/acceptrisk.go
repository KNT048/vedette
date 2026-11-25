package findings

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// ErrNothingToAccept is an accept of a device or software line that has no open question and no confirmed open finding.
var ErrNothingToAccept = &APIError{"not_found", 404, "Nothing is open on this device or software to accept the risk of."}

// AcceptResult is what AcceptRiskQuestions did.
type AcceptResult struct {
	Questions int // open questions answered "affected"
	Findings  int // findings that are accepted until the day now (new ones recorded from the questions, and confirmed open ones)
}

// AcceptRiskQuestions accepts the risk of one device (software "") or of one software line of it until a day, on the person's word, in
// one transaction: every open question there is answered "affected" and the finding of each CVE it asks about is recorded and handled
// as accepted until the day, and so is every confirmed open finding of the scope. "Vedette cannot check this device" is not a
// question about a CVE and is left. With question set the scope is that one question (one CVE row behind a software line): only its
// CVEs are accepted, no other finding. The acceptance ends by itself after the day (the findings open again); a CVE that matches later
// is a new question. One summary audit row, next to the history row of each finding. The note says why and is required.
func (s *Service) AcceptRiskQuestions(ctx context.Context, device, software, question, note string, until time.Time, user string) (AcceptResult, error) {
	var out AcceptResult
	if err := ValidUser(user); err != nil {
		return out, err
	}
	note, err := personNote(note, true)
	if err != nil {
		return out, err
	}
	if err := validUntil(until, s.now()); err != nil {
		return out, err
	}
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		out = AcceptResult{}
		if err := validUntil(until, now); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+questionColumns+` FROM fnd_question
			WHERE answer IS NULL AND kind <> ?1 AND asset_id = ?2 AND (?3 = '' OR software_id = ?3) AND (?4 = '' OR id = ?4) ORDER BY asked_at, id`,
			string(QuestionNothingToCheck), device, software, question)
		if err != nil {
			return fmt.Errorf("findings: reading the questions to accept: %w", err)
		}
		var qs []Question
		for rows.Next() {
			q, err := scanQuestion(rows)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("findings: reading a question: %w", err)
			}
			qs = append(qs, q)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("findings: reading the questions to accept: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("findings: reading the questions to accept: %w", err)
		}
		ids := map[string]bool{}
		for _, x := range qs {
			cves := []string{x.CVE}
			if x.CVE == "" {
				cves = slices.Clone(x.Detail.CVEList)
			}
			for _, c := range cves {
				if c == "" {
					continue
				}
				y := x
				y.CVE = c
				id, err := s.affectedByPerson(ctx, tx, y, note, user, now, emit)
				if err != nil {
					return err
				}
				ids[id] = true
			}
			if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET answer = ?, answered_by = ?, answered_at = ? WHERE id = ?`,
				AnswerAffected, user, store.FormatTS(now), x.ID); err != nil {
				return fmt.Errorf("findings: answering a question: %w", err)
			}
			out.Questions++
		}
		if question == "" { // the confirmed open findings of the same scope get the same acceptance
			where, args := `asset_id = ? AND state = ?`, []any{device, string(StateOpen)}
			if software != "" {
				where, args = where+` AND ifnull(software_id, '') = ?`, append(args, software)
			}
			open, err := queryFindings(ctx, tx, where, args...)
			if err != nil {
				return err
			}
			for _, f := range open {
				if f.Confirmed() {
					ids[f.ID] = true
				}
			}
		}
		if len(ids) == 0 {
			return ErrNothingToAccept
		}
		for _, id := range slices.Sorted(maps.Keys(ids)) {
			f, err := loadFinding(ctx, tx, id)
			if err != nil {
				return err
			}
			_, evs, err := s.step(ctx, tx, f, false, Trigger{Kind: TrHandle, At: now, Actor: user, Resolution: ResolutionAccepted, Note: note, Until: until}, emit)
			if err != nil {
				return err
			}
			if len(evs) > 0 {
				out.Findings++
			}
		}
		what := fmt.Sprintf("risk accepted on %s until %s: %d questions answered affected, %d findings accepted", device, until.Format(time.DateOnly), out.Questions, out.Findings)
		target := device
		if software != "" {
			what += " (software line " + software + ")"
			target = software
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.risk_accepted_in_bulk", Target: target, Detail: what + ": " + note})
	})
	if err != nil {
		return AcceptResult{}, err
	}
	return out, nil
}
