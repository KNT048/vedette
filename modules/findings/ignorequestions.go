package findings

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// ErrNothingToIgnore is an ignore of a device or software line that has no open question.
var ErrNothingToIgnore = &APIError{"not_found", 404, "This device has no open question to ignore."}

// IgnoreQuestions answers "not affected" to every open question of one device (software "") or of one software line of it, in one
// transaction with one audit row: the bypass of Needs your input, for a line or a device a person has no answer for and does not want
// asked about. "Vedette cannot check this device" is not a question a person can ignore away and is left. Each answered question is
// listed under Answered and can be asked again one by one. It returns how many questions it answered.
func (s *Service) IgnoreQuestions(ctx context.Context, device, software, note, user string) (int, error) {
	if err := ValidUser(user); err != nil {
		return 0, err
	}
	note, err := personNote(note, false)
	if err != nil {
		return 0, err
	}
	n := 0
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		res, err := tx.ExecContext(ctx, `UPDATE fnd_question SET answer = ?1, answered_by = ?2, answered_at = ?3
			WHERE answer IS NULL AND kind <> ?4 AND asset_id = ?5 AND (?6 = '' OR software_id = ?6)`,
			AnswerNotAffected, user, store.FormatTS(now), string(QuestionNothingToCheck), device, software)
		if err != nil {
			return fmt.Errorf("findings: ignoring questions: %w", err)
		}
		c, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("findings: ignoring questions: %w", err)
		}
		if n = int(c); n == 0 {
			return ErrNothingToIgnore
		}
		what := fmt.Sprintf("%d questions on %s answered not affected", n, device)
		target := device
		if software != "" {
			what += " (software line " + software + ")"
			target = software
		}
		if note != "" {
			what += ": " + note
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.questions_ignored", Target: target, Detail: what})
	})
	return n, err
}
