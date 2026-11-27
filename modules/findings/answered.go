package findings

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Answered questions: a question a person answered "not affected" leaves Needs your input, and no finding records it. A wrong click
// must not be final, so these answers are listed (GET /findings/answered) and each can be taken back (POST
// /findings/questions/{id}/unanswer): the question is asked again, as it was. An "affected" answer made a finding; it is changed on
// the finding's page (Undo Confirm vulnerability, Mark as handled), never here.

// ErrNotAnswered refuses taking back an answer that is not a "not affected" one.
var ErrNotAnswered = &APIError{"not_answered", 409, "This question has no \"not affected\" answer to take back. An \"affected\" answer is changed on its finding's page."}

// AnsweredJS is contract.ts AnsweredQuestion.
type AnsweredJS struct {
	ID       string         `json:"id"`
	Question string         `json:"question"`
	Device   deviceRefJS    `json:"device"`
	Software *softwareRefJS `json:"software"`
	CVE      *string        `json:"cve"`
	CVEs     int            `json:"cves"`
	Answer   string         `json:"answer"`
	By       string         `json:"by"`
	At       string         `json:"at"`
	Check    *CheckJS       `json:"check"` // the check of its evidence stored by the time of the answer (a confirmed AI proposal, an advisory); nil when none
}

// AnsweredList is contract.ts AnsweredList.
type AnsweredList struct {
	Items []AnsweredJS `json:"items"`
	Total int          `json:"total"`
}

// Answered reads one page of the questions answered "not affected" (of one device when device is set), the newest answer first.
// Devices a person ignored are left out, as in Needs your input.
func (s *Service) Answered(ctx context.Context, device string, p Page) (AnsweredList, error) {
	out := AnsweredList{Items: []AnsweredJS{}}
	err := s.readTx(ctx, func(ctx context.Context) error {
		ignored, err := s.cfg.Inventory.IgnoredIDs(ctx)
		if err != nil {
			return fmt.Errorf("findings: reading the ignored devices: %w", err)
		}
		ig, _ := json.Marshal(nonNilStrings(ignored))
		rows, err := s.rd(ctx).QueryContext(ctx, `SELECT `+questionColumns+` FROM fnd_question
			WHERE answer = ? AND asset_id NOT IN (SELECT value FROM json_each(?)) AND (?3 = '' OR asset_id = ?3)
			ORDER BY answered_at DESC, id`, AnswerNotAffected, string(ig), device)
		if err != nil {
			return fmt.Errorf("findings: reading answered questions: %w", err)
		}
		var qs []Question
		for rows.Next() {
			x, err := scanQuestion(rows)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("findings: reading answered questions: %w", err)
			}
			qs = append(qs, x)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("findings: reading answered questions: %w", err)
		}
		out.Total = len(qs)
		lo, hi := p.cut(len(qs))
		qs = qs[lo:hi]
		assets, lines := map[string]bool{}, map[string]bool{}
		for _, x := range qs {
			assets[x.AssetID] = true
			if x.SoftwareID != "" {
				lines[x.SoftwareID] = true
			}
		}
		ref, err := s.refs(ctx, keys(assets), keys(lines), nil)
		if err != nil {
			return err
		}
		checks, err := checksFor(ctx, s.rd(ctx), qs)
		if err != nil {
			return err
		}
		readings, err := readingsFor(ctx, s.rd(ctx), qs)
		if err != nil {
			return err
		}
		for _, x := range qs {
			it := AnsweredJS{ID: x.ID, Question: string(x.Kind), Device: deviceRef(ref.device(x.AssetID)), CVEs: max(x.Cves, 1),
				Answer: x.Answer, By: x.AnsweredBy, At: store.FormatTS(x.AnsweredAt)}
			if l, ok := ref.lines[x.SoftwareID]; ok && x.SoftwareID != "" {
				sw := &softwareRefJS{ID: l.ID, Name: cmp.Or(x.Detail.Software, l.Display)}
				if v := cmp.Or(x.Detail.Version, l.Version); v != "" {
					sw.Version = &v
				}
				it.Software = sw
			}
			if x.CVE != "" {
				cve := x.CVE
				it.CVE = &cve
			}
			// only a check stored by the time of the answer: one made later (for another device sharing the evidence) was not
			// what the person answered against
			if c, ok := checks[x.CheckKey]; ok && x.CheckKey != "" && !c.CheckedAt.After(x.AnsweredAt) {
				it.Check = checkJS(&c)
			} else if r, ok := readings[x.CheckKey]; ok && r.applied != nil && x.Detail.Check != nil && !r.applied.AskedAt.After(x.AnsweredAt) {
				c := r.applied.asCheck(*x.Detail.Check) // a person confirmed the AI's reading of the line
				it.Check = checkJS(&c)
			}
			out.Items = append(out.Items, it)
		}
		return nil
	})
	if err != nil {
		return AnsweredList{}, err
	}
	return out, nil
}

// UnanswerQuestion takes back a "not affected" answer: the question is open again and waits in Needs your input. One audit row.
func (s *Service) UnanswerQuestion(ctx context.Context, id, user string) error {
	if err := ValidUser(user); err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, _ time.Time, _ func(string, any)) error {
		x, err := scanQuestion(tx.QueryRowContext(ctx, `SELECT `+questionColumns+` FROM fnd_question WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoQuestion
		}
		if err != nil {
			return fmt.Errorf("findings: reading a question: %w", err)
		}
		if x.Answer != AnswerNotAffected {
			return ErrNotAnswered
		}
		if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET answer = NULL, answered_by = NULL, answered_at = NULL WHERE id = ?`, x.ID); err != nil {
			return fmt.Errorf("findings: taking back an answer: %w", err)
		}
		detail := questionAuditDetail(x, "asked again (was not affected, answered by "+x.AnsweredBy+")")
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.question_unanswered", Target: x.ID, Detail: strings.TrimSpace(detail)})
	})
}
