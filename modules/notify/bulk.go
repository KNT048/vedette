package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// MaxBulkIncidents is how many incidents one bulk change may name (INV-25): the 500 the Incidents page shows, in one short write.
const MaxBulkIncidents = 500

// BulkResult is the answer of POST /notify/incidents/status.
type BulkResult struct {
	Updated             int `json:"updated"`
	AlreadyResolved     int `json:"already_resolved"`
	AlreadyAcknowledged int `json:"already_acknowledged"`
}

// HandleIncidents acknowledges or resolves several incidents with one note (POST /notify/incidents/status, INV-25), like the
// findings bulk change (D-484). Every incident that changes gets what PATCH gives it: who, when, the note and its own core_audit row
// (INV-10). A resolved incident keeps its state and its note (already_resolved), and acknowledging an acknowledged one changes
// nothing (already_acknowledged): a bulk change never overwrites what someone wrote. Reopening is not a bulk action. All or nothing:
// an unknown id writes nothing. A duplicate id counts once.
func (s *Service) HandleIncidents(ctx context.Context, actor string, ids []string, status IncidentStatus, note string) (BulkResult, error) {
	var res BulkResult
	if status != StatusAcknowledged && status != StatusResolved {
		return res, badRequest("bad_status", "Status must be acknowledged or resolved.")
	}
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > maxNote {
		return res, badRequest("note_too_long", "A note can be at most 500 characters.")
	}
	seen := make(map[string]bool, len(ids))
	uniq := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 || len(uniq) > MaxBulkIncidents {
		return res, apierr.Invalid(fmt.Sprintf("Select between 1 and %d incidents.", MaxBulkIncidents))
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		res = BulkResult{}
		at := store.FormatTS(s.now())
		for _, id := range uniq {
			var title, cur string
			if err := tx.QueryRowContext(ctx, `SELECT title, status FROM notify_incident WHERE id = ?`, id).Scan(&title, &cur); errors.Is(err, sql.ErrNoRows) {
				return notFound("One of the selected incidents no longer exists. Reload the page and try again.")
			} else if err != nil {
				return fmt.Errorf("notify: read incident: %w", err)
			}
			switch {
			case cur == string(StatusResolved):
				res.AlreadyResolved++
				continue
			case cur == string(status):
				res.AlreadyAcknowledged++
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = ?, handled_by = ?, handled_at = ?, note = ? WHERE id = ?`,
				string(status), actor, at, nullable(note), id); err != nil {
				return fmt.Errorf("notify: update incident: %w", err)
			}
			detail := string(status)
			if note != "" {
				detail += ": " + note
			}
			if err := s.record(ctx, tx, actor, "notify.incident_status", clip(title, 400), detail); err != nil {
				return err
			}
			res.Updated++
		}
		return nil
	})
	if err != nil {
		return BulkResult{}, err
	}
	return res, nil
}
