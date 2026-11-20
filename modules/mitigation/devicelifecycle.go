package mitigation

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/knt048/vedette/core/lifecycle"
)

// FindingFolded is mitigation's part of a device merge that folds two findings of one CVE into one (core/lifecycle, inside the
// inventory's write, before the folded finding f.From is deleted): its "Applied" marks and AI results become f.Into's. An item both
// findings had marked applied keeps the earlier mark; of two AI results of the same skill the newer stays.
func FindingFolded(ctx context.Context, tx *sql.Tx, f lifecycle.FindingFold) error {
	for _, q := range []string{
		`INSERT INTO mit_applied (finding_id, item, ts, user) SELECT ?2, item, ts, user FROM mit_applied WHERE finding_id = ?1 AND true
			ON CONFLICT (finding_id, item) DO UPDATE SET ts = excluded.ts, user = excluded.user WHERE excluded.ts < mit_applied.ts`,
		`INSERT INTO mit_ai_output (finding_id, skill, payload, model, profile, created_at, activity_id)
			SELECT ?2, skill, payload, model, profile, created_at, activity_id FROM mit_ai_output WHERE finding_id = ?1 AND true
			ON CONFLICT (finding_id, skill) DO UPDATE SET payload = excluded.payload, model = excluded.model, profile = excluded.profile,
				created_at = excluded.created_at, activity_id = excluded.activity_id WHERE excluded.created_at > mit_ai_output.created_at`,
	} {
		if _, err := tx.ExecContext(ctx, q, f.From, f.Into); err != nil {
			return fmt.Errorf("mitigation: keep the applied items of a folded finding: %w", err)
		}
	}
	return nil
}
