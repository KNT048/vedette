package schedule

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/knt048/vedette/core/selfcheck"
)

// NextDueMismatches counts the schedules whose stored next due time is not Next of their rule from their Reference (nil while
// off): the rule that next_due_at has one writer and one function. It only reads.
func NextDueMismatches(ctx context.Context, db *sql.DB) (int64, error) {
	org, err := orgZoneName(ctx, db)
	if err != nil {
		return 0, err
	}
	rows, err := listRows(ctx, db, ``)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, r := range rows {
		if !sameTime(r.due(org), r.NextDueAt) && !firstRunDue(r) {
			n++
		}
	}
	return n, nil
}

// firstRunDue says the stored next due time is a first-run time: the schedule never came due and is due at its reference (Owner.
// FirstInWindow, known only to the running box; the self-check has no owners), so the scan window holds it until it opens.
func firstRunDue(r row) bool {
	if !r.Enabled || r.LastDueAt != nil || r.NextDueAt == nil {
		return false
	}
	ref := Reference(nil, r.UpdatedAt, r.PausedUntil).Truncate(time.Millisecond)
	return r.NextDueAt.Equal(ref)
}

// The rules of the schedules table are part of the box's self-check.
func init() {
	selfcheck.Register(selfcheck.Invariant{Name: "schedules.next_due_is_next_of_rule", Count: NextDueMismatches})
	selfcheck.Register(selfcheck.Invariant{
		Name:  "schedules.known_frequency",
		Query: `SELECT count(*) FROM core_schedule WHERE freq NOT IN (` + quotedFreqs() + `)`,
	})
}

func quotedFreqs() string {
	q := make([]string, len(Freqs))
	for i, f := range Freqs {
		q[i] = "'" + string(f) + "'"
	}
	return strings.Join(q, ", ")
}
