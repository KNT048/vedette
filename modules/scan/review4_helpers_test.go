package scan

import (
	"database/sql"
	"time"
)

// Helpers of the #164 review tests (S4).

func (r *runEnv) setNow(t time.Time) {
	r.clock.mu.Lock()
	r.clock.now = t
	r.clock.mu.Unlock()
}

func (r *runEnv) exec(q string, args ...any) {
	r.t.Helper()
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.ctx(), q, args...)
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
}
