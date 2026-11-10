package scan

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// L4: probe rows still open when the run ends are closed by finish.
func TestReview_L4_FinishClosesOpenProbes(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.onRun = func(nucleiargv.Job) { // a row the normal path will not close
		_ = r.db.Write(r.ctx(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_probe (id, ts, run_id, ip, label, template, request)
SELECT 'pr-extra', '2026-11-10T10:00:00.000Z', id, '192.168.10.21', 'x', 't.yaml', 'GET / HTTP/1.1' FROM scan_run WHERE status = 'running'`)
			return err
		})
	}
	r.start("a-nas02")
	r.wait()
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result IS NULL`); n != 0 {
		t.Fatalf("%d probe rows left open", n)
	}
}
