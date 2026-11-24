package core_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/core"
)

// Restore from a downloaded backup file on a box that is set up (S-CORE-1): the administrator uploads the file, the box says
// what it holds, and the restore is the one of a kept backup.

// uploadFile posts body to step 1 as Settings -> Data does: the file as the body, the administrator's session.
func (e *osEnv) uploadFile(c *client, body []byte, mutate ...func(*http.Request)) reply {
	e.t.Helper()
	return c.request("POST", "/core/data/restore/upload", nil, append([]func(*http.Request){func(q *http.Request) {
		q.Body, q.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		q.Header.Set("Content-Type", "application/octet-stream")
	}}, mutate...)...)
}

// setBoxKey writes the box's own key file.
func (e *osEnv) setBoxKey(key []byte) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.m.CoreData, "vedette.key"), key, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// imported is the backup the host imported from an upload, nil when none.
func (e *osEnv) imported() *api.Backup {
	e.t.Helper()
	bl, err := e.hh.Client.StateBackups(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	for i, b := range bl.Backups {
		if strings.HasPrefix(b.Label, "Uploaded backup") {
			return &bl.Backups[i]
		}
	}
	return nil
}

// A password-protected file downloaded from another box: without the password, with a wrong one, from an operator, without
// the confirmation and with a wrong account password nothing changes on the box (no import, no restore, no snapshot of the
// current data). With the right ones the key inside the file goes with the import, the restore runs as a restore of a kept
// backup and leaves the marker its end is recorded from, and the upload is used once.
func TestRestoreFromAProtectedFileOnASetUpBox(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	e.setBoxKey(newKey(t)) // this box's own key opens nothing in the other box's backup
	key := newKey(t)
	front, err := core.KeyMemberForTest(key, time.Date(2026, 11, 1, 8, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	file := sealed(t, append(front, backupOf(t, e.backupDB(key))...), backupPassword)
	nothingChanged := func(when string) {
		t.Helper()
		if f.calls != 0 || e.imported() != nil || e.count("data.restore") != 0 || e.count("data.restore_import") != 0 {
			t.Fatalf("%s: restore calls %d, imported %v, actions %v", when, f.calls, e.imported(), e.actions())
		}
	}

	wantStatus(t, e.uploadFile(e.admin, file), 409, "backup_password_required")
	wantStatus(t, e.uploadFile(e.admin, file, withPassword("not the password of this file")), 400, "wrong_backup_password")
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Fatalf("a refused upload left %v", d)
	}
	wantStatus(t, e.uploadFile(e.oper, file, withPassword(backupPassword)), 403, "forbidden")
	nothingChanged("refused uploads")
	if e.count("data.restore_upload") != 0 {
		t.Fatalf("a refused upload was audited: %v", e.actions())
	}

	up := e.uploadFile(e.admin, file, withPassword(backupPassword))
	wantOK(t, up, 200)
	if up.str("org") != "Other Co" || up.JSON["key_included"] != true || up.JSON["box_key"] != false || up.str("created_at") != "2026-11-01T08:30:00Z" {
		t.Fatalf("upload = %s", up.Raw)
	}
	id := up.str("id")
	restore := func(extra map[string]any) reply {
		b := map[string]any{"upload_id": id, "confirm_data_loss": true, "password": authtest.Password}
		for k, v := range extra {
			b[k] = v
		}
		return e.admin.post("/core/data/restore/file", b)
	}
	wantStatus(t, restore(map[string]any{"confirm_data_loss": false}), 409, "confirm_required")
	wantStatus(t, restore(map[string]any{"password": "wrong"}), 400, "wrong_password")
	wantStatus(t, restore(map[string]any{"key": "bm90IGEga2V5"}), 400, "invalid_key")
	wantStatus(t, e.oper.post("/core/data/restore/file", map[string]any{"upload_id": id, "confirm_data_loss": true, "password": authtest.Password}), 403, "forbidden")
	nothingChanged("refused restores")
	if d := e.snapshotDirs(); !slices.Equal(d, []string{id}) {
		t.Fatalf("a refused restore did not keep the upload: %v", d)
	}

	r := restore(nil)
	wantOK(t, r, 202)
	if r.str("status") != "running" || r.str("user") != "admin@acme.example" || r.str("backup_created_at") != "2026-11-01T08:30:00Z" || f.calls != 1 {
		t.Fatalf("restore = %s, calls %d", r.Raw, f.calls)
	}
	if b := e.imported(); b == nil || b.Kind != "manual" || !b.IncludesSecrets || r.str("backup_id") != b.BackupID {
		t.Fatalf("imported = %+v, restore %s", b, r.Raw)
	}
	for _, a := range []string{"data.restore_upload", "data.restore_import", "data.restore"} {
		if e.count(a) != 1 {
			t.Errorf("%s rows = %d (actions %v)", a, e.count(a), e.actions())
		}
	}
	if d := e.auditDetails("data.restore_import"); len(d) != 1 || !strings.HasSuffix(d[0], "with the key inside the protected backup") {
		t.Errorf("import detail = %q", d)
	}
	if _, err := os.Stat(filepath.Join(e.m.CoreData, "restore-pending.json")); err != nil {
		t.Errorf("no pending-restore marker: %v", err)
	}
	wantStatus(t, restore(nil), 404, "upload_unknown")
}

// A plain file of this box (its saved secrets open with the box's own key): no key file and no confirmation are asked, the box
// keeps its key. A plain file of another box asks for its key file or the confirmation that the secrets are lost.
func TestRestoreFromAPlainFileUsesThisBoxsKeyWhenItOpens(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	own := newKey(t)
	e.setBoxKey(own)

	other := e.uploadFile(e.admin, backupOf(t, e.backupDB(newKey(t))))
	wantOK(t, other, 200)
	if other.JSON["box_key"] != false || other.JSON["key_included"] != false || other.JSON["secrets"] == float64(0) {
		t.Fatalf("another box's file = %s", other.Raw)
	}
	body := map[string]any{"upload_id": other.str("id"), "confirm_data_loss": true, "password": authtest.Password}
	wantStatus(t, e.admin.post("/core/data/restore/file", body), 409, "confirm_required")
	body["key"] = base64.StdEncoding.EncodeToString(own)
	wantStatus(t, e.admin.post("/core/data/restore/file", body), 400, "wrong_key")
	if f.calls != 0 || e.imported() != nil {
		t.Fatalf("calls %d, imported %v", f.calls, e.imported())
	}

	mine := e.uploadFile(e.admin, backupOf(t, e.backupDB(own))) // replaces the other upload: one at a time
	wantOK(t, mine, 200)
	if mine.JSON["box_key"] != true || mine.JSON["key_included"] != false {
		t.Fatalf("this box's file = %s", mine.Raw)
	}
	if d := e.snapshotDirs(); !slices.Equal(d, []string{mine.str("id")}) {
		t.Fatalf("uploads kept = %v", d)
	}
	wantOK(t, e.admin.post("/core/data/restore/file", map[string]any{"upload_id": mine.str("id"), "confirm_data_loss": true, "password": authtest.Password}), 202)
	if b := e.imported(); b == nil || b.IncludesSecrets {
		t.Fatalf("imported = %+v: the box keeps its own key", b)
	}
	if d := e.auditDetails("data.restore_import"); len(d) != 1 || !strings.HasSuffix(d[0], "with this box's key") {
		t.Errorf("import detail = %q", d)
	}
	// A second restore while this one runs is refused before anything is staged.
	wantStatus(t, e.uploadFile(e.admin, backupOf(t, e.backupDB(own))), 409, "busy")
}

// With two-step sign-in on, the restore from a file needs a fresh code, asked before anything is imported.
func TestRestoreFromAFileNeedsTheTwoStepCode(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	up := e.uploadFile(e.admin, backupOf(t, e.backupDB(nil)))
	wantOK(t, up, 200)
	if err := e.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_user SET twofa_method = 'app' WHERE email = 'admin@acme.example'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.admin.post("/core/data/restore/file", map[string]any{"upload_id": up.str("id"), "confirm_data_loss": true, "confirm_without_key": true, "password": authtest.Password}), 400, "code_required")
	if f.calls != 0 || e.imported() != nil {
		t.Fatalf("calls %d, imported %v", f.calls, e.imported())
	}
}

// A restore from a file is recorded in the restored database with the date the file's backup was made, not the moment the
// host imported it: the host lists the imported copy as made at the import, and the restored database holds nothing of
// this run, so the record would otherwise say the data of the import moment came back.
func TestRestoreFromAFileIsRecordedWithTheBackupsDate(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	own := newKey(t)
	e.setBoxKey(own)
	up := e.uploadFile(e.admin, backupOf(t, e.backupDB(own)))
	wantOK(t, up, 200)
	wantOK(t, e.admin.post("/core/data/restore/file", map[string]any{"upload_id": up.str("id"), "confirm_data_loss": true, "password": authtest.Password}), 202)
	b := e.imported()
	if b == nil || b.CreatedAt.Equal(time.Date(2026, 11, 1, 8, 30, 0, 0, time.UTC)) {
		t.Fatalf("imported = %+v: the host dates the copy at the import", b)
	}
	f.mu.Lock()
	f.backups = append(f.backups, *b) // the host lists the imported copy, dated when it was imported
	f.mu.Unlock()
	e.swapIn()
	e.newHandlers(t, newFollowHost(t, f), 0) // core is back on the restored data; the run is not over yet
	f.finish(api.StatusSucceeded, api.BackupRestoreResult{RestoredBackupID: b.BackupID, PreRestoreBackupID: "dddd0000dddd0000dddd0000dddd0000"}, "")
	eventuallyOS(t, "the restore recorded in the restored database", func() bool { return e.count("data.restore_done") == 1 })
	if d := e.auditDetails("data.restore_done"); len(d) != 1 || !strings.Contains(d[0], "the backup from 1 Nov 2026") {
		t.Errorf("data.restore_done detail = %q, want the backup's own date", d)
	}
	if got := e.admin.get("/core/data/restore/run"); got.str("id") != "rn_restore1" || got.str("status") != "done" || got.str("backup_created_at") != "2026-11-01T08:30:00Z" {
		t.Fatalf("run = %s", got.Raw)
	}
}
