package core_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/host/api"
)

// The first-run restore from an uploaded backup and the key download (S-CORE-1, D-518).

type member struct {
	name string
	data []byte
	typ  byte
}

func tarGz(t *testing.T, ms ...member) []byte {
	t.Helper()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if m.typ != 0 {
			h.Typeflag, h.Size, h.Linkname = m.typ, 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if m.typ == 0 {
			if _, err := tw.Write(m.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

const manifestOK = `{"version":1,"db_schema":"core=1","created_at":"2026-11-01T08:30:00Z","includes_secrets":false}`

// backupDB is the database of another box: this world's schema, an organization that finished setup, and one secret
// sealed with key (none when key is nil). extra runs on it before it is read back.
func (e *osEnv) backupDB(key []byte, extra ...string) []byte {
	e.t.Helper()
	path := filepath.Join(e.t.TempDir(), "other.db")
	if err := e.env.DB.SnapshotTo(e.t.Context(), path); err != nil {
		e.t.Fatal(err)
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	stmts := append([]string{`INSERT INTO core_org (id, name, timezone, setup_complete, data_mode, install_id) VALUES (1, 'Other Co', 'UTC', 1, 'clean', 'ins-other')`}, extra...)
	for _, s := range stmts {
		if _, err := db.ExecContext(e.t.Context(), s); err != nil {
			e.t.Fatal(err)
		}
	}
	if key != nil { // nil: no secret of its own
		st, err := secrets.New(key)
		if err != nil {
			e.t.Fatal(err)
		}
		tx, err := db.BeginTx(e.t.Context(), nil)
		if err != nil {
			e.t.Fatal(err)
		}
		if _, _, err := st.Seal(e.t.Context(), tx, "test_secret", []byte("an ai key"), false); err != nil {
			e.t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			e.t.Fatal(err)
		}
	}
	_ = db.Close()
	b, err := os.ReadFile(path) //nolint:gosec // a test temp file
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, secrets.KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// upload posts body to step 1 as the first-run page does: the file as the body, the setup code in a header.
func (e *osEnv) upload(code string, body []byte, mutate ...func(*http.Request)) reply {
	e.t.Helper()
	return e.client().request("POST", "/core/setup/restore/upload", nil, append([]func(*http.Request){func(q *http.Request) {
		q.Body, q.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		q.Header.Set("Content-Type", "application/octet-stream")
		if code != "" {
			q.Header.Set("X-Setup-Code", code)
		}
	}}, mutate...)...)
}

// Step 1 takes a backup Download backup made and refuses anything else before it is kept: a bad setup code, a member that is
// not one of the three names (a path out of the directory, a link), a key inside, a file that is not gzip, a database of a
// newer Vedette, and a body over the cap. A refused file leaves nothing on the box.
func TestSetupRestoreUploadChecksTheFile(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	code := e.openSetup()
	key := newKey(t)
	good := tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: e.backupDB(key)})

	wantStatus(t, e.upload("", good), 403, "invalid_setup_code")
	wantStatus(t, e.upload("WRONG-CODE0-00000-00000", good), 403, "invalid_setup_code")
	for name, body := range map[string][]byte{
		"traversal":  tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "../vedette.db", data: []byte("x")}),
		"symlink":    tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", typ: tar.TypeSymlink}),
		"key":        tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: []byte("SQLite format 3\x00")}, member{name: "vedette.key", data: key}),
		"not gzip":   []byte("this is not a backup"),
		"no db":      tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}),
		"not sqlite": tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: []byte("hello")}),
	} {
		if r := e.upload(code, body); r.Code != 400 || r.code() != "not_a_backup" {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	newer := tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: e.backupDB(key, `INSERT INTO core_migration_core (version_id, is_applied) VALUES (99999, 1)`)})
	wantStatus(t, e.upload(code, newer), 409, "schema_newer")
	wantStatus(t, e.upload(code, good, func(q *http.Request) { q.ContentLength = 5 << 30 }), 413, "too_large")
	if dirs := e.snapshotDirs(); len(dirs) != 0 {
		t.Fatalf("a refused upload left %v", dirs)
	}

	r := e.upload(code, good)
	wantOK(t, r, 200)
	if r.str("org") != "Other Co" || r.str("created_at") != "2026-11-01T08:30:00Z" || r.JSON["secrets"].(float64) < 1 || r.JSON["users"] != float64(3) || r.JSON["admins_without_key"] != float64(1) || len(r.str("id")) != 32 {
		t.Fatalf("upload = %s", r.Raw)
	}
	if dirs := e.snapshotDirs(); len(dirs) != 1 || dirs[0] != r.str("id") {
		t.Fatalf("staged = %v", dirs)
	}
	if e.count("data.restore_upload") != 1 {
		t.Errorf("actions = %v", e.actions())
	}
	// A second upload replaces the first: the box keeps one.
	again := e.upload(code, good)
	wantOK(t, again, 200)
	if dirs := e.snapshotDirs(); len(dirs) != 1 || dirs[0] != again.str("id") {
		t.Fatalf("after a second upload = %v", dirs)
	}
}

// Once setup is done the first-run restore is closed: both steps answer 409 already_setup and nothing is read; its status says done.
func TestSetupRestoreIsRefusedAfterSetup(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	code := e.openSetup()
	good := tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: e.backupDB(newKey(t))})
	e.setZone("UTC") // an organization that finished setup
	wantStatus(t, e.upload(code, good), 409, "already_setup")
	wantStatus(t, e.client().post("/core/setup/restore", map[string]any{"setup_code": code, "upload_id": strings.Repeat("a", 32)}), 409, "already_setup")
	if r := e.client().get("/core/setup/restore"); r.Code != 200 || r.str("status") != "done" { // setup is done: nothing more than GET /setup says
		t.Fatalf("status after setup = %d %s", r.Code, r.Raw)
	}
	if f.calls != 0 || len(e.snapshotDirs()) != 0 {
		t.Fatalf("calls=%d snapshots=%v", f.calls, e.snapshotDirs())
	}
}

// Step 2 refuses a key of the wrong shape, a key that opens none of the backup's secrets, and a restore without a key that
// was not confirmed, before the host is asked anything; with the right key the host imports the upload as a manual backup
// that holds the key, the restore of D-377 starts on it, and the page follows it until it ends.
func TestSetupRestoreChecksTheKeyThenImportsAndRestores(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	code := e.openSetup()
	key := newKey(t)
	up := e.upload(code, tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: e.backupDB(key)}))
	wantOK(t, up, 200)
	id := up.str("id")
	restore := func(extra map[string]any) reply {
		b := map[string]any{"setup_code": code, "upload_id": id}
		for k, v := range extra {
			b[k] = v
		}
		return e.client().post("/core/setup/restore", b)
	}
	wantStatus(t, restore(map[string]any{"key": "bm90IGEga2V5"}), 400, "invalid_key")
	wantStatus(t, restore(map[string]any{"key": base64.StdEncoding.EncodeToString(newKey(t))}), 400, "wrong_key")
	wantStatus(t, restore(nil), 409, "confirm_required")
	wantStatus(t, restore(map[string]any{"setup_code": "WRONG"}), 403, "invalid_setup_code")
	if f.calls != 0 {
		t.Fatalf("the host was asked to restore %d times", f.calls)
	}
	if r := e.client().get("/core/setup/restore"); r.Code != 200 || r.Raw != "null" {
		t.Fatalf("before = %d %s", r.Code, r.Raw)
	}

	r := restore(map[string]any{"key": base64.StdEncoding.EncodeToString(key)})
	wantOK(t, r, 202)
	if r.str("status") != "running" || f.calls != 1 {
		t.Fatalf("restore = %s, calls %d", r.Raw, f.calls)
	}
	bl, err := e.hh.Client.StateBackups(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var imported *api.Backup
	for i, b := range bl.Backups {
		if b.Label == "Uploaded backup of 2026-11-01 08:30" {
			imported = &bl.Backups[i]
		}
	}
	if imported == nil || imported.Kind != "manual" || !imported.IncludesSecrets {
		t.Fatalf("host backups = %+v", bl.Backups)
	}
	for _, d := range e.snapshotDirs() {
		if d == id {
			t.Fatalf("the upload stayed after the import: %v", e.snapshotDirs())
		}
	}
	wantStatus(t, restore(map[string]any{"key": base64.StdEncoding.EncodeToString(key)}), 404, "upload_unknown")
	if got := e.client().get("/core/setup/restore"); got.str("status") != "running" {
		t.Fatalf("while running = %s", got.Raw)
	}
	f.finish(api.StatusReverted, api.BackupRestoreResult{RestoredBackupID: imported.BackupID, PreRestoreBackupID: "dddd0000dddd0000dddd0000dddd0000"}, api.CodeRestoreHealthFailed)
	e.newHandlers(t, f, 0) // core comes back on the fresh box's data
	got := e.client().get("/core/setup/restore")
	if got.Code != 200 || got.str("status") != "reverted" || got.str("error") == "" || got.JSON["backup_id"] != nil {
		t.Fatalf("after = %s", got.Raw)
	}
}

// The key download needs the administrator's password, is audited, and is the key file's bytes.
func TestDataKeyDownload(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	want, err := secrets.LoadKeyFile(filepath.Join(e.m.CoreData, "vedette.key"))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.admin.post("/core/data/key", map[string]any{"password": "not it"}), 400, "wrong_password")
	wantStatus(t, e.oper.post("/core/data/key", map[string]any{"password": authtest.Password}), 403, "forbidden")
	r := e.admin.post("/core/data/key", map[string]any{"password": authtest.Password})
	if r.Code != 200 || r.Raw != string(want) || !strings.Contains(r.Header.Get("Content-Disposition"), `filename="vedette-key-`) {
		t.Fatalf("download = %d %q %v", r.Code, r.Header.Get("Content-Disposition"), len(r.Raw))
	}
	if e.count("data.key_download") != 1 {
		t.Errorf("actions = %v", e.actions())
	}
	if strings.Contains(e.logs.String(), string(want)) || strings.Contains(e.logs.String(), base64.StdEncoding.EncodeToString(want)) {
		t.Error("the key is in the log")
	}
}

func backupOf(t *testing.T, db []byte) []byte {
	t.Helper()
	return tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: db})
}

// A backup whose triggers or views are not exactly the ones the migrations make at its versions is refused: one more trigger
// (an account made administrator at every sign-in), a missing append-only trigger of the audit log, an extra view (M1).
func TestSetupRestoreRefusesChangedSchemaObjects(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	code := e.openSetup()
	key := newKey(t)
	for name, stmt := range map[string]string{
		"extra trigger":   `CREATE TRIGGER evil AFTER INSERT ON core_session BEGIN UPDATE core_user SET role = 'admin'; END`,
		"dropped audit":   `DROP TRIGGER core_audit_no_delete`,
		"extra view":      `CREATE VIEW core_user_list AS SELECT email FROM core_user`,
		"changed trigger": `DROP TRIGGER core_audit_no_update; CREATE TRIGGER core_audit_no_update BEFORE UPDATE ON core_audit BEGIN SELECT 1; END`,
	} {
		if r := e.upload(code, backupOf(t, e.backupDB(key, stmt))); r.Code != 400 || r.code() != "not_a_backup" {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	if dirs := e.snapshotDirs(); len(dirs) != 0 {
		t.Fatalf("a refused upload left %v", dirs)
	}
}

// failingBody fails the test if anything reads it: a wrong setup code must be refused before the upload is read.
type failingBody struct{ read bool }

func (b *failingBody) Read([]byte) (int, error) { b.read = true; return 0, io.ErrUnexpectedEOF }

func TestSetupRestoreUploadIsNotReadWithoutTheCode(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	e.openSetup()
	body := &failingBody{}
	r := e.client().request("POST", "/core/setup/restore/upload", nil, func(q *http.Request) {
		q.Body, q.ContentLength = io.NopCloser(body), 1<<20
		q.Header.Set("Content-Type", "application/octet-stream")
		q.Header.Set("X-Setup-Code", "WRONG-CODE0-00000-00000")
	})
	wantStatus(t, r, 403, "invalid_setup_code")
	if body.read {
		t.Fatal("the upload was read before the setup code was accepted")
	}
}

// gateBody says when the handler starts reading it and then waits, so the test acts while an upload is in progress.
type gateBody struct {
	started, release chan struct{}
	once             sync.Once
}

func (g *gateBody) Read([]byte) (int, error) {
	g.once.Do(func() { close(g.started) })
	<-g.release
	return 0, io.EOF
}

// First-run setup and a first-run restore never overlap (M2): setup answers 409 busy while an upload is read and while the
// restore runs on the host; an upload left behind is removed when setup finishes (L1).
func TestSetupRestoreAndSetupDoNotOverlap(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	code := e.openSetup()
	setup := setupBody(code)
	setup["admin"] = map[string]any{"name": "Nia New", "email": "nia@acme.example", "password": authtest.Password}

	g := &gateBody{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan reply, 1)
	go func() {
		done <- e.client().request("POST", "/core/setup/restore/upload", nil, func(q *http.Request) {
			q.Body, q.ContentLength = io.NopCloser(g), -1
			q.Header.Set("Content-Type", "application/octet-stream")
			q.Header.Set("X-Setup-Code", code)
		})
	}()
	<-g.started
	wantStatus(t, e.client().post("/core/setup", setup), 409, "busy")
	close(g.release)
	wantStatus(t, <-done, 400, "not_a_backup")

	key := newKey(t)
	up := e.upload(code, backupOf(t, e.backupDB(key)))
	wantOK(t, up, 200)
	wantOK(t, e.client().post("/core/setup/restore", map[string]any{"setup_code": code, "upload_id": up.str("id"), "key": base64.StdEncoding.EncodeToString(key)}), 202)
	wantStatus(t, e.client().post("/core/setup", setup), 409, "busy") // the restore runs on the host
}

func TestSetupRestoreUploadIsDroppedWhenSetupFinishes(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	code := e.openSetup()
	wantOK(t, e.upload(code, backupOf(t, e.backupDB(newKey(t)))), 200)
	if len(e.snapshotDirs()) != 1 {
		t.Fatalf("staged = %v", e.snapshotDirs())
	}
	setup := setupBody(code)
	setup["admin"] = map[string]any{"name": "Nia New", "email": "nia@acme.example", "password": authtest.Password}
	wantOK(t, e.client().post("/core/setup", setup), 200)
	if dirs := e.snapshotDirs(); len(dirs) != 0 {
		t.Fatalf("an upload stayed on a box that is set up: %v", dirs)
	}
}

// A backup with no saved secret has nothing to check a key against: the key file is not installed, the box keeps its own (L2).
func TestSetupRestoreIgnoresAKeyItCannotCheck(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	code := e.openSetup()
	up := e.upload(code, backupOf(t, e.backupDB(nil, `DELETE FROM core_secret`)))
	wantOK(t, up, 200)
	if up.JSON["secrets"] != float64(0) {
		t.Fatalf("upload = %s", up.Raw)
	}
	wantOK(t, e.client().post("/core/setup/restore", map[string]any{"setup_code": code, "upload_id": up.str("id"), "key": base64.StdEncoding.EncodeToString(make([]byte, 32))}), 202)
	bl, err := e.hh.Client.StateBackups(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bl.Backups {
		if strings.HasPrefix(b.Label, "Uploaded backup") && b.IncludesSecrets {
			t.Fatalf("an unchecked key went with the import: %+v", b)
		}
	}
	if f.calls != 1 {
		t.Fatalf("restore calls = %d", f.calls)
	}
}

// The key download asks for the two-step code of an account that has one, before anything is written.
func TestDataKeyDownloadNeedsTheTwoStepCode(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	err := e.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_user SET twofa_method = 'app' WHERE email = 'admin@acme.example'`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.admin.post("/core/data/key", map[string]any{"password": authtest.Password}), 400, "code_required")
	if e.count("data.key_download") != 0 {
		t.Errorf("actions = %v", e.actions())
	}
}
