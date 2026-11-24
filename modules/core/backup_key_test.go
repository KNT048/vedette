package core_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/modules/core"
)

// A password-protected backup carries the box's decryption key inside its encryption; a plain one never does (S-CORE-1).

// worldKey is the master key the test world seals its secrets with (authtest): the key file of box A is set to it, as on a
// real box the key file and the secrets go together.
var worldKey = bytes.Repeat([]byte{9}, secrets.KeySize)

// members reads a tar.gz the way the standard tools do (every gzip member, the tar stream across them): the names in order and
// the bytes of each.
func members(t *testing.T, r io.Reader) ([]string, map[string][]byte) {
	t.Helper()
	zr, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var names []string
	data := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		data[h.Name] = b
	}
	return names, data
}

func decrypt(t *testing.T, raw []byte) []byte {
	t.Helper()
	id, err := age.NewScryptIdentity(backupPassword)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		t.Fatalf("the password does not open the file: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signInOn opens a restored database with key, as core does when it starts on the files the host put in place, and signs the
// authenticator-app user in with a fresh code.
func signInOn(t *testing.T, db []byte, key []byte, email string, totp []byte, at time.Time) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vedette.db")
	if err := os.WriteFile(path, db, 0o600); err != nil {
		t.Fatal(err)
	}
	sdb, err := store.Open(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	st, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return at }
	svc, err := auth.New(auth.Config{DB: sdb, Secrets: st, Audit: audit.New(now), Clock: now, Log: slog.New(slog.DiscardHandler), Argon2: authtest.Cheap, MaxHashing: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Login(t.Context(), auth.LoginRequest{Email: email, Password: authtest.Password, Code: auth.TOTPCode(totp, auth.TOTPStep(at)), IP: netip.MustParseAddr("192.0.2.1"), UserAgent: "test"})
	return err //nolint:wrapcheck // the test reads the API error
}

// A backup downloaded with a password restores whole on a box with ANOTHER key: the file carries the old box's key inside its
// encryption (a key entry in front of the archive, read by the standard tools as one tar stream), the first-run restore says
// so and needs no key file, the host imports it with the key, and the restored pair opens the saved secret and lets the
// authenticator-app user sign in. With the new box's own key the same user could not. The plain download of the same box
// never holds the key.
func TestProtectedBackupCarriesTheKeyToABoxWithAnotherKey(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newOSEnv(t, osOpts{})
	if err := os.WriteFile(filepath.Join(e.m.CoreData, "vedette.key"), worldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	var secretID string
	if err := e.env.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_org (id, name, timezone, setup_complete, data_mode, install_id) VALUES (1, 'Old Box Co', 'UTC', 1, 'clean', 'ins-old')`); err != nil {
			return err
		}
		var err error
		secretID, _, err = e.env.Secrets.Seal(ctx, tx, "test_secret", []byte("an ai key"), false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	app := e.env.User(t, "app@acme.example", routes.Viewer)
	setup, err := e.env.Svc.StartTOTP(ctx, app.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	totp := decodeBase32(t, setup.Secret)
	if err := only(e.env.Svc.ConfirmTOTP(ctx, app.ID, "", auth.TOTPCode(totp, auth.TOTPStep(e.env.Clock.Now())))); err != nil {
		t.Fatal(err)
	}

	r := e.admin.post("/core/data/backup", map[string]any{"password": backupPassword})
	wantOK(t, r, 200)
	raw := []byte(r.Raw)
	if bytes.Contains(raw, worldKey) {
		t.Fatal("the key shows through the encryption")
	}
	names, files := members(t, bytes.NewReader(decrypt(t, raw)))
	if !slices.Equal(names, []string{"vedette.key", "manifest.json", "vedette.db"}) || !bytes.Equal(files["vedette.key"], worldKey) {
		t.Fatalf("members = %v, key %d bytes", names, len(files["vedette.key"]))
	}
	var audit string
	if err := e.env.DB.Reader().QueryRowContext(ctx, "SELECT group_concat(coalesce(detail, ''), char(10)) FROM core_audit WHERE action = 'data.backup'").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit, "decryption key, encrypted with a password") {
		t.Errorf("audit detail = %q", audit)
	}
	for _, enc := range []string{base64.StdEncoding.EncodeToString(worldKey), string(worldKey)} {
		if strings.Contains(e.logs.String(), enc) || strings.Contains(audit, enc) {
			t.Fatal("the key is in the log or the audit log")
		}
	}

	// The plain download of the same box: the host's archive, no key member and no key bytes anywhere in it.
	e.clock.Advance(2 * time.Minute)
	p := e.admin.get("/core/data/backup")
	wantOK(t, p, 200)
	pnames, pfiles := members(t, strings.NewReader(p.Raw))
	if !slices.Equal(pnames, []string{"manifest.json", "vedette.db"}) || bytes.Contains(pfiles["vedette.db"], worldKey) {
		t.Fatalf("plain members = %v", pnames)
	}

	// A new box, with a key of its own.
	n, f := newRestoreEnv(t)
	if own, err := os.ReadFile(filepath.Join(n.m.CoreData, "vedette.key")); err != nil || bytes.Equal(own, worldKey) {
		t.Fatalf("the new box must have another key: %v", err)
	}
	code := n.openSetup()
	up := n.upload(code, raw, withPassword(backupPassword))
	wantOK(t, up, 200)
	if up.JSON["key_included"] != true || up.JSON["twofa_users"] != float64(1) || up.JSON["secrets"].(float64) < 2 {
		t.Fatalf("upload = %s", up.Raw)
	}
	b := map[string]any{"setup_code": code, "accept_terms": true, "upload_id": up.str("id")}
	wantOK(t, n.client().post("/core/setup/restore", b), 202)
	if f.calls != 1 {
		t.Fatalf("restore calls = %d", f.calls)
	}
	bl, err := n.hh.Client.StateBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var imported *api.Backup
	for i, x := range bl.Backups {
		if strings.HasPrefix(x.Label, "Uploaded backup of") {
			imported = &bl.Backups[i]
		}
	}
	if imported == nil || !imported.IncludesSecrets {
		t.Fatalf("host backups = %+v", bl.Backups)
	}
	if n.count("data.restore_import") != 1 {
		t.Fatalf("actions = %v", n.actions())
	}
	var detail string
	if err := n.env.DB.Reader().QueryRowContext(ctx, "SELECT detail FROM core_audit WHERE action = 'data.restore_import'").Scan(&detail); err != nil || !strings.Contains(detail, "with the key inside the protected backup") {
		t.Fatalf("import detail = %q %v", detail, err)
	}
	if slices.Contains(n.snapshotDirs(), up.str("id")) {
		t.Fatalf("the upload (and its key) stayed: %v", n.snapshotDirs())
	}
	hf, err := os.Open(filepath.Join(n.m.State, "backups", imported.BackupID+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hf.Close() }()
	got := map[string][]byte{}
	if err := ops.ReadArchive(hf, func(name string, data []byte) error { got[name] = data; return nil }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got["vedette.key"], worldKey) {
		t.Fatalf("the imported backup holds key %d bytes, not the old box's", len(got["vedette.key"]))
	}

	// The host's restore puts these two files in place (host TestContract_Restore_RoundTrip); core starts on them.
	sdb := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(sdb, got["vedette.db"], 0o600); err != nil {
		t.Fatal(err)
	}
	rdb, err := sql.Open("sqlite", sdb)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rdb.Close() }()
	st, _ := secrets.New(got["vedette.key"])
	if v, err := st.Open(ctx, rdb, secretID, "test_secret"); err != nil || string(v) != "an ai key" {
		t.Fatalf("the saved secret after the restore = %q %v", v, err)
	}
	later := e.env.Clock.Now().Add(2 * auth.TOTPPeriod * time.Second)
	if err := signInOn(t, got["vedette.db"], got["vedette.key"], app.Email, totp, later); err != nil {
		t.Fatalf("the authenticator-app user cannot sign in after the restore: %v", err)
	}
	apiCode(t, signInOn(t, got["vedette.db"], []byte(opstest.Key), app.Email, totp, later), 403, "twofa_reset_required") // the new box's own key
}

// What a protected file may carry is checked like a key file, and only inside the encryption: a key entry of the wrong size,
// a second key after the database, and a key entry in a plain file are 400 not_a_backup with nothing left staged; a key that
// opens none of the backup's secrets (changed by hand) and a key with a backup that holds no secret are not kept: the box
// keeps its own and the page asks for a key file as for a file without one, and step 2 without one needs confirm_without_key;
// a protected file without a key entry (age -p of a plain backup) still restores, without the key.
func TestProtectedBackupKeyIsCheckedBeforeItIsKept(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	code := e.openSetup()
	key := newKey(t)
	at := time.Date(2026, 11, 1, 8, 30, 0, 0, time.UTC)
	front, err := core.KeyMemberForTest(key, at)
	if err != nil {
		t.Fatal(err)
	}
	withSecrets := backupOf(t, e.backupDB(key))
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	short := func() []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		_ = tw.WriteHeader(&tar.Header{Name: "vedette.key", Mode: 0o600, Size: 31, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
		_, _ = tw.Write(key[:31])
		_ = tw.Flush()
		_ = zw.Close()
		return buf.Bytes()
	}()
	trailing := tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: e.backupDB(key)}, member{name: "vedette.key", data: key})
	other, _ := core.KeyMemberForTest(newKey(t), at)

	const crafted = "a password someone else chose for a crafted file"
	for name, file := range map[string][]byte{
		"a key entry of 31 bytes":         sealed(t, cat(short, withSecrets), crafted),
		"a second key after the database": sealed(t, cat(front, trailing), crafted),
	} {
		wantStatus(t, e.upload(code, file, withPassword(crafted)), 400, "not_a_backup")
		if d := e.snapshotDirs(); len(d) != 0 {
			t.Fatalf("%s: left %v", name, d)
		}
	}
	wantStatus(t, e.upload(code, cat(front, withSecrets)), 400, "not_a_backup") // never outside the encryption

	changed := e.upload(code, sealed(t, cat(other, withSecrets), backupPassword), withPassword(backupPassword))
	wantOK(t, changed, 200)
	if changed.JSON["key_included"] != false {
		t.Fatalf("a key that opens nothing = %s", changed.Raw)
	}
	if _, err := os.Stat(filepath.Join(e.m.CoreData, "snapshots", changed.str("id"), "upload.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a key that opens nothing was kept: %v", err)
	}
	wantStatus(t, e.client().post("/core/setup/restore", map[string]any{"setup_code": code, "accept_terms": true, "upload_id": changed.str("id")}), 409, "confirm_required")

	noSecret := e.upload(code, sealed(t, cat(front, backupOf(t, e.backupDB(nil))), backupPassword), withPassword(backupPassword))
	wantOK(t, noSecret, 200)
	if noSecret.JSON["key_included"] != false {
		t.Fatalf("no secret = %s", noSecret.Raw)
	}
	if _, err := os.Stat(filepath.Join(e.m.CoreData, "snapshots", noSecret.str("id"), "upload.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a key with nothing to open was kept: %v", err)
	}
	without := e.upload(code, sealed(t, withSecrets, backupPassword), withPassword(backupPassword))
	wantOK(t, without, 200)
	if without.JSON["key_included"] != false {
		t.Fatalf("without a key entry = %s", without.Raw)
	}
	plain := e.upload(code, withSecrets)
	wantOK(t, plain, 200)
	if plain.JSON["key_included"] != false {
		t.Fatalf("plain = %s", plain.Raw)
	}

	ok := e.upload(code, sealed(t, cat(front, withSecrets), backupPassword), withPassword(backupPassword))
	wantOK(t, ok, 200)
	staged := filepath.Join(e.m.CoreData, "snapshots", ok.str("id"), "upload.key")
	if st, err := os.Stat(staged); ok.JSON["key_included"] != true || err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("carried key: %s, staged %v", ok.Raw, err)
	}
	// Step 2 without a key file and without confirm_without_key: the carried key is used, nothing is asked.
	wantOK(t, e.client().post("/core/setup/restore", map[string]any{"setup_code": code, "accept_terms": true, "upload_id": ok.str("id")}), 202)
}

// A box whose key file cannot be read refuses a password-protected download before it makes anything (the file would not
// carry the key it promises); the plain download still works.
func TestProtectedBackupNeedsAReadableKeyFile(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	if err := os.Chmod(filepath.Join(e.m.CoreData, "vedette.key"), 0o644); err != nil { //nolint:gosec // a key file the box must refuse to read
		t.Fatal(err)
	}
	before := len(e.actions())
	wantStatus(t, e.admin.post("/core/data/backup", map[string]any{"password": backupPassword}), 409, "key_unreadable")
	if got := e.actions(); len(got) != before {
		t.Errorf("audit rows: %v", got[before:])
	}
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot made: %v", d)
	}
	if bl, err := e.hh.Client.StateBackups(t.Context()); err != nil || len(bl.Backups) != 0 {
		t.Errorf("backup made: %+v %v", bl, err)
	}
	wantOK(t, e.admin.get("/core/data/backup"), 200)
}
