package core_test

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/knt048/vedette/modules/core"
)

// A backup downloaded with a password (age, scrypt) and its restore on a new box (S-CORE-1).

const backupPassword = "correct horse battery staple, Hà Nội"

// withPassword sends the backup password as the first-run page does: base64 of its UTF-8 bytes.
func withPassword(p string) func(*http.Request) {
	return func(q *http.Request) { q.Header.Set("X-Backup-Password", base64.StdEncoding.EncodeToString([]byte(p))) }
}

// sealed encrypts data with password the way the `age -p` tool does, at a cheap scrypt work factor (2^10): the cost of a guess
// is not what these tests are about.
func sealed(t *testing.T, data []byte, password string) []byte {
	t.Helper()
	rcpt, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	rcpt.SetWorkFactor(10)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rcpt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// A download with a password is an age file named .tar.gz.age, of the length the box announced, holding nothing readable; it
// opens with the password into the host's archive; the first-run restore of another box asks for the password, refuses a
// wrong one and takes the right one. The password is in no audit row.
func TestBackupDownloadWithAPasswordRestoresOnAnotherBox(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	if err := e.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO core_org (id, name, timezone, setup_complete, data_mode, install_id) VALUES (1, 'Old Box Co', 'UTC', 1, 'clean', 'ins-old')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r := e.admin.post("/core/data/backup", map[string]any{"password": backupPassword})
	if r.Code != 200 {
		t.Fatalf("backup = %d %s", r.Code, r.Raw)
	}
	if cd := r.Header.Get("Content-Disposition"); !regexp.MustCompile(`^attachment; filename="vedette-backup-\d{4}-\d\d-\d\d-\d{4}\.tar\.gz\.age"$`).MatchString(cd) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if cl := r.Header.Get("Content-Length"); cl != strconv.Itoa(len(r.Raw)) {
		t.Errorf("Content-Length %q, body %d bytes", cl, len(r.Raw))
	}
	raw := []byte(r.Raw)
	if !bytes.HasPrefix(raw, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Fatalf("not an age file with a password: %q", raw[:min(len(raw), 60)])
	}
	if bytes.Contains(raw, []byte("manifest.json")) || bytes.Contains(raw, []byte("SQLite format 3")) {
		t.Error("the archive shows through the encryption")
	}
	id, err := age.NewScryptIdentity(backupPassword)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		t.Fatalf("the password does not open the file: %v", err)
	}
	// The key entry in front (TestProtectedBackupCarriesTheKeyToABoxWithAnotherKey), then the host's archive as it is.
	if names, _ := members(t, plain); !slices.Equal(names, []string{"vedette.key", "manifest.json", "vedette.db"}) {
		t.Fatalf("members = %v", names)
	}
	var audit string
	if err := e.env.DB.Reader().QueryRowContext(t.Context(), "SELECT group_concat(action || ' ' || target || ' ' || coalesce(detail, ''), char(10)) FROM core_audit").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "horse") || !strings.Contains(audit, "encrypted with a password") {
		t.Fatalf("audit rows: %s", audit)
	}

	n, _ := newRestoreEnv(t)
	code := n.openSetup()
	wantStatus(t, n.upload(code, raw), 409, "backup_password_required")
	wantStatus(t, n.upload(code, raw, withPassword("not the password at all")), 400, "wrong_backup_password")
	if dirs := n.snapshotDirs(); len(dirs) != 0 {
		t.Fatalf("a refused upload left %v", dirs)
	}
	up := n.upload(code, raw, withPassword(backupPassword))
	wantOK(t, up, 200)
	if up.str("org") != "Old Box Co" {
		t.Fatalf("upload = %s", up.Raw)
	}
	if strings.Contains(up.Raw, "horse") {
		t.Fatal("the answer echoes the password")
	}
}

// Without a password (POST with none or an empty one, or GET) the file is the plain archive as before; a password that would
// not pass as a sign-in password is refused before the box makes anything.
func TestBackupDownloadPasswordIsOptionalAndFollowsThePolicy(t *testing.T) {
	t.Parallel()
	for _, body := range []map[string]any{{}, {"password": ""}} {
		e := newOSEnv(t, osOpts{})
		r := e.admin.post("/core/data/backup", body)
		if r.Code != 200 || !strings.HasSuffix(r.Header.Get("Content-Disposition"), `.tar.gz"`) || !bytes.HasPrefix([]byte(r.Raw), []byte("\x1f\x8b")) {
			t.Fatalf("%v: %d %q %q", body, r.Code, r.Header.Get("Content-Disposition"), r.Raw[:min(len(r.Raw), 20)])
		}
	}
	e := newOSEnv(t, osOpts{})
	before := len(e.actions())
	for _, p := range []string{"short pass", "password1234", "admin@acme.example", strings.Repeat("long enough ", 30)} {
		r := e.admin.post("/core/data/backup", map[string]any{"password": p})
		if r.Code != 400 || (r.code() != "weak_password" && r.code() != "invalid") || strings.Contains(r.Raw, p) {
			t.Errorf("%q: %d %s", p, r.Code, r.Raw)
		}
	}
	if got := e.actions(); len(got) != before {
		t.Errorf("a refused password wrote audit rows: %v", got[before:])
	}
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("a refused password made a snapshot: %v", d)
	}
	if bl, err := e.hh.Client.StateBackups(t.Context()); err != nil || len(bl.Backups) != 0 {
		t.Errorf("a refused password made a backup: %+v %v", bl, err)
	}
}

// Wrong backup passwords are counted per address on a limiter of their own: the eleventh guess is 429 rate_limited with a
// sentence about backup passwords, the right password does not count, and what is not a guess (a file encrypted to a key, a
// damaged header, a plain file with a password) is answered without counting. The count is not the setup code's: the same
// address still gets a plain file in with the right setup code.
func TestBackupUploadPasswordGuessesAreLimited(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	code := e.openSetup()
	plain := tarGz(t, member{name: "manifest.json", data: []byte(manifestOK)}, member{name: "vedette.db", data: e.backupDB(nil)})
	file := sealed(t, plain, backupPassword)

	wantOK(t, e.upload(code, plain, withPassword("a password for nothing")), 200) // a plain file: the password protects nothing
	wantOK(t, e.upload(code, file, withPassword(backupPassword)), 200)
	wantStatus(t, e.upload(code, file, func(q *http.Request) { q.Header.Set("X-Backup-Password", "%%% not base64") }), 400, "wrong_backup_password")

	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var toKey bytes.Buffer
	w, err := age.Encrypt(&toKey, x.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plain)
	_ = w.Close()
	// Over the box's cap: refused before scrypt runs. None of these is a guess.
	strong := bytes.Replace(file, []byte(" 10\n"), []byte(" 19\n"), 1)
	for range 12 {
		wantStatus(t, e.upload(code, toKey.Bytes(), withPassword(backupPassword)), 400, "not_a_backup")
		wantStatus(t, e.upload(code, strong, withPassword(backupPassword)), 400, "not_a_backup")
		wantOK(t, e.upload(code, file, withPassword(backupPassword)), 200)
	}
	for i := range 10 {
		wantStatus(t, e.upload(code, file, withPassword("wrong guess number "+strconv.Itoa(i))), 400, "wrong_backup_password")
	}
	r := e.upload(code, file, withPassword("the eleventh wrong guess"))
	wantStatus(t, r, 429, "rate_limited")
	if msg := r.str("error", "message"); msg != "Too many wrong backup passwords. Try again in 30 seconds." {
		t.Fatalf("429 message %q, want one about backup passwords", msg)
	}
	wantStatus(t, e.upload(code, file, withPassword(backupPassword)), 429, "rate_limited")
	wantOK(t, e.upload(code, plain), 200) // the setup code of the same address is not locked by the backup passwords
}

// The box's own encryption is age's: any length of archive (empty, under, at and over a 64 KiB chunk) gives the length
// announced before the first byte, and opens with the password.
func TestEncryptedBackupLengthIsExact(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 65535, 65536, 65537, 3*65536 + 7} {
		data := make([]byte, n)
		_, _ = rand.Read(data)
		r, size, err := core.EncryptBackupForTest(io.NopCloser(bytes.NewReader(data)), int64(n), backupPassword)
		if err != nil {
			t.Fatal(err)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(out)) != size {
			t.Errorf("%d bytes: announced %d, wrote %d", n, size, len(out))
		}
		id, _ := age.NewScryptIdentity(backupPassword)
		pr, err := age.Decrypt(bytes.NewReader(out), id)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := io.ReadAll(pr); err != nil || !bytes.Equal(back, data) {
			t.Errorf("%d bytes: round trip = %d bytes, %v", n, len(back), err)
		}
	}
}
