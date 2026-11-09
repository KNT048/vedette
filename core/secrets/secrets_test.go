package secrets_test

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

const coreMigrations = "../../modules/core/migrations/sqlite"

func newStore(t *testing.T) (*secrets.Store, *store.DB) {
	t.Helper()
	key := bytes.Repeat([]byte{7}, secrets.KeySize)
	s, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return s, storetest.NewMigrated(t, "core", coreMigrations)
}

func TestKeyFile(t *testing.T) {
	t.Parallel()
	t.Run("generate then load", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "master.key")
		if err := secrets.GenerateKeyFile(p); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
		}
		key, err := secrets.LoadKeyFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != secrets.KeySize || bytes.Equal(key, make([]byte, secrets.KeySize)) {
			t.Fatalf("key = %x", key)
		}
		if err := secrets.GenerateKeyFile(p); err == nil {
			t.Fatal("GenerateKeyFile overwrote an existing file")
		}
		again, err := secrets.LoadKeyFile(p)
		if err != nil || !bytes.Equal(key, again) {
			t.Fatalf("key changed after failed overwrite: %v", err)
		}
	})
	t.Run("two generated keys differ", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		for _, p := range []string{a, b} {
			if err := secrets.GenerateKeyFile(p); err != nil {
				t.Fatal(err)
			}
		}
		ka, _ := secrets.LoadKeyFile(a)
		kb, _ := secrets.LoadKeyFile(b)
		if bytes.Equal(ka, kb) {
			t.Fatal("identical keys")
		}
	})
	t.Run("refuses loose permissions", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o601} {
			p := filepath.Join(t.TempDir(), "k")
			if err := os.WriteFile(p, make([]byte, secrets.KeySize), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := secrets.LoadKeyFile(p); err == nil {
				t.Errorf("mode %#o accepted", mode)
			}
		}
	})
	t.Run("refuses wrong size, directory, missing", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for _, n := range []int{0, 16, 31, 33, 64} {
			p := filepath.Join(dir, "k"+strings.Repeat("x", n))
			if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := secrets.LoadKeyFile(p); err == nil {
				t.Errorf("%d bytes accepted", n)
			}
		}
		if _, err := secrets.LoadKeyFile(dir); err == nil {
			t.Error("directory accepted")
		}
		if _, err := secrets.LoadKeyFile(filepath.Join(dir, "missing")); err == nil {
			t.Error("missing file accepted")
		}
	})
	t.Run("New rejects wrong key length", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{0, 16, 31, 33} {
			if _, err := secrets.New(make([]byte, n)); !errors.Is(err, secrets.ErrInvalid) {
				t.Errorf("%d-byte key: err = %v", n, err)
			}
		}
	})
}

func TestSealOpen(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()

	var id string
	secret := []byte("sk-ant-0123456789abcdef")
	err := db.Write(ctx, func(tx *sql.Tx) error {
		var last4 string
		var err error
		id, last4, err = s.Seal(ctx, tx, "ai_profile.api_key", secret, true)
		if last4 != "cdef" {
			t.Errorf("last4 = %q, want cdef", last4)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "sec-") {
		t.Fatalf("id = %q", id)
	}

	got, err := s.Open(ctx, db.Reader(), id, "ai_profile.api_key")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %q, %v", got, err)
	}

	// The plaintext is nowhere in the stored row.
	var nonce, ct []byte
	var l4 sql.NullString
	if err := db.Reader().QueryRowContext(ctx, "SELECT nonce, ciphertext, last4 FROM core_secret WHERE id = ?", id).Scan(&nonce, &ct, &l4); err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 12 || len(ct) != len(secret)+16 || bytes.Contains(ct, secret) || l4.String != "cdef" {
		t.Fatalf("row: nonce %d bytes, ct %d bytes, last4 %q", len(nonce), len(ct), l4.String)
	}

	t.Run("wrong purpose", func(t *testing.T) {
		if _, err := s.Open(ctx, db.Reader(), id, "notify_channel.secret"); !errors.Is(err, secrets.ErrDecrypt) {
			t.Fatalf("err = %v, want ErrDecrypt", err)
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		if _, err := s.Open(ctx, db.Reader(), "sec-nope", "ai_profile.api_key"); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other, _ := secrets.New(bytes.Repeat([]byte{9}, secrets.KeySize))
		if _, err := other.Open(ctx, db.Reader(), id, "ai_profile.api_key"); !errors.Is(err, secrets.ErrDecrypt) {
			t.Fatalf("err = %v, want ErrDecrypt", err)
		}
	})
	t.Run("copied to another row fails to open (AAD binds the id)", func(t *testing.T) {
		var id2 string
		err := db.Write(ctx, func(tx *sql.Tx) error {
			var err error
			id2, _, err = s.Seal(ctx, tx, "ai_profile.api_key", []byte("a different secret value"), false)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE core_secret SET nonce = ?, ciphertext = ? WHERE id = ?", nonce, ct, id2)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Open(ctx, db.Reader(), id2, "ai_profile.api_key"); !errors.Is(err, secrets.ErrDecrypt) {
			t.Fatalf("err = %v, want ErrDecrypt", err)
		}
	})
	t.Run("purpose column changed fails to open (AAD binds the purpose)", func(t *testing.T) {
		var id3 string
		err := db.Write(ctx, func(tx *sql.Tx) error {
			var err error
			id3, _, err = s.Seal(ctx, tx, "feeds_source.secret", []byte("feed token value 12345"), false)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE core_secret SET purpose = 'resp.blocklist_token' WHERE id = ?", id3)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"resp.blocklist_token", "feeds_source.secret"} {
			if _, err := s.Open(ctx, db.Reader(), id3, p); !errors.Is(err, secrets.ErrDecrypt) {
				t.Errorf("purpose %q: err = %v, want ErrDecrypt", p, err)
			}
		}
	})
	t.Run("flipped ciphertext bit fails", func(t *testing.T) {
		err := db.Write(ctx, func(tx *sql.Tx) error {
			bad := bytes.Clone(ct)
			bad[0] ^= 1
			_, err := tx.ExecContext(ctx, "UPDATE core_secret SET ciphertext = ? WHERE id = ?", bad, id)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Open(ctx, db.Reader(), id, "ai_profile.api_key"); !errors.Is(err, secrets.ErrDecrypt) {
			t.Fatalf("err = %v, want ErrDecrypt", err)
		}
	})
}

func TestSealRules(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()

	tests := []struct {
		name      string
		purpose   string
		plaintext string
		keep      bool
		wantLast4 string
		wantErr   bool
	}{
		{"keeps last 4 of 8 chars", "p.x", "12345678", true, "5678", false},
		{"7 chars reveal nothing", "p.x", "1234567", true, "", false},
		{"keepLast4 off", "p.x", "abcdefghijkl", false, "", false},
		{"last 4 characters not bytes", "p.x", "mật khẩu dài", true, " dài", false},
		{"empty secret", "p.x", "", false, "", true},
		{"uppercase purpose", "P.x", "12345678", false, "", true},
		{"purpose with space", "p x", "12345678", false, "", true},
		{"purpose with pipe", "p|x", "12345678", false, "", true},
		{"empty purpose", "", "12345678", false, "", true},
		{"digit first purpose", "1p", "12345678", false, "", true},
		{"purpose too long", "a" + strings.Repeat("b", 64), "12345678", false, "", true},
		{"purpose at max length", "a" + strings.Repeat("b", 63), "12345678", false, "", false},
		{"last4 on invalid UTF-8", "p.x", "abcd\xff\xfe\xfd\xfcefgh", true, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Write(ctx, func(tx *sql.Tx) error {
				id, last4, err := s.Seal(ctx, tx, tc.purpose, []byte(tc.plaintext), tc.keep)
				if err != nil {
					return err
				}
				if last4 != tc.wantLast4 {
					t.Errorf("last4 = %q, want %q", last4, tc.wantLast4)
				}
				var stored sql.NullString
				if err := tx.QueryRowContext(ctx, "SELECT last4 FROM core_secret WHERE id = ?", id).Scan(&stored); err != nil {
					return err
				}
				if stored.Valid != (tc.wantLast4 != "") || stored.String != tc.wantLast4 {
					t.Errorf("stored last4 = %+v, want %q", stored, tc.wantLast4)
				}
				return nil
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}

	t.Run("fresh nonce per seal", func(t *testing.T) {
		nonces := map[string]bool{}
		err := db.Write(ctx, func(tx *sql.Tx) error {
			for range 50 {
				id, _, err := s.Seal(ctx, tx, "p.x", []byte("same plaintext"), false)
				if err != nil {
					return err
				}
				var n []byte
				if err := tx.QueryRowContext(ctx, "SELECT nonce FROM core_secret WHERE id = ?", id).Scan(&n); err != nil {
					return err
				}
				nonces[string(n)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(nonces) != 50 {
			t.Fatalf("%d distinct nonces for 50 seals", len(nonces))
		}
	})
}

func TestReplaceDelete(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()

	var id string
	if err := db.Write(ctx, func(tx *sql.Tx) (err error) {
		id, _, err = s.Seal(ctx, tx, "p.x", []byte("first-value-1234"), true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var nonce1 []byte
	if err := db.Reader().QueryRowContext(ctx, "SELECT nonce FROM core_secret WHERE id = ?", id).Scan(&nonce1); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(ctx, func(tx *sql.Tx) error {
		l4, err := s.Replace(ctx, tx, id, "p.x", []byte("second-value-9876"), true)
		if l4 != "9876" {
			t.Errorf("last4 = %q", l4)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(ctx, db.Reader(), id, "p.x")
	if err != nil || string(got) != "second-value-9876" {
		t.Fatalf("Open after Replace = %q, %v", got, err)
	}
	var nonce2 []byte
	var rotated sql.NullString
	if err := db.Reader().QueryRowContext(ctx, "SELECT nonce, rotated_at FROM core_secret WHERE id = ?", id).Scan(&nonce2, &rotated); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonce1, nonce2) || !rotated.Valid {
		t.Fatalf("nonce reused or rotated_at unset: %v", rotated)
	}

	t.Run("replace with a short secret clears last4", func(t *testing.T) {
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			l4, err := s.Replace(ctx, tx, id, "p.x", []byte("short"), true)
			if l4 != "" {
				t.Errorf("last4 = %q", l4)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var stored sql.NullString
		if err := db.Reader().QueryRowContext(ctx, "SELECT last4 FROM core_secret WHERE id = ?", id).Scan(&stored); err != nil || stored.Valid {
			t.Fatalf("stored last4 = %+v, %v", stored, err)
		}
	})
	t.Run("replace with wrong purpose or id", func(t *testing.T) {
		err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := s.Replace(ctx, tx, id, "other.purpose", []byte("whatever-value"), false)
			return err
		})
		if !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("wrong purpose: err = %v", err)
		}
		err = db.Write(ctx, func(tx *sql.Tx) error {
			_, err := s.Replace(ctx, tx, "sec-missing", "p.x", []byte("whatever-value"), false)
			return err
		})
		if !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("missing id: err = %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		if err := db.Write(ctx, func(tx *sql.Tx) error { return s.Delete(ctx, tx, id) }); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Open(ctx, db.Reader(), id, "p.x"); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("Open after Delete: %v", err)
		}
		if err := db.Write(ctx, func(tx *sql.Tx) error { return s.Delete(ctx, tx, id) }); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("second Delete: %v", err)
		}
	})
	t.Run("seal rolled back with its transaction", func(t *testing.T) {
		var rolled string
		sentinel := errors.New("caller failed")
		err := db.Write(ctx, func(tx *sql.Tx) (err error) {
			rolled, _, err = s.Seal(ctx, tx, "p.x", []byte("never stored value"), false)
			if err != nil {
				return err
			}
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
		if _, err := s.Open(ctx, db.Reader(), rolled, "p.x"); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("rolled-back secret still readable: %v", err)
		}
	})
}

func TestLoadKeyFileRefusesSymlinkAndFIFO(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "keyPath.key")
	if err := secrets.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.LoadKeyFile(link); err == nil {
		t.Error("symlink to a valid key file accepted")
	}

	fifo := filepath.Join(dir, "fifo.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := secrets.LoadKeyFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("FIFO accepted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("LoadKeyFile blocked on a FIFO")
	}
}

func TestGenerateKeyFileMissingDirectory(t *testing.T) {
	t.Parallel()
	if err := secrets.GenerateKeyFile(filepath.Join(t.TempDir(), "no", "such", "dir", "k")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestOpenMalformedNonceDoesNotPanic(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()
	var id string
	if err := db.Write(ctx, func(tx *sql.Tx) (err error) {
		id, _, err = s.Seal(ctx, tx, "p.x", []byte("some secret value"), false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The migration CHECKs refuse bad nonces on write; switch them off to simulate a damaged file.
	for _, nonce := range []any{[]byte{1, 2, 3}, []byte{}, make([]byte, 13), "twelve-chars"} {
		err := db.Write(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "PRAGMA ignore_check_constraints = ON"); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "UPDATE core_secret SET nonce = ? WHERE id = ?", nonce, id)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Open(ctx, db.Reader(), id, "p.x"); !errors.Is(err, secrets.ErrDecrypt) {
			t.Errorf("nonce %v: err = %v, want ErrDecrypt", nonce, err)
		}
	}
}

func TestSchemaRejectsBadNonceAndCiphertext(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	ctx := t.Context()
	good12, good16 := make([]byte, 12), make([]byte, 16)
	tests := []struct {
		name       string
		nonce, ct  any
		wantReject bool
	}{
		{"good", good12, good16, false},
		{"short nonce", make([]byte, 11), good16, true},
		{"text nonce of 12 chars", "abcdefghijkl", good16, true},
		{"text ciphertext", good12, "0123456789abcdef", true},
		{"short ciphertext", good12, make([]byte, 15), true},
	}
	for i, tc := range tests {
		err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO core_secret (id, purpose, nonce, ciphertext, key_version, created_at) VALUES (?, 'p.x', ?, ?, 1, '2026-01-01T00:00:00.000Z')",
				fmt.Sprintf("sec-t%d", i), tc.nonce, tc.ct)
			return err
		})
		if (err != nil) != tc.wantReject {
			t.Errorf("%s: err = %v, wantReject %v", tc.name, err, tc.wantReject)
		}
	}
}

func TestOpenOrCreateMakesOneKeyPerPurpose(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()
	const purpose = "core_email_code.hmac_key"

	// Many callers racing on first use must end up with one row and the same bytes.
	keys := make(chan []byte, 8)
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			k, err := s.OpenOrCreate(ctx, db, purpose, 32)
			keys <- k
			errs <- err
		}()
	}
	var first []byte
	for range 8 {
		k, err := <-keys, <-errs
		if err != nil {
			t.Fatal(err)
		}
		if len(k) != 32 || bytes.Equal(k, make([]byte, 32)) {
			t.Fatalf("key = %x", k)
		}
		if first == nil {
			first = k
		} else if !bytes.Equal(first, k) {
			t.Fatal("two callers got different keys")
		}
	}
	var n int
	if err := db.Reader().QueryRowContext(ctx, "SELECT count(*) FROM core_secret WHERE purpose = ?", purpose).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d, %v; want 1", n, err)
	}
	// Stored encrypted, not in the clear.
	var ct []byte
	if err := db.Reader().QueryRowContext(ctx, "SELECT ciphertext FROM core_secret WHERE purpose = ?", purpose).Scan(&ct); err != nil || bytes.Contains(ct, first) {
		t.Fatalf("key stored in the clear: %v", err)
	}
	// Another purpose gets another key; a bad purpose or size is refused.
	other, err := s.OpenOrCreate(ctx, db, "core_other.key", 32)
	if err != nil || bytes.Equal(other, first) {
		t.Fatalf("other purpose: %x, %v", other, err)
	}
	if _, err := s.OpenOrCreate(ctx, db, "Bad Purpose", 32); !errors.Is(err, secrets.ErrInvalid) {
		t.Fatalf("bad purpose: %v", err)
	}
	if _, err := s.OpenOrCreate(ctx, db, "core_tiny.key", 8); !errors.Is(err, secrets.ErrInvalid) {
		t.Fatalf("size 8: %v", err)
	}
}

// Restrict hands the reading of one purpose to a single holder: Store.Open refuses it from then on, the Opener reads it, other
// purposes are not affected, and sealing, replacing and deleting stay open (the owner of a purpose still writes through Store).
func TestRestrictLeavesOneReader(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()
	const purpose = "restricted.demo"
	var id, other string
	err := db.Write(ctx, func(tx *sql.Tx) (err error) {
		if id, _, err = s.Seal(ctx, tx, purpose, []byte("the-token-0123456789"), true); err != nil {
			return err
		}
		other, _, err = s.Seal(ctx, tx, "other.demo", []byte("other-token-0123456789"), true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Open(ctx, db.Reader(), id, purpose); err != nil || string(got) != "the-token-0123456789" {
		t.Fatalf("Open before Restrict = %q, %v", got, err)
	}
	op, err := s.Restrict(purpose)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, db.Reader(), id, purpose); !errors.Is(err, secrets.ErrRestricted) {
		t.Fatalf("Store.Open of a restricted purpose = %v, want ErrRestricted", err)
	}
	if got, err := op.Open(ctx, db.Reader(), id); err != nil || string(got) != "the-token-0123456789" {
		t.Fatalf("Opener.Open = %q, %v", got, err)
	}
	if got, err := s.Open(ctx, db.Reader(), other, "other.demo"); err != nil || string(got) != "other-token-0123456789" {
		t.Fatalf("another purpose after Restrict = %q, %v", got, err)
	}
	// The opener reads its own purpose only: a secret of another purpose does not decrypt through it.
	if _, err := op.Open(ctx, db.Reader(), other); !errors.Is(err, secrets.ErrDecrypt) {
		t.Fatalf("Opener.Open of another purpose's secret = %v, want ErrDecrypt", err)
	}
	if _, err := s.Restrict(purpose); !errors.Is(err, secrets.ErrInvalid) {
		t.Fatalf("a second Restrict of the same purpose = %v, want ErrInvalid (one holder)", err)
	}
	if _, err := s.Restrict("Bad Purpose"); !errors.Is(err, secrets.ErrInvalid) {
		t.Fatalf("Restrict of a malformed purpose = %v", err)
	}
	err = db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := s.Replace(ctx, tx, id, purpose, []byte("a-newer-token-0123456789"), true); err != nil {
			return err
		}
		fresh, _, err := s.Seal(ctx, tx, purpose, []byte("another-0123456789"), true)
		if err != nil {
			return err
		}
		return s.Delete(ctx, tx, fresh)
	})
	if err != nil {
		t.Fatalf("writing a restricted purpose: %v", err)
	}
	if got, err := op.Open(ctx, db.Reader(), id); err != nil || string(got) != "a-newer-token-0123456789" {
		t.Fatalf("Opener.Open after Replace = %q, %v", got, err)
	}
}

// A reserved purpose is closed to Store.Open on every Store from the moment Reserve ran, before any holder has called
// Restrict; the holder still gets its Opener (core/pki reserves the CA purpose in an init function, D-110).
func TestReserveClosesAPurposeBeforeAnyHolderRestrictsIt(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	other, _ := newStore(t)
	ctx := t.Context()
	purpose := fmt.Sprintf("reserved.t%d", time.Now().UnixNano()) // Reserve is for the life of the process: a new purpose for every run
	var id string
	err := db.Write(ctx, func(tx *sql.Tx) (err error) {
		id, _, err = s.Seal(ctx, tx, purpose, []byte("the-secret-0123456789"), false)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Open(ctx, db.Reader(), id, purpose); err != nil || len(got) == 0 {
		t.Fatalf("before Reserve: %q %v", got, err)
	}
	secrets.Reserve(purpose)
	secrets.Reserve(purpose) // idempotent
	for name, st := range map[string]*secrets.Store{"the store that sealed it": s, "another store": other} {
		if _, err := st.Open(ctx, db.Reader(), id, purpose); !errors.Is(err, secrets.ErrRestricted) {
			t.Errorf("%s: Open of a reserved purpose = %v, want ErrRestricted", name, err)
		}
	}
	op, err := s.Restrict(purpose)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := op.Open(ctx, db.Reader(), id); err != nil || string(got) != "the-secret-0123456789" {
		t.Errorf("the holder's Opener = %q %v", got, err)
	}
	defer func() {
		if recover() == nil {
			t.Error("Reserve of a malformed purpose did not panic")
		}
	}()
	secrets.Reserve("Bad Purpose")
}
