// Package secrets stores secrets that Vedette must read back (API keys, SMTP passwords,
// TOTP keys, ...) encrypted with AES-256-GCM in core_secret (docs/DATA_MODEL.md section 5.4).
// The master key lives in a file with mode 0600, never in the database, logs or backups.
//
// OS assumption: Unix permission bits. LoadKeyFile refuses a key file readable by group or others.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// KeySize is the master key length in bytes (AES-256).
const KeySize = 32

// keyVersion is the only key version in use; rotation (re-encrypting rows) is not built yet.
const keyVersion = 1

var (
	// ErrNotFound is returned when no secret has the given id (and purpose).
	ErrNotFound = errors.New("secrets: not found")
	// ErrDecrypt is returned when a secret cannot be authenticated: wrong key, tampered
	// ciphertext, or a ciphertext moved to another row or purpose.
	ErrDecrypt = errors.New("secrets: cannot decrypt")
	// ErrInvalid is wrapped by input validation failures.
	ErrInvalid = errors.New("secrets: invalid input")
	// ErrRestricted is returned by Store.Open for a purpose whose reading was handed to one holder with Restrict.
	ErrRestricted = errors.New("secrets: this purpose can only be read by its holder")
)

var purposeRE = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// GenerateKeyFile creates path with 32 random bytes and mode 0600. It fails if the file exists.
func GenerateKeyFile(path string) (err error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("secrets: generate key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the key path comes from installer configuration, not from a request
	if err != nil {
		return fmt.Errorf("secrets: create key file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return fmt.Errorf("secrets: write key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("secrets: sync key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("secrets: close key file: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

// StageKeyFile writes a fresh random key next to path as path+".new" (mode 0600, owner and group of the existing key file, so a
// service that runs under another account can still read it), fsynced, and returns its name. PromoteKeyFile then renames it over
// path. Together they replace the key atomically: a crash leaves the old key or the new one, never a half file. An older
// leftover ".new" is overwritten.
func StageKeyFile(path string) (staged string, err error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("secrets: generate key: %w", err)
	}
	staged = path + ".new"
	_ = os.Remove(staged)
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the key path comes from installer configuration, not from a request
	if err != nil {
		return "", fmt.Errorf("secrets: create staged key file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(staged)
		}
	}()
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("secrets: write staged key file: %w", err)
	}
	if err := keepOwner(f, path); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("secrets: sync staged key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("secrets: close staged key file: %w", err)
	}
	return staged, nil
}

// keepOwner gives f the owner and group of the file at path, when that file exists and the process is allowed to (a process that
// created f as the same owner has nothing to change; a Chown refused for another owner is an error: the new key would be unreadable).
func keepOwner(f *os.File, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return nil //nolint:nilerr // no old key: nothing to keep
	}
	uid, gid, ok := ownerOf(info)
	if !ok {
		return nil
	}
	own, err := f.Stat()
	if err != nil {
		return fmt.Errorf("secrets: stat staged key file: %w", err)
	}
	if ouid, ogid, ok := ownerOf(own); ok && ouid == uid && ogid == gid {
		return nil
	}
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("secrets: give the new key the owner of the old one: %w", err)
	}
	return nil
}

// PromoteKeyFile renames a staged key over path and syncs the directory.
func PromoteKeyFile(staged, path string) error {
	if err := os.Rename(staged, path); err != nil {
		return fmt.Errorf("secrets: replace key file: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory so a newly created entry survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // parent of the key path from installer configuration
	if err != nil {
		return fmt.Errorf("secrets: open key directory: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("secrets: sync key directory: %w", err)
	}
	return d.Close()
}

// LoadKeyFile reads the master key. It refuses a symlink, a FIFO or any non-regular file, and a
// file that is not exactly 32 bytes or has group or other permission bits. The file is opened
// non-blocking and without following symlinks, so a planted FIFO cannot hang start-up.
func LoadKeyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|openFlags, 0) //nolint:gosec // the key path comes from installer configuration, not from a request
	if err != nil {
		return nil, fmt.Errorf("secrets: open key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("secrets: stat key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secrets: key file %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("secrets: key file %s has mode %#o; group and other access must be off (chmod 600)", path, perm)
	}
	if info.Size() != KeySize {
		return nil, fmt.Errorf("secrets: key file %s has %d bytes, want %d", path, info.Size(), KeySize)
	}
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, fmt.Errorf("secrets: read key file: %w", err)
	}
	return key, nil
}

// Store encrypts and decrypts rows of core_secret.
type Store struct {
	aead cipher.AEAD
	now  func() time.Time

	mu         sync.RWMutex
	restricted map[string]bool // purposes only their Opener may decrypt
}

// reserved holds the purposes that no Store.Open may read in this process, whichever Store it is called on and whether or not
// the holder has called Restrict yet. A holder package reserves its purpose in an init function, so the purpose is closed from the
// start of the process and not only after the holder's own start-up code has run (core/pki, D-110).
var reserved sync.Map

// Reserve closes purpose to Store.Open in this process (ErrRestricted for every caller), for every Store. It does not give
// anyone a way to read it: the holder still calls Restrict on its Store to get the Opener. It panics on a malformed purpose
// (a programming error in an init function) and is idempotent.
func Reserve(purpose string) {
	if err := checkPurpose(purpose); err != nil {
		panic(err)
	}
	reserved.Store(purpose, struct{}{})
}

// Opener decrypts one restricted purpose. Whoever holds it is the only reader of that purpose.
type Opener struct {
	s       *Store
	purpose string
}

// Restrict makes purpose readable only through the returned Opener: from now on Store.Open(purpose) answers ErrRestricted. It is
// for secrets that a single package must be the only one to decrypt (the credentials of device connections, D-93); sealing,
// replacing and deleting stay open to every caller. A purpose can be restricted once, so there is exactly one holder.
func (s *Store) Restrict(purpose string) (*Opener, error) {
	if err := checkPurpose(purpose); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.restricted[purpose] {
		return nil, fmt.Errorf("%w: purpose %q is already restricted", ErrInvalid, purpose)
	}
	if s.restricted == nil {
		s.restricted = map[string]bool{}
	}
	s.restricted[purpose] = true
	return &Opener{s: s, purpose: purpose}, nil
}

// Open decrypts secret id of the opener's purpose.
func (o *Opener) Open(ctx context.Context, q coredb.DBTX, id string) ([]byte, error) {
	return o.s.open(ctx, q, id, o.purpose)
}

// New builds a Store from a 32-byte master key.
func New(key []byte) (*Store, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key is %d bytes, want %d", ErrInvalid, len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return &Store{aead: aead, now: time.Now}, nil
}

func aad(id, purpose string) []byte { return []byte(id + "|" + purpose) }

func checkPurpose(purpose string) error {
	if !purposeRE.MatchString(purpose) {
		return fmt.Errorf("%w: purpose %q must match %s", ErrInvalid, purpose, purposeRE)
	}
	return nil
}

// encrypt returns nonce, ciphertext and last4 (nil when not kept).
func (s *Store) encrypt(id, purpose string, plaintext []byte, keepLast4 bool) (nonce, ct []byte, last4 *string, err error) {
	if err := checkPurpose(purpose); err != nil {
		return nil, nil, nil, err
	}
	if len(plaintext) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: empty secret", ErrInvalid)
	}
	if keepLast4 {
		if !utf8.Valid(plaintext) {
			return nil, nil, nil, fmt.Errorf("%w: last4 needs UTF-8 text", ErrInvalid)
		}
		// A short secret would be mostly revealed by its last 4 characters.
		if runes := []rune(string(plaintext)); len(runes) >= 8 {
			l := string(runes[len(runes)-4:])
			last4 = &l
		}
	}
	nonce = make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	return nonce, s.aead.Seal(nil, nonce, plaintext, aad(id, purpose)), last4, nil
}

// Seal encrypts plaintext into a new core_secret row inside tx and returns its id and last4
// ("" when no last4 is kept: keepLast4 false or fewer than 8 characters).
func (s *Store) Seal(ctx context.Context, tx *sql.Tx, purpose string, plaintext []byte, keepLast4 bool) (id, last4 string, err error) {
	id = store.NewID("sec")
	nonce, ct, l4, err := s.encrypt(id, purpose, plaintext, keepLast4)
	if err != nil {
		return "", "", err
	}
	err = coredb.New(tx).InsertSecret(ctx, coredb.InsertSecretParams{
		ID: id, Purpose: purpose, Nonce: nonce, Ciphertext: ct, KeyVersion: keyVersion, Last4: l4,
		CreatedAt: store.FormatTS(s.now()),
	})
	if err != nil {
		return "", "", fmt.Errorf("secrets: insert: %w", err)
	}
	if l4 != nil {
		last4 = *l4
	}
	return id, last4, nil
}

// Open decrypts the secret id. purpose must be the one it was sealed with, and not one that was handed to a single holder with
// Restrict (ErrRestricted).
func (s *Store) Open(ctx context.Context, q coredb.DBTX, id, purpose string) ([]byte, error) {
	s.mu.RLock()
	locked := s.restricted[purpose]
	s.mu.RUnlock()
	if _, ok := reserved.Load(purpose); ok {
		locked = true
	}
	if locked {
		return nil, fmt.Errorf("%w: %s", ErrRestricted, purpose)
	}
	return s.open(ctx, q, id, purpose)
}

func (s *Store) open(ctx context.Context, q coredb.DBTX, id, purpose string) ([]byte, error) {
	if err := checkPurpose(purpose); err != nil {
		return nil, err
	}
	row, err := coredb.New(q).GetSecret(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: read: %w", err)
	}
	if row.KeyVersion != keyVersion || row.Purpose != purpose {
		return nil, ErrDecrypt
	}
	if len(row.Nonce) != s.aead.NonceSize() { // cipher.AEAD.Open panics on a wrong-size nonce
		return nil, ErrDecrypt
	}
	pt, err := s.aead.Open(nil, row.Nonce, row.Ciphertext, aad(row.ID, purpose))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// maxCheckedRows bounds CountOpenable on a database that came from outside the box.
const maxCheckedRows = 10000

// CountOpenable reports how many rows of core_secret in q this store's key decrypts (opened) out of how many it tried
// (total, at most 10000). It is for a key file checked against a backup's database before a restore puts it on the box
// (D-518): no plaintext leaves it, and Restrict and Reserve do not apply, since nothing is read out.
func (s *Store) CountOpenable(ctx context.Context, q coredb.DBTX) (opened, total int, err error) {
	// ponytail: a hand-written query (sqlc has no list of every secret); move it to core/store/queries if a second caller needs it.
	rows, err := q.QueryContext(ctx, `SELECT id, purpose FROM core_secret LIMIT ?`, maxCheckedRows)
	if err != nil {
		return 0, 0, fmt.Errorf("secrets: list: %w", err)
	}
	type row struct{ id, purpose string }
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.purpose); err != nil {
			_ = rows.Close()
			return 0, 0, fmt.Errorf("secrets: list: %w", err)
		}
		all = append(all, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, 0, fmt.Errorf("secrets: list: %w", err)
	}
	for _, r := range all {
		_, err := s.open(ctx, q, r.id, r.purpose)
		switch {
		case err == nil:
			opened++
		case errors.Is(err, ErrDecrypt), errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound):
		default:
			return 0, 0, err
		}
	}
	return opened, len(all), nil
}

// Replace re-encrypts secret id with a new value (new nonce) and returns the new last4 ("" if none).
// purpose must match the stored one.
func (s *Store) Replace(ctx context.Context, tx *sql.Tx, id, purpose string, plaintext []byte, keepLast4 bool) (last4 string, err error) {
	nonce, ct, l4, err := s.encrypt(id, purpose, plaintext, keepLast4)
	if err != nil {
		return "", err
	}
	rotated := store.FormatTS(s.now())
	n, err := coredb.New(tx).ReplaceSecret(ctx, coredb.ReplaceSecretParams{
		Nonce: nonce, Ciphertext: ct, KeyVersion: keyVersion, Last4: l4, RotatedAt: &rotated, ID: id, Purpose: purpose,
	})
	if err != nil {
		return "", fmt.Errorf("secrets: replace: %w", err)
	}
	if n == 0 {
		return "", ErrNotFound
	}
	if l4 != nil {
		last4 = *l4
	}
	return last4, nil
}

// Delete removes secret id. Owners call it in the same transaction that deletes the row pointing at it.
func (s *Store) Delete(ctx context.Context, tx *sql.Tx, id string) error {
	n, err := coredb.New(tx).DeleteSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("secrets: delete: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// OpenOrCreate returns the one random key of a purpose (size 16 to 64 bytes), making and sealing it the
// first time it is asked for. It is for keys the box makes for itself (an HMAC key), not for secrets a user
// supplies: there is exactly one row per purpose, and callers racing on first use all get the same bytes
// (the check and the insert run in one write transaction).
func (s *Store) OpenOrCreate(ctx context.Context, db *store.DB, purpose string, size int) ([]byte, error) {
	if err := checkPurpose(purpose); err != nil {
		return nil, err
	}
	if size < 16 || size > 64 {
		return nil, fmt.Errorf("%w: key size %d, want 16 to 64", ErrInvalid, size)
	}
	if id, err := coredb.New(db.Reader()).GetSecretIDByPurpose(ctx, purpose); err == nil {
		return s.Open(ctx, db.Reader(), id, purpose)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("secrets: find %s: %w", purpose, err)
	}
	var key []byte
	err := db.Write(ctx, func(tx *sql.Tx) error {
		id, err := coredb.New(tx).GetSecretIDByPurpose(ctx, purpose)
		if err == nil { // another caller made it between our read and this transaction
			key, err = s.Open(ctx, tx, id, purpose)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("secrets: find %s: %w", purpose, err)
		}
		k := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			return fmt.Errorf("secrets: random key: %w", err)
		}
		if _, _, err := s.Seal(ctx, tx, purpose, k, false); err != nil {
			return err
		}
		key = k
		return nil
	})
	return key, err
}
