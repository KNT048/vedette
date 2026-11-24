package core

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/host/archive"
)

// A downloaded backup can be protected with a password: core encrypts the archive while it streams it, in the age format
// (age-encryption.org/v1) with the scrypt recipient, so the file opens on any box (the first-run restore asks for the
// password) and offline with the standard `age -d` tool. The password is never logged, audited, stored or echoed: it lives
// in the request and in the scrypt call only. The copy the box keeps of the backup is not encrypted (it never leaves the box).
//
// A password-protected file also carries the box's decryption key (vedette.key), so a restore on a new box keeps the saved
// secrets and two-step sign-in. The key goes INSIDE the encrypted stream, never next to it: the plaintext is one small gzip
// member holding a tar entry vedette.key (no end-of-archive blocks), followed by the host's archive unchanged. Standard
// tools read the two as one archive (`age -d f | tar -xz` gives vedette.key, manifest.json and vedette.db); the box splits
// the key member off and reads the rest with host/archive's rules. A plain download never carries the key.
const (
	ageMagic = "age-encryption.org/v1"
	// maxBackupWorkFactor is the highest scrypt cost (log2 N) an uploaded file may ask for: age's own default, what the box
	// writes and what the `age` tool writes. N=2^18, r=8 is 256 MiB of memory and about a second of CPU per try, once per
	// download or upload (each is one at a time); the core container has 2 GiB. A crafted file asking for more is refused
	// before scrypt runs.
	maxBackupWorkFactor = 18
	// ageChunk and ageTag are the payload's chunk size and the AEAD tag each chunk carries (age STREAM).
	ageChunk = 64 << 10
	ageTag   = 16
	// maxAgeHeader is how much of an upload is read to find its recipient stanzas; a box's header is under 200 bytes.
	maxAgeHeader = 4096

	codePasswordRequired    = "backup_password_required"
	codeWrongBackupPassword = "wrong_backup_password"
)

// backupWorkFactor is the scrypt cost of a backup the box encrypts: maxBackupWorkFactor (tests lower it).
var backupWorkFactor = maxBackupWorkFactor

// checkBackupPassword applies the sign-in password policy to a new backup password (12 to 256 characters, not guessable, not
// the email): the file can be attacked offline for as long as it exists, so its password must be at least as strong.
func checkBackupPassword(password, email string) error {
	if err := auth.ValidatePassword(password, email); err != nil {
		return apierr.New(err.Status, err.Code, strings.Replace(err.Message, "The password", "The backup password", 1))
	}
	return nil
}

// encryptBackup wraps the host's archive body (size bytes) in age with a scrypt recipient for password. It returns the
// encrypted stream, read as the response is written (no goroutine, nothing held whole), and its exact length, known before
// the first byte: the header and nonce age writes at once, the archive, and a 16-byte tag per 64 KiB chunk (at least one).
func encryptBackup(body io.ReadCloser, size int64, password string) (io.ReadCloser, int64, error) {
	rcpt, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, 0, fmt.Errorf("core: backup password: %w", err)
	}
	rcpt.SetWorkFactor(backupWorkFactor)
	r := &encryptingReader{src: body, buf: &bytes.Buffer{}, chunk: make([]byte, ageChunk)}
	if r.enc, err = age.Encrypt(r.buf, rcpt); err != nil {
		return nil, 0, fmt.Errorf("core: encrypt the backup: %w", err)
	}
	return r, int64(r.buf.Len()) + encryptedPayload(size), nil
}

// encryptedPayload is the length of age's payload (after the nonce) for n bytes of plaintext.
func encryptedPayload(n int64) int64 {
	chunks := max(1, (n+ageChunk-1)/ageChunk)
	return n + chunks*ageTag
}

// encryptingReader reads src through age's encrypting writer: each Read pulls plaintext until some ciphertext is ready.
type encryptingReader struct {
	src   io.ReadCloser
	enc   io.WriteCloser
	buf   *bytes.Buffer // ciphertext not yet read; the header and nonce first
	chunk []byte
	done  bool
}

func (r *encryptingReader) Read(p []byte) (int, error) {
	for r.buf.Len() == 0 {
		if r.done {
			return 0, io.EOF
		}
		n, err := r.src.Read(r.chunk)
		if n > 0 {
			if _, werr := r.enc.Write(r.chunk[:n]); werr != nil {
				return 0, fmt.Errorf("core: encrypt the backup: %w", werr)
			}
		}
		switch {
		case errors.Is(err, io.EOF):
			if cerr := r.enc.Close(); cerr != nil { // the last chunk
				return 0, fmt.Errorf("core: encrypt the backup: %w", cerr)
			}
			r.done = true
		case err != nil:
			return 0, err //nolint:wrapcheck // the host's read error, as for a plain download
		}
	}
	return r.buf.Read(p) //nolint:wrapcheck // a bytes.Buffer read
}

func (r *encryptingReader) Close() error { return r.src.Close() } //nolint:wrapcheck // the host body's close

// keyMember is the plaintext that precedes the host's archive in a password-protected download: a gzip member with one
// USTAR entry vedette.key (0600, the key's bytes, padded to the tar block) and no end-of-archive blocks, so the archive that
// follows continues the same tar stream. at is the entry's time.
func keyMember(key []byte, at time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	hdr := &tar.Header{Name: archive.MemberKey, Mode: 0o600, Size: int64(len(key)), ModTime: at.UTC().Truncate(time.Second), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("core: key member: %w", err)
	}
	if _, err := tw.Write(key); err != nil {
		return nil, fmt.Errorf("core: key member: %w", err)
	}
	if err := tw.Flush(); err != nil { // the padding of the entry, never Close: its end-of-archive blocks would end the tar here
		return nil, fmt.Errorf("core: key member: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("core: key member: %w", err)
	}
	return buf.Bytes(), nil
}

// maxKeyMember is how much of a decrypted upload is looked at for the key member: one is under 200 bytes.
const maxKeyMember = 4096

// errBadKeyMember: the decrypted file starts with a key entry that is not one keyMember writes.
var errBadKeyMember = errors.New("core: the key member of the backup is not valid")

// splitKeyMember takes the key member off the front of a decrypted backup in br, when there is one: the first gzip member
// whose first tar entry is vedette.key. It returns the key (nil when the file starts with the archive itself, as a file
// encrypted with `age -p` from a plain backup does; br is then left as it was) and consumes exactly the member. A first entry
// named vedette.key that is not a regular file of exactly secrets.KeySize bytes, alone in its gzip member, is errBadKeyMember.
// The bytes are untrusted: the password only says who made the file, not that the box did.
func splitKeyMember(br *bufio.Reader) ([]byte, error) {
	head, _ := br.Peek(maxKeyMember) // fewer bytes at the end of a short file
	src := bytes.NewReader(head)     // an io.ByteReader: gzip reads exactly one member from it, no more
	zr, err := gzip.NewReader(src)
	if err != nil {
		return nil, nil //nolint:nilerr // not gzip: host/archive says so with its own words
	}
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != archive.MemberKey {
		return nil, nil //nolint:nilerr // the archive itself: read by host/archive as it is
	}
	if hdr.Typeflag != tar.TypeReg || hdr.Size != secrets.KeySize || len(hdr.PAXRecords) > 0 {
		return nil, errBadKeyMember
	}
	key := make([]byte, secrets.KeySize)
	if _, err := io.ReadFull(tr, key); err != nil {
		return nil, errBadKeyMember
	}
	if _, err := tr.Next(); !errors.Is(err, io.EOF) { // the member ends right after the entry (its trailer checked)
		clear(key)
		return nil, errBadKeyMember
	}
	if _, err := br.Discard(len(head) - src.Len()); err != nil {
		clear(key)
		return nil, errBadKeyMember
	}
	return key, nil
}

// isAgeFile reports whether br starts with the age header line.
func isAgeFile(br *bufio.Reader) bool {
	head, _ := br.Peek(len(ageMagic) + 1)
	return string(head) == ageMagic+"\n"
}

// errAgeNotPassword: the file is encrypted to a key (an age identity), not with a password.
var errAgeNotPassword = errors.New("core: the age file is not password-encrypted")

// decryptBackup opens an age file from br with password. A file with no scrypt stanza (encrypted to a key) is refused
// before any work; the work factor is capped at the box's own (a bigger one from a crafted file would cost the box memory it
// does not have). A wrong password is wrongBackupPassword; anything else in the header is not a backup.
func decryptBackup(br *bufio.Reader, password string) (io.Reader, error) {
	head, _ := br.Peek(maxAgeHeader)
	if end := bytes.Index(head, []byte("\n---")); end < 0 || !bytes.Contains(head[:end], []byte("\n-> scrypt ")) {
		return nil, errAgeNotPassword
	}
	id, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, wrongBackupPassword()
	}
	id.SetMaxWorkFactor(maxBackupWorkFactor)
	r, err := age.Decrypt(br, id)
	var nomatch *age.NoIdentityMatchError
	switch {
	case err == nil:
		return r, nil
	case errors.As(err, &nomatch): // the file has a scrypt stanza (checked above): its password did not open it
		return nil, wrongBackupPassword()
	default: // a work factor over the cap, a damaged header
		return nil, notABackup("This file is encrypted in a way Vedette does not open, or it is damaged. Choose the file that Download backup saved.")
	}
}

func passwordRequired() *apierr.Error {
	return apierr.New(409, codePasswordRequired, "This backup is protected with a password. Enter the password that was set when it was downloaded.")
}

func wrongBackupPassword() *apierr.Error {
	return apierr.New(400, codeWrongBackupPassword, "The backup password is wrong. Enter the password that was set when the backup was downloaded.")
}

// backupPasswordHeader decodes X-Backup-Password: base64 of the password's UTF-8 bytes (a header carries ASCII only, and a
// password may be any text). "" when absent; a value that is not base64 of valid text is the wrong password.
func backupPasswordHeader(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) == 0 || len(b) > 4*auth.MaxPasswordLen || !utf8.Valid(b) {
		return "", wrongBackupPassword()
	}
	return string(b), nil
}
