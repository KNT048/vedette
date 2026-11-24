package core

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
)

// A downloaded backup can be protected with a password: core encrypts the archive while it streams it, in the age format
// (age-encryption.org/v1) with the scrypt recipient, so the file opens on any box (the first-run restore asks for the
// password) and offline with the standard `age -d` tool. The password is never logged, audited, stored or echoed: it lives
// in the request and in the scrypt call only. The copy the box keeps of the backup is not encrypted (it never leaves the box).
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
