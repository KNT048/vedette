package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// MinisignKey is one trusted minisign public key.
type MinisignKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// KeyID is the id as minisign prints it: 16 upper-case hex digits (the stored little-endian
// 8 bytes, reversed). index.json revocations name keys this way.
func (k MinisignKey) KeyID() string { return keyIDString(k.ID) }

func keyIDString(id [8]byte) string {
	var r [8]byte
	for i := range id {
		r[7-i] = id[i]
	}
	return strings.ToUpper(hex.EncodeToString(r[:]))
}

// validMinisignKeyID reports whether s looks like a minisign key id (16 upper-case hex digits).
func validMinisignKeyID(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

const (
	pubKeyLen  = 2 + 8 + 32
	sigFileLen = 2 + 8 + 64
	commentMax = 1024
	pubFileMax = 512
	untrusted  = "untrusted comment: "
	trusted    = "trusted comment: "
)

var errB64 = errors.New("not canonical base64")

// decodeB64 decodes standard, padded, canonical base64 (no whitespace, no line breaks, no stray
// padding bits) to at most limit bytes.
func decodeB64(s string, limit int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, errB64
	}
	if strings.ContainsAny(s, "\r\n") { // the decoder would silently skip them
		return nil, errB64
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > limit {
		return nil, errB64
	}
	return b, nil
}

// ParseMinisignPublicKey reads a minisign public key: either the one-line "RWQ…" form or the
// two-line .pub file ("untrusted comment: …" then the key line).
func ParseMinisignPublicKey(s string) (MinisignKey, error) {
	var k MinisignKey
	if len(s) > pubFileMax || strings.Contains(s, "\r") {
		return k, errors.New("minisign public key: too long or has a carriage return")
	}
	s = strings.TrimSuffix(s, "\n")
	lines := strings.Split(s, "\n")
	line := ""
	switch {
	case len(lines) == 1:
		line = lines[0]
	case len(lines) == 2 && strings.HasPrefix(lines[0], untrusted):
		line = lines[1]
	default:
		return k, errors.New("minisign public key: wrong layout")
	}
	b, err := decodeB64(line, pubKeyLen)
	if err != nil || len(b) != pubKeyLen {
		return k, errors.New("minisign public key: wrong encoding or length")
	}
	if b[0] != 'E' || b[1] != 'd' {
		return k, errors.New("minisign public key: wrong algorithm")
	}
	copy(k.ID[:], b[2:10])
	k.Key = ed25519.PublicKey(append([]byte(nil), b[10:]...))
	return k, nil
}

// minisigFile is a parsed .minisig.
type minisigFile struct {
	keyID          [8]byte
	sig            [64]byte
	trustedComment string
	globalSig      [64]byte
}

// parseMinisig parses the four-line .minisig layout strictly: algorithm "ED" (prehashed) only,
// "Ed" (legacy, signs the file itself) is refused, exact lengths, one optional final newline, no
// carriage returns or control characters in the signed comment.
func parseMinisig(raw []byte) (*minisigFile, error) {
	if len(raw) > MaxSigBytes {
		return nil, wrap(ErrTooLarge, "signature file")
	}
	s := string(raw)
	if strings.Contains(s, "\r") {
		return nil, wrap(ErrBadSignature, "carriage return in signature file")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], untrusted) || !strings.HasPrefix(lines[2], trusted) {
		return nil, wrap(ErrBadSignature, "signature file layout")
	}
	if len(lines[0]) > commentMax+len(untrusted) {
		return nil, wrap(ErrBadSignature, "untrusted comment too long")
	}
	tc := strings.TrimPrefix(lines[2], trusted)
	if len(tc) > commentMax {
		return nil, wrap(ErrBadSignature, "trusted comment too long")
	}
	for i := 0; i < len(tc); i++ {
		if tc[i] < 0x20 || tc[i] == 0x7f {
			return nil, wrap(ErrBadSignature, "control character in trusted comment")
		}
	}
	b, err := decodeB64(lines[1], sigFileLen)
	if err != nil || len(b) != sigFileLen {
		return nil, wrap(ErrBadSignature, "signature encoding")
	}
	switch string(b[:2]) {
	case "ED":
	case "Ed":
		return nil, wrap(ErrBadSignature, "legacy (non-prehashed) signature refused")
	default:
		return nil, wrap(ErrBadSignature, "unknown signature algorithm")
	}
	g, err := decodeB64(lines[3], 64)
	if err != nil || len(g) != 64 {
		return nil, wrap(ErrBadSignature, "global signature encoding")
	}
	f := &minisigFile{trustedComment: tc}
	copy(f.keyID[:], b[2:10])
	copy(f.sig[:], b[10:])
	copy(f.globalSig[:], g)
	return f, nil
}

// minisignResult is what a successful verification tells the caller.
type minisignResult struct {
	key            MinisignKey
	backup         bool
	trustedComment string
}

// verifyMinisign checks sig over msg against the trusted keys of t. The key id in the signature
// must be one of them (a match by id selects the key, it never replaces the check); the file
// signature is over BLAKE2b-512(msg); the global signature is over signature || trusted comment.
func verifyMinisign(msg, sig []byte, t Trust) (minisignResult, error) {
	var res minisignResult
	if len(msg) > MaxDocBytes {
		return res, wrap(ErrTooLarge, "document")
	}
	f, err := parseMinisig(sig)
	if err != nil {
		return res, err
	}
	switch f.keyID {
	case t.Active.ID:
		res.key = t.Active
	case t.Backup.ID:
		res.key, res.backup = t.Backup, true
	default:
		return res, wrap(ErrBadSignature, "key id %s is not trusted", keyIDString(f.keyID))
	}
	h := blake2b.Sum512(msg)
	if !ed25519.Verify(res.key.Key, h[:], f.sig[:]) {
		return res, wrap(ErrBadSignature, "file signature does not verify")
	}
	global := make([]byte, 0, 64+len(f.trustedComment))
	global = append(append(global, f.sig[:]...), f.trustedComment...)
	if !ed25519.Verify(res.key.Key, global, f.globalSig[:]) {
		return res, wrap(ErrBadSignature, "trusted comment signature does not verify")
	}
	res.trustedComment = f.trustedComment
	return res, nil
}
