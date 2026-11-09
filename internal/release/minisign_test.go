package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// D-103 (2): real minisign output verifies; Ed is refused; the key id must match.
func TestMinisignRealVectors(t *testing.T) {
	tr := tdTrust(t)
	doc := td(t, "minisign/doc.json")
	want := strings.TrimPrefix(strings.Split(string(td(t, "minisign/test.pub")), "\n")[0], "untrusted comment: minisign public key ")
	if got := tr.Active.KeyID(); got != want { // as `minisign -G` printed it in the .pub comment
		t.Fatalf("key id %s", got)
	}
	res, err := verifyMinisign(doc, td(t, "minisign/doc.json.minisig"), tr)
	if err != nil {
		t.Fatal(err)
	}
	if res.trustedComment != "file:doc.json timestamp:1700000000" || res.backup {
		t.Fatalf("%+v", res)
	}

	_, err = verifyMinisign(doc, td(t, "minisign/doc.json.legacy.minisig"), tr)
	if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("real minisign -l output must be refused as legacy Ed: %v", err)
	}
	// a valid signature by a key that is not trusted
	_, err = verifyMinisign(doc, td(t, "minisign/doc.json.other.minisig"), tr)
	if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "not trusted") {
		t.Fatal(err)
	}
	// the same signature is fine once its key is the trusted one
	other, err := ParseMinisignPublicKey(string(td(t, "minisign/other.pub")))
	if err != nil {
		t.Fatal(err)
	}
	t2 := tr
	t2.Active = other
	if _, err := verifyMinisign(doc, td(t, "minisign/doc.json.other.minisig"), t2); err != nil {
		t.Fatal(err)
	}
}

func TestMinisignKeyFormats(t *testing.T) {
	pubFile := string(td(t, "minisign/test.pub"))
	line := strings.Split(pubFile, "\n")[1]
	for name, in := range map[string]string{"two-line file": pubFile, "bare line": line, "bare line with newline": line + "\n"} {
		if _, err := ParseMinisignPublicKey(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	good, _ := base64.StdEncoding.DecodeString(line)
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	bad := map[string]string{
		"empty":            "",
		"crlf":             strings.ReplaceAll(pubFile, "\n", "\r\n"),
		"trailing junk":    line + "x",
		"two newlines":     line + "\n\n",
		"extra line":       pubFile + "more\n",
		"wrong comment":    "comment: x\n" + line,
		"short":            enc(good[:41]),
		"long":             enc(append(append([]byte{}, good...), 0)),
		"alg ED in pubkey": enc(append([]byte("ED"), good[2:]...)),
		"truncated":        line[:55],
		"space inside":     line[:10] + " " + line[10:],
		"huge":             strings.Repeat("A", 1000),
	}
	for name, in := range bad {
		if _, err := ParseMinisignPublicKey(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMinisignSignatureTampering(t *testing.T) {
	e := newEnv(t)
	msg := []byte(`{"schema":1}`)
	good := e.active.signC(msg, "file:x ts:1")
	if _, err := verifyMinisign(msg, good, e.trust); err != nil {
		t.Fatal(err)
	}
	refuse := func(name string, msg, sig []byte) {
		t.Helper()
		if _, err := verifyMinisign(msg, sig, e.trust); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the trusted comment is signed: change one character
	refuse("tampered trusted comment", msg, []byte(strings.Replace(string(good), "ts:1", "ts:2", 1)))
	// a trusted comment taken from another valid signature
	other := e.active.signC(msg, "file:x ts:9")
	lines := strings.Split(string(good), "\n")
	olines := strings.Split(string(other), "\n")
	refuse("comment swapped", msg, []byte(strings.Join([]string{lines[0], lines[1], olines[2], lines[3], ""}, "\n")))
	refuse("global signature swapped", msg, []byte(strings.Join([]string{lines[0], lines[1], lines[2], olines[3], ""}, "\n")))
	// a different document
	refuse("other document", []byte(`{"schema":2}`), good)
	// the other trusted key's id on a signature made by the active key
	var f = *mustParse(t, good)
	f.keyID = e.backup.id
	refuse("wrong key id", msg, sigFile("ED", f.keyID, f.sig[:], f.trustedComment, f.globalSig[:]))
	// an id nobody trusts
	f.keyID = [8]byte{1, 2, 3}
	refuse("unknown key id", msg, sigFile("ED", f.keyID, f.sig[:], f.trustedComment, f.globalSig[:]))

	// every bit of both signatures, and of the document
	f = *mustParse(t, good)
	for i := 0; i < 64*8; i++ {
		s := f.sig
		s[i/8] ^= 1 << (i % 8)
		g := f.globalSig
		g[i/8] ^= 1 << (i % 8)
		refuse("sig bit", msg, sigFile("ED", f.keyID, s[:], f.trustedComment, f.globalSig[:]))
		refuse("global bit", msg, sigFile("ED", f.keyID, f.sig[:], f.trustedComment, g[:]))
	}
	for i := 0; i < len(msg)*8; i++ {
		d := append([]byte{}, msg...)
		d[i/8] ^= 1 << (i % 8)
		refuse("doc bit", d, good)
	}
}

func mustParse(t *testing.T, b []byte) *minisigFile {
	t.Helper()
	f, err := parseMinisig(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Prehash bypass: "ED" must mean BLAKE2b-512 of the message; a signature over the raw message with
// an ED tag, or over the hash with an Ed tag, must not verify.
func TestMinisignPrehash(t *testing.T) {
	e := newEnv(t)
	msg := []byte(`{"schema":1}`)
	tc := "t"
	raw := ed25519.Sign(e.active.priv, msg) // legacy-style: signs the file itself
	glob := ed25519.Sign(e.active.priv, append(append([]byte{}, raw...), tc...))
	if _, err := verifyMinisign(msg, sigFile("ED", e.active.id, raw, tc, glob), e.trust); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ED tag over the raw message accepted: %v", err)
	}
	if _, err := verifyMinisign(msg, sigFile("Ed", e.active.id, raw, tc, glob), e.trust); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy Ed accepted: %v", err)
	}
	h := blake2b.Sum512(msg)
	hs := ed25519.Sign(e.active.priv, h[:])
	hg := ed25519.Sign(e.active.priv, append(append([]byte{}, hs...), tc...))
	if _, err := verifyMinisign(msg, sigFile("Ed", e.active.id, hs, tc, hg), e.trust); err == nil {
		t.Fatal("Ed tag over the hash accepted")
	}
	for _, alg := range []string{"ee", "EE", "E\x00", "\x00\x00", "Ed\x00"} {
		if _, err := verifyMinisign(msg, sigFile(alg, e.active.id, hs, tc, hg), e.trust); err == nil {
			t.Errorf("algorithm %q accepted", alg)
		}
	}
}

// Base64 leniency, layout leniency, caps.
func TestMinisignStrictLayout(t *testing.T) {
	e := newEnv(t)
	msg := []byte(`{"schema":1}`)
	good := string(e.active.sign(msg))
	if _, err := verifyMinisign(msg, []byte(strings.TrimSuffix(good, "\n")), e.trust); err != nil {
		t.Fatalf("no final newline is fine: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	join := func(l ...string) []byte { return []byte(strings.Join(l, "\n") + "\n") }
	sigLine := lines[1]
	cases := map[string][]byte{
		"crlf":                []byte(strings.ReplaceAll(good, "\n", "\r\n")),
		"trailing newline x2": []byte(good + "\n"),
		"trailing junk line":  []byte(good + "junk\n"),
		"trailing space":      join(lines[0], sigLine+" ", lines[2], lines[3]),
		"junk after base64":   join(lines[0], sigLine+"AAAA", lines[2], lines[3]),
		"unpadded sig":        join(lines[0], strings.TrimRight(sigLine, "="), lines[2], lines[3]),
		"inner newline":       join(lines[0], sigLine[:20], sigLine[20:], lines[2], lines[3]),
		"missing comment":     join(lines[1], lines[2], lines[3]),
		"comment prefix":      join(lines[0], lines[1], "trusted:"+lines[2][len("trusted comment:"):], lines[3]),
		"control in comment":  join(lines[0], lines[1], lines[2]+"\x01", lines[3]),
		"long comment":        join(lines[0], lines[1], lines[2]+strings.Repeat("a", 1100), lines[3]),
		"empty":               nil,
		"huge":                []byte(strings.Repeat("a", MaxSigBytes+1)),
	}
	for name, in := range cases {
		if _, err := verifyMinisign(msg, in, e.trust); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// non-canonical base64: the last character carries unused bits; set them
	g := []byte(lines[3])
	g[85] ^= 1 // the last data character of 64 bytes holds 4 data bits and 2 padding bits; set a padding bit
	if _, err := verifyMinisign(msg, join(lines[0], lines[1], lines[2], string(g)), e.trust); err == nil {
		t.Error("non-canonical base64 accepted")
	}
	// oversized document
	if _, err := verifyMinisign(make([]byte, MaxDocBytes+1), []byte(good), e.trust); !errors.Is(err, ErrTooLarge) {
		t.Error(err)
	}
}

// A signature by the backup key verifies and is reported as such.
func TestMinisignBackupKey(t *testing.T) {
	e := newEnv(t)
	msg := []byte(`{}`)
	res, err := verifyMinisign(msg, e.backup.sign(msg), e.trust)
	if err != nil || !res.backup || res.key.ID != e.backup.id {
		t.Fatal(res, err)
	}
}

// M4: minisign's own default trusted comment is "timestamp:<ts>\tfile:<name>\thashed" (default_trusted_comment
// in minisign.c), so a release signed with a plain `minisign -Sm index.json` must verify. Every other
// control byte stays refused.
func TestMinisignTrustedCommentAllowsTabsOnly(t *testing.T) {
	e := newEnv(t)
	raw := js(t, e.indexMap(1))
	if _, err := VerifyIndex(raw, e.active.signC(raw, "timestamp:1700000000\tfile:index.json\thashed"), e.trust, nil); err != nil {
		t.Errorf("signature with minisign's default trusted comment refused: %v", err)
	}
	for _, c := range []string{"\x00", "\x01", "\x08", "\x0b", "\x0c", "\x1b", "\x1f", "\x7f"} {
		if _, err := VerifyIndex(raw, e.active.signC(raw, "a"+c+"b"), e.trust, nil); !errors.Is(err, ErrBadSignature) {
			t.Errorf("control byte %q accepted: %v", c, err)
		}
	}
}
