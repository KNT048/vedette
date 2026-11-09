package release

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const sigstoreDigest = "sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"

// D-103 (3): payloads exactly as sigstore's payload.go and payload_test.go emit them (null optional,
// nested optional), signed with the vector key, verify.
func TestCosignSigstorePayloads(t *testing.T) {
	tr := tdTrust(t)
	for _, n := range []string{"null-optional", "nested-optional"} {
		c := CosignSig{base64.StdEncoding.EncodeToString(td(t, "cosign/sigstore-"+n+".json")), string(td(t, "cosign/sigstore-"+n+".sig"))}
		if err := verifyCosign(c, sigstoreDigest, tr.Cosign, nil); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestCosignRejects(t *testing.T) {
	e := newEnv(t)
	keys := e.trust.Cosign
	d := digestCore
	good := payloadFor(d)
	if err := verifyCosign(e.cosign.sign(t, good), d, keys, nil); err != nil {
		t.Fatal(err)
	}
	refuse := func(name string, c CosignSig, digest string, want error) {
		t.Helper()
		if err := verifyCosign(c, digest, keys, nil); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", name, err, want)
		}
	}
	// the digest in the payload must equal images[].digest, byte for byte
	refuse("other digest", e.cosign.sign(t, payloadFor(digestSensor)), d, ErrBadSignature)
	upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(d, "sha256:"))
	refuse("upper-case digest in payload", e.cosign.sign(t, payloadFor(upper)), d, ErrBadSignature)
	refuse("upper-case digest argument", e.cosign.sign(t, payloadFor(d)), upper, ErrMalformed)
	refuse("digest with algorithm in caps", e.cosign.sign(t, payloadFor(d)), "SHA256:"+strings.TrimPrefix(d, "sha256:"), ErrMalformed)
	refuse("short digest", e.cosign.sign(t, payloadFor(d)), d[:len(d)-1], ErrMalformed)
	refuse("empty payload digest", e.cosign.sign(t, payloadFor("")), d, ErrBadSignature)

	// critical.type
	wrongType := strings.Replace(string(good), "cosign container image signature", "atomic container signature", 1)
	refuse("atomic type", e.cosign.sign(t, []byte(wrongType)), d, ErrBadSignature)
	refuse("empty type", e.cosign.sign(t, []byte(strings.Replace(string(good), "cosign container image signature", "", 1))), d, ErrBadSignature)

	// signature problems
	c := e.cosign.sign(t, good)
	other := newCsigner(t)
	refuse("other key", other.sign(t, good), d, ErrBadSignature)
	tam := []byte(string(good))
	tam[10] ^= 1
	refuse("tampered payload", CosignSig{base64.StdEncoding.EncodeToString(tam), c.Signature}, d, ErrBadSignature)
	sig, _ := base64.StdEncoding.DecodeString(c.Signature)
	for i := 0; i < len(sig)*8; i++ {
		s := append([]byte{}, sig...)
		s[i/8] ^= 1 << (i % 8)
		refuse("signature bit", CosignSig{c.Payload, base64.StdEncoding.EncodeToString(s)}, d, ErrBadSignature)
	}
	b64 := base64.StdEncoding.EncodeToString
	refuse("DER with trailing bytes", CosignSig{c.Payload, b64(append(append([]byte{}, sig...), 0))}, d, ErrBadSignature)
	refuse("DER with trailing sequence", CosignSig{c.Payload, b64(append(append([]byte{}, sig...), sig...))}, d, ErrBadSignature)
	refuse("DER truncated", CosignSig{c.Payload, b64(sig[:len(sig)-1])}, d, ErrBadSignature)
	refuse("raw r||s instead of DER", CosignSig{c.Payload, b64(make([]byte, 64))}, d, ErrBadSignature)
	refuse("empty signature", CosignSig{c.Payload, ""}, d, ErrBadSignature)
	refuse("huge signature", CosignSig{c.Payload, b64(make([]byte, 200))}, d, ErrBadSignature)
	refuse("empty payload", CosignSig{"", c.Signature}, d, ErrBadSignature)

	// base64 leniency
	refuse("payload with newline", CosignSig{c.Payload[:20] + "\n" + c.Payload[20:], c.Signature}, d, ErrBadSignature)
	refuse("payload with crlf at end", CosignSig{c.Payload + "\r\n", c.Signature}, d, ErrBadSignature)
	refuse("payload urlsafe alphabet", CosignSig{strings.NewReplacer("+", "-", "/", "_").Replace(c.Payload + "+/"), c.Signature}, d, ErrBadSignature)
	refuse("truncated signature text", CosignSig{c.Payload, c.Signature[:len(c.Signature)-1]}, d, ErrBadSignature)
	refuse("signature with space", CosignSig{c.Payload, c.Signature + " "}, d, ErrBadSignature)
	refuse("payload too big", e.cosign.sign(t, []byte(strings.Repeat(" ", maxCosignPayload+1))), d, ErrBadSignature)
}

// A high-S signature is the same signature with S replaced by N-S. cosign does not normalise S, so
// genuine signatures are high-S about half the time: both forms must verify.
func TestCosignHighS(t *testing.T) {
	e := newEnv(t)
	p := payloadFor(digestCore)
	sig := e.cosign.signRaw(t, p)
	flipped, flippedHigh := flipS(t, sig)
	low, high := sig, flipped
	if !flippedHigh {
		low, high = flipped, sig
	}
	for name, s := range map[string][]byte{"low-S": low, "high-S": high} {
		c := CosignSig{base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(s)}
		if err := verifyCosign(c, digestCore, e.trust.Cosign, nil); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// JSON decoding of the payload (smuggling): repeats, case-folded repeats, unknown fields, nesting.
func TestCosignPayloadStrictJSON(t *testing.T) {
	e := newEnv(t)
	d := digestCore
	ok := string(payloadFor(d))
	crit := `"critical":{"identity":{"docker-reference":"x"},"image":{"docker-manifest-digest":"` + d + `"},"type":"cosign container image signature"}`
	cases := map[string]string{
		"duplicate critical":      `{` + crit + `,` + crit + `,"optional":null}`,
		"duplicate digest key":    strings.Replace(ok, `"docker-manifest-digest":"`+d+`"`, `"docker-manifest-digest":"`+d+`","docker-manifest-digest":"`+d+`"`, 1),
		"case-folded duplicate":   strings.Replace(ok, `"type":"cosign container image signature"`, `"type":"cosign container image signature","Type":"x"`, 1),
		"case-folded digest key":  strings.Replace(ok, `"image":{`, `"image":{"DOCKER-MANIFEST-DIGEST":"`+sigstoreDigest+`",`, 1),
		"kelvin-sign duplicate":   strings.Replace(ok, `"optional":null`, `"optional":{"k":1,"K":2}`, 1),
		"duplicate in optional":   strings.Replace(ok, `"optional":null`, `"optional":{"a":{"b":1,"b":2}}`, 1),
		"unknown top-level field": strings.Replace(ok, `"optional":null`, `"optional":null,"extra":1`, 1),
		"unknown critical field":  strings.Replace(ok, `"type":`, `"extra":1,"type":`, 1),
		"trailing data":           ok + ` {}`,
		"trailing garbage":        ok + `x`,
		"not an object":           `[` + ok + `]`,
		"null":                    `null`,
		"digest not a string":     strings.Replace(ok, `"`+d+`"`, `1`, 1),
		"deep optional":           strings.Replace(ok, `"optional":null`, `"optional":`+strings.Repeat("[", 100)+strings.Repeat("]", 100), 1),
	}
	for name, p := range cases {
		err := verifyCosign(e.cosign.sign(t, []byte(p)), d, e.trust.Cosign, nil)
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// accepted shapes: whitespace, nested optional, number optional values (sigstore's own test payloads)
	good := `  {"critical":{"image":{"docker-manifest-digest":"` + d + `"},"type":"cosign container image signature"},"optional":{"timestamp":1458239713,"n":{"x":null}}}` + "\n"
	if err := verifyCosign(e.cosign.sign(t, []byte(good)), d, e.trust.Cosign, nil); err != nil {
		t.Errorf("good payload: %v", err)
	}
}

func TestCosignKeyRotationAndRevocation(t *testing.T) {
	e := newEnv(t)
	second := newCsigner(t)
	keys := []*ecdsa.PublicKey{e.cosign.pub(), second.pub()}
	p := payloadFor(digestCore)
	for name, s := range map[string]*csigner{"first": e.cosign, "second": second} {
		if err := verifyCosign(s.sign(t, p), digestCore, keys, nil); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	skip := map[string]bool{CosignKeyID(e.cosign.pub()): true}
	if err := verifyCosign(e.cosign.sign(t, p), digestCore, keys, skip); !errors.Is(err, ErrBadSignature) {
		t.Errorf("revoked first key still verifies: %v", err)
	}
	if err := verifyCosign(second.sign(t, p), digestCore, keys, skip); err != nil {
		t.Errorf("second key refused: %v", err)
	}
	skip[CosignKeyID(second.pub())] = true
	if err := verifyCosign(second.sign(t, p), digestCore, keys, skip); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("all keys revoked: %v", err)
	}
}

func TestCosignPublicKeyParsing(t *testing.T) {
	pemText := string(td(t, "cosign/cosign.pub"))
	if _, err := ParseCosignPublicKey(pemText); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"empty":      "",
		"two blocks": pemText + pemText,
		"junk after": pemText + "x",
		"wrong type": strings.ReplaceAll(pemText, "PUBLIC KEY", "EC PUBLIC KEY"),
		"not der":    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		"huge":       strings.Repeat("A", 2000),
	} {
		if _, err := ParseCosignPublicKey(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
