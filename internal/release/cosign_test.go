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
// nested optional with numbers, booleans and null) parse, and their signatures are valid. As
// sigstore wrote them they name example.com, so verification refuses them for the wrong repository;
// with docker-reference set to the repository of vedette-core (what `cosign sign <repo>@<digest>`
// emits for our images) they verify for core and for no other service.
func TestCosignSigstorePayloads(t *testing.T) {
	tr := tdTrust(t)
	for _, n := range []string{"null-optional", "nested-optional"} {
		orig := CosignSig{base64.StdEncoding.EncodeToString(td(t, "cosign/sigstore-"+n+".json")), string(td(t, "cosign/sigstore-"+n+".sig"))}
		ref, d, err := parseCosignPayload(td(t, "cosign/sigstore-"+n+".json"))
		if err != nil || d != sigstoreDigest || !strings.HasPrefix(ref, "example.com/") {
			t.Errorf("%s: parse %q %q %v", n, ref, d, err)
		}
		if err := verifyCosign(orig, "core", sigstoreDigest, tr.Cosign, nil); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "repository") {
			t.Errorf("%s: payload for example.com verified for core, or the signature itself failed: %v", n, err)
		}
		forCore := CosignSig{base64.StdEncoding.EncodeToString(td(t, "cosign/sigstore-"+n+"-for-core.json")), string(td(t, "cosign/sigstore-"+n+"-for-core.sig"))}
		if err := verifyCosign(forCore, "core", sigstoreDigest, tr.Cosign, nil); err != nil {
			t.Errorf("%s: %v", n, err)
		}
		if err := verifyCosign(forCore, "sensor", sigstoreDigest, tr.Cosign, nil); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: a vedette-core signature verified for sensor: %v", n, err)
		}
	}
}

// M3: the signature travels inside the manifest, so docker-reference is what ties it to a repository.
// A genuine signature made for vedette-core must not verify another service's image entry, and
// docker-reference must be exactly the repository (no tag, no digest, no other registry).
func TestCosignSignatureBoundToService(t *testing.T) {
	e := newEnv(t)
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mx := e.manifestMap()
	sensor := e.image("sensor", "1.4.0", digestCore)
	sensor["cosign"] = e.cosign.sign(t, payloadFor("core", digestCore)) // the genuine core signature
	core := e.image("core", "1.4.0", digestCore)
	mx["images"] = []any{core, sensor}
	mf := e.verifiedManifest(mx, idx)
	if err := VerifyImage(mf, "core", digestCore, e.trust); err != nil {
		t.Fatal(err)
	}
	if err := VerifyImage(mf, "sensor", digestCore, e.trust); !errors.Is(err, ErrBadSignature) {
		t.Errorf("the core image's cosign signature verified the sensor entry: %v", err)
	}
	withRef := func(ref string) []byte {
		return []byte(strings.Replace(string(payloadFor("core", digestCore)), RegistryPrefix+"core", ref, 1))
	}
	for name, ref := range map[string]string{
		"with tag":        RegistryPrefix + "core:1.4.0",
		"with digest":     RegistryPrefix + "core@" + digestCore,
		"other registry":  "evil.example/knt048/vedette-core",
		"other owner":     "ghcr.io/other/vedette-core",
		"upper-case host": "GHCR.io/knt048/vedette-core",
		"empty":           "",
		"prefix only":     RegistryPrefix,
	} {
		if err := verifyCosign(e.cosign.sign(t, withRef(ref)), "core", digestCore, e.trust.Cosign, nil); !errors.Is(err, ErrBadSignature) {
			t.Errorf("docker-reference %s: %v", name, err)
		}
	}
	noIdentity := []byte(`{"critical":{"image":{"docker-manifest-digest":"` + digestCore + `"},"type":"cosign container image signature"},"optional":null}`)
	if err := verifyCosign(e.cosign.sign(t, noIdentity), "core", digestCore, e.trust.Cosign, nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("payload without identity: %v", err)
	}
}

func TestCosignRejects(t *testing.T) {
	e := newEnv(t)
	keys := e.trust.Cosign
	d := digestCore
	good := payloadFor("core", d)
	if err := verifyCosign(e.cosign.sign(t, good), "core", d, keys, nil); err != nil {
		t.Fatal(err)
	}
	refuse := func(name string, c CosignSig, digest string, want error) {
		t.Helper()
		if err := verifyCosign(c, "core", digest, keys, nil); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", name, err, want)
		}
	}
	// the digest in the payload must equal images[].digest, byte for byte
	refuse("other digest", e.cosign.sign(t, payloadFor("core", digestSensor)), d, ErrBadSignature)
	upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(d, "sha256:"))
	refuse("upper-case digest in payload", e.cosign.sign(t, payloadFor("core", upper)), d, ErrBadSignature)
	refuse("upper-case digest argument", e.cosign.sign(t, payloadFor("core", d)), upper, ErrMalformed)
	refuse("digest with algorithm in caps", e.cosign.sign(t, payloadFor("core", d)), "SHA256:"+strings.TrimPrefix(d, "sha256:"), ErrMalformed)
	refuse("short digest", e.cosign.sign(t, payloadFor("core", d)), d[:len(d)-1], ErrMalformed)
	refuse("empty payload digest", e.cosign.sign(t, payloadFor("core", "")), d, ErrBadSignature)

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
	p := payloadFor("core", digestCore)
	sig := e.cosign.signRaw(t, p)
	flipped, flippedHigh := flipS(t, sig)
	low, high := sig, flipped
	if !flippedHigh {
		low, high = flipped, sig
	}
	for name, s := range map[string][]byte{"low-S": low, "high-S": high} {
		c := CosignSig{base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(s)}
		if err := verifyCosign(c, "core", digestCore, e.trust.Cosign, nil); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// JSON decoding of the payload (smuggling): repeats, case-folded repeats, unknown fields, nesting.
func TestCosignPayloadStrictJSON(t *testing.T) {
	e := newEnv(t)
	d := digestCore
	ok := string(payloadFor("core", d))
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
		err := verifyCosign(e.cosign.sign(t, []byte(p)), "core", d, e.trust.Cosign, nil)
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// accepted shapes: whitespace, nested optional, number optional values (sigstore's own test payloads)
	good := `  {"critical":{"identity":{"docker-reference":"` + RegistryPrefix + `core"},"image":{"docker-manifest-digest":"` + d + `"},"type":"cosign container image signature"},"optional":{"timestamp":1458239713,"n":{"x":null}}}` + "\n"
	if err := verifyCosign(e.cosign.sign(t, []byte(good)), "core", d, e.trust.Cosign, nil); err != nil {
		t.Errorf("good payload: %v", err)
	}
}

func TestCosignKeyRotationAndRevocation(t *testing.T) {
	e := newEnv(t)
	second := newCsigner(t)
	keys := []*ecdsa.PublicKey{e.cosign.pub(), second.pub()}
	p := payloadFor("core", digestCore)
	for name, s := range map[string]*csigner{"first": e.cosign, "second": second} {
		if err := verifyCosign(s.sign(t, p), "core", digestCore, keys, nil); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	skip := map[string]bool{CosignKeyID(e.cosign.pub()): true}
	if err := verifyCosign(e.cosign.sign(t, p), "core", digestCore, keys, skip); !errors.Is(err, ErrBadSignature) {
		t.Errorf("revoked first key still verifies: %v", err)
	}
	if err := verifyCosign(second.sign(t, p), "core", digestCore, keys, skip); err != nil {
		t.Errorf("second key refused: %v", err)
	}
	skip[CosignKeyID(second.pub())] = true
	if err := verifyCosign(second.sign(t, p), "core", digestCore, keys, skip); !errors.Is(err, ErrKeyRevoked) {
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
