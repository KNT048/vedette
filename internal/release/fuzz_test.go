package release

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Fuzz targets for every parser of untrusted input (SYS-6). Each checks that nothing panics and
// that whatever is accepted is canonical.
//
//	go test -run '^$' -fuzz FuzzParseIndex -fuzztime 60s ./internal/release/

func FuzzParseMinisignPublicKey(f *testing.F) {
	f.Add(string(td(f, "minisign/test.pub")))
	f.Add(strings.Split(string(td(f, "minisign/test.pub")), "\n")[1])
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseMinisignPublicKey(s)
		if err != nil {
			return
		}
		if len(k.Key) != 32 || !validMinisignKeyID(k.KeyID()) {
			t.Fatalf("accepted a malformed key: %+v", k)
		}
		raw := append(append([]byte("Ed"), k.ID[:]...), k.Key...)
		if !strings.Contains(s, base64.StdEncoding.EncodeToString(raw)) {
			t.Fatalf("accepted a non-canonical encoding: %q", s)
		}
	})
}

func FuzzParseMinisig(f *testing.F) {
	for _, n := range []string{"doc.json.minisig", "doc.json.legacy.minisig", "doc.json.other.minisig"} {
		f.Add(td(f, "minisign/"+n))
	}
	f.Add(td(f, "release/index.json.minisig"))
	e := newEnv(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		sf, err := parseMinisig(b)
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		again := strings.Split(strings.TrimSuffix(string(sigFile("ED", sf.keyID, sf.sig[:], sf.trustedComment, sf.globalSig[:])), "\n"), "\n")
		if len(lines) != 4 || strings.Join(lines[1:], "\n") != strings.Join(again[1:], "\n") {
			t.Fatalf("accepted a non-canonical signature file: %q", b)
		}
		// whatever parsed must never verify under unrelated keys
		if _, err := verifyMinisign([]byte("x"), b, e.trust); err == nil {
			t.Fatal("random signature verified")
		}
	})
}

func FuzzDecodeB64(f *testing.F) {
	f.Add("AAAA")
	f.Add("AA==")
	f.Add("AA==\n")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := decodeB64(s, 128)
		if err != nil {
			return
		}
		if base64.StdEncoding.EncodeToString(b) != s || len(b) > 128 {
			t.Fatalf("non-canonical base64 accepted: %q", s)
		}
	})
}

func FuzzCosignPayload(f *testing.F) {
	f.Add(td(f, "cosign/sigstore-null-optional.json"))
	f.Add(td(f, "cosign/sigstore-nested-optional.json"))
	f.Add(td(f, "cosign/sigstore-nested-optional-for-core.json"))
	f.Add(payloadFor("core", digestCore))
	f.Fuzz(func(t *testing.T, b []byte) {
		ref, d, err := parseCosignPayload(b)
		if err != nil {
			return
		}
		var std struct {
			Critical struct {
				Type     string
				Identity struct {
					DockerReference string `json:"docker-reference"`
				}
				Image struct {
					DockerManifestDigest string `json:"docker-manifest-digest"`
				}
			}
		}
		if json.Unmarshal(b, &std) != nil || std.Critical.Type != cosignType || std.Critical.Image.DockerManifestDigest != d || std.Critical.Identity.DockerReference != ref {
			t.Fatalf("accepted payload disagrees with encoding/json: %q", b)
		}
	})
}

func FuzzParseIndex(f *testing.F) {
	f.Add(td(f, "release/index.json"))
	e := newEnv(f)
	f.Add(js(f, e.indexMap(1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		x, err := parseIndex(b)
		if err != nil {
			return
		}
		if x.Schema != 1 || x.Sequence == 0 || len(x.Channels) == 0 || x.validate() != nil {
			t.Fatalf("accepted an invalid index: %q", b)
		}
		for _, c := range x.Channels {
			if !validVersion(c.Latest) || c.Rollout == nil || !httpsURL(c.Manifest) {
				t.Fatal("channel not validated")
			}
		}
	})
}

func FuzzParseManifest(f *testing.F) {
	f.Add(td(f, "release/release-manifest.json"))
	e := newEnv(f)
	f.Add(js(f, e.manifestMap()))
	f.Fuzz(func(t *testing.T, b []byte) {
		mf, err := parseManifest(b)
		if err != nil {
			return
		}
		if mf.Schema != 1 || !validVersion(mf.Version) || len(mf.Images) == 0 || len(mf.Images) > MaxImages || mf.validate() != nil {
			t.Fatalf("accepted an invalid manifest: %q", b)
		}
		seen := map[string]bool{}
		for _, im := range mf.Images {
			if !digestRE.MatchString(im.Digest) || seen[im.Service] || bytes.ContainsAny([]byte(im.Service), "/.:@ ") {
				t.Fatalf("image not validated: %+v", im)
			}
			seen[im.Service] = true
			if _, err := PullRef(im.Service, im.Digest); err != nil {
				t.Fatal(err)
			}
		}
	})
}
