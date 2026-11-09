# Test vectors of `internal/release`

Everything here is a throwaway: keys exist only for the tests, and no private key is committed. The keys
have no password and were made for this directory. Regenerating replaces all of them, so after a
regeneration also update `../keys_testonly.go` (the test `TestTestKeysBuild` with
`-tags releasetestkeys` fails until you do).

## minisign (made with the real tool, minisign 0.12, ISC)

From `internal/release/testdata`:

```sh
cd minisign
printf '{"schema":1,"sequence":7}\n' > doc.json
minisign -G -W -f -p test.pub   -s test.key   -c "vedette test-only key 1"
minisign -G -W -f -p other.pub  -s other.key  -c "vedette test-only key 2"
minisign -G -W -f -p backup.pub -s backup.key -c "vedette test-only key 3 (backup)"
# default mode: prehashed "ED" (BLAKE2b-512), the only one the verifier accepts
minisign -S -s test.key  -m doc.json -x doc.json.minisig        -t "file:doc.json timestamp:1700000000" -c "vedette test signature"
# legacy "Ed": must be refused
minisign -S -l -s test.key -m doc.json -x doc.json.legacy.minisig -t "file:doc.json legacy"
# valid signature by a key that is not trusted
minisign -S -s other.key -m doc.json -x doc.json.other.minisig  -t "file:doc.json other"
cd ..
go run gen.go .          # from the repo root: go run internal/release/testdata/gen.go internal/release/testdata
minisign -S -s minisign/test.key   -m release/index.json            -x release/index.json.minisig          -t "file:index.json sequence:7"
minisign -S -s minisign/test.key   -m release/release-manifest.json -x release/release-manifest.json.minisig -t "file:release-manifest.json version:1.4.0"
minisign -S -s minisign/backup.key -m release/index.json            -x release/index.json.backup.minisig   -t "file:index.json sequence:7"
rm minisign/*.key
```

`test.pub` is the active key, `backup.pub` the offline backup key, `other.pub` an untrusted key.
`minisign -V` verified the default-mode signatures and the legacy one when they were made.

## cosign (legacy format, built in Go; the cosign CLI is not installed)

`gen.go` (`//go:build ignore`) makes a fresh ECDSA P-256 test key, writes `cosign/cosign.pub` (PEM, what
`cosign generate-key-pair` writes), and builds simple-signing payloads exactly as sigstore's
`pkg/signature/payload` marshals them (`{"critical":{"identity":{"docker-reference":...},"image":{"docker-manifest-digest":...},"type":"cosign container image signature"},"optional":null}`),
then signs SHA-256 of the payload bytes with `ecdsa.SignASN1` (ASN.1 DER, base64), as
`cosign sign --key --new-bundle-format=false --use-signing-config=false` does. The private key is not written.
It also writes the unsigned `release/index.json` and `release/release-manifest.json` (two images, with their
`cosign` blocks); the commands above sign them with minisign.

### Cross-check with sigstore

No real cosign signature fixture (payload plus signature plus public key) was found at a pinned commit of
the sigstore repositories (guessed paths under sigstore/cosign returned 404). What exists is the golden payload
text of sigstore's own marshalling tests. Two of those strings are copied as `cosign/sigstore-null-optional.json`
and `cosign/sigstore-nested-optional.json` (Apache-2.0, unchanged), and `gen.go` signs them with the test key:

- Source: https://github.com/sigstore/sigstore/blob/cb58109ea91db68619f7f9ae6a72102abf3fcda1/pkg/signature/payload/payload_test.go
  (commit `cb58109ea91db68619f7f9ae6a72102abf3fcda1`, `TestMarshalCosign` expected strings, lines 50 and 77).
- Struct definition and JSON key names: https://github.com/sigstore/sigstore/blob/cb58109ea91db68619f7f9ae6a72102abf3fcda1/pkg/signature/payload/payload.go
- Spec ("`critical.identity.docker-reference` is ignored", the type string, ECDSA P-256 with SHA-256):
  https://github.com/sigstore/cosign/blob/92514f9fedfabaf562f4946469a29b18c1ea68e7/specs/SIGNATURE_SPEC.md

These show the real key spelling (`docker-manifest-digest`, lower case; the spec's example capitalises it),
`"optional":null`, and nested optional values with numbers, booleans and nulls.

Negative cases (tampered trusted comment, wrong key id, bit flips, high-S, DER trailing bytes, upper-case digest,
duplicate keys and so on) are built in Go inside the tests; they need no committed files.
