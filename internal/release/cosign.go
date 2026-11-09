package release

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// CosignSig is images[].cosign: the simple-signing payload and the signature, both base64.
type CosignSig struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// cosignType is critical.type of every cosign container image signature (cosign SIGNATURE_SPEC).
const cosignType = "cosign container image signature"

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// payload is the simple-signing document exactly as sigstore's payload.go emits it. The spec says
// critical.identity.docker-reference is ignored, and optional is free-form annotations.
type payload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
	Optional any `json:"optional"`
}

// parseCosignPayload decodes a payload strictly and returns the digest it claims, after checking
// critical.type. It does not compare the digest; the caller does.
func parseCosignPayload(b []byte) (string, error) {
	if len(b) > maxCosignPayload {
		return "", wrap(ErrTooLarge, "cosign payload")
	}
	var p payload
	if err := jsonstrict.Decode(b, &p); err != nil {
		return "", wrap(ErrMalformed, "cosign payload: %v", errClass(err))
	}
	if p.Critical.Type != cosignType {
		return "", wrap(ErrBadSignature, "cosign payload type %q", clip(p.Critical.Type))
	}
	return p.Critical.Image.DockerManifestDigest, nil
}

// errClass gives a decoder error without echoing document text.
func errClass(err error) string {
	switch {
	case errors.Is(err, jsonstrict.ErrAmbiguous):
		return "repeated key or too deep"
	case errors.Is(err, jsonstrict.ErrTrailing):
		return "trailing data"
	case errors.Is(err, jsonstrict.ErrNotObject):
		return "not an object"
	}
	var se *json.SyntaxError
	var ue *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return "syntax error"
	case errors.As(err, &ue):
		return "wrong type for a field"
	}
	return "unknown field or wrong shape"
}

// verifyCosign checks that c is a valid cosign signature, by one of keys that is not in skip (key
// ids revoked by the index), for exactly the image digest digest ("sha256:" and 64 lower-case hex).
//
// The signature is ECDSA P-256 over SHA-256 of the raw payload bytes, ASN.1 DER. ecdsa.VerifyASN1
// refuses trailing bytes and non-minimal DER. High-S signatures are accepted on purpose: cosign
// (sigstore) signs with ecdsa.SignASN1 and does not normalise S, so about half of genuine
// signatures are high-S, and S malleability buys an attacker nothing here because trust is in the
// digest the payload names, not in the signature bytes.
func verifyCosign(c CosignSig, digest string, keys []*ecdsa.PublicKey, skip map[string]bool) error {
	if !digestRE.MatchString(digest) {
		return wrap(ErrMalformed, "digest %q", clip(digest))
	}
	pl, err := decodeB64(c.Payload, maxCosignPayload)
	if err != nil || len(pl) == 0 {
		return wrap(ErrBadSignature, "cosign payload encoding")
	}
	sig, err := decodeB64(c.Signature, maxCosignSig)
	if err != nil || len(sig) == 0 {
		return wrap(ErrBadSignature, "cosign signature encoding")
	}
	h := sha256.Sum256(pl)
	ok, usable := false, 0
	for _, k := range keys {
		if skip[CosignKeyID(k)] {
			continue
		}
		usable++
		if ecdsa.VerifyASN1(k, h[:], sig) {
			ok = true
			break
		}
	}
	if usable == 0 {
		return ErrKeyRevoked
	}
	if !ok {
		return wrap(ErrBadSignature, "cosign signature does not verify")
	}
	got, err := parseCosignPayload(pl)
	if err != nil {
		return err
	}
	if got != digest { // exact: a different case or any other text is a different digest
		return wrap(ErrBadSignature, "cosign payload names another digest")
	}
	return nil
}
