package release

// VerifyContent checks a detached minisign signature over msg (a content statement the caller builds from the files it holds,
// D-346) with the active or the backup key of t. A retired key is refused, as for anything new. The message is capped at
// MaxDocBytes and the signature at MaxSigBytes, as the index and the manifest are.
//
// Key revocations live in the stored index, which only vedette-host holds today; this check does not read them (D-346, deferred).
func VerifyContent(msg, sig []byte, t Trust) error {
	if err := t.validate(); err != nil {
		return wrap(ErrNoTrustKeys, "%v", err)
	}
	if len(sig) > MaxSigBytes {
		return wrap(ErrTooLarge, "signature")
	}
	_, err := verifyMinisign(msg, sig, t)
	return err
}
