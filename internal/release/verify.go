package release

// VerifyIndex checks index.json against the trusted keys and the stored index (the newest one the
// caller has accepted before; nil on the first ever check). It returns the parsed index, with the
// sticky key revocations of stored carried over, which the caller stores in place of stored.
//
// Order: size, minisign signature, signer not revoked by stored, schema and shape, key
// revocations authorised, sequence not below stored (equal is allowed). An expired index is not an
// error; ask Index.Expired.
func VerifyIndex(raw, sig []byte, trust Trust, stored *Index) (*Index, error) {
	if err := trust.validate(); err != nil {
		return nil, wrap(ErrNoTrustKeys, "%v", err)
	}
	res, err := verifyMinisign(raw, sig, trust)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.KeyRevoked(res.key.KeyID()) {
		return nil, ErrKeyRevoked
	}
	x, err := parseIndex(raw)
	if err != nil {
		return nil, err
	}
	if err := authoriseRevocations(x, res, trust); err != nil {
		return nil, err
	}
	if stored != nil && x.Sequence < stored.Sequence {
		return nil, wrap(ErrSequenceRegress, "%d < %d", x.Sequence, stored.Sequence)
	}
	carryStickyRevocations(x, stored, trust)
	x.KeyID = res.key.KeyID()
	return x, nil
}

// VerifyManifest checks release-manifest.json against the trusted keys and idx, the verified index
// (required: revocation comes only from it). The signer must not be revoked, the release version
// and every image digest must not be revoked, and every image ref must be the fixed registry ref.
// It does not check the cosign signatures (VerifyImage does, per image), the platform, the install
// mode or the upgrade path (CheckPlatform, CheckInstallMode, CheckUpgrade), and it does not require
// the release to be the channel's latest: older releases can be pulled again.
func VerifyManifest(raw, sig []byte, trust Trust, idx *Index) (*Manifest, error) {
	if err := trust.validate(); err != nil {
		return nil, wrap(ErrNoTrustKeys, "%v", err)
	}
	if idx == nil {
		return nil, ErrIndexRequired
	}
	res, err := verifyMinisign(raw, sig, trust)
	if err != nil {
		return nil, err
	}
	if idx.KeyRevoked(res.key.KeyID()) {
		return nil, ErrKeyRevoked
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	if idx.revoked(KindRelease, m.Version) != nil {
		return nil, wrap(ErrReleaseRevoked, "version %s", m.Version)
	}
	for _, im := range m.Images {
		if idx.revoked(KindImageDigest, im.Digest) != nil {
			return nil, wrap(ErrReleaseRevoked, "image %s digest", im.Service)
		}
		if im.Ref != ImageRef(im.Service, m.Version) {
			return nil, wrap(ErrRegistryNotAllowed, "image %s", im.Service)
		}
	}
	m.KeyID = res.key.KeyID()
	m.revokedCosign = idx.revokedCosignKeys(trust)
	return m, nil
}

// VerifyImage checks that digest is the manifest's digest for service (exact text: "sha256:" and
// 64 lower-case hex) and that the image's cosign signature verifies for it against the embedded
// cosign key, not revoked when the manifest was verified. m must come from VerifyManifest.
func VerifyImage(m *Manifest, service string, digest string, trust Trust) error {
	if err := trust.validate(); err != nil {
		return wrap(ErrNoTrustKeys, "%v", err)
	}
	im := m.image(service)
	if im == nil || im.Digest != digest {
		return wrap(ErrDigestNotInManifest, "service %s", clip(service))
	}
	return verifyCosign(im.Cosign, im.Digest, trust.Cosign, m.revokedCosign)
}
