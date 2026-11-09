package release

// Revocation rules (update-manifest.md §8, D-104 (2), D-108). The newest index the box has accepted
// (the "stored" index) is the source of revocations, and revocations are sticky: a newer index
// cannot quietly drop them. The rules keep a leaked active key from using revocation as a weapon, or
// from undoing one:
//
//  1. Key revocations (kind "key") count only when the backup key signed the index. In an index
//     signed by the active key they are dropped, whether or not this binary embeds the key, and a
//     log line says so. So a leaked active key cannot pre-revoke the keys a future binary embeds.
//  2. The backup key is never revoked: an index that names it is refused, and a stored revocation
//     of the binary's current backup key is ignored when loading and when carrying forward.
//  3. Key, release and image-digest revocations of the stored index are carried into every newer
//     index. Only an index signed by the backup key may drop a release or digest revocation (its own
//     list is then authoritative); a key revocation is never dropped.
//  4. A backup-signed index that revokes the signer of the stored index may set any sequence, lower
//     included (revoke.go sequence rule in VerifyIndex). The revocation is sticky, so this fires at
//     most once per leaked key.
//
// The carried list is not part of the signed index, so it may be longer than the 256 entries one
// index may carry; it is capped at maxCarried to keep a leaked active key from growing it forever.

// maxCarried bounds the revocations a stored index holds.
const maxCarried = 4096

// keyRevokedFor reports whether id is revoked in x, ignoring any revocation of t's current backup key.
func (x *Index) keyRevokedFor(id string, t Trust) bool {
	return id != t.Backup.KeyID() && x.KeyRevoked(id)
}

// filterKeyRevocations applies rules 1 and 2 to a freshly verified index x signed by res.
func filterKeyRevocations(x *Index, res minisignResult, t Trust) error {
	kept := x.Revoked[:0]
	dropped := 0
	for _, r := range x.Revoked {
		if r.Kind != KindKey {
			kept = append(kept, r)
			continue
		}
		switch {
		case res.backup && r.ID == t.Backup.KeyID():
			return wrap(ErrKeyNotAuthorised, "the backup key cannot be revoked by an index")
		case !res.backup:
			dropped++
		default:
			kept = append(kept, r)
		}
	}
	x.Revoked = kept
	if dropped > 0 {
		logger.Warn("release: dropped key revocations from an index not signed by the backup key", "count", dropped, "signer", res.key.KeyID()) //nolint:sloglint // see keys.go
	}
	return nil
}

// carryRevocations applies rule 3: copy into x what stored revokes and x lacks.
func carryRevocations(x, stored *Index, res minisignResult, t Trust) error {
	if stored == nil {
		return nil
	}
	for _, r := range stored.Revoked {
		switch r.Kind {
		case KindKey:
			if r.ID == t.Backup.KeyID() {
				continue
			}
		case KindRelease, KindImageDigest:
			if res.backup { // the backup key's own list is authoritative
				continue
			}
		default:
			continue
		}
		if x.revoked(r.Kind, r.ID) == nil {
			x.Revoked = append(x.Revoked, r)
		}
	}
	if len(x.Revoked) > maxCarried {
		return wrap(ErrMalformed, "too many carried revocations; an index signed by the backup key must reset them")
	}
	return nil
}

// revokedCosignKeys lists the cosign key ids x revokes.
func (x *Index) revokedCosignKeys(t Trust) map[string]bool {
	out := map[string]bool{}
	for _, k := range t.Cosign {
		if id := CosignKeyID(k); x.KeyRevoked(id) {
			out[id] = true
		}
	}
	return out
}
