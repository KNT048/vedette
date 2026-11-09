package release

// Revocation rules (update-manifest.md §8, D-104 (2)). The newest index the box has accepted is
// the only source of revocations. Three rules keep a leaked key from using revocation as a weapon:
//
//  1. An index revokes an embedded key (minisign or cosign) only when the backup key signed it.
//     A leaked active key therefore cannot revoke the backup key, and cannot revoke itself into
//     some state the attacker prefers (it can only ever damage what the backup key can repair).
//  2. The backup key is never revoked by an index: it is the recovery path, and replacing it needs
//     a new binary (§13 (b)).
//  3. Revocations of embedded keys are sticky: they are copied into every later index, so an index
//     that omits one (a mistake, or an attacker who still holds a not-yet-revoked key) does not
//     bring the key back. Revocations of releases and digests are replaced by each newer index.
//
// A revocation that names a key not embedded in this binary is allowed and informational.

// authoriseRevocations applies rules 1 and 2 to a freshly verified index x signed by res.
func authoriseRevocations(x *Index, res minisignResult, t Trust) error {
	for _, r := range x.Revoked {
		if r.Kind != KindKey || !t.isEmbeddedKeyID(r.ID) {
			continue
		}
		if r.ID == t.Backup.KeyID() {
			return wrap(ErrKeyNotAuthorised, "the backup key cannot be revoked by an index")
		}
		if !res.backup {
			return wrap(ErrKeyNotAuthorised, "only the backup key may revoke key %s", clip(r.ID))
		}
	}
	return nil
}

// carryStickyRevocations copies into x the embedded-key revocations of stored that x lacks (rule 3).
func carryStickyRevocations(x, stored *Index, t Trust) {
	if stored == nil {
		return
	}
	for _, r := range stored.Revoked {
		if r.Kind == KindKey && t.isEmbeddedKeyID(r.ID) && x.revoked(KindKey, r.ID) == nil {
			x.Revoked = append(x.Revoked, r)
		}
	}
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
