package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// Index is index.json (update-manifest.md §4.1) after verification.
type Index struct {
	Schema      int                `json:"schema"`
	Sequence    uint64             `json:"sequence"`
	GeneratedAt time.Time          `json:"generated_at"`
	ExpiresAt   time.Time          `json:"expires_at"`
	Channels    map[string]Channel `json:"channels"`
	Revoked     []Revocation       `json:"revoked"`
	Advisories  []Advisory         `json:"advisories"`
	Keys        []KeyInfo          `json:"keys"`

	// KeyID is the minisign key that signed this index; set by VerifyIndex, never read from JSON.
	KeyID string `json:"-"`
	// RawSHA256 is the SHA-256 (hex) of the signed bytes; set by VerifyIndex, never read from JSON.
	RawSHA256 string `json:"-"`
}

// Channel is one release channel entry of the index.
type Channel struct {
	Latest         string   `json:"latest"`
	Manifest       string   `json:"manifest"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	Rollout        *Rollout `json:"rollout"`
}

// Rollout is the percentage of boxes a release is offered to.
type Rollout struct {
	Percent int `json:"percent"`
}

// Revocation kinds and actions (§8).
const (
	KindRelease      = "release"
	KindImageDigest  = "image_digest"
	KindKey          = "key"
	KindAdvisoryOnly = "advisory_only"
)

// Revocation is one entry of the index revocation list (§8).
type Revocation struct {
	Kind   string    `json:"kind"`
	ID     string    `json:"id"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
	Action string    `json:"action"`
}

// Advisory is a product advisory shown as a banner.
type Advisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Affects  string `json:"affects"`
	FixedIn  string `json:"fixed_in"`
	URL      string `json:"url"`
}

// KeyInfo is informational: the root of trust is the binary, not this list.
type KeyInfo struct {
	KeyID    string    `json:"key_id"`
	Kind     string    `json:"kind"`
	Status   string    `json:"status"`
	NotAfter time.Time `json:"not_after"`
}

const (
	maxRevoked    = 256
	maxAdvisories = 256
	maxKeyInfos   = 16
	maxIndexAge   = 14 * 24 * time.Hour
)

// hex64RE matches a SHA-256 in hex, and a cosign key id (CosignKeyID).
var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// parseIndex decodes and validates index.json bytes. The schema is read first, loosely, so that a
// newer schema is reported as such instead of as an unknown field.
func parseIndex(raw []byte) (*Index, error) {
	if len(raw) > MaxDocBytes {
		return nil, wrap(ErrTooLarge, "index")
	}
	if err := checkSchema(raw); err != nil {
		return nil, err
	}
	var x Index
	if err := jsonstrict.Decode(raw, &x); err != nil {
		return nil, wrap(ErrMalformed, "index: %s", errClass(err))
	}
	if err := x.validate(); err != nil {
		return nil, err
	}
	return &x, nil
}

// checkSchema returns ErrUnknownSchema unless the top-level "schema" is the integer 1.
func checkSchema(raw []byte) error {
	if jsonstrict.Ambiguous(raw) != "" {
		return wrap(ErrMalformed, "repeated key, nested too deep or malformed")
	}
	var head struct {
		Schema json.RawMessage `json:"schema"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return wrap(ErrMalformed, "not a JSON object")
	}
	if string(head.Schema) != "1" {
		return wrap(ErrUnknownSchema, "schema %q", clip(string(head.Schema)))
	}
	return nil
}

func bad(format string, a ...any) error { return wrap(ErrMalformed, format, a...) }

func httpsURL(s string) bool {
	if len(s) == 0 || len(s) > 1024 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func shortText(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

func (x *Index) validate() error {
	if x.Sequence == 0 {
		return bad("sequence")
	}
	if x.GeneratedAt.IsZero() || x.ExpiresAt.IsZero() || x.ExpiresAt.Before(x.GeneratedAt) || x.ExpiresAt.Sub(x.GeneratedAt) > maxIndexAge {
		return bad("generated_at/expires_at")
	}
	if len(x.Channels) == 0 {
		return bad("channels")
	}
	for name, c := range x.Channels {
		if name != "stable" && name != "beta" {
			return bad("channel %q", clip(name))
		}
		if !validVersion(c.Latest) || !httpsURL(c.Manifest) || !hex64RE.MatchString(c.ManifestSHA256) ||
			c.Rollout == nil || c.Rollout.Percent < 0 || c.Rollout.Percent > 100 {
			return bad("channel %s", name)
		}
	}
	if len(x.Revoked) > maxRevoked || len(x.Advisories) > maxAdvisories || len(x.Keys) > maxKeyInfos {
		return bad("too many entries")
	}
	for _, r := range x.Revoked {
		if err := r.validate(); err != nil {
			return err
		}
	}
	for _, a := range x.Advisories {
		if !shortText(a.ID, 64) || a.ID == "" || !shortText(a.Title, 256) || !shortText(a.Affects, 128) ||
			(a.FixedIn != "" && !validVersion(a.FixedIn)) || !httpsURL(a.URL) {
			return bad("advisory")
		}
		switch a.Severity {
		case "critical", "high", "medium", "low":
		default:
			return bad("advisory severity")
		}
	}
	for _, k := range x.Keys {
		if !validMinisignKeyID(k.KeyID) && !hex64RE.MatchString(k.KeyID) {
			return bad("key id")
		}
		if (k.Kind != "minisign" && k.Kind != "cosign") || (k.Status != "active" && k.Status != "retired") {
			return bad("key entry")
		}
	}
	return nil
}

func (r Revocation) validate() error {
	switch r.Action {
	case "block_install", "block_install_and_warn", "rollback_if_possible":
	default:
		return bad("revocation action")
	}
	if !shortText(r.Reason, 256) || r.Since.IsZero() {
		return bad("revocation reason/since")
	}
	ok := false
	switch r.Kind {
	case KindRelease:
		ok = validVersion(r.ID)
	case KindImageDigest:
		ok = digestRE.MatchString(r.ID)
	case KindKey:
		ok = validMinisignKeyID(r.ID) || hex64RE.MatchString(r.ID)
	case KindAdvisoryOnly:
		ok = r.ID != "" && shortText(r.ID, 64)
	}
	if !ok {
		return bad("revocation %s id", clip(r.Kind))
	}
	return nil
}

// Expired reports whether the index is past expires_at at now. Expiry only warns (§4.1, D-104).
func (x *Index) Expired(now time.Time) bool { return now.After(x.ExpiresAt) }

// revoked returns the blocking revocation of kind and id, if any.
func (x *Index) revoked(kind, id string) *Revocation {
	for i := range x.Revoked {
		if x.Revoked[i].Kind == kind && x.Revoked[i].ID == id {
			return &x.Revoked[i]
		}
	}
	return nil
}

// KeyRevoked reports whether the key id (minisign: 16 upper-case hex; cosign: CosignKeyID) is revoked.
func (x *Index) KeyRevoked(id string) bool { return x.revoked(KindKey, id) != nil }

// CheckManifestSHA256 compares raw with manifest_sha256 of the channel's latest release (§5.3
// step 4). Older releases are not listed in the index and have no hash to compare.
func CheckManifestSHA256(x *Index, channel string, raw []byte) error {
	c, ok := x.Channels[channel]
	if !ok {
		return bad("channel %q is not in the index", clip(channel))
	}
	s := sha256.Sum256(raw)
	if hex.EncodeToString(s[:]) != c.ManifestSHA256 {
		return ErrManifestHash
	}
	return nil
}
