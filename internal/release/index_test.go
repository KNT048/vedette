package release

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyIndexBasics(t *testing.T) {
	e := newEnv(t)
	x := e.verifiedIndex(e.active, e.indexMap(5))
	if x.Sequence != 5 || x.KeyID != e.trust.Active.KeyID() || x.Channels["stable"].Latest != "1.4.0" {
		t.Fatalf("%+v", x)
	}
	// backup-signed index is fine too
	if y := e.verifiedIndex(e.backup, e.indexMap(5)); y.KeyID != e.trust.Backup.KeyID() {
		t.Fatal(y.KeyID)
	}
	// expiry only warns
	if x.Expired(t0.Add(13 * 24 * time.Hour)) {
		t.Error("expired too early")
	}
	if !x.Expired(t0.Add(15 * 24 * time.Hour)) {
		t.Error("not expired")
	}
	// a signature over other bytes
	raw, sig := e.signedIndex(e.active, e.indexMap(5))
	raw = append(raw, ' ')
	if _, err := VerifyIndex(raw, sig, e.trust, nil); !errors.Is(err, ErrBadSignature) {
		t.Error(err)
	}
	// nothing trusted: refuse everything
	raw, sig = e.signedIndex(e.active, e.indexMap(5))
	if _, err := VerifyIndex(raw, sig, Trust{}, nil); !errors.Is(err, ErrNoTrustKeys) {
		t.Error(err)
	}
	// too big
	big := make([]byte, MaxDocBytes+1)
	if _, err := VerifyIndex(big, e.active.sign(big), e.trust, nil); !errors.Is(err, ErrTooLarge) {
		t.Error(err)
	}
}

// Schema, strict JSON, shape.
func TestParseIndexRejects(t *testing.T) {
	e := newEnv(t)
	mut := func(f func(x m)) m { x := e.indexMap(5); f(x); return x }
	signed := func(raw []byte) error {
		_, err := VerifyIndex(raw, e.active.sign(raw), e.trust, nil)
		return err
	}
	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"schema 2":            {js(t, mut(func(x m) { x["schema"] = 2 })), ErrUnknownSchema},
		"schema 0":            {js(t, mut(func(x m) { x["schema"] = 0 })), ErrUnknownSchema},
		"schema string":       {js(t, mut(func(x m) { x["schema"] = "1" })), ErrUnknownSchema},
		"schema missing":      {js(t, mut(func(x m) { delete(x, "schema") })), ErrUnknownSchema},
		"schema 1.0":          {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"schema":1`, `"schema":1.0`, 1)), ErrUnknownSchema},
		"newer schema extras": {js(t, mut(func(x m) { x["schema"] = 2; x["new_field"] = true })), ErrUnknownSchema},
		"unknown field":       {js(t, mut(func(x m) { x["extra"] = 1 })), ErrMalformed},
		"unknown nested":      {js(t, mut(func(x m) { x["channels"].(m)["stable"].(m)["extra"] = 1 })), ErrMalformed},
		"sequence zero":       {js(t, mut(func(x m) { x["sequence"] = 0 })), ErrMalformed},
		"sequence negative":   {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"sequence":5`, `"sequence":-1`, 1)), ErrMalformed},
		"sequence float":      {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"sequence":5`, `"sequence":5.5`, 1)), ErrMalformed},
		"sequence huge":       {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"sequence":5`, `"sequence":99999999999999999999`, 1)), ErrMalformed},
		"duplicate key":       {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"schema":1,`, `"schema":1,"schema":1,`, 1)), ErrMalformed},
		"duplicate sequence":  {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"sequence":5`, `"sequence":5,"sequence":9`, 1)), ErrMalformed},
		"case-folded key":     {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"sequence":5`, `"sequence":5,"Sequence":9`, 1)), ErrMalformed},
		"case-folded nested":  {[]byte(strings.Replace(string(js(t, e.indexMap(5))), `"percent":100`, `"percent":100,"PERCENT":1`, 1)), ErrMalformed},
		"trailing data":       {append(js(t, e.indexMap(5)), []byte(` {}`)...), ErrMalformed},
		"array":               {[]byte(`[]`), ErrMalformed},
		"expires too far":     {js(t, mut(func(x m) { x["expires_at"] = t0.Add(15 * 24 * time.Hour).Format(time.RFC3339) })), ErrMalformed},
		"expires before gen":  {js(t, mut(func(x m) { x["expires_at"] = t0.Add(-time.Hour).Format(time.RFC3339) })), ErrMalformed},
		"bad time":            {js(t, mut(func(x m) { x["generated_at"] = "yesterday" })), ErrMalformed},
		"no channels":         {js(t, mut(func(x m) { x["channels"] = m{} })), ErrMalformed},
		"channel name":        {js(t, mut(func(x m) { x["channels"] = m{"nightly": x["channels"].(m)["stable"]} })), ErrMalformed},
		"rollout 101":         {js(t, mut(func(x m) { x["channels"].(m)["stable"].(m)["rollout"] = m{"percent": 101} })), ErrMalformed},
		"rollout missing":     {js(t, mut(func(x m) { delete(x["channels"].(m)["stable"].(m), "rollout") })), ErrMalformed},
		"latest v-prefixed":   {js(t, mut(func(x m) { x["channels"].(m)["stable"].(m)["latest"] = "v1.4.0" })), ErrMalformed},
		"manifest http":       {js(t, mut(func(x m) { x["channels"].(m)["stable"].(m)["manifest"] = "http://example.com/m.json" })), ErrMalformed},
		"manifest userinfo":   {js(t, mut(func(x m) { x["channels"].(m)["stable"].(m)["manifest"] = "https://a:b@example.com/m.json" })), ErrMalformed},
		"manifest sha upper":  {js(t, mut(func(x m) { x["channels"].(m)["stable"].(m)["manifest_sha256"] = strings.Repeat("A", 64) })), ErrMalformed},
		"revocation kind":     {js(t, mut(func(x m) { x["revoked"] = []any{revocation("tag", "1.0.0")} })), ErrMalformed},
		"revocation digest":   {js(t, mut(func(x m) { x["revoked"] = []any{revocation(KindImageDigest, "sha256:ABC")} })), ErrMalformed},
		"revocation action":   {js(t, mut(func(x m) { r := revocation(KindRelease, "1.0.0"); r["action"] = "shrug"; x["revoked"] = []any{r} })), ErrMalformed},
		"too many revoked": {js(t, mut(func(x m) {
			r := []any{}
			for i := 0; i < 257; i++ {
				r = append(r, revocation(KindAdvisoryOnly, "a"))
			}
			x["revoked"] = r
		})), ErrMalformed},
		"advisory severity": {js(t, mut(func(x m) {
			x["advisories"] = []any{m{"id": "A", "severity": "meh", "title": "t", "affects": "<1.4", "url": "https://x.example/a"}}
		})), ErrMalformed},
		"null channels": {js(t, mut(func(x m) { x["channels"] = nil })), ErrMalformed},
	} {
		if err := signed(tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	// the good form of those edge cases parses
	if _, err := VerifyIndex(js(t, e.indexMap(5)), e.active.sign(js(t, e.indexMap(5))), e.trust, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCheckManifestSHA256(t *testing.T) {
	e := newEnv(t)
	raw := []byte("manifest bytes")
	x := e.indexMap(1)
	x["channels"].(m)["stable"].(m)["manifest_sha256"] = "e9d2e7ab6f3ec2a9b8a5ff2db1dd1d8e8eb0e8f6b8ac7bc5ce0d8e9a6b7c4d11"
	idx := e.verifiedIndex(e.active, x)
	if err := CheckManifestSHA256(idx, "stable", raw); !errors.Is(err, ErrManifestHash) {
		t.Error(err)
	}
	if err := CheckManifestSHA256(idx, "beta", raw); !errors.Is(err, ErrMalformed) {
		t.Error(err)
	}
}
