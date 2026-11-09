package release

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestVerifyManifestBasics(t *testing.T) {
	e := newEnv(t)
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mf := e.verifiedManifest(e.manifestMap(), idx)
	if mf.Version != "1.4.0" || mf.KeyID != e.trust.Active.KeyID() || len(mf.Images) != 2 {
		t.Fatalf("%+v", mf)
	}
	raw := js(t, e.manifestMap())
	if _, err := VerifyManifest(raw, e.active.sign(raw), e.trust, nil); !errors.Is(err, ErrIndexRequired) {
		t.Error("manifest without index:", err)
	}
	if _, err := VerifyManifest(raw, e.active.sign(raw), Trust{}, idx); !errors.Is(err, ErrNoTrustKeys) {
		t.Error(err)
	}
	if _, err := VerifyManifest(append(raw, ' '), e.active.sign(raw), e.trust, idx); !errors.Is(err, ErrBadSignature) {
		t.Error(err)
	}
	// a signature by a key nobody trusts
	if _, err := VerifyManifest(raw, newMsigner(t).sign(raw), e.trust, idx); !errors.Is(err, ErrBadSignature) {
		t.Error(err)
	}
}

// D-104 (3): a revoked release or image digest is refused, whatever the revocation's action.
func TestManifestRevocations(t *testing.T) {
	e := newEnv(t)
	raw := js(t, e.manifestMap())
	sig := e.active.sign(raw)
	for name, r := range map[string]m{
		"release":      revocation(KindRelease, "1.4.0"),
		"core digest":  revocation(KindImageDigest, digestCore),
		"other digest": revocation(KindImageDigest, digestSensor),
	} {
		for _, action := range []string{"block_install", "block_install_and_warn", "rollback_if_possible"} {
			x := e.indexMap(1)
			r["action"] = action
			x["revoked"] = []any{r}
			idx := e.verifiedIndex(e.active, x)
			if _, err := VerifyManifest(raw, sig, e.trust, idx); !errors.Is(err, ErrReleaseRevoked) || !errors.Is(err, ErrRevoked) {
				t.Errorf("%s/%s: %v", name, action, err)
			}
		}
	}
	// other versions and digests are not affected; advisory_only never blocks
	x := e.indexMap(1)
	x["revoked"] = []any{revocation(KindRelease, "1.3.2"), revocation(KindImageDigest, "sha256:"+strings.Repeat("c", 64)), revocation(KindAdvisoryOnly, "1.4.0")}
	idx := e.verifiedIndex(e.active, x)
	if _, err := VerifyManifest(raw, sig, e.trust, idx); err != nil {
		t.Fatal(err)
	}
}

func TestParseManifestRejects(t *testing.T) {
	e := newEnv(t)
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mut := func(f func(x m)) []byte { x := e.manifestMap(); f(x); return js(t, x) }
	img := func(x m, i int) m { return x["images"].([]any)[i].(m) }
	base := string(js(t, e.manifestMap()))
	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"schema 2":             {mut(func(x m) { x["schema"] = 2 }), ErrUnknownSchema},
		"unknown field":        {mut(func(x m) { x["extra"] = 1 }), ErrMalformed},
		"unknown image field":  {mut(func(x m) { img(x, 0)["extra"] = 1 }), ErrMalformed},
		"duplicate key":        {[]byte(strings.Replace(base, `"version":"1.4.0"`, `"version":"1.4.0","version":"9.9.9"`, 1)), ErrMalformed},
		"case-folded key":      {[]byte(strings.Replace(base, `"version":"1.4.0"`, `"version":"1.4.0","Version":"9.9.9"`, 1)), ErrMalformed},
		"version v prefix":     {mut(func(x m) { x["version"] = "v1.4.0" }), ErrMalformed},
		"version build meta":   {mut(func(x m) { x["version"] = "1.4.0+build" }), ErrMalformed},
		"version two parts":    {mut(func(x m) { x["version"] = "1.4" }), ErrMalformed},
		"version leading zero": {mut(func(x m) { x["version"] = "01.4.0" }), ErrMalformed},
		"bad channel":          {mut(func(x m) { x["channel"] = "nightly" }), ErrMalformed},
		"min_upgrade above":    {mut(func(x m) { x["min_upgrade_from"] = "1.5.0" }), ErrMalformed},
		"rollback min above":   {mut(func(x m) { x["rollback"] = m{"safe": true, "min_version": "2.0.0"} }), ErrMalformed},
		"no install modes":     {mut(func(x m) { x["install_modes"] = []string{} }), ErrMalformed},
		"unknown install mode": {mut(func(x m) { x["install_modes"] = []string{"vm"} }), ErrMalformed},
		"no images":            {mut(func(x m) { x["images"] = []any{} }), ErrMalformed},
		"17 images": {mut(func(x m) {
			a := []any{}
			for i := 0; i < 17; i++ {
				a = append(a, e.image("core", "1.4.0", digestCore))
			}
			x["images"] = a
		}), ErrMalformed},
		"unknown service":      {mut(func(x m) { img(x, 0)["service"] = "shell" }), ErrMalformed},
		"duplicate service":    {mut(func(x m) { img(x, 1)["service"] = "core" }), ErrMalformed},
		"digest upper":         {mut(func(x m) { img(x, 0)["digest"] = "sha256:" + strings.Repeat("A", 64) }), ErrMalformed},
		"digest short":         {mut(func(x m) { img(x, 0)["digest"] = "sha256:abc" }), ErrMalformed},
		"digest md5":           {mut(func(x m) { img(x, 0)["digest"] = "md5:" + strings.Repeat("a", 64) }), ErrMalformed},
		"no cosign":            {mut(func(x m) { delete(img(x, 0), "cosign") }), ErrMalformed},
		"empty cosign payload": {mut(func(x m) { img(x, 0)["cosign"] = m{"payload": "", "signature": "x"} }), ErrMalformed},
		"unknown cosign field": {nil, ErrMalformed}, // built below
		"negative size":        {mut(func(x m) { img(x, 0)["size"] = -1 }), ErrMalformed},
		"no platforms":         {mut(func(x m) { img(x, 0)["platforms"] = []string{} }), ErrMalformed},
		"bad platform":         {mut(func(x m) { img(x, 0)["platforms"] = []string{"Linux AMD64"} }), ErrMalformed},
		"host bad file": {mut(func(x m) {
			x["host"] = m{"version": "1.4.0", "files": []any{m{"name": "../x", "sha256": strings.Repeat("0", 64), "size": 1}}}
		}), ErrMalformed},
		"content path dotdot": {mut(func(x m) {
			x["content"] = []any{m{"name": "n", "version": "1", "in_image": "core", "path": "/a/../b", "sha256": strings.Repeat("0", 64)}}
		}), ErrMalformed},
		"sbom http": {mut(func(x m) {
			x["sbom"] = m{"format": "CycloneDX", "url": "http://x.example/s", "sha256": strings.Repeat("0", 64)}
		}), ErrMalformed},
		"notes control": {mut(func(x m) { x["notes"] = "a\x00b" }), ErrMalformed},
		"notes long":    {mut(func(x m) { x["notes"] = strings.Repeat("a", 2049) }), ErrMalformed},
	} {
		if name == "unknown cosign field" {
			tc.raw = mut(func(x m) { img(x, 0)["cosign"] = m{"payload": "AA==", "signature": "AA==", "bundle": "x"} })
		}
		_, err := VerifyManifest(tc.raw, e.active.sign(tc.raw), e.trust, idx)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

// D-104 (1): ref must be exactly ghcr.io/knt048/vedette-<service>:<version>.
func TestManifestRefs(t *testing.T) {
	e := newEnv(t)
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	for name, ref := range map[string]string{
		"other registry":  "evil.example/knt048/vedette-core:1.4.0",
		"other owner":     "ghcr.io/other/vedette-core:1.4.0",
		"wrong service":   "ghcr.io/knt048/vedette-sensor:1.4.0",
		"wrong tag":       "ghcr.io/knt048/vedette-core:1.3.0",
		"latest":          "ghcr.io/knt048/vedette-core:latest",
		"digest form":     "ghcr.io/knt048/vedette-core@" + digestCore,
		"upper-case host": "GHCR.io/knt048/vedette-core:1.4.0",
		"trailing space":  "ghcr.io/knt048/vedette-core:1.4.0 ",
	} {
		x := e.manifestMap()
		x["images"].([]any)[0].(m)["ref"] = ref
		raw := js(t, x)
		if _, err := VerifyManifest(raw, e.active.sign(raw), e.trust, idx); !errors.Is(err, ErrRegistryNotAllowed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := PullRef("core", digestCore); err != nil || got != "ghcr.io/knt048/vedette-core@"+digestCore {
		t.Fatal(got, err)
	}
	for _, c := range [][2]string{{"shell", digestCore}, {"core", "sha256:ABC"}, {"core/../x", digestCore}, {"", digestCore}} {
		if _, err := PullRef(c[0], c[1]); err == nil {
			t.Errorf("PullRef(%q, %q) accepted", c[0], c[1])
		}
	}
}

func TestVerifyImage(t *testing.T) {
	e := newEnv(t)
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mf := e.verifiedManifest(e.manifestMap(), idx)
	if err := VerifyImage(mf, "core", digestCore, e.trust); err != nil {
		t.Fatal(err)
	}
	if err := VerifyImage(mf, "sensor", digestSensor, e.trust); err != nil {
		t.Fatal(err)
	}
	upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(digestCore, "sha256:"))
	for name, c := range map[string][2]string{
		"digest of another service": {"core", digestSensor},
		"service not in manifest":   {"scan", digestCore},
		"upper-case digest":         {"core", upper},
		"empty digest":              {"core", ""},
		"unknown service":           {"../core", digestCore},
	} {
		if err := VerifyImage(mf, c[0], c[1], e.trust); !errors.Is(err, ErrDigestNotInManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := VerifyImage(mf, "core", digestCore, Trust{}); !errors.Is(err, ErrNoTrustKeys) {
		t.Error(err)
	}
	// a manifest whose image carries a signature of a different digest, or by another key
	x := e.manifestMap()
	x["images"].([]any)[0].(m)["cosign"] = e.cosign.sign(t, payloadFor("core", digestSensor))
	bad := e.verifiedManifest(x, idx) // the manifest itself is validly signed...
	if err := VerifyImage(bad, "core", digestCore, e.trust); !errors.Is(err, ErrBadSignature) {
		t.Errorf("...but its image signature names another digest: %v", err)
	}
	x["images"].([]any)[0].(m)["cosign"] = newCsigner(t).sign(t, payloadFor("core", digestCore))
	if err := VerifyImage(e.verifiedManifest(x, idx), "core", digestCore, e.trust); !errors.Is(err, ErrBadSignature) {
		t.Errorf("signed by another key: %v", err)
	}
}

func TestManifestChecks(t *testing.T) {
	e := newEnv(t)
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mf := e.verifiedManifest(e.manifestMap(), idx) // min_upgrade_from 1.2.0, rollback.min_version 1.3.0
	for _, tc := range []struct {
		running string
		want    error
	}{
		{"", nil}, {"1.2.0", nil}, {"1.3.5", nil}, {"1.4.0", nil}, {"1.4.0-beta.1", nil},
		{"1.1.9", ErrUpgradePath}, {"1.2.0-rc.1", ErrUpgradePath},
		{"1.4.1", ErrDowngrade}, {"2.0.0", ErrDowngrade}, {"1.10.0", ErrDowngrade},
	} {
		if err := CheckUpgrade(mf, tc.running); (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("CheckUpgrade running %q: %v, want %v", tc.running, err, tc.want)
		}
	}
	if err := CheckUpgrade(mf, "banana"); !errors.Is(err, ErrMalformed) {
		t.Error(err)
	}
	for _, tc := range []struct {
		prev string
		want error
	}{{"1.3.0", nil}, {"1.3.9", nil}, {"1.3.0-rc.1", ErrRollbackNotAllowed}, {"1.2.9", ErrRollbackNotAllowed}, {"0.9.0", ErrRollbackNotAllowed},
		// a rollback goes to a lower version than the running one
		{"1.4.0", ErrRollbackNotAllowed}, {"1.4.1", ErrRollbackNotAllowed}, {"2.0.0", ErrRollbackNotAllowed}, {"1.4.0-rc.1", nil}} {
		if err := CheckRollback(mf, tc.prev); (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("CheckRollback previous %q: %v, want %v", tc.prev, err, tc.want)
		}
	}
	if err := CheckRollback(mf, "x"); !errors.Is(err, ErrMalformed) {
		t.Error(err)
	}
	if mf.CheckInstallMode("appliance") != nil || mf.CheckInstallMode("container") != nil || !errors.Is(mf.CheckInstallMode("vm"), ErrInstallMode) {
		t.Error("install modes")
	}
	x := e.manifestMap()
	x["install_modes"] = []string{"container"}
	if err := e.verifiedManifest(x, idx).CheckInstallMode("appliance"); !errors.Is(err, ErrInstallMode) {
		t.Error(err)
	}
	if err := mf.CheckPlatform("core", "linux/amd64"); err != nil {
		t.Error(err)
	}
	if err := mf.CheckPlatform("core", "linux/arm64"); !errors.Is(err, ErrPlatform) {
		t.Error(err)
	}
	if err := mf.CheckPlatform("scan", "linux/amd64"); !errors.Is(err, ErrDigestNotInManifest) {
		t.Error(err)
	}
	// no min_upgrade_from and no rollback.min_version: nothing to enforce
	x = e.manifestMap()
	delete(x, "min_upgrade_from")
	x["rollback"] = m{"safe": false}
	free := e.verifiedManifest(x, idx)
	if CheckUpgrade(free, "0.0.1") != nil || CheckRollback(free, "0.0.1") != nil {
		t.Error("optional rules enforced")
	}
}

// SemVer 2.0.0 §11: a prerelease is lower than its release; numeric parts compare as numbers.
func TestVersionOrdering(t *testing.T) {
	ordered := []string{"0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0-beta.1", "2.0.0"}
	for i, a := range ordered {
		for j, b := range ordered {
			got, err := CompareVersions(a, b)
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if err != nil || got != want {
				t.Errorf("CompareVersions(%s, %s) = %d, %v; want %d", a, b, got, err, want)
			}
		}
	}
	for _, bad := range []string{"", "v1.0.0", "1.0", "1", "1.0.0+x", "1.0.0-", "1.0.0-01", "01.0.0", "1.0.0 ", "1.0.0\n", "1.0.0-beta..1", strings.Repeat("1", 70) + ".0.0"} {
		if _, err := CompareVersions(bad, "1.0.0"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// L3: VerifyImage only trusts a Manifest that VerifyManifest produced.
func TestVerifyImageRefusesUnverifiedManifest(t *testing.T) {
	e := newEnv(t)
	im := e.image("core", "1.4.0", digestCore)
	raw := js(t, im)
	var img Image
	if err := json.Unmarshal(raw, &img); err != nil {
		t.Fatal(err)
	}
	lit := &Manifest{Version: "1.4.0", Images: []Image{img}} // never went through VerifyManifest
	if err := VerifyImage(lit, "core", digestCore, e.trust); !errors.Is(err, ErrBadSignature) {
		t.Errorf("hand-built manifest: %v", err)
	}
	parsed, err := parseManifest(js(t, e.manifestMap())) // parsed but not verified
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyImage(parsed, "core", digestCore, e.trust); !errors.Is(err, ErrBadSignature) {
		t.Errorf("parsed-only manifest: %v", err)
	}
}

func TestTrustRefusesSameKeyTwice(t *testing.T) {
	e := newEnv(t)
	same := e.trust
	same.Backup = MinisignKey{ID: [8]byte{9, 9, 9}, Key: e.trust.Active.Key} // other id, same key bytes
	if err := same.validate(); err == nil {
		t.Error("active and backup with the same key bytes accepted")
	}
	same.Backup = MinisignKey{ID: e.trust.Active.ID, Key: e.trust.Backup.Key}
	if err := same.validate(); err == nil {
		t.Error("active and backup with the same id accepted")
	}
}
