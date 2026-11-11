//nolint:gosec // test code: every path is in a directory the test made, and the scripts it writes are fakes of the signing tool
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
)

// testSigner is the in-process Signer of the tests: the same interface MinisignCLI implements, backed by releasetest's key.
type testSigner struct {
	t testing.TB
	m *releasetest.Minisign
}

func (s testSigner) SignFile(_ context.Context, path, sigPath, tc string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // a path the test made
	if err != nil {
		return err
	}
	return os.WriteFile(sigPath, s.m.SignComment(raw, tc), 0o600)
}

type rig struct {
	t              testing.TB
	active, backup *releasetest.Minisign
	cos            *releasetest.Cosign
	trust          release.Trust
}

func newRig(t testing.TB) *rig {
	t.Helper()
	r := &rig{t: t, active: releasetest.NewMinisign(t), backup: releasetest.NewMinisign(t), cos: releasetest.NewCosign(t)}
	var err error
	r.trust, err = release.NewTrust(r.active.PubLine(), r.backup.PubLine(), r.cos.PubPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var t1 = time.Date(2026, 12, 2, 8, 0, 0, 0, time.UTC)

func digestOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// cosignDir writes what `cosign sign --output-payload --output-signature` writes for each image.
func (r *rig) cosignDir(version string, services ...string) (dir string, imgs []ImageIn) {
	r.t.Helper()
	dir = r.t.TempDir()
	for _, s := range services {
		d := digestOf(s + version)
		p := releasetest.Payload(release.RegistryPrefix+s, d)
		_, sig := r.cos.Sign(r.t, p)
		must(r.t, os.WriteFile(filepath.Join(dir, s+".payload.json"), p, 0o600))
		must(r.t, os.WriteFile(filepath.Join(dir, s+".sig"), []byte(sig+"\n"), 0o600)) // cosign writes a trailing newline
		imgs = append(imgs, ImageIn{Service: s, Digest: d, Size: 1234, Platforms: []string{"linux/amd64", "linux/arm64"}})
	}
	return dir, imgs
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// build runs the whole offline pipeline of a release into a fresh directory: manifest, index, active signatures, and (for the
// first call of a chain) the backup signature on the index. prevDir is the directory of the published index or "".
type buildOpts struct {
	version, channel string
	safe             bool
	minVersion       string // rollback.min_version
	minUpgrade       string // min_upgrade_from
	prevDir          string
	baseline, cur    Tree // migrations at rollback.min_version, and at this release
	services         []string
	mutateIndex      func(*release.Index)
}

func (r *rig) build(o buildOpts) (dir string, err error) {
	r.t.Helper()
	if o.channel == "" {
		o.channel = "beta"
	}
	if o.services == nil {
		o.services = []string{"core", "sensor"}
	}
	cdir, imgs := r.cosignDir(o.version, o.services...)
	deb := filepath.Join(r.t.TempDir(), "vedette-host_"+o.version+"_amd64.deb")
	must(r.t, os.WriteFile(deb, []byte("deb "+o.version), 0o600))
	sbom := filepath.Join(r.t.TempDir(), "sbom.json")
	must(r.t, os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX"}`), 0o600))
	in := Inputs{
		Version: o.version, Channel: o.channel, Notes: "Test release & <notes>", InstallModes: []string{"appliance", "container"},
		Rollback: release.Rollback{Safe: o.safe, MinVersion: o.minVersion}, MinUpgradeFrom: o.minUpgrade, Images: imgs,
		Host:    &HostIn{Version: o.version, Files: []string{deb}},
		Content: []release.Content{{Name: "packs", Version: "1", InImage: "core", Path: "/opt/packs", SHA256: strings.Repeat("0", 64)}},
		Bundled: []release.Bundled{{Service: "honeypot", Name: "opencanary", Version: "0.9.4"}},
		SBOM:    &SBOMIn{URL: "https://github.com/knt048/vedette/releases/download/v" + o.version + "/sbom.json", File: sbom},
	}
	env := Env{Now: t1, CosignDir: cdir, CurTree: o.cur, Baseline: o.baseline}
	var prevIdx *release.Index
	if o.prevDir != "" {
		prevIdx, err = LoadPrevIndex(o.prevDir, r.trust)
		if err != nil {
			return "", err
		}
		env.PrevIndex = prevIdx
	}
	res, err := BuildManifest(in, env)
	if err != nil {
		return "", err
	}
	dir = r.t.TempDir()
	must(r.t, os.WriteFile(filepath.Join(dir, manifestFile), res.Manifest, 0o600))
	files, err := BuildIndex(prevIdx, IndexParams{Now: t1, Rollout: -1, Channel: o.channel, ManifestVersion: o.version, ManifestRaw: res.Manifest})
	if err != nil {
		return "", err
	}
	for _, f := range files {
		data := f.Data
		if o.mutateIndex != nil && f.Name == indexFile {
			var x release.Index
			must(r.t, json.Unmarshal(data, &x))
			o.mutateIndex(&x)
			data, err = marshal(x)
			must(r.t, err)
		}
		must(r.t, os.WriteFile(filepath.Join(dir, f.Name), data, 0o600))
	}
	ctx := context.Background()
	if _, err := SignRelease(ctx, testSigner{r.t, r.active}, dir, false); err != nil {
		return "", err
	}
	if _, err := SignRelease(ctx, testSigner{r.t, r.backup}, dir, true); err != nil {
		return "", err
	}
	return dir, nil
}

var addOnlyTree = Tree{"modules/a/migrations/sqlite/0001_a.sql": up("CREATE TABLE a (id INT);")}

func TestRoundTripFirstRelease(t *testing.T) {
	r := newRig(t)
	dir, err := r.build(buildOpts{version: "0.1.0-beta.1", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	s, err := VerifyDir(dir, "", r.trust)
	if err != nil {
		t.Fatal(err)
	}
	if s.Sequence != 1 || s.Version != "0.1.0-beta.1" || s.Channel != "beta" || len(s.Images) != 2 || !s.BackupSig || s.IndexKeyID != r.trust.Active.KeyID() {
		t.Fatalf("%+v", s)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, manifestFile))
	if !bytes.HasSuffix(raw, []byte("}\n")) || bytes.Contains(raw, []byte(`\u003c`)) {
		t.Errorf("manifest formatting: one final newline, no HTML escaping:\n%s", raw)
	}
	for _, want := range []string{`"db_schema": 1`, `"safe": false`, `"ref": "ghcr.io/knt048/vedette-core:0.1.0-beta.1"`, `"name": "vedette-host_0.1.0-beta.1_amd64.deb"`, `"format": "CycloneDX"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("manifest lacks %s", want)
		}
	}
	// the builder is deterministic: the same files give the same bytes
	cdir, imgs := r.cosignDir("0.1.0", "core")
	in := Inputs{Version: "0.1.0", Channel: "beta", InstallModes: []string{"appliance"}, Images: imgs}
	m1, err1 := BuildManifest(in, Env{Now: t1, CosignDir: cdir, CurTree: addOnlyTree})
	m2, err2 := BuildManifest(in, Env{Now: t1, CosignDir: cdir, CurTree: addOnlyTree})
	if err1 != nil || err2 != nil || !bytes.Equal(m1.Manifest, m2.Manifest) {
		t.Error("manifest is not deterministic", err1, err2)
	}
	p := IndexParams{Now: t1, Rollout: -1, Channel: "beta", ManifestVersion: "0.1.0", ManifestRaw: m1.Manifest}
	i1, _ := BuildIndex(nil, p)
	i2, _ := BuildIndex(nil, p)
	if !bytes.Equal(i1[0].Data, i2[0].Data) {
		t.Error("index is not deterministic")
	}
	// the files the verifier reads are exactly the layout of the committed vectors
	for _, n := range []string{"index.json", "index.json.minisig", "index.json.backup.minisig", "release-manifest.json", "release-manifest.json.minisig"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Error(err)
		}
	}
}

func TestSecondReleaseChain(t *testing.T) {
	r := newRig(t)
	first, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	// The previous index carries a revocation; the next index must carry it on.
	prev, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree, mutateIndex: func(x *release.Index) {
		x.Revoked = append(x.Revoked, release.Revocation{Kind: release.KindRelease, ID: "0.0.9", Reason: "broken", Since: t1, Action: "block_install"})
		x.Advisories = append(x.Advisories, release.Advisory{ID: "VED-1", Severity: "high", Title: "t", Affects: "<0.1.0", URL: "https://example.com/a"})
	}})
	if err != nil {
		t.Fatal(err)
	}
	_ = first
	next := Tree{
		"modules/a/migrations/sqlite/0001_a.sql": addOnlyTree["modules/a/migrations/sqlite/0001_a.sql"],
		"modules/a/migrations/sqlite/0002_a.sql": up("ALTER TABLE a ADD COLUMN x INT;"),
	}
	dir, err := r.build(buildOpts{version: "0.2.0", channel: "stable", safe: true, minVersion: "0.1.0", prevDir: prev, baseline: addOnlyTree, cur: next})
	if err != nil {
		t.Fatal(err)
	}
	s, err := VerifyDir(dir, prev, r.trust)
	if err != nil {
		t.Fatal(err)
	}
	if s.Sequence != 2 || s.Version != "0.2.0" {
		t.Fatalf("%+v", s)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, indexFile))
	for _, want := range []string{`"id": "0.0.9"`, `"id": "VED-1"`, `"latest": "0.2.0"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("index lost %s:\n%s", want, raw)
		}
	}
	mraw, _ := os.ReadFile(filepath.Join(dir, manifestFile))
	if !strings.Contains(string(mraw), `"db_schema": 2`) || !strings.Contains(string(mraw), `"safe": true`) {
		t.Errorf("manifest:\n%s", mraw)
	}
	// the new index does not verify against a stored index that is newer (sequence never goes back)
	if _, err := VerifyDir(prev, dir, r.trust); !errors.Is(err, release.ErrSequenceRegress) {
		t.Errorf("an older index against a newer stored one: %v", err)
	}
	// a chain of three: the next one continues from dir
	if d3, err := r.build(buildOpts{version: "0.2.1", channel: "stable", safe: true, minVersion: "0.2.0", prevDir: dir, baseline: next, cur: next}); err != nil {
		t.Fatal(err)
	} else if s3, err := VerifyDir(d3, dir, r.trust); err != nil || s3.Sequence != 3 {
		t.Fatal(s3, err)
	}
}

// D-183: the manifest builder refuses rollback.safe=true unless every migration since the previous release is add-only.
func TestRollbackGuard(t *testing.T) {
	r := newRig(t)
	prev, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	dropping := Tree{
		"modules/a/migrations/sqlite/0001_a.sql": addOnlyTree["modules/a/migrations/sqlite/0001_a.sql"],
		"modules/a/migrations/sqlite/0002_a.sql": up("DROP TABLE a;"),
	}
	cases := []struct {
		name      string
		o         buildOpts
		wantGuard string
		wantErr   string
	}{
		{"first release may not claim a safe rollback: no baseline", buildOpts{version: "0.1.0", safe: true, minVersion: "0.0.1", cur: addOnlyTree}, "", "cannot be proved"},
		{"safe needs rollback.min_version", buildOpts{version: "0.2.0", safe: true, prevDir: prev, baseline: addOnlyTree, cur: addOnlyTree}, "", "needs rollback.min_version"},
		{"min_version must be below the version", buildOpts{version: "0.2.0", safe: true, minVersion: "0.2.0", prevDir: prev, baseline: addOnlyTree, cur: addOnlyTree}, "", "must be a version below"},
		{"min_version above the version", buildOpts{version: "0.2.0", safe: true, minVersion: "0.3.0", prevDir: prev, baseline: addOnlyTree, cur: addOnlyTree}, "", "must be a version below"},
		{"safe without the baseline migrations cannot be proved", buildOpts{version: "0.2.0", safe: true, minVersion: "0.1.0", prevDir: prev, cur: addOnlyTree}, "", "cannot be proved"},
		{"safe with a DROP is refused", buildOpts{version: "0.2.0", safe: true, minVersion: "0.1.0", prevDir: prev, baseline: addOnlyTree, cur: dropping}, "0002_a.sql: cannot classify", ""},
		{"safe with an edited migration is refused", buildOpts{version: "0.2.0", safe: true, minVersion: "0.1.0", prevDir: prev, baseline: addOnlyTree, cur: Tree{"modules/a/migrations/sqlite/0001_a.sql": up("CREATE TABLE a (id INT, z INT);")}}, "was edited", ""},
		{"safe with an empty baseline is refused", buildOpts{version: "0.2.0", safe: true, minVersion: "0.1.0", prevDir: prev, baseline: Tree{}, cur: addOnlyTree}, "wrong ref", ""},
		{"a version that is not above the channel's latest", buildOpts{version: "0.1.0", prevDir: prev, cur: addOnlyTree}, "", "not above 0.1.0"},
		{"min_upgrade_from above the published latest", buildOpts{version: "0.2.0", minUpgrade: "0.1.5", prevDir: prev, cur: addOnlyTree}, "", "no box could upgrade"},
		{"min_upgrade_from at the published latest is fine", buildOpts{version: "0.2.0", minUpgrade: "0.1.0", prevDir: prev, cur: addOnlyTree}, "", ""},
		{"safe=false is always allowed", buildOpts{version: "0.2.0", minVersion: "0.1.0", prevDir: prev, baseline: addOnlyTree, cur: dropping}, "", ""},
		{"safe=false without the baseline migrations is allowed", buildOpts{version: "0.2.0", prevDir: prev, cur: dropping}, "", ""},
	}
	for _, c := range cases {
		c.o.channel = "stable"
		_, err := r.build(c.o)
		var ge *GuardError
		switch {
		case c.wantGuard != "":
			if !errors.As(err, &ge) || !strings.Contains(err.Error(), c.wantGuard) || !strings.Contains(err.Error(), "D-183") {
				t.Errorf("%s: want a guard refusal naming %q, got %v", c.name, c.wantGuard, err)
			}
		case c.wantErr != "":
			if err == nil || errors.As(err, &ge) || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: want error %q, got %v", c.name, c.wantErr, err)
			}
		case err != nil:
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// the exit code of the command line says "guard" apart from other failures
	var out, errb bytes.Buffer
	if code := run([]string{"verify", "-dir", t.TempDir(), "-keys-dir", t.TempDir()}, nil, &out, &errb); code != 1 {
		t.Errorf("exit code %d", code)
	}
}

func TestBuildManifestRefusals(t *testing.T) {
	r := newRig(t)
	cdir, imgs := r.cosignDir("0.1.0", "core")
	good := Inputs{Version: "0.1.0", Channel: "beta", InstallModes: []string{"appliance"}, Images: imgs}
	env := Env{Now: t1, CosignDir: cdir, CurTree: addOnlyTree}
	if _, err := BuildManifest(good, env); err != nil {
		t.Fatal(err)
	}
	mod := func(f func(*Inputs)) Inputs {
		in := good
		in.Images = append([]ImageIn(nil), imgs...)
		f(&in)
		return in
	}
	cases := map[string]Inputs{
		"version with v":         mod(func(i *Inputs) { i.Version = "v0.1.0" }),
		"no channel":             mod(func(i *Inputs) { i.Channel = "" }),
		"unknown channel":        mod(func(i *Inputs) { i.Channel = "nightly" }),
		"unknown service":        mod(func(i *Inputs) { i.Images[0].Service = "nginx" }),
		"duplicate service":      mod(func(i *Inputs) { i.Images = append(i.Images, i.Images[0]) }),
		"upper-case digest":      mod(func(i *Inputs) { i.Images[0].Digest = strings.ToUpper(i.Images[0].Digest) }),
		"short digest":           mod(func(i *Inputs) { i.Images[0].Digest = i.Images[0].Digest[:20] }),
		"digest of another":      mod(func(i *Inputs) { i.Images[0].Digest = digestOf("other") }),
		"no images":              mod(func(i *Inputs) { i.Images = nil }),
		"released_at not a time": mod(func(i *Inputs) { i.ReleasedAt = "yesterday" }),
		"missing host file":      mod(func(i *Inputs) { i.Host = &HostIn{Version: "0.1.0", Files: []string{"/nonexistent/x.deb"}} }),
		"missing sbom file":      mod(func(i *Inputs) { i.SBOM = &SBOMIn{URL: "https://example.com/s", File: "/nonexistent"} }),
	}
	for name, in := range cases {
		if _, err := BuildManifest(in, env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the cosign files must belong to the image
	if _, err := BuildManifest(good, Env{Now: t1, CosignDir: t.TempDir(), CurTree: addOnlyTree}); err == nil {
		t.Error("no cosign files: accepted")
	}
	if _, err := BuildManifest(good, Env{Now: t1, CurTree: addOnlyTree}); err == nil {
		t.Error("no cosign dir: accepted")
	}
	other := t.TempDir()
	p := releasetest.Payload(release.RegistryPrefix+"sensor", imgs[0].Digest) // right digest, wrong repository
	_, sig := r.cos.Sign(t, p)
	must(t, os.WriteFile(filepath.Join(other, "core.payload.json"), p, 0o600))
	must(t, os.WriteFile(filepath.Join(other, "core.sig"), []byte(sig), 0o600))
	if _, err := BuildManifest(good, Env{Now: t1, CosignDir: other, CurTree: addOnlyTree}); err == nil || !strings.Contains(err.Error(), "not for") {
		t.Errorf("payload for another repository: %v", err)
	}
	must(t, os.WriteFile(filepath.Join(other, "core.sig"), []byte("not base64!"), 0o600))
	p = releasetest.Payload(release.RegistryPrefix+"core", imgs[0].Digest)
	must(t, os.WriteFile(filepath.Join(other, "core.payload.json"), p, 0o600))
	if _, err := BuildManifest(good, Env{Now: t1, CosignDir: other, CurTree: addOnlyTree}); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("signature not base64: %v", err)
	}
}

// What the builder wrote is refused after any tampering: the verifier is the one the box runs.
func TestTamperingIsRefused(t *testing.T) {
	r := newRig(t)
	dir, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir, "", r.trust); err != nil {
		t.Fatal(err)
	}
	clone := func() string {
		d := t.TempDir()
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			must(t, os.WriteFile(filepath.Join(d, e.Name()), b, 0o600))
		}
		return d
	}
	edit := func(d, name string, f func([]byte) []byte) {
		p := filepath.Join(d, name)
		b, err := os.ReadFile(p)
		must(t, err)
		must(t, os.WriteFile(p, f(b), 0o600))
	}
	replace := func(from, to string) func([]byte) []byte {
		return func(b []byte) []byte {
			if !bytes.Contains(b, []byte(from)) {
				t.Fatalf("%q not in document", from)
			}
			return bytes.Replace(b, []byte(from), []byte(to), 1)
		}
	}
	cases := []struct {
		name string
		do   func(d string)
		want error
	}{
		{"manifest edited", func(d string) { edit(d, manifestFile, replace(`"0.1.0"`, `"0.1.1"`)) }, release.ErrBadSignature},
		{"manifest db_schema edited", func(d string) { edit(d, manifestFile, replace(`"safe": false`, `"safe": true`)) }, release.ErrBadSignature},
		{"index edited", func(d string) { edit(d, indexFile, replace(`"sequence": 1`, `"sequence": 9`)) }, release.ErrBadSignature},
		{"manifest signature bit flipped", func(d string) {
			edit(d, manifestFile+".minisig", func(b []byte) []byte {
				lines := strings.Split(string(b), "\n")
				raw, _ := base64.StdEncoding.DecodeString(lines[1])
				raw[20] ^= 1
				lines[1] = base64.StdEncoding.EncodeToString(raw)
				return []byte(strings.Join(lines, "\n"))
			})
		}, release.ErrBadSignature},
		{"trusted comment edited", func(d string) { edit(d, manifestFile+".minisig", replace("version:0.1.0", "version:9.9.9")) }, release.ErrBadSignature},
		{"signatures swapped", func(d string) {
			a, _ := os.ReadFile(filepath.Join(d, manifestFile+".minisig"))
			b, _ := os.ReadFile(filepath.Join(d, indexFile+".minisig"))
			must(t, os.WriteFile(filepath.Join(d, manifestFile+".minisig"), b, 0o600))
			must(t, os.WriteFile(filepath.Join(d, indexFile+".minisig"), a, 0o600))
		}, release.ErrBadSignature},
		{"manifest signature missing", func(d string) { must(t, os.Remove(filepath.Join(d, manifestFile+".minisig"))) }, os.ErrNotExist},
		{"index missing", func(d string) { must(t, os.Remove(filepath.Join(d, indexFile))) }, os.ErrNotExist},
		{"manifest signed by the backup key", func(d string) {
			raw, _ := os.ReadFile(filepath.Join(d, manifestFile))
			must(t, os.WriteFile(filepath.Join(d, manifestFile+".minisig"), r.backup.Sign(raw), 0o600))
		}, nil}, // verifies as a signature, but the builder's check says the manifest must be the active key's
		{"an older manifest under the new index", func(d string) {
			old, err := r.build(buildOpts{version: "0.0.9", channel: "stable", cur: addOnlyTree})
			must(t, err)
			for _, n := range []string{manifestFile, manifestFile + ".minisig"} {
				b, _ := os.ReadFile(filepath.Join(old, n))
				must(t, os.WriteFile(filepath.Join(d, n), b, 0o600))
			}
		}, release.ErrManifestHash},
		{"a cosign signature for another digest", func(d string) {
			// re-sign a manifest whose core digest was swapped: the payload still names the old digest
			var m release.Manifest
			raw, _ := os.ReadFile(filepath.Join(d, manifestFile))
			must(t, json.Unmarshal(raw, &m))
			m.Images[0].Digest = digestOf("something else")
			nm, err := marshal(m)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(d, manifestFile), nm, 0o600))
			must(t, os.WriteFile(filepath.Join(d, manifestFile+".minisig"), r.active.SignComment(nm, "x"), 0o600))
			// keep the index in step with the new manifest so only the cosign check can catch it
			var x release.Index
			ib, _ := os.ReadFile(filepath.Join(d, indexFile))
			must(t, json.Unmarshal(ib, &x))
			c := x.Channels["stable"]
			s := sha256.Sum256(nm)
			c.ManifestSHA256 = hex.EncodeToString(s[:])
			x.Channels["stable"] = c
			nib, err := marshal(x)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(d, indexFile), nib, 0o600))
			must(t, os.WriteFile(filepath.Join(d, indexFile+".minisig"), r.active.SignComment(nib, "x"), 0o600))
			must(t, os.Remove(filepath.Join(d, indexFile+".backup.minisig")))
		}, release.ErrBadSignature},
		{"a release the index revokes", func(d string) {
			var x release.Index
			ib, _ := os.ReadFile(filepath.Join(d, indexFile))
			must(t, json.Unmarshal(ib, &x))
			x.Revoked = append(x.Revoked, release.Revocation{Kind: release.KindRelease, ID: "0.1.0", Reason: "bad", Since: t1, Action: "block_install"})
			nib, err := marshal(x)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(d, indexFile), nib, 0o600))
			must(t, os.WriteFile(filepath.Join(d, indexFile+".minisig"), r.active.SignComment(nib, "x"), 0o600))
			must(t, os.Remove(filepath.Join(d, indexFile+".backup.minisig")))
		}, release.ErrReleaseRevoked},
	}
	for _, c := range cases {
		d := clone()
		c.do(d)
		_, err := VerifyDir(d, "", r.trust)
		switch {
		case err == nil:
			t.Errorf("%s: accepted", c.name)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: want %v, got %v", c.name, c.want, err)
		case c.want == nil && !strings.Contains(err.Error(), "active key"):
			t.Errorf("%s: got %v", c.name, err)
		}
	}
	// other keys: the right documents under the wrong trust
	other := newRig(t)
	if _, err := VerifyDir(dir, "", other.trust); !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("wrong minisign keys: %v", err)
	}
	wrongCos := r.trust
	wrongCos.Cosign = []*ecdsa.PublicKey{other.cos.Public()}
	if _, err := VerifyDir(dir, "", wrongCos); !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("wrong cosign key: %v", err)
	}
	swapped := r.trust
	swapped.Active, swapped.Backup = r.trust.Backup, r.trust.Active
	if _, err := VerifyDir(dir, "", swapped); err == nil {
		t.Error("active and backup swapped: accepted")
	}
}

func TestBuildIndexRules(t *testing.T) {
	man := []byte(`{"version":"1.0.0"}`)
	p := IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: man}
	files, err := BuildIndex(nil, p)
	if err != nil || len(files) != 1 || files[0].Name != "index.json" {
		t.Fatal(files, err)
	}
	var x release.Index
	must(t, json.Unmarshal(files[0].Data, &x))
	sum := sha256.Sum256(man)
	if x.Sequence != 1 || x.Schema != 1 || x.Channels["stable"].ManifestSHA256 != hex.EncodeToString(sum[:]) || x.Channels["stable"].Rollout.Percent != 100 ||
		x.ExpiresAt.Sub(x.GeneratedAt) != 14*24*time.Hour || x.Channels["stable"].Manifest != "https://github.com/knt048/vedette/releases/download/v1.0.0/release-manifest.json" {
		t.Fatalf("%+v", x)
	}
	for _, k := range []string{`"revoked": []`, `"advisories": []`, `"keys": []`} {
		if !strings.Contains(string(files[0].Data), k) {
			t.Errorf("an empty list must be [], not null: %s", k)
		}
	}
	prev := &x
	bad := map[string]IndexParams{
		"sequence equal":             {Now: t1, Sequence: 1, Channel: "stable", ManifestVersion: "1.0.1", ManifestRaw: man, Rollout: -1},
		"sequence lower":             {Now: t1, Sequence: 0, Channel: "stable", ManifestVersion: "0.9.0", ManifestRaw: man, Rollout: -1},
		"latest goes down":           {Now: t1, Channel: "stable", ManifestVersion: "0.9.0", ManifestRaw: man, Rollout: -1},
		"valid for 15 days":          {Now: t1, ValidFor: 15 * 24 * time.Hour, Channel: "stable", ManifestVersion: "1.0.1", ManifestRaw: man, Rollout: -1},
		"negative validity":          {Now: t1, ValidFor: -time.Hour, Channel: "stable", ManifestVersion: "1.0.1", ManifestRaw: man, Rollout: -1},
		"rollout 101":                {Now: t1, Channel: "stable", ManifestVersion: "1.0.1", ManifestRaw: man, Rollout: 101},
		"channel unknown":            {Now: t1, Channel: "nightly", ManifestVersion: "1.0.1", ManifestRaw: man, Rollout: -1},
		"version not semver":         {Now: t1, Channel: "stable", ManifestVersion: "v1", ManifestRaw: man, Rollout: -1},
		"manifest without its bytes": {Now: t1, Channel: "stable", ManifestVersion: "1.0.1", Rollout: -1},
	}
	for name, q := range bad {
		if _, err := BuildIndex(prev, q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := BuildIndex(nil, IndexParams{Now: t1, Rollout: -1}); err == nil {
		t.Error("an index with no channel was built")
	}
	// the weekly refresh: no manifest, the sequence goes up, channels stay
	f2, err := BuildIndex(prev, IndexParams{Now: t1.Add(7 * 24 * time.Hour), Rollout: -1})
	if err != nil {
		t.Fatal(err)
	}
	var y release.Index
	must(t, json.Unmarshal(f2[0].Data, &y))
	if y.Sequence != 2 || y.Channels["stable"].Latest != "1.0.0" || !y.GeneratedAt.After(x.GeneratedAt) {
		t.Fatalf("%+v", y)
	}
	// a beta channel next to stable keeps stable, and a rollout percentage is honoured
	f3, err := BuildIndex(&y, IndexParams{Now: t1, Rollout: 10, Channel: "beta", ManifestVersion: "1.1.0-beta.1", ManifestRaw: man})
	if err != nil {
		t.Fatal(err)
	}
	var z release.Index
	must(t, json.Unmarshal(f3[0].Data, &z))
	if z.Channels["stable"].Latest != "1.0.0" || z.Channels["beta"].Rollout.Percent != 10 || z.Sequence != 3 {
		t.Fatalf("%+v", z)
	}
}

// D-108: when the index schema moves on, the previous schema's index is published beside it; until a writer exists the builder
// refuses to publish rather than strand the boxes that can only read the old schema.
func TestLegacyIndexSchema(t *testing.T) {
	old := indexSchema
	oldW := legacyWriters
	t.Cleanup(func() { indexSchema, legacyWriters = old, oldW })
	indexSchema = 2
	legacyWriters = map[int]func(release.Index) ([]byte, error){}
	p := IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: []byte("{}")}
	if _, err := BuildIndex(nil, p); err == nil || !strings.Contains(err.Error(), "D-108") {
		t.Fatalf("a schema-2 index without a schema-1 writer: %v", err)
	}
	legacyWriters[1] = func(x release.Index) ([]byte, error) {
		x.Schema = 1
		return marshal(x)
	}
	files, err := BuildIndex(nil, p)
	if err != nil || len(files) != 2 || files[0].Name != "index.json" || files[1].Name != "index.v1.json" {
		t.Fatal(files, err)
	}
	if !strings.Contains(string(files[0].Data), `"schema": 2`) || !strings.Contains(string(files[1].Data), `"schema": 1`) {
		t.Errorf("schemas:\n%s\n%s", files[0].Data, files[1].Data)
	}
	// both are signed
	dir := t.TempDir()
	for _, f := range files {
		must(t, os.WriteFile(filepath.Join(dir, f.Name), f.Data, 0o600))
	}
	r := newRig(t)
	written, err := SignRelease(t.Context(), testSigner{t, r.active}, dir, true)
	if err != nil || len(written) != 2 || !strings.HasSuffix(written[1], "index.v1.json.backup.minisig") {
		t.Fatal(written, err)
	}
}

func TestSignReleaseSlots(t *testing.T) {
	r := newRig(t)
	dir, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	// the backup slot signs indexes only: no backup signature of a manifest exists
	if _, err := os.Stat(filepath.Join(dir, manifestFile+".backup.minisig")); err == nil {
		t.Error("the backup key signed a manifest")
	}
	// the trusted comments say what was signed
	sig, _ := os.ReadFile(filepath.Join(dir, indexFile+".minisig"))
	if !strings.Contains(string(sig), "trusted comment: file:index.json sequence:1\n") {
		t.Errorf("%s", sig)
	}
	sig, _ = os.ReadFile(filepath.Join(dir, manifestFile+".minisig"))
	if !strings.Contains(string(sig), "trusted comment: file:release-manifest.json version:0.1.0\n") {
		t.Errorf("%s", sig)
	}
	if _, err := SignRelease(t.Context(), testSigner{t, r.active}, t.TempDir(), false); err == nil {
		t.Error("signing an empty directory succeeded")
	}
}

func TestParseInputsIsStrict(t *testing.T) {
	good := `{"version":"0.1.0","channel":"beta","images":[{"service":"core","digest":"sha256:` + strings.Repeat("a", 64) + `","size":1,"platforms":["linux/amd64"]}]}`
	if _, err := ParseInputs([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown field":  `{"version":"0.1.0","dbschema":3}`,
		"repeated key":   `{"version":"0.1.0","version":"0.2.0"}`,
		"case collision": `{"version":"0.1.0","Version":"0.2.0"}`,
		"trailing":       `{"version":"0.1.0"} {}`,
		"not an object":  `[]`,
		"db_schema":      `{"db_schema":3}`,
	} {
		if _, err := ParseInputs([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCosignPlan(t *testing.T) {
	d := digestOf("core")
	argv, err := CosignArgv("cosign", "/keys/cosign.key", "dist/release/cosign", "core", d)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cosign", "sign", "--key", "/keys/cosign.key", "--new-bundle-format=false", "--use-signing-config=false", "--upload=false", "--tlog-upload=false",
		"--output-payload", "dist/release/cosign/core.payload.json", "--output-signature", "dist/release/cosign/core.sig", "ghcr.io/knt048/vedette-core@" + d}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%q", argv)
	}
	for _, c := range [][2]string{{"nginx", d}, {"core", "sha256:abc"}, {"core", strings.ToUpper(d)}, {"core", "latest"}, {"core", ""}} {
		if _, err := CosignArgv("cosign", "k", "o", c[0], c[1]); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	for in, want := range map[string]string{"plain-1.2/x": "plain-1.2/x", "": "''", "a b": "'a b'", "it's": `'it'\''s'`, "$(x)": "'$(x)'"} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
	// the command prints one line per image, and reads the inputs strictly
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	must(t, os.WriteFile(in, []byte(`{"version":"0.1.0","channel":"beta","images":[{"service":"core","digest":"`+d+`","size":1,"platforms":["linux/amd64"]},{"service":"sensor","digest":"`+digestOf("s")+`","size":1,"platforms":["linux/amd64"]}]}`), 0o600))
	var out, errb bytes.Buffer
	if code := run([]string{"cosign-plan", "-in", in, "-key", "/keys/c.key", "-out", "dist/c"}, nil, &out, &errb); code != 0 {
		t.Fatalf("%d %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || lines[0] != "mkdir -p dist/c" || !strings.Contains(lines[1], "vedette-core@"+d) || !strings.Contains(lines[2], "vedette-sensor@") {
		t.Fatalf("%q", lines)
	}
	if code := run([]string{"cosign-plan", "-in", in}, nil, &out, &errb); code == 0 {
		t.Error("cosign-plan without -key succeeded")
	}
	if code := run([]string{"nonsense"}, nil, &out, &errb); code != 2 {
		t.Error(code)
	}
}

// Secrets stay out of argv; the key file is vetted; the signature file of a failed run does not survive.
func TestMinisignCLIHandling(t *testing.T) {
	work := t.TempDir()
	argvFile, stdinFile := filepath.Join(work, "argv"), filepath.Join(work, "stdin")
	fake := filepath.Join(work, "minisign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvFile + "\ncat > " + stdinFile + "\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -x ]; then echo sig > \"$2\"; fi; shift; done\n"
	must(t, os.WriteFile(fake, []byte(script), 0o755))
	key := filepath.Join(work, "key")
	must(t, os.WriteFile(key, []byte("secret key"), 0o600))
	doc := filepath.Join(work, "doc.json")
	must(t, os.WriteFile(doc, []byte("{}"), 0o600))
	sigPath := doc + ".minisig"

	s := MinisignCLI{Bin: fake, KeyPath: key, Passphrase: []byte("hunter2 correct horse")}
	must(t, s.SignFile(t.Context(), doc, sigPath, "file:doc.json sequence:1"))
	argv, _ := os.ReadFile(argvFile)
	if strings.Contains(string(argv), "hunter2") || strings.Contains(string(argv), "correct") {
		t.Fatalf("the passphrase is in argv: %s", argv)
	}
	// the signer hands minisign the key with symlinks resolved (a temp dir under a symlink, like macOS /var -> /private/var, differs)
	resolvedKey, err := filepath.EvalSymlinks(key)
	must(t, err)
	if want := "-S\n-s\n" + resolvedKey + "\n-m\n" + doc + "\n-x\n" + sigPath + "\n-t\nfile:doc.json sequence:1\n"; string(argv) != want {
		t.Fatalf("argv:\n%q\nwant\n%q", argv, want)
	}
	if in, _ := os.ReadFile(stdinFile); string(in) != "hunter2 correct horse\n" {
		t.Fatalf("stdin: %q", in)
	}
	// vetting
	bad := func(name string, s MinisignCLI, tc string) {
		t.Helper()
		if err := s.SignFile(t.Context(), doc, sigPath, tc); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	loose := filepath.Join(work, "loose")
	must(t, os.WriteFile(loose, []byte("k"), 0o600))
	must(t, os.Chmod(loose, 0o644)) // readable by others
	bad("key readable by others", MinisignCLI{Bin: fake, KeyPath: loose}, "t")
	bad("key missing", MinisignCLI{Bin: fake, KeyPath: filepath.Join(work, "none")}, "t")
	bad("relative binary", MinisignCLI{Bin: "minisign", KeyPath: key}, "t")
	bad("binary missing", MinisignCLI{Bin: filepath.Join(work, "nope"), KeyPath: key}, "t")
	bad("newline in the comment", s, "a\nb")
	bad("empty comment", s, "")
	bad("control character in the comment", s, "a\x01b")
	bad("non-ASCII comment", s, "é")
	// a key inside the repository (the working directory of the test is scripts/release)
	inRepo, err := os.CreateTemp(".", "keytest-*")
	must(t, err)
	must(t, inRepo.Chmod(0o600))
	must(t, inRepo.Close())
	t.Cleanup(func() { _ = os.Remove(inRepo.Name()) })
	abs, _ := filepath.Abs(inRepo.Name())
	bad("key inside the working directory", MinisignCLI{Bin: fake, KeyPath: abs}, "t")
	// a tool that fails leaves no signature behind, and its output is in the error but not the passphrase
	failing := filepath.Join(work, "failing")
	must(t, os.WriteFile(failing, []byte("#!/bin/sh\necho 'wrong password' >&2\necho stale > \"$7\"\nexit 1\n"), 0o755))
	err = MinisignCLI{Bin: failing, KeyPath: key, Passphrase: []byte("pw")}.SignFile(t.Context(), doc, sigPath, "t")
	if err == nil || !strings.Contains(err.Error(), "wrong password") || strings.Contains(err.Error(), "pw\n") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(sigPath); err == nil {
		t.Error("a failed run left a signature file")
	}
	// a tool that exits 0 without a signature is an error
	lying := filepath.Join(work, "lying")
	must(t, os.WriteFile(lying, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	if err := (MinisignCLI{Bin: lying, KeyPath: key, Passphrase: []byte("x")}).SignFile(t.Context(), doc, sigPath, "t"); err == nil {
		t.Error("success without a signature was believed")
	}
}

func TestReadLine(t *testing.T) {
	for in, want := range map[string]string{"pw\nrest": "pw", "pw\r\n": "pw", "pw": "pw", " spaced pw \n": " spaced pw "} { //nolint:gosec // test input, not a credential
		got, err := readLine(strings.NewReader(in))
		if err != nil || string(got) != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := readLine(strings.NewReader("")); err == nil {
		t.Error("empty stdin gave a passphrase")
	}
	if _, err := readLine(strings.NewReader(strings.Repeat("x", 2000))); err == nil {
		t.Error("a 2000-byte line was accepted")
	}
}

func TestLoadTrust(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "minisign.pub"), []byte("untrusted comment: x\n"+r.active.PubLine()+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "minisign-backup.pub"), []byte(r.backup.PubLine()+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "cosign.pub"), []byte(r.cos.PubPEM(t)), 0o600))
	tr, err := LoadTrust(dir)
	if err != nil || tr.Active.KeyID() != r.trust.Active.KeyID() {
		t.Fatal(tr, err)
	}
	must(t, os.Remove(filepath.Join(dir, "cosign.pub")))
	if _, err := LoadTrust(dir); err == nil {
		t.Error("trust without a cosign key")
	}
	// no keys dir = the keys compiled into this build: none in a production build (refuses), the throwaway ones in a test build
	if _, err := LoadTrust(""); err != nil && !errors.Is(err, release.ErrNoTrustKeys) {
		t.Errorf("embedded keys: %v", err)
	}
}
