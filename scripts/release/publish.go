package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// Publishing (WP-08k, D-457): the assets of a release go to the GitHub release v<version> (kien's tag), created as a draft, filled,
// checked, then published; index.json and its signature go to the fixed release "index" last, so a box never sees an index that
// announces a release whose files are not there yet. A published version is never changed.

const (
	ghRepo   = "KNT048/vedette"
	indexTag = "index"
	// installer and installerSig are install.sh with its three baked lines and its signature (release-bake-install, part A).
	installer    = "install.sh"
	installerSig = "install.sh.minisig"
	ghcrBase     = "https://ghcr.io"
)

// fileRecord is a file's SHA-256 and size, taken once from the bytes that were verified; every later step compares with it.
type fileRecord struct {
	SHA256 string
	Size   int64
}

// publishPlan is what goes where.
type publishPlan struct {
	Dir        string
	Version    string // empty: an index-only refresh (D-150), nothing but the index is uploaded
	Prerelease bool
	Notes      string
	Assets     []string // files of the release v<version>
	Index      []string // files of the release "index", uploaded last
	Record     map[string]fileRecord
	Images     []release.Image // what boxes pull anonymously, checked before the release and the index go public
	// ManifestKeyID and IndexKeyID are the keys that signed the manifest and the index (a real publish requires the embedded
	// production keys, requireProductionSigners).
	ManifestKeyID, IndexKeyID string
	Rescue                    bool
}

// bakedLineRE is one of install.sh's three baked lines (release-bake-install, part A): KEY="value" alone on its line.
var bakedLineRE = regexp.MustCompile(`(?m)^(VEDETTE_VERSION|VEDETTE_DEB_SHA256_AMD64|VEDETTE_DEB_SHA256_ARM64)=(.*)$`)

// checkInstaller verifies install.sh as boxes and customers will run it: signed by the key that signed the manifest, with the trusted
// comment "file:install.sh version:<v>", and its three baked lines naming exactly this release and the SHA-256 of its two packages.
func checkInstaller(dir string, m *release.Manifest, manifestKey string, trust release.Trust) error {
	raw, sig, err := readSigned(filepath.Join(dir, installer))
	if err != nil {
		return fmt.Errorf("%s and its signature: %w (release-bake-install writes them into %s)", installer, err, dir)
	}
	if err := release.VerifyContent(raw, sig, trust); err != nil {
		return fmt.Errorf("%s: %w", installer, err)
	}
	tc, key, err := minisigCommentAndKey(sig, trust)
	if err != nil {
		return fmt.Errorf("%s: %w", installer, err)
	}
	if key != manifestKey {
		return fmt.Errorf("%s is signed by %s, the manifest by %s", installer, key, manifestKey)
	}
	if want := "file:" + installer + " version:" + m.Version; tc != want {
		return fmt.Errorf("%s: trusted comment %q, want %q", installer, tc, want)
	}
	want := map[string]string{"VEDETTE_VERSION": m.Version}
	for _, f := range m.Host.Files {
		if _, arch, ok := release.ParseHostPackageName(f.Name); ok {
			want["VEDETTE_DEB_SHA256_"+strings.ToUpper(arch)] = f.SHA256
		}
	}
	seen := map[string]int{}
	for _, l := range bakedLineRE.FindAllStringSubmatch(string(raw), -1) {
		seen[l[1]]++
		if w, ok := want[l[1]]; !ok || l[2] != `"`+w+`"` {
			return fmt.Errorf("%s: %s=%s, want %q (the signed manifest)", installer, l[1], l[2], want[l[1]])
		}
	}
	for _, k := range []string{"VEDETTE_VERSION", "VEDETTE_DEB_SHA256_AMD64", "VEDETTE_DEB_SHA256_ARM64"} {
		if seen[k] != 1 {
			return fmt.Errorf("%s: the baked line %s is there %d times, want once", installer, k, seen[k])
		}
	}
	return nil
}

// planPublish lists and records the files of a directory VerifyDir has just passed. in is the release description (the .deb
// paths); nil for a refresh. It refuses a -test. version, a missing file, a symlink, an install.sh that is not this release's, and a
// .deb whose SHA-256 or size is not the one the signed manifest names.
func planPublish(dir string, s *Summary, in *Inputs, trust release.Trust) (*publishPlan, error) {
	p := &publishPlan{Dir: dir, IndexKeyID: s.IndexKeyID, Rescue: s.Rescue, Record: map[string]fileRecord{}}
	p.Index = []string{filepath.Join(dir, indexFile), filepath.Join(dir, indexFile+".minisig")}
	legacy, err := filepath.Glob(filepath.Join(dir, "index.v*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(legacy)
	for _, l := range legacy {
		p.Index = append(p.Index, l, l+".minisig")
	}
	var m release.Manifest
	if !s.IndexOnly {
		if err := refuseTestVersion(s.Version); err != nil {
			return nil, err
		}
		if in == nil {
			return nil, errors.New("a release needs its release.in.json (the .deb paths)")
		}
		raw, msig, err := readSigned(filepath.Join(dir, manifestFile))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		if m.Version != s.Version || in.Version != s.Version || m.Host == nil || in.Host == nil {
			return nil, fmt.Errorf("release.in.json is for %q, the signed manifest for %q", in.Version, s.Version)
		}
		if _, p.ManifestKeyID, err = minisigCommentAndKey(msig, trust); err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		if err := checkInstaller(dir, &m, p.ManifestKeyID, trust); err != nil {
			return nil, err
		}
		p.Version = s.Version
		p.Prerelease = s.Channel == "beta" || strings.Contains(s.Version, "-")
		p.Notes = m.Notes
		if p.Notes == "" {
			p.Notes = "Vedette " + s.Version
		}
		p.Images = m.Images
		p.Assets = []string{filepath.Join(dir, manifestFile), filepath.Join(dir, manifestFile+".minisig"),
			filepath.Join(dir, installer), filepath.Join(dir, installerSig)}
		if s.ContainerAssets {
			for _, n := range containerAssets {
				p.Assets = append(p.Assets, filepath.Join(dir, n), filepath.Join(dir, n+".minisig"))
			}
		}
		for _, f := range m.Host.Files {
			i := slices.IndexFunc(in.Host.Files, func(path string) bool { return filepath.Base(path) == f.Name })
			if i < 0 {
				return nil, fmt.Errorf("release.in.json names no %s", f.Name)
			}
			p.Assets = append(p.Assets, in.Host.Files[i])
		}
	}
	for _, f := range append(slices.Clone(p.Assets), p.Index...) {
		fi, err := os.Lstat(f)
		if err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is missing or not a regular file (a symlink is refused: what is uploaded is what was verified)", f)
		}
		name := filepath.Base(f)
		if _, dup := p.Record[name]; dup {
			return nil, fmt.Errorf("two files are named %s", name)
		}
		sum, size, err := hashFile(f)
		if err != nil {
			return nil, err
		}
		p.Record[name] = fileRecord{sum, size}
	}
	if !s.IndexOnly {
		for _, f := range m.Host.Files {
			if r := p.Record[f.Name]; r.SHA256 != f.SHA256 || r.Size != f.Size {
				return nil, fmt.Errorf("%s is not the package the signed manifest names (sha256 %s, %d bytes): rebuilt after release-manifest?", f.Name, f.SHA256, f.Size)
			}
		}
	}
	return p, nil
}

// checkLocal re-hashes files right before they are uploaded: each must still be the recorded, verified bytes.
func (p *publishPlan) checkLocal(files []string) error {
	for _, f := range files {
		fi, err := os.Lstat(f)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%s changed since it was verified (missing or not a regular file)", f)
		}
		sum, size, err := hashFile(f)
		if err != nil {
			return err
		}
		if r := p.Record[filepath.Base(f)]; r.SHA256 != sum || r.Size != size {
			return fmt.Errorf("%s changed since it was verified: verify again", f)
		}
	}
	return nil
}

// requireProductionSigners refuses a real publish of anything not signed by the keys compiled into this build (prod): the active
// key, or the backup key for a rescue. -keys-dir changes what verify reasons with (a rescue checks against the keys the installed
// boxes trust), never which signer may be published.
func requireProductionSigners(p *publishPlan, prod release.Trust) error {
	if prod.TestOnly {
		return errors.New("this build carries the throwaway release keys: a real publish needs a build without -tags releasetestkeys")
	}
	ok := []string{prod.Active.KeyID()}
	if p.Rescue {
		ok = append(ok, prod.Backup.KeyID())
	}
	for what, id := range map[string]string{"index": p.IndexKeyID, "manifest": p.ManifestKeyID} {
		if (what == "manifest" && p.Version == "") || slices.Contains(ok, id) {
			continue
		}
		return fmt.Errorf("the %s is signed by %s, not by the production key %s compiled into this build", what, id, strings.Join(ok, " or "))
	}
	return nil
}

// ghAsset is one asset as `gh release view --json assets` prints it.
type ghAsset struct {
	Name   string  `json:"name"`
	Size   int64   `json:"size"`
	Digest *string `json:"digest"`
	State  string  `json:"state"`
}

type ghRelease struct {
	IsDraft bool      `json:"isDraft"`
	Assets  []ghAsset `json:"assets"`
}

func (r *ghRelease) has(name string) bool {
	return slices.ContainsFunc(r.Assets, func(a ghAsset) bool { return a.Name == name })
}

// publishEnv is what Publish talks to.
type publishEnv struct {
	run          runFunc
	reg          registryHTTP  // ghcr.io, anonymous: what a box sees
	repo         string        // git repository root (the tag)
	trust        release.Trust // the keys VerifyDir used
	prevDir      string        // the published index the release was built on
	firstRelease bool          // no index has been published yet
	stdout       io.Writer
}

// viewRelease reads a release; nil without error when it does not exist.
func (e publishEnv) viewRelease(ctx context.Context, tag string) (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := e.run(ctx, "gh", "release", "view", tag, "--repo", ghRepo, "--json", "isDraft,assets")
	if err != nil {
		if strings.Contains(err.Error(), "release not found") {
			return nil, nil //nolint:nilnil // "not there" is an answer, not an error
		}
		return nil, err
	}
	var r ghRelease
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("gh release view %s: %w", tag, err)
	}
	return &r, nil
}

// readBack reads a release that must exist (after an upload or edit).
func (e publishEnv) readBack(ctx context.Context, tag string) (*ghRelease, error) {
	r, err := e.viewRelease(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("read back %s: %w", tag, err)
	}
	if r == nil {
		return nil, fmt.Errorf("read back %s: release not found", tag)
	}
	return r, nil
}

// download fetches named assets of a release into a new temporary directory, which the caller removes.
func (e publishEnv) download(ctx context.Context, tag string, names ...string) (string, error) {
	tmp, err := os.MkdirTemp("", "vedette-publish-*")
	if err != nil {
		return "", err
	}
	argv := []string{"gh", "release", "download", tag, "--repo", ghRepo, "--dir", tmp}
	for _, n := range names {
		argv = append(argv, "--pattern", n)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := e.run(ctx, argv...); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	return tmp, nil
}

// checkAssets compares the assets of a release with the record: each there, uploaded, of the recorded size and SHA-256. When GitHub
// reports no digest the asset is downloaded and hashed. exact also refuses an asset that is not one of files.
func (e publishEnv) checkAssets(ctx context.Context, p *publishPlan, r *ghRelease, files []string, exact bool, tag string) error {
	var errs []error
	var noDigest []string
	for _, f := range files {
		name := filepath.Base(f)
		rec := p.Record[name]
		i := slices.IndexFunc(r.Assets, func(a ghAsset) bool { return a.Name == name })
		if i < 0 {
			errs = append(errs, fmt.Errorf("%s: no asset %s", tag, name))
			continue
		}
		a := r.Assets[i]
		switch {
		case a.State != "uploaded" || a.Size != rec.Size || (a.Digest != nil && *a.Digest != "sha256:"+rec.SHA256):
			errs = append(errs, fmt.Errorf("%s: asset %s is not the verified file (state %s, %d bytes, digest %s; verified %d bytes, sha256:%s)", tag, name, a.State, a.Size, deref(a.Digest), rec.Size, rec.SHA256))
		case a.Digest == nil:
			noDigest = append(noDigest, name)
		}
	}
	if exact {
		for _, a := range r.Assets {
			if !slices.ContainsFunc(files, func(f string) bool { return filepath.Base(f) == a.Name }) {
				errs = append(errs, fmt.Errorf("%s: asset %s is not part of this release: remove it with `gh release delete-asset %s %s --repo %s`", tag, a.Name, tag, a.Name, ghRepo))
			}
		}
	}
	if len(errs) == 0 && len(noDigest) > 0 {
		tmp, err := e.download(ctx, tag, noDigest...)
		if err != nil {
			return fmt.Errorf("%s: GitHub gives no digest for %v and the download failed: %w", tag, noDigest, err)
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		for _, n := range noDigest {
			sum, size, err := hashFile(filepath.Join(tmp, n))
			switch rec := p.Record[n]; {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s: the downloaded %s: %w", tag, n, err))
			case sum != rec.SHA256 || size != rec.Size:
				errs = append(errs, fmt.Errorf("%s: the downloaded %s is not the verified file (sha256:%s, %d bytes)", tag, n, sum, size))
			}
		}
	}
	return errors.Join(errs...)
}

func deref(s *string) string {
	if s == nil {
		return "none"
	}
	return *s
}

// checkPullable proves every image of the release can be pulled the way a box pulls it: anonymously, by digest, from ghcr.io.
func (e publishEnv) checkPullable(ctx context.Context, p *publishPlan) error {
	path := strings.TrimPrefix(release.RegistryPrefix, "ghcr.io/")
	for _, im := range p.Images {
		if _, err := e.reg.manifest(ctx, "HEAD", path+im.Service, im.Digest, acceptList); err != nil {
			if errors.Is(err, errDenied) {
				return fmt.Errorf("%s%s@%s cannot be pulled anonymously (%w): make the package public (plan §3 (3)), then run again", release.RegistryPrefix, im.Service, im.Digest, err)
			}
			return err
		}
	}
	return nil
}

// liveIndex is the index boxes read now: the bytes of index.json and its signature on the release "index", verified, and the same
// bytes as the -prev-index the release was built on (or, for the first release, no index at all). It returns the bytes so a later
// look can tell whether the index moved meanwhile.
func (e publishEnv) liveIndex(ctx context.Context) ([]byte, error) {
	r, err := e.viewRelease(ctx, indexTag)
	if err != nil {
		return nil, err
	}
	if r == nil || r.IsDraft {
		return nil, fmt.Errorf("no published release %q: kien creates it once by hand (docs/plans/2026-11-12-wp08k-release-job.md §3)", indexTag)
	}
	if !r.has(indexFile) {
		if !e.firstRelease || e.prevDir != "" {
			return nil, fmt.Errorf("the release %q has no %s: only the first release publishes without one (-first-release, no -prev-index)", indexTag, indexFile)
		}
		return nil, nil
	}
	if e.firstRelease {
		return nil, fmt.Errorf("-first-release, but the release %q already has an %s: build on it (-prev-index)", indexTag, indexFile)
	}
	if e.prevDir == "" {
		return nil, errors.New("a real publish needs -prev-index (RELEASE_PREV_INDEX): the published index this release was built on")
	}
	tmp, err := e.download(ctx, indexTag, indexFile, indexFile+".minisig")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if _, err := LoadPrevIndex(tmp, e.trust); err != nil {
		return nil, fmt.Errorf("the live index: %w", err)
	}
	var live []byte
	for _, n := range []string{indexFile, indexFile + ".minisig"} {
		a, err1 := readDoc(filepath.Join(tmp, n))
		b, err2 := readDoc(filepath.Join(e.prevDir, n))
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		if !bytes.Equal(a, b) {
			return nil, fmt.Errorf("the live %s differs from -prev-index %s: another index was published since; build again on the live one", n, e.prevDir)
		}
		live = append(live, a...)
	}
	return live, nil
}

// Publish prints the gh commands (doRun false) or runs them. Run, it is safe to repeat after a failure: a draft is filled again,
// a published version is only compared (never changed), and the index goes up last.
func Publish(ctx context.Context, e publishEnv, p *publishPlan, doRun bool) error {
	tag := "v" + p.Version
	if p.Version != "" {
		gctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := e.run(gctx, "git", "-C", e.repo, "rev-parse", "--verify", "--quiet", "refs/tags/"+tag+"^{commit}")
		cancel()
		if err != nil {
			return fmt.Errorf("no tag %s: kien creates and pushes it by hand before publishing (AI creates no tag): %w", tag, err)
		}
	}
	notes := filepath.Join(p.Dir, "release-notes.md")
	if doRun {
		f, err := os.CreateTemp("", "vedette-notes-*.md")
		if err != nil {
			return err
		}
		notes = f.Name()
		_ = f.Close()
		defer func() { _ = os.Remove(notes) }()
	}
	if p.Version != "" {
		if err := os.WriteFile(notes, []byte(p.Notes+"\n"), 0o600); err != nil {
			return err
		}
	}
	create := []string{"gh", "release", "create", tag, "--repo", ghRepo, "--verify-tag", "--draft", "--title", "Vedette " + p.Version, "--notes-file", notes}
	if p.Prerelease {
		create = append(create, "--prerelease")
	}
	upload := append([]string{"gh", "release", "upload", tag, "--repo", ghRepo, "--clobber"}, p.Assets...)
	undraft := []string{"gh", "release", "edit", tag, "--repo", ghRepo, "--draft=false"}
	index := append([]string{"gh", "release", "upload", indexTag, "--repo", ghRepo, "--clobber"}, p.Index...)

	if !doRun {
		say(e.stdout, "# D-457: run in this order; PUBLISH=1 runs them and checks every asset, the live index and anonymous pulls. Never edit a published v<version>.")
		if p.Version != "" {
			for _, c := range [][]string{create, upload, undraft} {
				say(e.stdout, "%s", quoteArgv(c))
			}
		}
		say(e.stdout, "# last: the index, once %s is published with every asset", tag)
		say(e.stdout, "%s", quoteArgv(index))
		return nil
	}

	long := func(argv []string) error {
		c, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		_, err := e.run(c, argv...)
		return err
	}
	live, err := e.liveIndex(ctx)
	if err != nil {
		return err
	}
	if p.Version != "" {
		r, err := e.viewRelease(ctx, tag)
		if err != nil {
			return err
		}
		switch {
		case r != nil && !r.IsDraft:
			if err := e.checkAssets(ctx, p, r, p.Assets, true, tag); err != nil {
				return fmt.Errorf("%s is published and differs from this directory; a published version is never changed (release the next one):\n%w", tag, err)
			}
			say(e.stdout, "%s is already published with these assets", tag)
		default:
			if r == nil {
				if err := long(create); err != nil {
					return err
				}
				say(e.stdout, "created draft %s", tag)
			}
			if err := p.checkLocal(p.Assets); err != nil {
				return err
			}
			if err := long(upload); err != nil {
				return fmt.Errorf("%w (the release is still a draft: run again)", err)
			}
			if r, err = e.readBack(ctx, tag); err != nil {
				return err
			}
			if err := e.checkAssets(ctx, p, r, p.Assets, true, tag); err != nil {
				return fmt.Errorf("%w (the release is still a draft: run again)", err)
			}
			if err := e.checkPullable(ctx, p); err != nil {
				return fmt.Errorf("%w (the release is still a draft)", err)
			}
			if err := long(undraft); err != nil {
				return err
			}
			if r, err = e.readBack(ctx, tag); err != nil {
				return err
			}
			if r.IsDraft {
				return fmt.Errorf("%s is still a draft after gh release edit --draft=false", tag)
			}
			say(e.stdout, "published %s (%d assets)", tag, len(p.Assets))
		}
	}
	if err := e.checkPullable(ctx, p); err != nil {
		return fmt.Errorf("%w (the index was not uploaded)", err)
	}
	again, err := e.liveIndex(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, live) {
		return errors.New("the live index changed while publishing: the index was not uploaded")
	}
	if err := p.checkLocal(p.Index); err != nil {
		return err
	}
	if err := long(index); err != nil {
		return fmt.Errorf("%w (the index may be half replaced: boxes refuse it until the next run uploads both files; run again now)", err)
	}
	r, err := e.readBack(ctx, indexTag)
	if err != nil {
		return err
	}
	if err := e.checkAssets(ctx, p, r, p.Index, false, indexTag); err != nil {
		return err
	}
	say(e.stdout, "uploaded the index (%s) to the release %q", strings.Join(baseNames(p.Index), ", "), indexTag)
	return nil
}

func baseNames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

func quoteArgv(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

func cmdPublish(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("publish")
	dir := fs.String("dir", "dist/release", "directory of the signed and verified release (or index-only refresh)")
	in := fs.String("in", "release.in.json", "release description (the .deb paths); not read for a refresh")
	prev := fs.String("prev-index", "", "directory of the published index this release was built on (required with -run, except -first-release)")
	first := fs.Bool("first-release", false, "the very first release: no index is published yet (the release \"index\" has no index.json)")
	keys := fs.String("keys-dir", "", "directory with the public keys to verify with (default: the keys compiled in); with -run the signers must still be the compiled-in keys")
	repo := fs.String("repo", ".", "repository root (the tag is looked up there)")
	doRun := fs.Bool("run", false, "run the gh commands (default: print them)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	trust, err := LoadTrust(*keys)
	if err != nil {
		return err
	}
	// What is uploaded is what the box's verifier passes: verify, record the bytes, verify again, and compare the record.
	s, err := VerifyDir(*dir, *prev, trust)
	if err != nil {
		return err
	}
	var inputs *Inputs
	if !s.IndexOnly {
		x, err := readInputs(*in)
		if err != nil {
			return err
		}
		inputs = &x
	}
	p, err := planPublish(*dir, s, inputs, trust)
	if err != nil {
		return err
	}
	if _, err := VerifyDir(*dir, *prev, trust); err != nil {
		return err
	}
	if err := p.checkLocal(append(slices.Clone(p.Assets), p.Index...)); err != nil {
		return err
	}
	if *doRun {
		prod, err := release.Embedded()
		if err != nil {
			return err
		}
		if err := requireProductionSigners(p, prod); err != nil {
			return err
		}
	}
	e := publishEnv{run: execRun, reg: newRegistryHTTP(ghcrBase), repo: *repo, trust: trust, prevDir: *prev, firstRelease: *first, stdout: stdout}
	return Publish(ctx, e, p, *doRun)
}
