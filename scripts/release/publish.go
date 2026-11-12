package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// Publishing (WP-08k, D-457): the assets of a release go to the GitHub release v<version> (kien's tag), created as a draft, filled,
// then published; index.json and its signature go to the fixed release "index" last, so a box never sees an index that announces a
// release whose files are not there yet. A published version is never changed.

const (
	ghRepo   = "KNT048/vedette"
	indexTag = "index"
	// installer and installerSig are install.sh with its three baked lines and its signature (release-bake-install, part A).
	installer    = "install.sh"
	installerSig = "install.sh.minisig"
)

// publishPlan is what goes where.
type publishPlan struct {
	Version    string // empty: an index-only refresh (D-150), nothing but the index is uploaded
	Prerelease bool
	Notes      string
	Assets     []string // files of the release v<version>
	Index      []string // files of the release "index", uploaded last
}

// planPublish lists the files of a verified directory. in is the release description (the .deb paths); nil for a refresh.
// It refuses a missing file and a .deb whose SHA-256 or size is not the one the signed manifest names.
func planPublish(dir string, s *Summary, in *Inputs) (*publishPlan, error) {
	p := &publishPlan{}
	p.Index = []string{filepath.Join(dir, indexFile), filepath.Join(dir, indexFile+".minisig")}
	legacy, err := filepath.Glob(filepath.Join(dir, "index.v*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(legacy)
	for _, l := range legacy {
		p.Index = append(p.Index, l, l+".minisig")
	}
	if !s.IndexOnly {
		if in == nil {
			return nil, errors.New("a release needs its release.in.json (the .deb paths)")
		}
		raw, err := readDoc(filepath.Join(dir, manifestFile))
		if err != nil {
			return nil, err
		}
		var m release.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		if m.Version != s.Version || in.Version != s.Version || m.Host == nil {
			return nil, fmt.Errorf("release.in.json is for %q, the signed manifest for %q", in.Version, s.Version)
		}
		p.Version = s.Version
		p.Prerelease = s.Channel == "beta" || strings.Contains(s.Version, "-")
		p.Notes = m.Notes
		if p.Notes == "" {
			p.Notes = "Vedette " + s.Version
		}
		p.Assets = []string{filepath.Join(dir, manifestFile), filepath.Join(dir, manifestFile+".minisig"),
			filepath.Join(dir, installer), filepath.Join(dir, installerSig)}
		if s.ContainerAssets {
			for _, n := range containerAssets {
				p.Assets = append(p.Assets, filepath.Join(dir, n), filepath.Join(dir, n+".minisig"))
			}
		}
		if in.Host == nil {
			return nil, errors.New("release.in.json has no host part")
		}
		for _, f := range m.Host.Files {
			i := slices.IndexFunc(in.Host.Files, func(path string) bool { return filepath.Base(path) == f.Name })
			if i < 0 {
				return nil, fmt.Errorf("release.in.json names no %s", f.Name)
			}
			sum, size, err := hashFile(in.Host.Files[i])
			if err != nil {
				return nil, err
			}
			if sum != f.SHA256 || size != f.Size {
				return nil, fmt.Errorf("%s is not the package the signed manifest names (sha256 %s, %d bytes): rebuilt after release-manifest?", in.Host.Files[i], f.SHA256, f.Size)
			}
			p.Assets = append(p.Assets, in.Host.Files[i])
		}
	}
	for _, f := range append(slices.Clone(p.Assets), p.Index...) {
		fi, err := os.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			if filepath.Base(f) == installer || filepath.Base(f) == installerSig {
				return nil, fmt.Errorf("%s is missing: release-bake-install writes install.sh and its signature into %s", filepath.Base(f), dir)
			}
			return nil, fmt.Errorf("%s is missing", f)
		}
	}
	return p, nil
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

// viewRelease reads a release; nil without error when it does not exist.
func viewRelease(ctx context.Context, run runFunc, tag string) (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := run(ctx, "gh", "release", "view", tag, "--repo", ghRepo, "--json", "isDraft,assets")
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
func readBack(ctx context.Context, run runFunc, tag string) (*ghRelease, error) {
	r, err := viewRelease(ctx, run, tag)
	if err != nil {
		return nil, fmt.Errorf("read back %s: %w", tag, err)
	}
	if r == nil {
		return nil, fmt.Errorf("read back %s: release not found", tag)
	}
	return r, nil
}

// checkAssets compares the assets of a release with the local files: each one there, uploaded, of the same size and, when GitHub
// reports a digest, the same SHA-256. exact also refuses an asset that is not a local file.
func checkAssets(r *ghRelease, files []string, exact bool, tag string) error {
	var errs []error
	for _, f := range files {
		name := filepath.Base(f)
		i := slices.IndexFunc(r.Assets, func(a ghAsset) bool { return a.Name == name })
		if i < 0 {
			errs = append(errs, fmt.Errorf("%s: no asset %s", tag, name))
			continue
		}
		a := r.Assets[i]
		sum, size, err := hashFile(f)
		if err != nil {
			return err
		}
		if a.State != "uploaded" || a.Size != size || (a.Digest != nil && *a.Digest != "sha256:"+sum) {
			errs = append(errs, fmt.Errorf("%s: asset %s is not the local file (state %s, %d bytes, digest %v; local %d bytes, sha256:%s)", tag, name, a.State, a.Size, deref(a.Digest), size, sum))
		}
	}
	if exact {
		for _, a := range r.Assets {
			if !slices.ContainsFunc(files, func(f string) bool { return filepath.Base(f) == a.Name }) {
				errs = append(errs, fmt.Errorf("%s: asset %s is not part of the release", tag, a.Name))
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

// Publish prints the gh commands (doRun false) or runs them. Run, it is safe to repeat after a failure: a draft is filled again,
// a published version is only compared (never changed), and the index goes up last.
func Publish(ctx context.Context, run runFunc, repo string, p *publishPlan, doRun bool, stdout io.Writer) error {
	tag := "v" + p.Version
	if p.Version != "" {
		gctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := run(gctx, "git", "-C", repo, "rev-parse", "--verify", "--quiet", "refs/tags/"+tag+"^{commit}")
		cancel()
		if err != nil {
			return fmt.Errorf("no tag %s: kien creates and pushes it by hand before publishing (AI creates no tag): %w", tag, err)
		}
	}
	create := []string{"gh", "release", "create", tag, "--repo", ghRepo, "--verify-tag", "--draft", "--title", "Vedette " + p.Version, "--notes", p.Notes}
	if p.Prerelease {
		create = append(create, "--prerelease")
	}
	upload := append([]string{"gh", "release", "upload", tag, "--repo", ghRepo, "--clobber"}, p.Assets...)
	undraft := []string{"gh", "release", "edit", tag, "--repo", ghRepo, "--draft=false"}
	index := append([]string{"gh", "release", "upload", indexTag, "--repo", ghRepo, "--clobber"}, p.Index...)

	if !doRun {
		say(stdout, "# D-457: run in this order; PUBLISH=1 runs them and checks every asset after. Never edit a published v<version>.")
		if p.Version != "" {
			for _, c := range [][]string{create, upload, undraft} {
				say(stdout, "%s", quoteArgv(c))
			}
		}
		say(stdout, "# last: the index, once %s is published with every asset", tag)
		say(stdout, "%s", quoteArgv(index))
		return nil
	}

	long := func(argv []string) error {
		c, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		_, err := run(c, argv...)
		return err
	}
	if p.Version != "" {
		r, err := viewRelease(ctx, run, tag)
		if err != nil {
			return err
		}
		switch {
		case r != nil && !r.IsDraft:
			if err := checkAssets(r, p.Assets, true, tag); err != nil {
				return fmt.Errorf("%s is published and differs from this directory; a published version is never changed (release the next one):\n%w", tag, err)
			}
			say(stdout, "%s is already published with these assets", tag)
		default:
			if r == nil {
				if err := long(create); err != nil {
					return err
				}
				say(stdout, "created draft %s", tag)
			}
			if err := long(upload); err != nil {
				return fmt.Errorf("%w (the release is still a draft: run again)", err)
			}
			if r, err = readBack(ctx, run, tag); err != nil {
				return err
			}
			if err := checkAssets(r, p.Assets, true, tag); err != nil {
				return fmt.Errorf("%w (the release is still a draft: run again)", err)
			}
			if err := long(undraft); err != nil {
				return err
			}
			if r, err = readBack(ctx, run, tag); err != nil {
				return err
			}
			if r.IsDraft {
				return fmt.Errorf("%s is still a draft after gh release edit --draft=false", tag)
			}
			say(stdout, "published %s (%d assets)", tag, len(p.Assets))
		}
	}
	r, err := viewRelease(ctx, run, indexTag)
	if err != nil {
		return err
	}
	if r == nil || r.IsDraft {
		return fmt.Errorf("no published release %q: kien creates it once by hand (docs/plans/2026-11-12-wp08k-release-job.md); the index was not uploaded", indexTag)
	}
	if err := long(index); err != nil {
		return fmt.Errorf("%w (the index may be half replaced: boxes refuse it until the next run uploads both files; run again now)", err)
	}
	if r, err = readBack(ctx, run, indexTag); err != nil {
		return err
	}
	if err := checkAssets(r, p.Index, false, indexTag); err != nil {
		return err
	}
	say(stdout, "uploaded the index (%s) to the release %q", strings.Join(baseNames(p.Index), ", "), indexTag)
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
	prev := fs.String("prev-index", "", "directory of the published index (as for verify)")
	keys := fs.String("keys-dir", "", "directory with the public keys (default: the keys compiled in)")
	repo := fs.String("repo", ".", "repository root (the tag is looked up there)")
	doRun := fs.Bool("run", false, "run the gh commands (default: print them)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	trust, err := LoadTrust(*keys)
	if err != nil {
		return err
	}
	// What is uploaded is what the box's verifier passes, checked again here, not only by the earlier release-verify.
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
	p, err := planPublish(*dir, s, inputs)
	if err != nil {
		return err
	}
	return Publish(ctx, execRun, *repo, p, *doRun, stdout)
}
