package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec" //nolint:depguard // release helper outside the product: fixed argv (podman, git, gh), no shell
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/internal/release"
)

// The release job's registry and GitHub steps (WP-08k, D-457): push the manifest lists of `make images` by digest and record them
// (images.json), turn that into the release description (release.in.json), and publish the signed documents and packages as
// GitHub release assets. Every external command is a fixed argv through runFunc; the tests replace it.

// runFunc runs one command with a fixed argv (no shell) and returns its standard output.
type runFunc func(ctx context.Context, argv ...string) ([]byte, error)

// execRun is the real runFunc. The environment is inherited: podman reads its registry login and gh its token from there, and
// neither ever appears in argv.
func execRun(ctx context.Context, argv ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // fixed argv built by this file; values validated before
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		name := argv[0]
		if len(argv) > 2 {
			name += " " + argv[1] + " " + argv[2]
		}
		return out, fmt.Errorf("%s: %w%s", name, err, tail(stderr.String()))
	}
	return out, nil
}

// publishedImages are the manifest lists `make images` builds (localhost/vedette-<local>:<version>) and the service each one is
// published as (release.Services). scan-base is published as vedette-scan: the box builds its scan image FROM it (D-147), and
// the manifest, cosign identity and vedette.env all name it "scan".
var publishedImages = []struct{ local, service string }{
	{"core", "core"}, {"sensor", "sensor"}, {"scan-base", "scan"}, {"honeypot", "honeypot"},
}

// realRegistry is the one registry a release is pushed to (D-104 (1)).
var realRegistry = strings.TrimSuffix(release.RegistryPrefix, "/vedette-")

// ImagesDoc is dist/release/images.json: what was pushed, by digest. cosign-plan/attest (part C) and `release in` read it.
type ImagesDoc struct {
	Version string        `json:"version"`
	Images  []PushedImage `json:"images"`
}

// PushedImage is one pushed manifest list: the index digest the registry returned for it, and the digest of each platform.
type PushedImage struct {
	Service     string           `json:"service"`
	Repo        string           `json:"repo"`
	IndexDigest string           `json:"index_digest"`
	Platforms   []PlatformDigest `json:"platforms"`
}

// PlatformDigest is one platform of a manifest list.
type PlatformDigest struct {
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
}

const imagesFile = "images.json"

var (
	registryRE = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]{1,5})?(/[a-z0-9._-]+)*$`)
	platformRE = regexp.MustCompile(`^linux/(amd64|arm64)$`)
)

// loopbackRegistry says whether reg is a registry on this machine (127.0.0.1, ::1 or localhost, any port): the rehearsal. Only
// there are TLS verification and the release guards off.
func loopbackRegistry(reg string) bool {
	host := strings.SplitN(reg, "/", 2)[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// pushOpts says what `release push` does.
type pushOpts struct {
	Version   string
	Registry  string
	Platforms []string
	Repo      string // git repository root
	Out       string // directory images.json is written to
}

// listIndex is the part of a manifest list (OCI index or Docker list) the push reads, as `podman manifest inspect` prints it.
type listIndex struct {
	MediaType string `json:"mediaType"`
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"manifests"`
}

// platformDigests parses a manifest list and returns its platforms and digests, sorted by platform. It refuses a document that is
// not a list, a malformed digest, a platform listed twice, and any set of platforms other than want.
func platformDigests(raw []byte, want []string, what string) ([]PlatformDigest, error) {
	var x listIndex
	if err := json.Unmarshal(raw, &x); err != nil {
		return nil, fmt.Errorf("%s: not a manifest list: %w", what, err)
	}
	switch x.MediaType {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
	default:
		return nil, fmt.Errorf("%s: media type %q is not a manifest list: make images builds one list per image (D-158)", what, x.MediaType)
	}
	var got []PlatformDigest
	for _, m := range x.Manifests {
		p := m.Platform.OS + "/" + m.Platform.Architecture
		if m.Platform.Variant != "" {
			p += "/" + m.Platform.Variant
		}
		if !serviceDigestRE.MatchString(m.Digest) {
			return nil, fmt.Errorf("%s: malformed digest %q for %s", what, m.Digest, p)
		}
		if slices.ContainsFunc(got, func(g PlatformDigest) bool { return g.Platform == p }) {
			return nil, fmt.Errorf("%s: platform %s is listed twice", what, p)
		}
		got = append(got, PlatformDigest{Platform: p, Digest: m.Digest})
	}
	slices.SortFunc(got, func(a, b PlatformDigest) int { return strings.Compare(a.Platform, b.Platform) })
	have := make([]string, len(got))
	for i, g := range got {
		have[i] = g.Platform
	}
	w := slices.Clone(want)
	slices.Sort(w)
	if !slices.Equal(have, w) {
		return nil, fmt.Errorf("%s: platforms %v, want %v", what, have, w)
	}
	return got, nil
}

// localList prints a manifest list of local storage. `podman manifest inspect` alone falls back to a registry when the name is not
// local (it then dials https://localhost for a localhost/ name), so `manifest exists` asks first.
func localList(ctx context.Context, run runFunc, name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := run(ctx, "podman", "manifest", "exists", name); err != nil {
		return nil, fmt.Errorf("%s: no local manifest list (make images IMAGE_TAG=<version> IMAGE_VERSION=<version>): %w", name, err)
	}
	return run(ctx, "podman", "manifest", "inspect", name)
}

// checkReleaseTree refuses to push from a tree with uncommitted changes to tracked files, or from a commit that is not v<version>:
// the images were built from this tree, and what is pushed under a release version must be that tag (kien tags it, D-457).
func checkReleaseTree(ctx context.Context, run runFunc, repo, version string) error {
	out, err := run(ctx, "git", "-C", repo, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		return fmt.Errorf("the tree has uncommitted changes (a release is its commit):\n%s", s)
	}
	head, err := run(ctx, "git", "-C", repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	tag, err := run(ctx, "git", "-C", repo, "rev-parse", "--verify", "--quiet", "refs/tags/v"+version+"^{commit}")
	if err != nil {
		return fmt.Errorf("no tag v%s here: kien tags the release commit by hand before images are pushed (AI creates no tag): %w", version, err)
	}
	if strings.TrimSpace(string(head)) != strings.TrimSpace(string(tag)) {
		return fmt.Errorf("HEAD %s is not v%s (%s): build and push the images from the tagged commit", strings.TrimSpace(string(head)), version, strings.TrimSpace(string(tag)))
	}
	return nil
}

// Push pushes every manifest list of publishedImages to the registry by digest, reads each back and returns what was pushed.
// The version tag is pushed too, as a convenience for people; nothing downstream reads it, and it must resolve to the same list.
func Push(ctx context.Context, run runFunc, o pushOpts, stdout io.Writer) (*ImagesDoc, error) {
	if _, err := release.CompareVersions(o.Version, o.Version); err != nil {
		return nil, fmt.Errorf("version %q is not SemVer (no v, no build metadata)", o.Version)
	}
	if !registryRE.MatchString(o.Registry) {
		return nil, fmt.Errorf("registry %q is malformed", o.Registry)
	}
	rehearsal := loopbackRegistry(o.Registry)
	if o.Registry != realRegistry && !rehearsal {
		return nil, fmt.Errorf("registry %q: a release is pushed to %s only (the box pulls nothing else, D-104); a rehearsal uses a registry on 127.0.0.1", o.Registry, realRegistry)
	}
	if len(o.Platforms) == 0 {
		return nil, errors.New("no platforms")
	}
	for _, p := range o.Platforms {
		if !platformRE.MatchString(p) {
			return nil, fmt.Errorf("platform %q: a release is built for linux/amd64 and linux/arm64", p)
		}
	}
	if rehearsal {
		say(stdout, "rehearsal: %s is on this machine; TLS verification, the -test. refusal and the git checks are off", o.Registry)
	} else {
		if err := refuseTestVersion(o.Version); err != nil {
			return nil, err
		}
		if err := checkReleaseTree(ctx, run, o.Repo, o.Version); err != nil {
			return nil, err
		}
	}
	var tls []string
	if rehearsal {
		tls = []string{"--tls-verify=false"}
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil { //nolint:gosec // build output, not secret
		return nil, err
	}
	doc := &ImagesDoc{Version: o.Version}
	for _, im := range publishedImages {
		local := "localhost/vedette-" + im.local + ":" + o.Version
		repo := o.Registry + "/vedette-" + im.service
		short := func(ctx context.Context, argv ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			return run(ctx, argv...)
		}
		raw, err := localList(ctx, run, local)
		if err != nil {
			return nil, err
		}
		if _, err := platformDigests(raw, o.Platforms, local); err != nil {
			return nil, err
		}
		dfile, err := os.CreateTemp(o.Out, ".digest-*")
		if err != nil {
			return nil, err
		}
		_ = dfile.Close()
		dpath := dfile.Name()
		pctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		argv := append(append([]string{"podman", "manifest", "push", "--all", "--quiet"}, tls...), "--digestfile", dpath, local, "docker://"+repo+":"+o.Version)
		_, err = run(pctx, argv...)
		cancel()
		dig, rerr := os.ReadFile(dpath) //nolint:gosec // the temporary file made above
		_ = os.Remove(dpath)
		if err != nil {
			return nil, fmt.Errorf("push %s: %w", repo, err)
		}
		digest := strings.TrimSpace(string(dig))
		if rerr != nil || !serviceDigestRE.MatchString(digest) {
			return nil, fmt.Errorf("push %s: podman wrote no digest (%q)", repo, digest)
		}
		// Read back by digest: podman refuses a manifest whose bytes do not hash to the digest asked for ("Manifest does not match
		// provided manifest digest", measured with podman 5.7, D-457), so a list read here is the one the boxes will pull.
		raw, err = short(ctx, append(append([]string{"podman", "manifest", "inspect"}, tls...), repo+"@"+digest)...)
		if err != nil {
			return nil, fmt.Errorf("read back %s@%s: %w", repo, digest, err)
		}
		plats, err := platformDigests(raw, o.Platforms, repo+"@"+digest)
		if err != nil {
			return nil, err
		}
		raw, err = short(ctx, append(append([]string{"podman", "manifest", "inspect"}, tls...), repo+":"+o.Version)...)
		if err != nil {
			return nil, fmt.Errorf("read back %s:%s: %w", repo, o.Version, err)
		}
		byTag, err := platformDigests(raw, o.Platforms, repo+":"+o.Version)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(byTag, plats) {
			return nil, fmt.Errorf("%s:%s does not name the list just pushed (%s): another push of this version?", repo, o.Version, digest)
		}
		doc.Images = append(doc.Images, PushedImage{Service: im.service, Repo: repo, IndexDigest: digest, Platforms: plats})
		say(stdout, "pushed %s@%s (%s)", repo, digest, strings.Join(o.Platforms, ", "))
	}
	return doc, nil
}

func cmdPush(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("push")
	version := fs.String("version", "", "release version (SemVer, no v); the local lists are localhost/vedette-<image>:<version>")
	reg := fs.String("registry", realRegistry, "registry and namespace; anything but "+realRegistry+" must be on 127.0.0.1 (a rehearsal)")
	plats := fs.String("platforms", "linux/amd64,linux/arm64", "platforms every list must hold, comma separated (PLATFORMS of make images)")
	out := fs.String("out", "dist/release", "directory images.json is written to")
	repo := fs.String("repo", ".", "repository root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doc, err := Push(ctx, execRun, pushOpts{Version: *version, Registry: *reg, Platforms: strings.Split(*plats, ","), Repo: *repo, Out: *out}, stdout)
	if err != nil {
		return err
	}
	b, err := marshal(doc)
	if err != nil {
		return err
	}
	p := filepath.Join(*out, imagesFile)
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // build output, not secret
		return err
	}
	say(stdout, "wrote %s", p)
	return nil
}

// readImages reads images.json strictly and checks it is a release's: every image of publishedImages once, in the real registry,
// with well-formed digests.
func readImages(p string) (*ImagesDoc, error) {
	raw, err := readSmall(p, 1<<20)
	if err != nil {
		return nil, err
	}
	var d ImagesDoc
	if err := jsonstrict.Decode(raw, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if len(d.Images) != len(publishedImages) {
		return nil, fmt.Errorf("%s lists %d images, a release has %d", p, len(d.Images), len(publishedImages))
	}
	for _, im := range d.Images {
		if !slices.ContainsFunc(publishedImages, func(pi struct{ local, service string }) bool { return pi.service == im.Service }) {
			return nil, fmt.Errorf("%s: unknown service %q", p, im.Service)
		}
		if n := len(slices.DeleteFunc(slices.Clone(d.Images), func(o PushedImage) bool { return o.Service != im.Service })); n != 1 {
			return nil, fmt.Errorf("%s: service %s is listed %d times", p, im.Service, n)
		}
		if im.Repo != release.RegistryPrefix+im.Service {
			return nil, fmt.Errorf("%s: %s was pushed to %s, not %s%s (a rehearsal's images.json is not a release's)", p, im.Service, im.Repo, release.RegistryPrefix, im.Service)
		}
		if !serviceDigestRE.MatchString(im.IndexDigest) || len(im.Platforms) == 0 {
			return nil, fmt.Errorf("%s: %s has a malformed index digest or no platform", p, im.Service)
		}
		for _, pl := range im.Platforms {
			if !platformRE.MatchString(pl.Platform) || !serviceDigestRE.MatchString(pl.Digest) {
				return nil, fmt.Errorf("%s: %s has a malformed platform %q or digest", p, im.Service, pl.Platform)
			}
		}
	}
	return &d, nil
}

// localImageSizes returns, for each service, the largest unpacked size of its platforms in the local lists of `make images`:
// images[].size of the manifest, used by the box only for its free-space check (low_disk below 2 x size, D-104) and never compared
// with what it downloads. The registry digests differ from the local ones (layers are compressed on push), so the size comes from
// the platforms of the local list, which must be the platforms that were pushed.
func localImageSizes(ctx context.Context, run runFunc, doc *ImagesDoc) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	raw, err := run(ctx, "podman", "images", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}
	type localImage struct {
		Digest string `json:"Digest"`
		Size   int64  `json:"Size"`
	}
	var all []localImage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("podman images: %w", err)
	}
	sizes := map[string]int64{}
	for _, im := range doc.Images {
		local := ""
		for _, pi := range publishedImages {
			if pi.service == im.Service {
				local = "localhost/vedette-" + pi.local + ":" + doc.Version
			}
		}
		want := make([]string, len(im.Platforms))
		for i, p := range im.Platforms {
			want[i] = p.Platform
		}
		raw, err := localList(ctx, run, local)
		if err != nil {
			return nil, fmt.Errorf("the size of each image is read from the local lists of make images: %w", err)
		}
		plats, err := platformDigests(raw, want, local)
		if err != nil {
			return nil, err
		}
		for _, p := range plats {
			i := slices.IndexFunc(all, func(a localImage) bool { return a.Digest == p.Digest })
			if i < 0 || all[i].Size <= 0 {
				return nil, fmt.Errorf("%s: no local image %s for %s", local, p.Digest, p.Platform)
			}
			sizes[im.Service] = max(sizes[im.Service], all[i].Size)
		}
	}
	return sizes, nil
}

// inputsOpts are the parts of release.in.json that cannot be measured: the maintainer gives them, nothing is guessed.
type inputsOpts struct {
	Channel        string
	RollbackSafe   string // "true" or "false", required
	RollbackMin    string
	MinUpgradeFrom string
	DebDir         string
}

// BuildInputs writes the release description from what was pushed and built: the images of images.json with their index digests,
// platforms and local sizes; the two vedette-host packages; install_modes appliance and container (D-451); released_at empty (the
// builder fills it). Channel and rollback come from the maintainer.
func BuildInputs(ctx context.Context, run runFunc, doc *ImagesDoc, o inputsOpts) (Inputs, error) {
	var in Inputs
	if _, err := release.CompareVersions(doc.Version, doc.Version); err != nil {
		return in, fmt.Errorf("version %q is not SemVer", doc.Version)
	}
	if err := refuseTestVersion(doc.Version); err != nil {
		return in, err
	}
	if o.Channel != "stable" && o.Channel != "beta" {
		return in, fmt.Errorf("channel must be stable or beta (RELEASE_CHANNEL), got %q", o.Channel)
	}
	var safe bool
	switch o.RollbackSafe {
	case "true":
		safe = true
		if o.RollbackMin == "" {
			return in, errors.New("rollback.safe=true needs rollback.min_version (RELEASE_ROLLBACK_MIN): the oldest release a box may roll back to")
		}
	case "false":
	default:
		return in, fmt.Errorf("say whether a box may roll back across this release: RELEASE_ROLLBACK_SAFE=true or false (got %q); the builder proves true from the migrations (D-183)", o.RollbackSafe)
	}
	for _, v := range []string{o.RollbackMin, o.MinUpgradeFrom} {
		if v == "" {
			continue
		}
		if _, err := release.CompareVersions(v, doc.Version); err != nil {
			return in, fmt.Errorf("version %q is not SemVer", v)
		}
	}
	sizes, err := localImageSizes(ctx, run, doc)
	if err != nil {
		return in, err
	}
	in = Inputs{
		Version: doc.Version, Channel: o.Channel, MinUpgradeFrom: o.MinUpgradeFrom,
		InstallModes: []string{installAppliance, installContainer},
		Rollback:     release.Rollback{Safe: safe, MinVersion: o.RollbackMin},
		Content:      []release.Content{}, Bundled: []release.Bundled{},
	}
	for _, im := range doc.Images {
		ii := ImageIn{Service: im.Service, Digest: im.IndexDigest, Size: sizes[im.Service]}
		for _, p := range im.Platforms {
			ii.Platforms = append(ii.Platforms, p.Platform)
		}
		in.Images = append(in.Images, ii)
	}
	h := HostIn{Version: doc.Version}
	for _, arch := range []string{"amd64", "arm64"} {
		h.Files = append(h.Files, filepath.Join(o.DebDir, release.HostPackageName(doc.Version, arch)))
	}
	if _, err := buildHostPart(h, doc.Version, in.Images); err != nil {
		return in, fmt.Errorf("%w (host-deb writes them to %s; a version with a prerelease needs the SemVer spelling, not nfpm's ~)", err, o.DebDir)
	}
	in.Host = &h
	if err := checkInstallModes(in.InstallModes); err != nil {
		return in, err
	}
	return in, nil
}

func cmdInputs(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("in")
	images := fs.String("images", "dist/release/images.json", "what release push wrote")
	out := fs.String("out", "release.in.json", "release description to write (refused when it exists: it may hold your notes)")
	var o inputsOpts
	fs.StringVar(&o.Channel, "channel", "", "stable or beta (required)")
	fs.StringVar(&o.RollbackSafe, "rollback-safe", "", "true or false (required): may a box roll back across this release (D-183)")
	fs.StringVar(&o.RollbackMin, "rollback-min-version", "", "rollback.min_version: the oldest release a box may roll back to (required with true)")
	fs.StringVar(&o.MinUpgradeFrom, "min-upgrade-from", "", "min_upgrade_from (empty: none)")
	fs.StringVar(&o.DebDir, "deb-dir", "dist", "directory with vedette-host_<version>_<amd64|arm64>.deb")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists: it may hold notes you wrote; remove or rename it first", *out)
	}
	doc, err := readImages(*images)
	if err != nil {
		return err
	}
	in, err := BuildInputs(ctx, execRun, doc, o)
	if err != nil {
		return err
	}
	b, err := marshal(in)
	if err != nil {
		return err
	}
	if _, err := ParseInputs(b); err != nil { // what is written is what manifest reads
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil { //nolint:gosec // a description, not secret
		return err
	}
	say(stdout, "wrote %s (version %s, channel %s, rollback.safe=%s): add the notes, then release-cosign-plan", *out, in.Version, in.Channel, o.RollbackSafe)
	return nil
}
