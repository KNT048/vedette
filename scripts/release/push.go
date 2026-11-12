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
	"syscall"
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
// neither ever appears in argv. The command runs in its own process group, and a cancel or timeout of ctx kills the whole group: the
// go build and nfpm under `make host-deb` (gates' rebuild) die with it (Linux and macOS; Windows is not a release machine).
func execRun(ctx context.Context, argv ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // fixed argv built by this file; values validated before
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone // the group is already gone: like Process.Kill, Wait keeps the command's own status
		}
		return err
	}
	cmd.WaitDelay = 10 * time.Second // a grandchild holding the stderr pipe open cannot keep Output waiting
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

// PlatformDigest is one platform of a manifest list. Config, in images.json only, is the config digest of the platform image that
// was pushed (the local image ID; a push does not change it): part C attests to Digest only the SBOM trivy made of that image.
type PlatformDigest struct {
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
	Config   string `json:"config,omitempty"`
}

const imagesFile = "images.json"

var (
	registryRE = regexp.MustCompile(`^(\[::1\]|[a-z0-9.-]+)(:[0-9]{1,5})?(/[a-z0-9._-]+)*$`)
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
	Gates     string // gates.json of `release gates` (step 3): only the platform images it checked are pushed
	// HTTP reads an existing remote list anonymously (registryBase of Registry; a test points it at httptest).
	HTTP registryHTTP
}

// versionLabel is the label every Containerfile sets from VERSION (make images IMAGE_VERSION=...).
const versionLabel = "org.opencontainers.image.version"

// localPlatform is one platform of a local manifest list: its manifest digest, its image ID (the config digest), its size and its
// version and floor labels, from `podman images --all --format json`.
type localPlatform struct {
	Platform, Digest, Config, Version, MinSequence string
	Size                                           int64
}

// localPlatforms reads a local manifest list and the local image of each of its platforms; the platforms must be want.
func localPlatforms(ctx context.Context, run runFunc, name string, want []string) ([]localPlatform, error) {
	raw, err := localList(ctx, run, name)
	if err != nil {
		return nil, err
	}
	plats, err := platformDigests(raw, want, name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := run(ctx, "podman", "images", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}
	type podmanImage struct {
		ID     string            `json:"Id"`
		Digest string            `json:"Digest"`
		Size   int64             `json:"Size"`
		Labels map[string]string `json:"Labels"`
	}
	var all []podmanImage
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, fmt.Errorf("podman images: %w", err)
	}
	var res []localPlatform
	for _, p := range plats {
		i := slices.IndexFunc(all, func(a podmanImage) bool { return a.Digest == p.Digest })
		if i < 0 || !serviceDigestRE.MatchString("sha256:"+all[i].ID) || all[i].Size <= 0 {
			return nil, fmt.Errorf("%s: no local image %s for %s", name, p.Digest, p.Platform)
		}
		res = append(res, localPlatform{Platform: p.Platform, Digest: p.Digest, Config: "sha256:" + all[i].ID, Version: all[i].Labels[versionLabel], MinSequence: all[i].Labels[minSequenceLabel], Size: all[i].Size})
	}
	return res, nil
}

// absentRemote says whether a podman read error means the registry has no such manifest (as opposed to a login or network error).
func absentRemote(err error) bool {
	s := err.Error()
	return strings.Contains(s, "manifest unknown") || strings.Contains(s, "name unknown")
}

// sameRemote compares a list that already exists in the registry under repo:<version> with the local one, platform by platform, by
// config digest (the image content; the manifest digests differ because layers are compressed on push). It returns the remote
// index digest when they are the same images, and refuses when they are not: a pushed version is never replaced (D-457).
func sameRemote(ctx context.Context, h registryHTTP, repoPath, version string, local []localPlatform, want []string) (string, error) {
	raw, err := h.manifest(ctx, "GET", repoPath, version, acceptList)
	if err != nil {
		return "", fmt.Errorf("%s:%s is already in the registry and cannot be compared (%w): make the package public (plan §3) or delete that version, then run again", repoPath, version, err)
	}
	plats, err := platformDigests(raw, want, repoPath+":"+version)
	if err != nil {
		return "", err
	}
	for i, p := range plats {
		m, err := h.manifest(ctx, "GET", repoPath, p.Digest, acceptImage)
		if err != nil {
			return "", err
		}
		cfg, err := configDigest(m)
		if err != nil {
			return "", fmt.Errorf("%s@%s: %w", repoPath, p.Digest, err)
		}
		if cfg != local[i].Config {
			return "", fmt.Errorf("%s:%s is already in the registry with other images (%s config %s, local %s): a pushed version is never replaced; release the next version", repoPath, version, p.Platform, cfg, local[i].Config)
		}
	}
	return digestBytes(raw), nil
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
	if err := refuseTestVersion(o.Version); err != nil { // a rehearsal too: it pushes a real version the gates passed
		return nil, err
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
	gates, err := readGates(o.Gates)
	if err != nil {
		return nil, err
	}
	if err := gates.checkVersion(o.Version); err != nil {
		return nil, err
	}
	if rehearsal {
		// Linux only: podman on macOS runs in a VM (podman machine), whose 127.0.0.1 is not the Mac's.
		say(stdout, "rehearsal: %s is on this machine; TLS verification and the git checks are off", o.Registry)
	} else if err := checkReleaseTree(ctx, run, o.Repo, o.Version); err != nil {
		return nil, err
	}
	var tls []string
	if rehearsal {
		tls = []string{"--tls-verify=false"}
	}
	// Every list is read and compared with the gates record before anything is pushed: a make images after the gates is refused
	// whole, not after the first lists are in the registry.
	lps := make([][]localPlatform, len(publishedImages))
	for i, im := range publishedImages {
		local := "localhost/vedette-" + im.local + ":" + o.Version
		lp, err := localPlatforms(ctx, run, local, o.Platforms)
		if err != nil {
			return nil, err
		}
		now := map[string]string{}
		for _, p := range lp {
			// what B's gate checks too, here per platform of exactly the list being pushed
			if p.Version != o.Version {
				return nil, fmt.Errorf("%s %s has label %s=%q, not %s: build with make images IMAGE_VERSION=%s", local, p.Platform, versionLabel, p.Version, o.Version, o.Version)
			}
			now[p.Platform] = p.Config
		}
		if err := gates.checkImage(im.service, local, now); err != nil {
			return nil, err
		}
		lps[i] = lp
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil { //nolint:gosec // build output, not secret
		return nil, err
	}
	doc := &ImagesDoc{Version: o.Version}
	_, ns := registryBase(o.Registry)
	short := func(ctx context.Context, argv ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return run(ctx, argv...)
	}
	for n, im := range publishedImages {
		local := "localhost/vedette-" + im.local + ":" + o.Version
		repo := o.Registry + "/vedette-" + im.service
		repoPath := strings.TrimPrefix(ns+"/vedette-"+im.service, "/")
		lp := lps[n]
		// podman resolves a name to local storage first: with a local image of the remote name the read-back below would read it,
		// not the registry (podman manifest inspect has no docker:// form, measured with 5.7). Refuse instead.
		if _, err := short(ctx, "podman", "image", "exists", repo+":"+o.Version); err == nil {
			return nil, fmt.Errorf("a local image is named %s:%s: remove it (podman rmi or podman manifest rm) so the read-back reads the registry", repo, o.Version)
		}
		var digest string
		switch _, err := short(ctx, append(append([]string{"podman", "manifest", "inspect"}, tls...), repo+":"+o.Version)...); {
		case err == nil:
			// a re-run after a failed push, or a version pushed before: the same images are reused, other images are refused
			if digest, err = sameRemote(ctx, o.HTTP, repoPath, o.Version, lp, o.Platforms); err != nil {
				return nil, err
			}
			say(stdout, "%s:%s is already in the registry with these images: not pushed again", repo, o.Version)
		case absentRemote(err):
			if digest, err = pushList(ctx, run, tls, local, repo+":"+o.Version, o.Out); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("does %s:%s exist? %w", repo, o.Version, err)
		}
		// Read back by digest: podman refuses a manifest whose bytes do not hash to the digest asked for ("Manifest does not match
		// provided manifest digest", measured with podman 5.7, D-457), so a list read here is the one the boxes will pull.
		raw, err := short(ctx, append(append([]string{"podman", "manifest", "inspect"}, tls...), repo+"@"+digest)...)
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
		for i := range plats {
			j := slices.IndexFunc(lp, func(l localPlatform) bool { return l.Platform == plats[i].Platform })
			if j < 0 {
				return nil, fmt.Errorf("%s@%s: %s is not a platform of %s", repo, digest, plats[i].Platform, local)
			}
			plats[i].Config = lp[j].Config
		}
		doc.Images = append(doc.Images, PushedImage{Service: im.service, Repo: repo, IndexDigest: digest, Platforms: plats})
		say(stdout, "in the registry and read back: %s@%s (%s)", repo, digest, strings.Join(o.Platforms, ", "))
	}
	return doc, nil
}

// pushList pushes a local list to dest (repo:tag) with every image (--all) and gzip layers (what every podman and Docker on a box
// can pull, whatever the build machine's containers.conf says) and returns the index digest podman writes.
func pushList(ctx context.Context, run runFunc, tls []string, local, dest, tmpDir string) (string, error) {
	dfile, err := os.CreateTemp(tmpDir, ".digest-*")
	if err != nil {
		return "", err
	}
	_ = dfile.Close()
	dpath := dfile.Name()
	defer func() { _ = os.Remove(dpath) }()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	argv := append(append([]string{"podman", "manifest", "push", "--all", "--quiet", "--compression-format=gzip"}, tls...), "--digestfile", dpath, local, "docker://"+dest)
	if _, err := run(ctx, argv...); err != nil {
		return "", fmt.Errorf("push %s: %w", dest, err)
	}
	dig, err := os.ReadFile(dpath) //nolint:gosec // the temporary file made above
	digest := strings.TrimSpace(string(dig))
	if err != nil || !serviceDigestRE.MatchString(digest) {
		return "", fmt.Errorf("push %s: podman wrote no digest (%q)", dest, digest)
	}
	return digest, nil
}

func cmdPush(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("push")
	version := fs.String("version", "", "release version (SemVer, no v); the local lists are localhost/vedette-<image>:<version>")
	reg := fs.String("registry", realRegistry, "registry and namespace; anything but "+realRegistry+" must be on 127.0.0.1 (a rehearsal)")
	plats := fs.String("platforms", "linux/amd64,linux/arm64", "platforms every list must hold, comma separated (PLATFORMS of make images)")
	out := fs.String("out", "dist/release", "directory images.json is written to")
	repo := fs.String("repo", ".", "repository root")
	gates := fs.String("gates", "", "the record of release gates (default <out>/gates.json); refused when missing or when a local image is not the one it checked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *gates == "" {
		*gates = filepath.Join(*out, gatesFile)
	}
	base, _ := registryBase(*reg)
	doc, err := Push(ctx, execRun, pushOpts{Version: *version, Registry: *reg, Platforms: strings.Split(*plats, ","), Repo: *repo, Out: *out, Gates: *gates, HTTP: newRegistryHTTP(base)}, stdout)
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
			if !platformRE.MatchString(pl.Platform) || !serviceDigestRE.MatchString(pl.Digest) || !serviceDigestRE.MatchString(pl.Config) {
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
// The local lists must still be the images the gates checked (and so the ones pushed), or the sizes would be of others.
func localImageSizes(ctx context.Context, run runFunc, doc *ImagesDoc, gates *GatesDoc) (map[string]int64, error) {
	sizes := map[string]int64{}
	for _, im := range doc.Images {
		local := "localhost/vedette-" + localName(im.Service) + ":" + doc.Version
		want := make([]string, len(im.Platforms))
		for i, p := range im.Platforms {
			want[i] = p.Platform
		}
		lp, err := localPlatforms(ctx, run, local, want)
		if err != nil {
			return nil, fmt.Errorf("the size of each image is read from the local lists of make images: %w", err)
		}
		now := map[string]string{}
		for _, p := range lp {
			sizes[im.Service] = max(sizes[im.Service], p.Size)
			now[p.Platform] = p.Config
		}
		if err := gates.checkImage(im.Service, local, now); err != nil {
			return nil, err
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
	Gates          string // gates.json of `release gates`: the .deb and the images must be the ones it checked
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
	gates, err := readGates(o.Gates)
	if err != nil {
		return in, err
	}
	if err := gates.checkVersion(doc.Version); err != nil {
		return in, err
	}
	// images.json records the config digest of each platform pushed: it must be what the gates checked
	for _, im := range doc.Images {
		pushed := map[string]string{}
		for _, p := range im.Platforms {
			pushed[p.Platform] = p.Config
		}
		if err := gates.checkImage(im.Service, "images.json "+im.Service, pushed); err != nil {
			return in, err
		}
	}
	sizes, err := localImageSizes(ctx, run, doc, gates)
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
	hp, err := buildHostPart(h, doc.Version, in.Images)
	if err != nil {
		return in, fmt.Errorf("%w (host-deb writes them to %s; a version with a prerelease needs the SemVer spelling, not nfpm's ~: make release-deb-name)", err, o.DebDir)
	}
	if err := gates.checkHost(hp, h.Files); err != nil {
		return in, err
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
	fs.StringVar(&o.Gates, "gates", "", "the record of release gates (default gates.json next to -images); refused when missing or when a .deb or image is not the one it checked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.Gates == "" {
		o.Gates = filepath.Join(filepath.Dir(*images), gatesFile)
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
