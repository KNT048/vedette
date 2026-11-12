package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

// The container-only install (D-168, D-451): every release that lists install mode "container" publishes these four files of
// deploy/compose/container-only/, each with a .minisig signed by the key that signs the manifest. The compose files are copied
// unchanged; vedette.env gets its three image lines filled and nothing else. The customer fetches and checks all four on every
// update (docs/INSTALL-CONTAINER.md section 5), so a release that changes a compose file reaches them.
var containerAssets = []string{"compose.yaml", "compose.sensors.yaml", "compose.syslog.yaml", "vedette.env"}

const (
	containerEnv       = "vedette.env"
	containerComposeIn = "deploy/compose/container-only"
	installAppliance   = "appliance"
	installContainer   = "container"
)

// containerImageKeys are the image lines of vedette.env and the service each one names (compose.yaml, compose.sensors.yaml).
var containerImageKeys = []struct{ key, service string }{
	{"VEDETTE_CORE_IMAGE", "core"}, {"VEDETTE_SENSOR_IMAGE", "sensor"}, {"VEDETTE_SCAN_IMAGE", "scan"},
}

// containerImageRE is the one form an image value of vedette.env may take (L5): fixed registry, digest only, never ":tag@". The
// Updates page checks the downloaded vedette.env with `grep -cF` for exactly this text (matchCmd in web/src/features/core/ContainerOnly.tsx).
var containerImageRE = regexp.MustCompile(`^ghcr\.io/knt048/vedette-(core|sensor|scan)@sha256:[0-9a-f]{64}$`)

// anyImageLineRE catches an image line of the template the builder does not know (a fourth service added to compose without the builder).
var anyImageLineRE = regexp.MustCompile(`^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*_IMAGE\s*=`)

// checkInstallModes refuses what internal/release refuses later on the box (an empty list, a value other than appliance and
// container, a repeat), so the maintainer hears it from the builder.
func checkInstallModes(modes []string) error {
	if len(modes) == 0 {
		return errors.New(`install_modes is empty: list "appliance" and "container" (D-451)`)
	}
	for i, m := range modes {
		if m != installAppliance && m != installContainer {
			return fmt.Errorf("install_modes: unknown mode %q (appliance, container)", m)
		}
		if slices.Contains(modes[:i], m) {
			return fmt.Errorf("install_modes: %q is listed twice", m)
		}
	}
	return nil
}

// BuildContainerAssets turns the four files of the repository (src, by name) into the release's (D-451). It refuses:
//   - install_modes that are empty, unknown, or without "container" (the assets would be published for a release no container
//     install is offered);
//   - a missing file, one that does not start with a "#" comment line (nothing signed with the release key may look like a JSON
//     document or a content statement), or one larger than a signed document may be;
//   - a release without the core, sensor or scan image, or with a malformed digest;
//   - a vedette.env whose three image lines are not there exactly once and empty, or that has another *_IMAGE= line;
//   - any value that is not ghcr.io/knt048/vedette-<service>@sha256:<64 hex>, and any change to a line other than those three.
func BuildContainerAssets(in Inputs, src map[string][]byte) (map[string][]byte, error) {
	if err := checkInstallModes(in.InstallModes); err != nil {
		return nil, err
	}
	if !slices.Contains(in.InstallModes, installContainer) {
		return nil, errors.New(`install_modes does not list "container": no container-only install would be offered this release, so its compose files are not published (D-451)`)
	}
	out := map[string][]byte{}
	for _, n := range containerAssets {
		b, ok := src[n]
		if !ok {
			return nil, fmt.Errorf("%s is missing", n)
		}
		if len(b) == 0 || b[0] != '#' {
			return nil, fmt.Errorf("%s must start with a # comment line: a file signed with the release key must not look like a JSON document", n)
		}
		if len(b) > release.MaxDocBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", n, release.MaxDocBytes)
		}
		out[n] = bytes.Clone(b)
	}
	digest := map[string]string{}
	for _, im := range in.Images {
		digest[im.Service] = im.Digest
	}
	lines := strings.Split(string(src[containerEnv]), "\n")
	filled := slices.Clone(lines)
	seen := map[string]bool{}
	for i, l := range lines {
		k := slices.IndexFunc(containerImageKeys, func(c struct{ key, service string }) bool { return strings.HasPrefix(l, c.key+"=") })
		if k < 0 {
			if anyImageLineRE.MatchString(l) {
				return nil, fmt.Errorf("vedette.env line %d %q is an image line the builder does not fill (only %s)", i+1, l, imageKeyList())
			}
			continue
		}
		c := containerImageKeys[k]
		if seen[c.key] {
			return nil, fmt.Errorf("vedette.env has %s twice", c.key)
		}
		seen[c.key] = true
		if l != c.key+"=" {
			return nil, fmt.Errorf("vedette.env line %d: %s must be empty in the repository (a release fills it), got %q", i+1, c.key, l)
		}
		d, ok := digest[c.service]
		if !ok {
			return nil, fmt.Errorf("the release has no %s image: a container-only install runs core, sensor and scan", c.service)
		}
		if !serviceDigestRE.MatchString(d) {
			return nil, fmt.Errorf("image %s: malformed digest %q (need sha256: and 64 lower-case hex)", c.service, d)
		}
		v := release.RegistryPrefix + c.service + "@" + d
		if !containerImageRE.MatchString(v) {
			return nil, fmt.Errorf("%s=%s is not ghcr.io/knt048/vedette-%s@sha256:<64 hex>", c.key, v, c.service)
		}
		filled[i] = c.key + "=" + v
	}
	for _, c := range containerImageKeys {
		if !seen[c.key] {
			return nil, fmt.Errorf("vedette.env has no %s= line", c.key)
		}
	}
	// What changed is exactly the three image lines: checked on the result, not assumed from the loop above.
	for i := range lines {
		if filled[i] != lines[i] && !slices.ContainsFunc(containerImageKeys, func(c struct{ key, service string }) bool { return lines[i] == c.key+"=" }) {
			return nil, fmt.Errorf("vedette.env line %d would change: %q", i+1, lines[i])
		}
	}
	out[containerEnv] = []byte(strings.Join(filled, "\n"))
	return out, nil
}

func imageKeyList() string {
	var k []string
	for _, c := range containerImageKeys {
		k = append(k, c.key)
	}
	return strings.Join(k, ", ")
}

// cmdContainerAssets: container-assets -in release.in.json -out dist/release [-ref v<version>] [-repo .] [-compose-dir DIR].
// The files are read from git at the release's tag, like the migrations of `manifest`: what is tagged is what ships, never an
// edit left in the working tree.
func cmdContainerAssets(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("container-assets")
	in := fs.String("in", "release.in.json", "release description")
	out := fs.String("out", "dist/release", "output directory (the one release-sign signs)")
	ref := fs.String("ref", "", "git ref the files are read at (default v<version>)")
	repo := fs.String("repo", ".", "repository root")
	dir := fs.String("compose-dir", containerComposeIn, "directory of the four files inside the repository")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs, err := readInputs(*in)
	if err != nil {
		return err
	}
	if *ref == "" {
		*ref = "v" + inputs.Version
	}
	src, err := gitFiles(ctx, *repo, *ref, *dir, containerAssets)
	if err != nil {
		return err
	}
	files, err := BuildContainerAssets(inputs, src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // build output, not secret
		return err
	}
	for _, n := range containerAssets {
		p := filepath.Join(*out, n)
		if err := os.WriteFile(p, files[n], 0o644); err != nil { //nolint:gosec // build output, not secret
			return err
		}
		say(stdout, "wrote %s", p)
	}
	return nil
}

var repoPathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

// gitFiles reads dir/<name> of each name at ref, with git (fixed argv, no shell).
func gitFiles(ctx context.Context, repo, ref, dir string, names []string) (map[string][]byte, error) {
	if !gitRefRE.MatchString(ref) || strings.Contains(ref, "..") {
		return nil, fmt.Errorf("git ref %q is not a plain tag, branch or commit name", ref)
	}
	dir = strings.TrimSuffix(dir, "/")
	if !repoPathRE.MatchString(dir) || strings.Contains(dir, "..") {
		return nil, fmt.Errorf("-compose-dir %q is not a plain path inside the repository", dir)
	}
	src := map[string][]byte{}
	for _, n := range names {
		b, err := gitRun(ctx, repo, "show", ref+":"+path.Join(dir, n))
		if err != nil {
			return nil, fmt.Errorf("%s at %s: %w", n, ref, err)
		}
		src[n] = b
	}
	return src, nil
}

// containerAssetComment is the trusted comment of an asset's signature: the file and the release, which `minisign -V` prints, so
// the customer sees a signed file of another release for what it is.
func containerAssetComment(name, version string) string {
	return "file:" + name + " version:" + version
}

// containerAssetsToSign lists the assets of dir that SignRelease signs, with their trusted comments: all four or none, and only
// next to a manifest (whose version they carry).
func containerAssetsToSign(dir string) (paths []string, comments map[string]string, err error) {
	var have []string
	for _, n := range containerAssets {
		switch _, err := os.Lstat(filepath.Join(dir, n)); {
		case err == nil:
			have = append(have, n)
		case !errors.Is(err, os.ErrNotExist):
			return nil, nil, err
		}
	}
	if len(have) == 0 {
		return nil, nil, nil
	}
	if len(have) != len(containerAssets) {
		return nil, nil, fmt.Errorf("%s holds %s but not all of %s: run release container-assets again", dir, strings.Join(have, ", "), strings.Join(containerAssets, ", "))
	}
	raw, err := readDoc(filepath.Join(dir, manifestFile))
	if err != nil {
		return nil, nil, fmt.Errorf("container assets are signed with the version of the manifest next to them: %w", err)
	}
	tc, err := trustedComment(manifestFile, raw)
	if err != nil {
		return nil, nil, err
	}
	version := strings.TrimPrefix(tc, "file:"+manifestFile+" version:")
	comments = map[string]string{}
	for _, n := range containerAssets {
		p := filepath.Join(dir, n)
		paths = append(paths, p)
		comments[p] = containerAssetComment(n, version)
	}
	return paths, comments, nil
}

// verifyContainerAssets is VerifyDir's check of the assets (D-451): a manifest that lists "container" must have all four, each
// signed by the key that signed the manifest with the trusted comment of this release, and vedette.env must name exactly the
// manifest's core, sensor and scan digests; a manifest without "container" must have none. It returns whether they were there.
func verifyContainerAssets(dir string, m *release.Manifest, trust release.Trust) (bool, error) {
	if !slices.Contains(m.InstallModes, installContainer) {
		for _, n := range containerAssets {
			if _, err := os.Lstat(filepath.Join(dir, n)); !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("%s is here but the manifest does not list install mode container", n)
			}
		}
		return false, nil
	}
	for _, n := range containerAssets {
		raw, sig, err := readSigned(filepath.Join(dir, n))
		if err != nil {
			return false, fmt.Errorf("the manifest lists install mode container, so every release publishes %s and its signature (make release-container-assets): %w", n, err)
		}
		if err := release.VerifyContent(raw, sig, trust); err != nil {
			return false, fmt.Errorf("%s: %w", n, err)
		}
		tc, keyID, err := minisigCommentAndKey(sig, trust)
		if err != nil {
			return false, fmt.Errorf("%s: %w", n, err)
		}
		if keyID != m.KeyID {
			return false, fmt.Errorf("%s is signed by %s, the manifest by %s", n, keyID, m.KeyID)
		}
		if want := containerAssetComment(n, m.Version); tc != want {
			return false, fmt.Errorf("%s: trusted comment %q, want %q", n, tc, want)
		}
		if n == containerEnv {
			if err := checkEnvImages(raw, m); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}

// checkEnvImages: each of the three image lines is there once and equals the manifest's pull reference of that service.
func checkEnvImages(raw []byte, m *release.Manifest) error {
	for _, c := range containerImageKeys {
		im, ok := m.Image(c.service)
		if !ok {
			return fmt.Errorf("the manifest has no %s image, which a container-only install runs", c.service)
		}
		want := c.key + "=" + release.RegistryPrefix + c.service + "@" + im.Digest
		n := 0
		for _, l := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(l, c.key+"=") {
				n++
				if l != want || !containerImageRE.MatchString(strings.TrimPrefix(l, c.key+"=")) {
					return fmt.Errorf("vedette.env: %q, want %q", l, want)
				}
			}
		}
		if n != 1 {
			return fmt.Errorf("vedette.env has %d %s lines, want 1", n, c.key)
		}
	}
	return nil
}

// minisigCommentAndKey reads the trusted comment and the signer of a .minisig that release.VerifyContent has just accepted (the
// same four-line layout it parsed, so these are the bytes it verified).
func minisigCommentAndKey(sig []byte, trust release.Trust) (comment, keyID string, err error) {
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	const trusted = "trusted comment: "
	if len(lines) != 4 || !strings.HasPrefix(lines[2], trusted) {
		return "", "", errors.New("signature file layout")
	}
	b, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(b) < 10 {
		return "", "", errors.New("signature encoding")
	}
	var id [8]byte
	copy(id[:], b[2:10])
	for _, k := range []release.MinisignKey{trust.Active, trust.Backup} {
		if k.ID == id {
			return strings.TrimPrefix(lines[2], trusted), k.KeyID(), nil
		}
	}
	return "", "", errors.New("signed by a key that is neither the active nor the backup key")
}
