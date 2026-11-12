package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

// The cosign plan (WP-08k step 6, part C of D-457): the exact cosign commands kien runs with the release key, printed and never run
// here. One `cosign sign` per image (the index digest of release.in.json, written to <out>/<service>.{payload.json,sig}, which
// `release manifest` reads), then one `cosign attest --type cyclonedx` per platform of each image, attaching the SBOM `make sbom`
// wrote for that platform (dist/sbom/<local image>-<arch>.cdx.json) to the platform digest `release push` recorded in images.json.

// maxSBOM bounds the SBOM read to check it is CycloneDX; trivy's SBOM of the largest image is a few MiB.
const maxSBOM = 64 << 20

// CosignPlanOpts are the inputs of the plan; Out and SBOMDir must be relative paths inside dist/.
type CosignPlanOpts struct {
	Bin, Key, Out, SBOMDir string
}

// CosignPlan returns the argv of every command of the plan, in order: mkdir of Out, the sign lines, the attest lines. It refuses
// anything it cannot prove belongs to this release: images.json and release.in.json naming another version, other services, other
// index digests or other platforms; a missing, non-regular or symlinked SBOM, or one that is not CycloneDX JSON; Out or SBOMDir
// outside dist/; a key or binary path a shell or cosign could read as something else.
func CosignPlan(in Inputs, images *ImagesDoc, o CosignPlanOpts) ([][]string, error) {
	if err := planArg("-cosign", o.Bin); err != nil {
		return nil, err
	}
	if err := planArg("-key", o.Key); err != nil {
		return nil, err
	}
	for _, p := range [][2]string{{"-out", o.Out}, {"-sbom", o.SBOMDir}} {
		if err := insideDist(p[0], p[1]); err != nil {
			return nil, err
		}
	}
	if images.Version != in.Version {
		return nil, fmt.Errorf("images.json is version %q, release.in.json %q", images.Version, in.Version)
	}
	if len(in.Images) != len(images.Images) {
		return nil, fmt.Errorf("release.in.json lists %d images, images.json %d", len(in.Images), len(images.Images))
	}
	plan := [][]string{{"mkdir", "-p", o.Out}}
	var attest [][]string
	for _, im := range in.Images {
		i := slices.IndexFunc(images.Images, func(p PushedImage) bool { return p.Service == im.Service })
		if i < 0 {
			return nil, fmt.Errorf("image %q of release.in.json is not in images.json", im.Service)
		}
		pushed := images.Images[i]
		if pushed.IndexDigest != im.Digest {
			return nil, fmt.Errorf("%s: release.in.json names %s, images.json pushed %s", im.Service, im.Digest, pushed.IndexDigest)
		}
		plats := make([]string, len(pushed.Platforms))
		for j, p := range pushed.Platforms {
			plats[j] = p.Platform
		}
		if !slices.Equal(slices.Sorted(slices.Values(plats)), slices.Sorted(slices.Values(im.Platforms))) {
			return nil, fmt.Errorf("%s: release.in.json has platforms %v, images.json %v", im.Service, im.Platforms, plats)
		}
		argv, err := CosignArgv(o.Bin, o.Key, o.Out, im.Service, im.Digest)
		if err != nil {
			return nil, err
		}
		plan = append(plan, argv)
		local := localName(im.Service)
		if local == "" {
			return nil, fmt.Errorf("no local image is published as %q", im.Service)
		}
		for _, p := range pushed.Platforms {
			sbom := filepath.Join(o.SBOMDir, local+"-"+strings.TrimPrefix(p.Platform, "linux/")+".cdx.json")
			if err := checkSBOM(sbom); err != nil {
				return nil, fmt.Errorf("%s %s: %w", im.Service, p.Platform, err)
			}
			argv, err := AttestArgv(o.Bin, o.Key, im.Service, p.Digest, sbom)
			if err != nil {
				return nil, err
			}
			attest = append(attest, argv)
		}
	}
	return append(plan, attest...), nil
}

// AttestArgv is the exact argv that attaches one platform's SBOM to its image as a CycloneDX attestation, in the same legacy
// format and with the same offline choices as CosignArgv (no bundle, no signing config, nothing to Rekor, D-57 (3)); unlike sign,
// the attestation is uploaded to the registry next to the image (the .att tag). --replace drops an earlier cyclonedx attestation
// of the same digest, so a re-run after a failure leaves one, not two. Flags read from `cosign attest --help` of the pinned v2.6.5.
func AttestArgv(cosignBin, keyPath, service, digest, sbomPath string) ([]string, error) {
	if !slices.ContainsFunc(publishedImages, func(p struct{ local, service string }) bool { return p.service == service }) ||
		!serviceDigestRE.MatchString(digest) {
		return nil, fmt.Errorf("image %q: unknown service or malformed digest", service)
	}
	return []string{
		cosignBin, "attest", "--key", keyPath, "--type", "cyclonedx", "--predicate", sbomPath,
		"--new-bundle-format=false", "--use-signing-config=false", "--tlog-upload=false", "--replace",
		release.RegistryPrefix + service + "@" + digest,
	}, nil
}

// localName is the name `make images` and `make sbom` give the image published as service.
func localName(service string) string {
	for _, p := range publishedImages {
		if p.service == service {
			return p.local
		}
	}
	return ""
}

// planArg refuses an empty value, a control character (a newline would end the printed line), and a leading "-" (cosign would read
// it as a flag).
func planArg(flag, v string) error {
	if v == "" || strings.HasPrefix(v, "-") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s %q: empty, starts with '-', or has a control character", flag, v)
	}
	return nil
}

// insideDist accepts only a clean relative path under dist/ (the output tree the release job keeps and `make clean` removes).
func insideDist(flag, p string) error {
	if err := planArg(flag, p); err != nil {
		return err
	}
	if filepath.IsAbs(p) || filepath.Clean(p) != p || !strings.HasPrefix(p, "dist/") || slices.Contains(strings.Split(p, "/"), "..") {
		return fmt.Errorf("%s %q: must be a clean relative path inside dist/", flag, p)
	}
	return nil
}

// checkSBOM refuses an SBOM that is not a regular file reached without any symlink, or not CycloneDX JSON (what --type cyclonedx
// claims it is). cosign reads the file again when kien runs the line; this is a check of the release tree, not a lock on it.
func checkSBOM(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("SBOM: %w (make sbom RELEASE=1 writes it)", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("SBOM %s is not a regular file", p)
	}
	// p is a clean relative path under dist/ (insideDist): every directory on the way must be a real one, not a link out of dist/
	for d := filepath.Dir(p); d != "."; d = filepath.Dir(d) {
		if fi, err := os.Lstat(d); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("SBOM %s is reached through a symlink or a missing directory (%s)", p, d)
		}
	}
	raw, err := readSmall(p, maxSBOM)
	if err != nil {
		return err
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil || bom.BOMFormat != "CycloneDX" || bom.SpecVersion == "" {
		return errors.New("SBOM " + p + " is not CycloneDX JSON")
	}
	return nil
}
