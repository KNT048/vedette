package main

import (
	"context"
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

// maxSBOM bounds the SBOM read; trivy's SBOM of the largest image is a few MiB.
const maxSBOM = 64 << 20

// trivyImageID is the property trivy writes on the SBOM's metadata.component: the config digest of the image it read (measured with
// the pinned trivy 0.76.2 on an OCI layout: exactly one, equal to podman's image ID).
const trivyImageID = "aquasecurity:trivy:ImageID"

// CosignPlanOpts are the inputs of the plan. Dir is the absolute directory the plan runs in (the repository root): the plan starts
// with `cd Dir`, Out and SBOMDir are relative paths inside dist/ under it, Key is absolute.
type CosignPlanOpts struct {
	Bin, Key, Dir, Out, SBOMDir string
}

// CosignPlan returns the argv of every command of the plan, in order: cd, mkdir of Out, the sign lines, the attest lines. It refuses
// anything it cannot prove belongs to this release: images.json and release.in.json naming another version, other or repeated
// services, other index digests or other platforms; an SBOM that is missing, not a regular file inside dist/ reached without a
// symlink, not CycloneDX, or made from another image than the platform image of the local list `release push` pushed (trivy's
// ImageID against the config digest podman reports, read through run); Out or SBOMDir outside dist/; a key, binary or directory a
// shell or cosign could read as something else.
func CosignPlan(ctx context.Context, run runFunc, in Inputs, images *ImagesDoc, o CosignPlanOpts) ([][]string, error) {
	if err := planArg("-cosign", o.Bin); err != nil {
		return nil, err
	}
	if o.Bin != "cosign" && !filepath.IsAbs(o.Bin) { // a first word like A=b would be read by sh as an assignment
		return nil, fmt.Errorf("-cosign %q: must be an absolute path or cosign", o.Bin)
	}
	for _, p := range [][2]string{{"-key", o.Key}, {"directory", o.Dir}} {
		if err := planArg(p[0], p[1]); err != nil {
			return nil, err
		}
		if !filepath.IsAbs(p[1]) {
			return nil, fmt.Errorf("%s %q: must be an absolute path (the plan starts with cd)", p[0], p[1])
		}
	}
	for _, p := range [][2]string{{"-out", o.Out}, {"-sbom", o.SBOMDir}} {
		if err := insideDist(p[0], p[1]); err != nil {
			return nil, err
		}
		if err := noSymlinks(o.Dir, p[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", p[0], err)
		}
	}
	if images.Version != in.Version {
		return nil, fmt.Errorf("images.json is version %q, release.in.json %q", images.Version, in.Version)
	}
	if len(in.Images) != len(images.Images) {
		return nil, fmt.Errorf("release.in.json lists %d images, images.json %d", len(in.Images), len(images.Images))
	}
	plan := [][]string{{"cd", o.Dir}, {"mkdir", "-p", o.Out}}
	var attest [][]string
	for k, im := range in.Images {
		if slices.ContainsFunc(in.Images[:k], func(o ImageIn) bool { return o.Service == im.Service }) {
			return nil, fmt.Errorf("release.in.json lists %s twice", im.Service)
		}
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
		sorted := slices.Sorted(slices.Values(plats))
		if len(slices.Compact(slices.Clone(sorted))) != len(sorted) || !slices.Equal(sorted, slices.Sorted(slices.Values(im.Platforms))) {
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
		lp, err := localPlatforms(ctx, run, "localhost/vedette-"+local+":"+in.Version, plats)
		if err != nil {
			return nil, fmt.Errorf("each SBOM is matched to the platform image of the local list that was pushed: %w", err)
		}
		for _, p := range pushed.Platforms {
			arch := strings.TrimPrefix(p.Platform, "linux/")
			j := slices.IndexFunc(lp, func(l localPlatform) bool { return l.Platform == p.Platform })
			if j < 0 || lp[j].Version != in.Version {
				return nil, fmt.Errorf("%s %s: the local image is not version %s", im.Service, p.Platform, in.Version)
			}
			sbom := filepath.Join(o.SBOMDir, local+"-"+arch+".cdx.json")
			if err := checkSBOM(o.Dir, sbom, lp[j].Config); err != nil {
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
// the attestation is uploaded to the registry next to the image (the .att tag). --replace drops an earlier attestation of the same
// predicate type on that digest (a re-run after a failure; not yet measured against ghcr). Flags read from `cosign attest --help`
// of the pinned v2.6.5; the same argv with --no-upload and a throwaway key gave an in-toto statement of predicate type
// https://cyclonedx.org/bom on the repository + digest, offline, without a prompt.
func AttestArgv(cosignBin, keyPath, service, digest, sbomPath string) ([]string, error) {
	if localName(service) == "" || !serviceDigestRE.MatchString(digest) {
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
	switch {
	case v == "":
		return fmt.Errorf("%s is empty", flag)
	case strings.HasPrefix(v, "-"):
		return fmt.Errorf("%s %q starts with '-'", flag, v)
	case strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fmt.Errorf("%s %q has a control character", flag, v)
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

// noSymlinks refuses a path (relative to dir) any existing component of which is a symlink: a link would take the files the plan
// writes or reads out of dist/. Components that do not exist yet are fine (mkdir -p makes them).
func noSymlinks(dir, rel string) error {
	p := ""
	for _, c := range strings.Split(rel, "/") {
		p = filepath.Join(p, c)
		fi, err := os.Lstat(filepath.Join(dir, p))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", p)
		}
	}
	return nil
}

// checkSBOM refuses an SBOM that is not a regular file reached without any symlink, not CycloneDX JSON (what --type cyclonedx
// claims), or not trivy's SBOM of the image whose config digest is config: an SBOM left from another build would otherwise be
// signed as the bill of materials of this release. cosign reads the file again when kien runs the line; this checks the tree, it
// does not lock it.
func checkSBOM(dir, rel, config string) error {
	if err := noSymlinks(dir, rel); err != nil {
		return fmt.Errorf("SBOM %s: %w", rel, err)
	}
	p := filepath.Join(dir, rel)
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("SBOM: %w (make sbom RELEASE=1 IMAGE_TAG=<version> writes it)", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("SBOM %s is not a regular file", rel)
	}
	raw, err := readSmall(p, maxSBOM)
	if err != nil {
		return err
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil || bom.BOMFormat != "CycloneDX" || bom.SpecVersion == "" {
		return errors.New("SBOM " + rel + " is not CycloneDX JSON")
	}
	var ids []string
	for _, pr := range bom.Metadata.Component.Properties {
		if pr.Name == trivyImageID {
			ids = append(ids, pr.Value)
		}
	}
	if len(ids) != 1 || ids[0] != config {
		return fmt.Errorf("SBOM %s is of image %v, not of the local image %s that was pushed (make sbom RELEASE=1 IMAGE_TAG=<version>)", rel, ids, config)
	}
	return nil
}
