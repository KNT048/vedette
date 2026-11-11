package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/internal/release"
)

// Inputs is the release description the maintainer writes (release.in.json). Everything that can be measured is measured
// by the builder instead: file hashes and sizes are computed from the files, db_schema from the migrations, refs from the
// service and version, the cosign blocks from the files cosign wrote.
type Inputs struct {
	Version        string            `json:"version"`
	Channel        string            `json:"channel"`
	ReleasedAt     string            `json:"released_at"` // RFC 3339; empty = now
	MinUpgradeFrom string            `json:"min_upgrade_from"`
	Notes          string            `json:"notes"`
	InstallModes   []string          `json:"install_modes"`
	Rollback       release.Rollback  `json:"rollback"`
	Images         []ImageIn         `json:"images"`
	Host           *HostIn           `json:"host"`
	Content        []release.Content `json:"content"`
	Bundled        []release.Bundled `json:"bundled"`
	SBOM           *SBOMIn           `json:"sbom"`
}

// ImageIn is one built image: the digest is the digest of the multi-platform index that was pushed.
type ImageIn struct {
	Service   string   `json:"service"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	Platforms []string `json:"platforms"`
}

// HostIn lists the vedette-host packages by path; name, size and SHA-256 come from the files.
type HostIn struct {
	Version string   `json:"version"`
	Files   []string `json:"files"`
}

// SBOMIn names the SBOM file and the URL it will be published at.
type SBOMIn struct {
	URL  string `json:"url"`
	File string `json:"file"`
}

// ParseInputs reads release.in.json strictly: an unknown field or a repeated key is an error.
func ParseInputs(raw []byte) (Inputs, error) {
	var in Inputs
	if len(raw) > 1<<20 {
		return in, errors.New("inputs: larger than 1 MiB")
	}
	if err := jsonstrict.Decode(raw, &in); err != nil {
		return in, fmt.Errorf("inputs: %w", err)
	}
	return in, nil
}

// Env is everything the builder reads besides Inputs.
type Env struct {
	Now       time.Time
	CosignDir string // <service>.payload.json and <service>.sig, as `cosign sign --output-payload --output-signature` wrote them
	// PrevIndex is the published index, verified (D-150); nil before the first release. It says what each channel's latest is, so a
	// hotfix on stable after a beta is judged against stable. It is not the rollback baseline.
	PrevIndex *release.Index
	// Baseline is the migrations of release rollback.min_version, the oldest release a box may roll back to (D-164); nil when unknown.
	Baseline Tree
	CurTree  Tree // migrations of the revision being released
}

// Result is the built manifest and what the guard found.
type Result struct {
	Manifest []byte
	DBSchema int
	Findings []Finding // reasons rollback.safe=true is not allowed (empty when the migrations are add-only)
}

const maxHashedFile = 1 << 30

var serviceDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// BuildManifest builds release-manifest.json (unsigned). It refuses, with the reason:
//   - a version that is not above the channel's latest in the published index, or a min_upgrade_from above that latest;
//   - rollback.safe=true without rollback.min_version (below this version), without the migrations at that release, or unless every
//     migration since that release is add-only (D-183, D-164: the whole span a box may roll back across, not one step);
//   - an image of an unknown service, a repeated service, a malformed digest, or a missing or unreadable cosign file.
//
// The result is then signed and checked by the verifier of internal/release (`release sign`, `release verify`).
func BuildManifest(in Inputs, env Env) (Result, error) {
	var res Result
	if _, err := release.CompareVersions(in.Version, in.Version); err != nil {
		return res, fmt.Errorf("version %q is not SemVer (no v, no build metadata)", in.Version)
	}
	if in.Channel != "stable" && in.Channel != "beta" {
		return res, fmt.Errorf("channel must be stable or beta, got %q", in.Channel)
	}
	if env.PrevIndex != nil {
		if ch, ok := env.PrevIndex.Channels[in.Channel]; ok {
			c, err := release.CompareVersions(in.Version, ch.Latest)
			if err != nil {
				return res, err
			}
			if c <= 0 {
				return res, fmt.Errorf("version %s is not above %s, the latest of channel %s in the published index", in.Version, ch.Latest, in.Channel)
			}
			if in.MinUpgradeFrom != "" {
				if c, err := release.CompareVersions(in.MinUpgradeFrom, ch.Latest); err != nil || c > 0 {
					return res, fmt.Errorf("min_upgrade_from %s is above %s, the latest published: no box could upgrade", in.MinUpgradeFrom, ch.Latest)
				}
			}
		}
	}
	released := env.Now.UTC().Truncate(time.Second)
	if in.ReleasedAt != "" {
		t, err := time.Parse(time.RFC3339, in.ReleasedAt)
		if err != nil {
			return res, fmt.Errorf("released_at: %w", err)
		}
		released = t.UTC()
	}

	// D-183: the rollback guard.
	res.DBSchema = env.CurTree.Count()
	if env.Baseline != nil {
		res.Findings = CheckMigrations(env.Baseline, env.CurTree)
	}
	if in.Rollback.Safe {
		// The host lets a box roll back to any release from rollback.min_version (host/ops/update.go), so "safe" must hold across
		// everything since that release, not since the previous one: a release that dropped a table in between is not undone by a
		// later add-only release.
		minv := in.Rollback.MinVersion
		if minv == "" {
			return res, errors.New("rollback.safe=true needs rollback.min_version: the oldest release a box may roll back to; the guard checks every migration since that release")
		}
		if c, err := release.CompareVersions(minv, in.Version); err != nil || c >= 0 {
			return res, fmt.Errorf("rollback.min_version %s must be a version below %s", minv, in.Version)
		}
		switch {
		case env.Baseline == nil:
			return res, fmt.Errorf("rollback.safe=true cannot be proved without the migrations of release %s (its git tag v%s, or -baseline-ref); say safe=false or give it", minv, minv)
		case len(res.Findings) > 0:
			return res, &GuardError{res.Findings}
		}
	}

	m := release.Manifest{
		Schema: 1, Version: in.Version, Channel: in.Channel, ReleasedAt: released,
		MinUpgradeFrom: in.MinUpgradeFrom, DBSchema: res.DBSchema, Rollback: in.Rollback,
		InstallModes: in.InstallModes, Notes: in.Notes,
		Content: orEmpty(in.Content), Bundled: orEmpty(in.Bundled),
	}
	seen := map[string]bool{}
	for _, im := range in.Images {
		if seen[im.Service] {
			return res, fmt.Errorf("image %s is listed twice", im.Service)
		}
		seen[im.Service] = true
		if _, err := release.PullRef(im.Service, im.Digest); err != nil || !serviceDigestRE.MatchString(im.Digest) {
			return res, fmt.Errorf("image %q: unknown service or malformed digest (need sha256: and 64 lower-case hex)", im.Service)
		}
		cos, err := readCosign(env.CosignDir, im.Service, im.Digest)
		if err != nil {
			return res, err
		}
		m.Images = append(m.Images, release.Image{
			Service: im.Service, Ref: release.ImageRef(im.Service, in.Version), Digest: im.Digest, Size: im.Size,
			Platforms: im.Platforms, Cosign: cos,
		})
	}
	if in.Host != nil {
		h := &release.HostPart{Version: in.Host.Version, Files: []release.HostFile{}}
		for _, p := range in.Host.Files {
			sum, size, err := hashFile(p)
			if err != nil {
				return res, fmt.Errorf("host file: %w", err)
			}
			h.Files = append(h.Files, release.HostFile{Name: filepath.Base(p), SHA256: sum, Size: size})
		}
		m.Host = h
	}
	if in.SBOM != nil {
		sum, _, err := hashFile(in.SBOM.File)
		if err != nil {
			return res, fmt.Errorf("sbom: %w", err)
		}
		m.SBOM = &release.SBOM{Format: "CycloneDX", URL: in.SBOM.URL, SHA256: sum}
	}
	if m.Images == nil {
		return res, errors.New("a release needs at least one image")
	}
	b, err := marshal(m)
	if err != nil {
		return res, err
	}
	res.Manifest = b
	return res, nil
}

// GuardError is the D-183 refusal: the reasons the migrations are not add-only.
type GuardError struct{ Findings []Finding }

func (e *GuardError) Error() string {
	var b strings.Builder
	b.WriteString("rollback.safe=true refused (D-183): the migrations since the previous release are not add-only; say safe=false (the host then restores the database on rollback)\n")
	for _, f := range e.Findings {
		b.WriteString("  - " + f.String() + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// marshal is the one way documents are written: two-space indent, no HTML escaping, one final newline.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func hashFile(p string) (sum string, size int64, err error) {
	f, err := os.Open(p) //nolint:gosec // a path the maintainer named in release.in.json
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxHashedFile+1))
	if err != nil {
		return "", 0, err
	}
	if n > maxHashedFile {
		return "", 0, fmt.Errorf("%s is larger than %d bytes", p, int64(maxHashedFile))
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// readCosign reads the two files cosign wrote for an image and checks, cheaply, that they are what the manifest needs: the
// payload names this digest and this service's repository. The signature itself is checked by `release verify` (the real
// verifier, against the cosign public key); the builder never signs.
func readCosign(dir, service, digest string) (release.CosignSig, error) {
	var c release.CosignSig
	if dir == "" {
		return c, errors.New("no cosign directory given")
	}
	payload, err := readSmall(filepath.Join(dir, service+".payload.json"), 4<<10)
	if err != nil {
		return c, fmt.Errorf("cosign payload of %s: %w", service, err)
	}
	sig, err := readSmall(filepath.Join(dir, service+".sig"), 256)
	if err != nil {
		return c, fmt.Errorf("cosign signature of %s: %w", service, err)
	}
	var p struct {
		Critical struct {
			Identity struct {
				Ref string `json:"docker-reference"`
			} `json:"identity"`
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return c, fmt.Errorf("cosign payload of %s is not JSON: %w", service, err)
	}
	if p.Critical.Image.Digest != digest || p.Critical.Identity.Ref != release.RegistryPrefix+service {
		return c, fmt.Errorf("cosign payload of %s is for %q@%q, not for %s@%s", service, p.Critical.Identity.Ref, p.Critical.Image.Digest, release.RegistryPrefix+service, digest)
	}
	s := strings.TrimSpace(string(sig))
	if _, err := base64.StdEncoding.Strict().DecodeString(s); err != nil || s == "" {
		return c, fmt.Errorf("cosign signature of %s is not base64", service)
	}
	return release.CosignSig{Payload: base64.StdEncoding.EncodeToString(payload), Signature: s}, nil
}

func readSmall(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // a fixed name inside the cosign directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, limit)
	}
	return b, nil
}

// CosignArgv is the exact argv that signs one image (D-103: legacy format, signature kept next to the payload, nothing
// uploaded here, identity = the repository without tag or digest), the flags of internal/release/testdata/README.md plus
// --tlog-upload=false (D-57 (3): verification is offline, so nothing goes to Rekor). Read in the cosign docs on 2026-11-11:
// these flags exist in cosign v2.6.1 and are gone from `cosign sign` in v3.1.4 (which has --bundle and --signing-config), so the
// cosign WP-08k pins must be a v2 release; whether v2 still contacts the registry with --upload=false is for 08k to measure
// (.ai/deferred/feat-release-builder.md). The key file's password comes from COSIGN_PASSWORD in
// the environment of the maintainer's shell, never from argv.
func CosignArgv(cosignBin, keyPath, outDir, service, digest string) ([]string, error) {
	if _, err := release.PullRef(service, digest); err != nil || !serviceDigestRE.MatchString(digest) {
		return nil, fmt.Errorf("image %q: unknown service or malformed digest", service)
	}
	if !slices.Contains(release.Services, service) {
		return nil, fmt.Errorf("unknown service %q", service)
	}
	return []string{
		cosignBin, "sign", "--key", keyPath,
		"--new-bundle-format=false", "--use-signing-config=false", "--upload=false", "--tlog-upload=false",
		"--output-payload", filepath.Join(outDir, service+".payload.json"),
		"--output-signature", filepath.Join(outDir, service+".sig"),
		release.RegistryPrefix + service + "@" + digest,
	}, nil
}
