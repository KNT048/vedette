package release

import (
	"regexp"
	"slices"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// RegistryPrefix is the only registry and repository family images come from (D-104 (1)); the host
// builds pull references from it and a digest, never from the manifest's ref string.
const RegistryPrefix = "ghcr.io/knt048/vedette-"

// Services is the closed set of image services (D-55).
var Services = []string{"core", "sensor", "honeypot", "scan", "greenbone"}

// ImageRef is the ref a manifest must carry for service at version.
func ImageRef(service, version string) string { return RegistryPrefix + service + ":" + version }

// PullRef is the reference to pull: fixed registry, service from the enum, the verified digest.
func PullRef(service, digest string) (string, error) {
	if !slices.Contains(Services, service) || !digestRE.MatchString(digest) {
		return "", wrap(ErrMalformed, "service or digest")
	}
	return RegistryPrefix + service + "@" + digest, nil
}

// Manifest is release-manifest.json (§4.2) after verification.
type Manifest struct {
	Schema         int       `json:"schema"`
	Version        string    `json:"version"`
	Channel        string    `json:"channel"`
	ReleasedAt     time.Time `json:"released_at"`
	MinUpgradeFrom string    `json:"min_upgrade_from"`
	DBSchema       int       `json:"db_schema"`
	Rollback       Rollback  `json:"rollback"`
	InstallModes   []string  `json:"install_modes"`
	Images         []Image   `json:"images"`
	Host           *HostPart `json:"host"`
	Content        []Content `json:"content"`
	Bundled        []Bundled `json:"bundled"`
	SBOM           *SBOM     `json:"sbom"`
	Notes          string    `json:"notes"`

	// KeyID is the minisign key that signed the manifest; set by VerifyManifest, never from JSON.
	KeyID string `json:"-"`
	// revokedCosign holds the cosign key ids the index revoked when the manifest was verified.
	revokedCosign map[string]bool
}

// Rollback says whether the previous version may run on the new database.
type Rollback struct {
	Safe       bool   `json:"safe"`
	MinVersion string `json:"min_version"`
}

// Image is one container image of a release.
type Image struct {
	Service   string    `json:"service"`
	Ref       string    `json:"ref"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platforms []string  `json:"platforms"`
	Cosign    CosignSig `json:"cosign"`
}

// HostPart is the vedette-host package that ships with a release.
type HostPart struct {
	Version string     `json:"version"`
	Files   []HostFile `json:"files"`
}

// HostFile is one file of the host package.
type HostFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Content is a content pack that ships inside an image.
type Content struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	InImage string `json:"in_image"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

// Bundled is a pinned dependency shown under Managed packages.
type Bundled struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SBOM points at the release SBOM.
type SBOM struct {
	Format string `json:"format"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

var (
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	platformRE = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)
	textVerRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$`)
)

const maxSize = 1 << 40 // 1 TiB: a sanity bound on a declared size

func parseManifest(raw []byte) (*Manifest, error) {
	if len(raw) > MaxDocBytes {
		return nil, wrap(ErrTooLarge, "manifest")
	}
	if err := checkSchema(raw); err != nil {
		return nil, err
	}
	var m Manifest
	if err := jsonstrict.Decode(raw, &m); err != nil {
		return nil, wrap(ErrMalformed, "manifest: %s", errClass(err))
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if !validVersion(m.Version) || (m.Channel != "stable" && m.Channel != "beta") || m.ReleasedAt.IsZero() {
		return bad("version/channel/released_at")
	}
	if m.MinUpgradeFrom != "" && (!validVersion(m.MinUpgradeFrom) || compareVersions(m.MinUpgradeFrom, m.Version) > 0) {
		return bad("min_upgrade_from")
	}
	if m.Rollback.MinVersion != "" && (!validVersion(m.Rollback.MinVersion) || compareVersions(m.Rollback.MinVersion, m.Version) > 0) {
		return bad("rollback.min_version")
	}
	if m.DBSchema < 0 || !shortText(m.Notes, 2048) {
		return bad("db_schema/notes")
	}
	if len(m.InstallModes) == 0 || len(m.InstallModes) > 2 {
		return bad("install_modes")
	}
	for i, im := range m.InstallModes {
		if (im != "appliance" && im != "container") || slices.Contains(m.InstallModes[:i], im) {
			return bad("install_modes")
		}
	}
	if len(m.Images) == 0 || len(m.Images) > MaxImages {
		return bad("images")
	}
	seen := map[string]bool{}
	for _, im := range m.Images {
		if !slices.Contains(Services, im.Service) || seen[im.Service] {
			return bad("image service")
		}
		seen[im.Service] = true
		if !digestRE.MatchString(im.Digest) {
			return bad("image digest")
		}
		if !shortText(im.Ref, 256) || im.Size < 0 || im.Size > maxSize {
			return bad("image ref/size")
		}
		if im.Cosign.Payload == "" || im.Cosign.Signature == "" {
			return bad("image %s has no cosign signature", im.Service)
		}
		if len(im.Platforms) == 0 || len(im.Platforms) > 8 {
			return bad("image platforms")
		}
		for _, p := range im.Platforms {
			if !platformRE.MatchString(p) {
				return bad("platform %q", clip(p))
			}
		}
	}
	if h := m.Host; h != nil {
		if !validVersion(h.Version) || len(h.Files) > 16 {
			return bad("host")
		}
		for _, f := range h.Files {
			if !nameRE.MatchString(f.Name) || !hex64RE.MatchString(f.SHA256) || f.Size < 0 || f.Size > maxSize {
				return bad("host file")
			}
		}
	}
	if len(m.Content) > 64 || len(m.Bundled) > 64 {
		return bad("too many entries")
	}
	for _, c := range m.Content {
		if !nameRE.MatchString(c.Name) || !textVerRE.MatchString(c.Version) || !slices.Contains(Services, c.InImage) ||
			!hex64RE.MatchString(c.SHA256) || !shortText(c.Path, 256) || len(c.Path) == 0 || c.Path[0] != '/' || containsDotDot(c.Path) {
			return bad("content entry")
		}
	}
	for _, b := range m.Bundled {
		if !slices.Contains(Services, b.Service) || !nameRE.MatchString(b.Name) || !textVerRE.MatchString(b.Version) {
			return bad("bundled entry")
		}
	}
	if s := m.SBOM; s != nil && (s.Format != "CycloneDX" || !httpsURL(s.URL) || !hex64RE.MatchString(s.SHA256)) {
		return bad("sbom")
	}
	return nil
}

func containsDotDot(p string) bool {
	for i := 0; i+1 < len(p); i++ {
		if p[i] == '.' && p[i+1] == '.' && (i == 0 || p[i-1] == '/') && (i+2 == len(p) || p[i+2] == '/') {
			return true
		}
	}
	return false
}

// image returns the manifest's entry for service.
func (m *Manifest) image(service string) *Image {
	for i := range m.Images {
		if m.Images[i].Service == service {
			return &m.Images[i]
		}
	}
	return nil
}

// Image returns the entry for service, if the manifest has one.
func (m *Manifest) Image(service string) (Image, bool) {
	if im := m.image(service); im != nil {
		return *im, true
	}
	return Image{}, false
}

// CheckInstallMode refuses a release that does not list mode ("appliance" or "container").
func (m *Manifest) CheckInstallMode(mode string) error {
	if !slices.Contains(m.InstallModes, mode) {
		return wrap(ErrInstallMode, "%s", clip(mode))
	}
	return nil
}

// CheckPlatform refuses an image that is not built for platform ("linux/amd64").
func (m *Manifest) CheckPlatform(service, platform string) error {
	im := m.image(service)
	if im == nil {
		return wrap(ErrDigestNotInManifest, "no image for service %s", clip(service))
	}
	if !slices.Contains(im.Platforms, platform) {
		return wrap(ErrPlatform, "%s", clip(platform))
	}
	return nil
}
