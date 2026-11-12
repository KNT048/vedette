// Package pack reads the index of the safe nuclei template pack (D-125 (4)): the list of templates the signed scan
// image carries, built at release time with the pack. Core reads it to choose templates (one per CVE a device is
// suspected of), to write the request line of the probe log before anything is sent (INV-7), and to refuse a template
// that is not in the safe set (INV-4); the worker reads the same index to check each template file's SHA-256 before
// nuclei starts. The index is the project's own format, so it is decoded strictly (internal/jsonstrict) and every
// entry is checked again here, behind the release builder's own checks.
package pack

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// Limits of an index.
const (
	MaxSize      = 2 << 20 // bytes
	MaxTemplates = 5000
	maxTags      = 32
	maxRequest   = 200
)

// SafeTags are the tags a template must carry one of: the KEV sets (CISA KEV, VulnCheck KEV) (INV-4).
var SafeTags = []string{"kev", "vkev"}

// Template is one entry of the index.
type Template struct {
	ID      string   `json:"id"`      // nuclei template id, the -id value
	CVE     string   `json:"cve"`     // the CVE it confirms
	Path    string   `json:"path"`    // relative to nucleiargv.TemplatesDir
	SHA256  string   `json:"sha256"`  // of the template file
	Tags    []string `json:"tags"`    //
	Request string   `json:"request"` // the first request line, for the probe log (contract.ts ProbeEntry.request)
}

// Index is the whole pack.
type Index struct {
	Version   string     `json:"version"`
	SHA256    string     `json:"sha256"` // of the pack as shipped; a job names it so the worker can refuse another pack
	Templates []Template `json:"templates"`

	byCVE map[string][]int
}

var (
	idRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`) // a nuclei template id: no comma, no leading dash
	versionRE = regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,4}$`)
	cveRE     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
	shaRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	requestRE = regexp.MustCompile(`^[ -~]{1,200}$`)
)

// Parse decodes and checks an index. Any entry that breaks a rule refuses the whole index: a pack that is not
// exactly what the builder promised is not used at all.
func Parse(raw []byte) (*Index, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("pack: index of %d bytes is over the %d cap", len(raw), MaxSize)
	}
	var ix Index
	if err := jsonstrict.Decode(raw, &ix); err != nil {
		return nil, fmt.Errorf("pack: reading the index: %w", err)
	}
	if !versionRE.MatchString(ix.Version) || !shaRE.MatchString(ix.SHA256) {
		return nil, errors.New("pack: the index has no valid version or hash")
	}
	if len(ix.Templates) == 0 || len(ix.Templates) > MaxTemplates {
		return nil, fmt.Errorf("pack: an index has 1 to %d templates, got %d", MaxTemplates, len(ix.Templates))
	}
	ix.byCVE = map[string][]int{}
	ids := map[string]bool{}
	for i, t := range ix.Templates {
		if err := t.check(); err != nil {
			return nil, fmt.Errorf("pack: template %d (%.100q): %w", i, t.ID, err)
		}
		if ids[t.ID] {
			return nil, fmt.Errorf("pack: template id %q is listed twice", t.ID)
		}
		ids[t.ID] = true
		ix.byCVE[t.CVE] = append(ix.byCVE[t.CVE], i)
	}
	return &ix, nil
}

func (t Template) check() error {
	switch {
	case !idRE.MatchString(t.ID):
		return errors.New("id is not a template id")
	case !cveRE.MatchString(t.CVE):
		return errors.New("cve is not a CVE id")
	case !nucleiargv.ValidTemplatePath(t.Path):
		return errors.New("path is not a relative .yaml path")
	case !runsUnderProtocols(t.Path):
		return errors.New("path is not under http/, network/ or ssl/: nuclei runs with -pt http,tcp,ssl and would drop it without a line")
	case !shaRE.MatchString(t.SHA256):
		return errors.New("sha256 is not a lower-case SHA-256")
	case len(t.Tags) == 0 || len(t.Tags) > maxTags:
		return fmt.Errorf("a template has 1 to %d tags", maxTags)
	case len(t.Request) > maxRequest || !requestRE.MatchString(t.Request):
		return errors.New("request is not one printable request line")
	}
	safe := false
	forbidden := nucleiargv.ForbiddenTags() // nuclei is told to exclude the same list (-etags)
	for _, tag := range t.Tags {
		if !tagRE.MatchString(tag) {
			return fmt.Errorf("tag %.40q is not valid", tag)
		}
		if slices.Contains(forbidden, tag) {
			return fmt.Errorf("tag %q is never allowed", tag)
		}
		if tag == "oast" { // L3: nuclei runs with -ni, so a check that needs an out-of-band answer would always say "not matched"
			return errors.New("needs out-of-band interaction (oast), which nuclei runs without")
		}
		safe = safe || slices.Contains(SafeTags, tag)
	}
	if !safe {
		return errors.New("not in the KEV sets (kev, vkev)")
	}
	return nil
}

// runsUnderProtocols says whether a template path sits in a directory of a protocol nuclei runs (-pt http,tcp,ssl in
// nucleiargv): every other protocol is dropped silently and would read as "no match reported", so the pack refuses it
// here and a template of the pack always runs.
func runsUnderProtocols(path string) bool {
	return strings.HasPrefix(path, "http/") || strings.HasPrefix(path, "network/") || strings.HasPrefix(path, "ssl/")
}

// ForCVE returns the templates that confirm cve, in index order; none when the pack has no template for it
// (the result is then no_template, and nothing is sent: INV-8).
func (ix *Index) ForCVE(cve string) []Template {
	var out []Template
	for _, i := range ix.byCVE[cve] {
		out = append(out, ix.Templates[i])
	}
	return out
}

// Has says whether id is a template of the pack.
func (ix *Index) Has(id string) bool {
	return slices.ContainsFunc(ix.Templates, func(t Template) bool { return t.ID == id })
}
