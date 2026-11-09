package modreg

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Tier says how a module ships: core is always on, standard is on by default, optional is off by default.
type Tier string

// The tiers of docs/MODULES.md.
const (
	TierCore     Tier = "core"
	TierStandard Tier = "standard"
	TierOptional Tier = "optional"
)

// KindComponent marks a manifest that is not a module (modules/host): it has a contract but no
// on/off switch and no core_module row.
const KindComponent = "component"

var idRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Manifest is the part of MANIFEST.yaml that core reads. The rest (name, summary, ports, stories...)
// is documentation for people and other tools.
type Manifest struct {
	ID        string
	Tier      Tier
	Component bool
	Default   bool // on at first start
	Depends   []string
}

type rawManifest struct {
	ID      string   `yaml:"id"`
	Kind    string   `yaml:"kind"`
	Tier    string   `yaml:"tier"`
	Default any      `yaml:"default"`
	Depends []string `yaml:"depends"`
}

// ErrManifest is wrapped by every manifest validation failure.
var ErrManifest = errors.New("modreg: invalid manifest")

// Load reads every <dir>/MANIFEST.yaml in fsys and validates the set: the id equals the folder name,
// tiers are known, dependencies exist, there are no cycles, and exactly one module has tier core.
// Folders whose name starts with "_" (the module template) are skipped.
func Load(fsys fs.FS) ([]Manifest, error) {
	files, err := fs.Glob(fsys, "*/MANIFEST.yaml")
	if err != nil {
		return nil, fmt.Errorf("modreg: list manifests: %w", err)
	}
	slices.Sort(files)
	var out []Manifest
	for _, name := range files {
		dir, _, _ := strings.Cut(name, "/")
		if strings.HasPrefix(dir, "_") {
			continue
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("modreg: read %s: %w", name, err)
		}
		m, err := parse(dir, b)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrManifest, name, err)
		}
		out = append(out, m)
	}
	if err := validateSet(out); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	return out, nil
}

func parse(dir string, b []byte) (Manifest, error) {
	var raw rawManifest
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return Manifest{}, fmt.Errorf("parse: %w", err)
	}
	if raw.ID != dir {
		return Manifest{}, fmt.Errorf("id %q does not match the folder name %q", raw.ID, dir)
	}
	if !idRE.MatchString(raw.ID) {
		return Manifest{}, fmt.Errorf("id %q must match %s", raw.ID, idRE)
	}
	m := Manifest{ID: raw.ID, Tier: Tier(raw.Tier), Depends: raw.Depends}
	switch raw.Kind {
	case "":
	case KindComponent:
		m.Component = true
	default:
		return Manifest{}, fmt.Errorf("kind %q is not known (use %q or leave it out)", raw.Kind, KindComponent)
	}
	switch m.Tier {
	case TierCore, TierStandard, TierOptional:
	default:
		return Manifest{}, fmt.Errorf("tier %q must be core, standard or optional", raw.Tier)
	}
	def, err := parseDefault(raw.Default, m.Tier)
	if err != nil {
		return Manifest{}, err
	}
	if m.Tier == TierCore && !def {
		return Manifest{}, errors.New("a core module cannot default to off")
	}
	m.Default = def
	seen := map[string]bool{}
	for _, d := range m.Depends {
		if !idRE.MatchString(d) {
			return Manifest{}, fmt.Errorf("dependency %q is not a module id", d)
		}
		if seen[d] {
			return Manifest{}, fmt.Errorf("dependency %q is listed twice", d)
		}
		seen[d] = true
	}
	return m, nil
}

// parseDefault accepts true/false and on/off. A missing value means on for core and off otherwise.
func parseDefault(v any, tier Tier) (bool, error) {
	switch x := v.(type) {
	case nil:
		return tier == TierCore, nil
	case bool:
		return x, nil
	case string:
		switch strings.ToLower(x) {
		case "on", "true":
			return true, nil
		case "off", "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("default %v must be true, false, on or off", v)
}

func validateSet(ms []Manifest) error {
	byID := make(map[string]Manifest, len(ms))
	for _, m := range ms {
		if _, dup := byID[m.ID]; dup {
			return fmt.Errorf("module %q appears twice", m.ID)
		}
		byID[m.ID] = m
	}
	cores := 0
	for _, m := range ms {
		if m.Tier == TierCore && !m.Component {
			cores++
		}
		for _, d := range m.Depends {
			dep, ok := byID[d]
			switch {
			case !ok:
				return fmt.Errorf("module %q depends on %q, which has no manifest", m.ID, d)
			case dep.Component:
				return fmt.Errorf("module %q depends on %q, which is a component, not a module", m.ID, d)
			case m.Component:
				return fmt.Errorf("component %q cannot depend on modules", m.ID)
			}
		}
	}
	if cores != 1 {
		return fmt.Errorf("exactly one module must have tier core, found %d", cores)
	}
	return findCycle(byID)
}

// findCycle reports the first dependency cycle, depth-first, in id order so the message is stable.
func findCycle(byID map[string]Manifest) error {
	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]int, len(byID))
	var path []string
	var visit func(id string) error
	visit = func(id string) error {
		switch state[id] {
		case done:
			return nil
		case visiting:
			i := slices.Index(path, id)
			return fmt.Errorf("dependency cycle: %s", strings.Join(append(slices.Clone(path[i:]), id), " -> "))
		}
		state[id] = visiting
		path = append(path, id)
		for _, d := range byID[id].Depends {
			if err := visit(d); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		state[id] = done
		return nil
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}
