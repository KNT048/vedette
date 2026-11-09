package modreg_test

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/modreg"
)

func fsOf(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for dir, body := range files {
		m[dir+"/MANIFEST.yaml"] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

const coreYAML = "id: core\ntier: core\ndefault: true\ndepends: []\n"

func TestLoadRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"id differs from folder", map[string]string{"core": coreYAML, "feeds": "id: feed\ntier: standard\n"}, "does not match the folder"},
		{"unknown tier", map[string]string{"core": coreYAML, "feeds": "id: feeds\ntier: gold\n"}, "tier"},
		{"unknown dependency", map[string]string{"core": coreYAML, "feeds": "id: feeds\ntier: standard\ndepends: [core, nope]\n"}, "has no manifest"},
		{"cycle", map[string]string{"core": coreYAML, "a": "id: a\ntier: optional\ndepends: [b]\n", "b": "id: b\ntier: optional\ndepends: [c]\n", "c": "id: c\ntier: optional\ndepends: [a]\n"}, "a -> b -> c -> a"},
		{"self dependency", map[string]string{"core": coreYAML, "a": "id: a\ntier: optional\ndepends: [a]\n"}, "a -> a"},
		{"no core", map[string]string{"a": "id: a\ntier: optional\n"}, "exactly one"},
		{"two cores", map[string]string{"core": coreYAML, "b": "id: b\ntier: core\n"}, "exactly one"},
		{"core default off", map[string]string{"core": "id: core\ntier: core\ndefault: off\n"}, "cannot default to off"},
		{"bad default", map[string]string{"core": coreYAML, "a": "id: a\ntier: optional\ndefault: maybe\n"}, "default"},
		{"bad kind", map[string]string{"core": coreYAML, "a": "id: a\ntier: optional\nkind: widget\n"}, "kind"},
		{"depends on a component", map[string]string{"core": coreYAML, "host": "id: host\nkind: component\ntier: core\n", "a": "id: a\ntier: optional\ndepends: [host]\n"}, "component"},
		{"default-on needs a default-off dependency", map[string]string{"core": coreYAML, "a": "id: a\ntier: optional\n", "b": "id: b\ntier: standard\ndefault: on\ndepends: [a]\n"}, "off by default"},
		{"core depends on a non-core module", map[string]string{"core": "id: core\ntier: core\ndepends: [a]\n", "a": "id: a\ntier: standard\ndefault: on\n"}, "core cannot need"},
		{"not yaml", map[string]string{"core": coreYAML, "a": "id: [unclosed\n"}, "parse"},
		{"bad id", map[string]string{"core": coreYAML, "A": "id: A\ntier: optional\n"}, "must match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := modreg.Load(fsOf(tt.files))
			if !errors.Is(err, modreg.ErrManifest) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want ErrManifest containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadDefaultsAndComponents(t *testing.T) {
	t.Parallel()
	ms, err := modreg.Load(fsOf(map[string]string{
		"core": coreYAML,
		"a":    "id: a\ntier: standard\ndefault: true\ndepends: [core]\n",
		"b":    "id: b\ntier: optional\ndefault: off\n",
		"c":    "id: c\ntier: optional\n", // no default: off
		"d":    "id: d\ntier: optional\ndefault: on\n",
		"host": "id: host\nkind: component\ntier: core\ndefault: on\n", // a second tier-core entry is fine for a component
		"_tpl": "id: example\ntier: optional\n",                        // skipped: the template folder
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]modreg.Manifest{}
	for _, m := range ms {
		got[m.ID] = m
	}
	if len(got) != 6 {
		t.Fatalf("loaded %d manifests, want 6 (template skipped)", len(got))
	}
	for id, want := range map[string]bool{"core": true, "a": true, "b": false, "c": false, "d": true} {
		if got[id].Default != want {
			t.Errorf("%s default = %v, want %v", id, got[id].Default, want)
		}
	}
	if !got["host"].Component || got["core"].Component {
		t.Errorf("component flags wrong: host=%v core=%v", got["host"].Component, got["core"].Component)
	}
}

// The real manifests of the repository pass validation (the registry would refuse to start otherwise).
func TestLoadRepositoryManifests(t *testing.T) {
	t.Parallel()
	ms, err := modreg.Load(os.DirFS("../../modules"))
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.ID)
	}
	for _, want := range []string{"core", "feeds", "inventory", "response", "host"} {
		if !slices.Contains(ids, want) {
			t.Errorf("manifest %q not loaded (have %v)", want, ids)
		}
	}
	if slices.Contains(ids, "example") {
		t.Error("the _template manifest was loaded")
	}
}
