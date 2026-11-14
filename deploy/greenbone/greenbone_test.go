// Package greenbone checks the two compose files of OpenVAS (Greenbone Community Edition, D-529, FULL-2, LEAN-1) that the vedette-host
// package ships: Greenbone's official file is unmodified apart from its digest pins, the pins are those of pins.env, and Vedette's
// override hands gvmd's socket to the host directory core mounts, publishes no port and runs only what Vedette's GMP path uses. It
// starts nothing: the N100 walk of D-529 checks the effect.
package greenbone

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/host/api"
)

// officialSHA256 is the SHA-256 of https://greenbone.github.io/docs/latest/_static/compose.yaml as fetched on 2026-11-14.
const officialSHA256 = "5b5117a7c200491de13bc7b79c97dc858c016c51017982d8f1de7ca077c1a868"

// feedServices are the seven feed data services: Greenbone's tag, no digest (the weekly update pulls their new versions).
var feedServices = []string{"notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data", "cert-bund-data", "report-formats", "data-objects"}

// disabled are the services Vedette never starts (LEAN-1): the web interface and its helpers, the log viewer.
var disabled = []string{"gsa", "gsad", "nginx", "gvm-config", "gvm-tools", "openvas"}

var pinRE = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // a file of this directory
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type official struct {
	Name     string `yaml:"name"`
	Services map[string]struct {
		Image     string    `yaml:"image"`
		Ports     []string  `yaml:"ports"`
		DependsOn yaml.Node `yaml:"depends_on"`
	} `yaml:"services"`
}

func loadOfficial(t *testing.T) official {
	t.Helper()
	var o official
	if err := yaml.Unmarshal(read(t, "compose.yaml"), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// compose.yaml is Greenbone's file byte for byte once its header comment and its "@sha256:" pins are taken out.
func TestComposeIsGreenbonesFileWithPinsOnly(t *testing.T) {
	t.Parallel()
	text := string(read(t, "compose.yaml"))
	var kept []string
	header := true
	for _, l := range strings.SplitAfter(text, "\n") {
		if header && strings.HasPrefix(l, "#") {
			continue
		}
		header = false
		kept = append(kept, l)
	}
	sum := sha256.Sum256([]byte(pinRE.ReplaceAllString(strings.Join(kept, ""), "")))
	if got := hex.EncodeToString(sum[:]); got != officialSHA256 {
		t.Fatalf("compose.yaml without its header and pins has SHA-256 %s, want Greenbone's %s: Vedette's changes go in compose.vedette.yaml", got, officialSHA256)
	}
	if o := loadOfficial(t); o.Name != "greenbone-community-edition" {
		t.Fatalf("project name %q", o.Name)
	}
}

// Every image that runs code is pinned by digest, the GREENBONE_* value of pins.env with Greenbone's tag before the digest; the seven
// feed data images, and only they, keep the tag.
func TestGreenbonePinsAgree(t *testing.T) {
	t.Parallel()
	pins := map[string]bool{}
	for _, l := range strings.Split(string(read(t, filepath.Join("..", "containers", "pins.env"))), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.HasPrefix(k, "GREENBONE_") {
			pins[v] = false
		}
	}
	if len(pins) == 0 {
		t.Fatal("no GREENBONE_* pin in deploy/containers/pins.env")
	}
	for name, s := range loadOfficial(t).Services {
		if !strings.HasPrefix(s.Image, "registry.community.greenbone.net/community/") {
			t.Errorf("%s: image %q is not from Greenbone's registry", name, s.Image)
		}
		if slices.Contains(feedServices, name) {
			if strings.Contains(s.Image, "@") || strings.Contains(s.Image, ":") {
				t.Errorf("%s: a feed data image keeps Greenbone's own tag, unpinned (%q)", name, s.Image)
			}
			continue
		}
		ref, digest, ok := strings.Cut(s.Image, "@")
		if !ok || !pinRE.MatchString("@"+digest) {
			t.Errorf("%s: image %q is not pinned by digest", name, s.Image)
			continue
		}
		if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
			ref = ref[:i] // the tag
		}
		if _, ok := pins[ref+"@"+digest]; !ok {
			t.Errorf("%s: %s@%s is not a GREENBONE_* value of pins.env", name, ref, digest)
			continue
		}
		pins[ref+"@"+digest] = true
	}
	for v, used := range pins {
		if !used {
			t.Errorf("pins.env pins %s, which compose.yaml does not use", v)
		}
	}
	got := 0
	for _, f := range feedServices {
		if _, ok := loadOfficial(t).Services[f]; ok {
			got++
		}
	}
	if got != len(feedServices) {
		t.Errorf("compose.yaml has %d of the seven feed services %v", got, feedServices)
	}
}

type override struct {
	Services map[string]struct {
		Profiles []string          `yaml:"profiles"`
		Labels   map[string]string `yaml:"labels"`
		Volumes  []struct {
			Type   string `yaml:"type"`
			Source string `yaml:"source"`
			Target string `yaml:"target"`
			Bind   struct {
				CreateHostPath bool `yaml:"create_host_path"`
			} `yaml:"bind"`
		} `yaml:"volumes"`
	} `yaml:"services"`
}

// The override hands gvmd's socket to the host directory core mounts, adds labels, turns the web interface and its helpers off and
// nothing else: no port, no capability, no other mount (decoded with KnownFields, so any other key fails here).
func TestOverrideOnlyHandsOverTheSocketAndRunsWhatVedetteUses(t *testing.T) {
	t.Parallel()
	dec := yaml.NewDecoder(strings.NewReader(string(read(t, "compose.vedette.yaml"))))
	dec.KnownFields(true)
	var ov override
	if err := dec.Decode(&ov); err != nil {
		t.Fatalf("compose.vedette.yaml: %v (only profiles, labels and gvmd's socket volume belong in it)", err)
	}
	off := loadOfficial(t)
	var gotOff []string
	for name, s := range ov.Services {
		if _, ok := off.Services[name]; !ok {
			t.Errorf("the override names %s, which Greenbone's file does not have", name)
		}
		if len(s.Profiles) > 0 {
			if !slices.Equal(s.Profiles, []string{"disabled"}) || len(s.Labels) > 0 || len(s.Volumes) > 0 {
				t.Errorf("%s: a disabled service carries only profiles: [disabled]", name)
			}
			gotOff = append(gotOff, name)
			continue
		}
		if s.Labels["io.vedette.started-by"] != "vedette-host" || len(s.Labels) != 1 {
			t.Errorf("%s: labels %v, want exactly io.vedette.started-by=vedette-host", name, s.Labels)
		}
		if name != "gvmd" && len(s.Volumes) > 0 {
			t.Errorf("%s: the override mounts something; only gvmd's socket directory is handed over", name)
		}
	}
	slices.Sort(gotOff)
	want := slices.Clone(disabled)
	slices.Sort(want)
	if !slices.Equal(gotOff, want) {
		t.Errorf("disabled services %v, want %v", gotOff, want)
	}
	v := ov.Services["gvmd"].Volumes
	if len(v) != 1 || v[0].Type != "bind" || v[0].Source != api.GreenboneSocketDir || v[0].Target != "/run/gvmd" || v[0].Bind.CreateHostPath {
		t.Errorf("gvmd's volumes %+v, want one bind of %s on /run/gvmd that compose never creates", v, api.GreenboneSocketDir)
	}
	for name, s := range off.Services {
		if slices.Contains(disabled, name) {
			continue
		}
		if _, ok := ov.Services[name]; !ok {
			t.Errorf("%s runs without the label of the override", name)
		}
		if len(s.Ports) > 0 { // nothing of Greenbone listens on a port of the box: only nginx publishes, and it is off
			t.Errorf("%s publishes %v", name, s.Ports)
		}
		for _, dep := range dependsOn(t, s.DependsOn) {
			if slices.Contains(disabled, dep) {
				t.Errorf("%s depends on %s, which the override turns off", name, dep)
			}
		}
	}
}

// dependsOn reads depends_on in both of compose's forms (a list of names, or a map of name to condition).
func dependsOn(t *testing.T, n yaml.Node) []string {
	t.Helper()
	var out []string
	switch n.Kind {
	case 0:
	case yaml.SequenceNode:
		if err := n.Decode(&out); err != nil {
			t.Fatal(err)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
	default:
		t.Fatalf("depends_on of kind %d", n.Kind)
	}
	return out
}
