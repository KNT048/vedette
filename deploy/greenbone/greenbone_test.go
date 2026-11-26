// Package greenbone checks the two compose files of OpenVAS (Greenbone Community Edition) that the vedette-host
// package ships: Greenbone's official file is unmodified apart from its digest pins, the pins are those of pins.env, and Vedette's
// override hands gvmd's socket to the host directory core mounts, gives gvmd Vedette's GMP login at the creation of its admin user,
// publishes no port, runs only what Vedette's GMP path uses (no web interface, no SCAP or CERT data) and limits the memory of each
// service. It starts no container: a run on a test box checks the effect.
package greenbone

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec" //nolint:depguard // the test runs the override's own gvmd command under /bin/sh, as the container would; SYS-1 is about the product
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/host/api"
)

// officialSHA256 is the SHA-256 of https://greenbone.github.io/docs/latest/_static/compose.yaml as fetched on 2026-11-14.
const officialSHA256 = "5b5117a7c200491de13bc7b79c97dc858c016c51017982d8f1de7ca077c1a868"

// feedServices are the seven feed data services of Greenbone's file: Greenbone's tag, no digest (the weekly update pulls their new
// versions; Vedette runs four of them).
var feedServices = []string{"notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data", "cert-bund-data", "report-formats", "data-objects"}

// disabled are the services Vedette never starts: the web interface and its helpers, the log viewer, and the SCAP and CERT
// data (stage A).
var disabled = []string{"gsa", "gsad", "nginx", "gvm-config", "gvm-tools", "openvas", "scap-data", "cert-bund-data", "dfn-cert-data"}

// gvmdDropped are gvmd's mounts of Greenbone's file that the override takes out; the third is replaced by the host's socket
// directory.
var gvmdDropped = []string{"scap_data_vol:/var/lib/gvm/scap-data/", "cert_data_vol:/var/lib/gvm/cert-data", "gvmd_socket_vol:/run/gvmd"}

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
		Volumes   []string  `yaml:"volumes"`
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
	Secrets map[string]struct {
		File string `yaml:"file"`
	} `yaml:"secrets"`
	Services map[string]struct {
		Profiles  []string          `yaml:"profiles"`
		Labels    map[string]string `yaml:"labels"`
		Command   []string          `yaml:"command"`
		Secrets   []string          `yaml:"secrets"`
		Volumes   yaml.Node         `yaml:"volumes"`
		DependsOn yaml.Node         `yaml:"depends_on"`
		Logging   *struct {
			Driver  string            `yaml:"driver"`
			Options map[string]string `yaml:"options"`
		} `yaml:"logging"`
		MemLimit string `yaml:"mem_limit"`
	} `yaml:"services"`
}

// memLimits is the memory limit of every service Vedette runs (compose's mem_limit, a cgroup limit podman applies): enough for its
// own peak (gvmd and PostgreSQL load the feed, ospd-openvas runs the scanner's processes), small for the feed data services that only
// copy files, and all of them together far below what the box needs for core and the sensors. A service over its limit is killed
// by the kernel and Greenbone's restart policy starts it again.
var memLimits = map[string]string{
	"gvmd": "2g", "pg-gvm": "1536m", "ospd-openvas": "2g", "redis-server": "1g", "openvasd": "512m",
	"pg-gvm-migrator": "512m", "configure-openvas": "128m", "gpg-data": "128m",
	"vulnerability-tests": "512m", "notus-data": "512m", "data-objects": "512m", "report-formats": "512m",
}

// memBudget is the most the limits of the services that run may add up to: about half of a 16 GB box. The preflight asks for 6 GB
// of memory before OpenVAS may be enabled, and the trial measured about 4 GB used at the peak of the first feed load.
const memBudget = 10 << 30

func memBytes(t *testing.T, v string) int64 {
	t.Helper()
	unit := map[byte]int64{'m': 1 << 20, 'g': 1 << 30}[v[len(v)-1]]
	n, err := strconv.ParseInt(v[:len(v)-1], 10, 64)
	if unit == 0 || err != nil || n <= 0 {
		t.Fatalf("mem_limit %q is not a number of m or g", v)
	}
	return n * unit
}

// Every service Vedette runs has its memory limit (memLimits), so a runaway feed load or scan never takes the memory core and the
// sensors need; the disabled ones have none (they never start). The limits together stay within memBudget, and each service that
// stays up keeps Greenbone's restart policy, which starts it again after the kernel killed it over its limit.
func TestOverrideLimitsTheMemoryOfEveryServiceThatRuns(t *testing.T) {
	t.Parallel()
	dec := yaml.NewDecoder(strings.NewReader(string(read(t, "compose.vedette.yaml"))))
	dec.KnownFields(true)
	var ov override
	if err := dec.Decode(&ov); err != nil {
		t.Fatal(err)
	}
	var total int64
	for name, s := range ov.Services {
		if len(s.Profiles) > 0 {
			if s.MemLimit != "" {
				t.Errorf("%s is disabled and carries mem_limit %q", name, s.MemLimit)
			}
			continue
		}
		want, ok := memLimits[name]
		if !ok || s.MemLimit != want {
			t.Errorf("%s: mem_limit %q, want %q", name, s.MemLimit, want)
			continue
		}
		total += memBytes(t, s.MemLimit)
	}
	if total > memBudget {
		t.Errorf("the memory limits add up to %d MiB, more than %d MiB", total>>20, memBudget>>20)
	}
	var off struct {
		Services map[string]struct {
			Deploy struct {
				RestartPolicy struct {
					Condition string `yaml:"condition"`
				} `yaml:"restart_policy"`
			} `yaml:"deploy"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "compose.yaml"), &off); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gvmd", "pg-gvm", "ospd-openvas", "redis-server", "openvasd"} {
		if c := off.Services[name].Deploy.RestartPolicy.Condition; c != "any" {
			t.Errorf("%s: Greenbone's restart policy is %q, want any (it starts again after an out-of-memory kill)", name, c)
		}
	}
}

// bindMount is the long form of one volume entry.
type bindMount struct {
	Type   string `yaml:"type"`
	Source string `yaml:"source"`
	Target string `yaml:"target"`
	Bind   struct {
		CreateHostPath bool `yaml:"create_host_path"`
	} `yaml:"bind"`
}

// The override hands gvmd's socket to the host directory core mounts, adds labels and a bounded log file, turns the web interface, its helpers and the SCAP
// and CERT data off and takes their mounts and dependencies out of gvmd, and nothing else: no port, no capability, no other mount
// (decoded with KnownFields, so any other key fails here).
func TestOverrideOnlyHandsOverTheSocketAndRunsWhatVedetteUses(t *testing.T) {
	t.Parallel()
	dec := yaml.NewDecoder(strings.NewReader(string(read(t, "compose.vedette.yaml"))))
	dec.KnownFields(true)
	var ov override
	if err := dec.Decode(&ov); err != nil {
		t.Fatalf("compose.vedette.yaml: %v (only profiles, labels, logging, memory limits and gvmd's socket volume belong in it)", err)
	}
	off := loadOfficial(t)
	var gotOff []string
	for name, s := range ov.Services {
		if _, ok := off.Services[name]; !ok {
			t.Errorf("the override names %s, which Greenbone's file does not have", name)
		}
		if len(s.Profiles) > 0 {
			if !slices.Equal(s.Profiles, []string{"disabled"}) || len(s.Labels) > 0 || s.Volumes.Kind != 0 || s.DependsOn.Kind != 0 || s.Logging != nil {
				t.Errorf("%s: a disabled service carries only profiles: [disabled]", name)
			}
			gotOff = append(gotOff, name)
			continue
		}
		if s.Labels["io.vedette.started-by"] != "vedette-host" || len(s.Labels) != 1 {
			t.Errorf("%s: labels %v, want exactly io.vedette.started-by=vedette-host", name, s.Labels)
		}
		// Each service logs to its own bounded file, never to the box's journal
		if l := s.Logging; l == nil || l.Driver != "json-file" || len(l.Options) != 1 || l.Options["max-size"] != "10m" {
			t.Errorf("%s: logging %+v, want json-file with max-size 10m", name, s.Logging)
		}
		if name != "gvmd" && (s.Volumes.Kind != 0 || s.DependsOn.Kind != 0 || len(s.Command) > 0 || len(s.Secrets) > 0) {
			t.Errorf("%s: the override mounts something or changes its command; only gvmd's socket directory and login are handed over", name)
		}
	}
	slices.Sort(gotOff)
	want := slices.Clone(disabled)
	slices.Sort(want)
	if !slices.Equal(gotOff, want) {
		t.Errorf("disabled services %v, want %v", gotOff, want)
	}
	checkGvmdMounts(t, ov.Services["gvmd"].Volumes, off.Services["gvmd"].Volumes)
	reset := checkGvmdDependencies(t, ov.Services["gvmd"].DependsOn, dependsOn(t, off.Services["gvmd"].DependsOn))
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
			if slices.Contains(disabled, dep) && (name != "gvmd" || !slices.Contains(reset, dep)) {
				t.Errorf("%s depends on %s, which the override turns off", name, dep)
			}
		}
	}
}

// checkGvmdMounts: gvmd's volume list replaces Greenbone's as a whole (compose's `!override`, since a merge cannot take an entry out):
// Greenbone's entries in their order without the SCAP and CERT data and the socket volume, and in the socket's place one bind of the
// host directory on /run/gvmd that compose never creates. A bump of compose.yaml that changes gvmd's mounts fails here.
func checkGvmdMounts(t *testing.T, n yaml.Node, upstream []string) {
	t.Helper()
	if n.Kind != yaml.SequenceNode || n.Tag != "!override" {
		t.Fatalf("gvmd's volumes are a %v tagged %q, want a list tagged !override", n.Kind, n.Tag)
	}
	var short []string
	binds := 0
	for i, e := range n.Content {
		if e.Kind == yaml.ScalarNode {
			short = append(short, e.Value)
			continue
		}
		var b bindMount
		if err := e.Decode(&b); err != nil {
			t.Fatal(err)
		}
		if b.Type != "bind" || b.Source != api.GreenboneSocketDir || b.Target != "/run/gvmd" || b.Bind.CreateHostPath || slices.Index(upstream, gvmdDropped[2]) != i+2 {
			t.Errorf("gvmd's mount %d %+v, want a bind of %s on /run/gvmd that compose never creates, where Greenbone mounts its socket volume", i, b, api.GreenboneSocketDir)
		}
		binds++
	}
	want := slices.DeleteFunc(slices.Clone(upstream), func(v string) bool { return slices.Contains(gvmdDropped, v) })
	if binds != 1 || !slices.Equal(short, want) || len(upstream) != len(want)+len(gvmdDropped) {
		t.Errorf("gvmd's mounts %q and %d bind(s), want Greenbone's %q without %q and one bind", short, binds, upstream, gvmdDropped)
	}
}

// checkGvmdDependencies: the override removes exactly gvmd's dependencies on the SCAP and CERT data services (compose's `!reset`);
// it returns them.
func checkGvmdDependencies(t *testing.T, n yaml.Node, upstream []string) []string {
	t.Helper()
	if n.Kind != yaml.MappingNode {
		t.Fatalf("gvmd's depends_on in the override is %v, want a map of !reset entries", n.Kind)
	}
	var reset []string
	for i := 0; i < len(n.Content); i += 2 {
		if v := n.Content[i+1]; v.Tag != "!reset" || v.Value != "null" {
			t.Errorf("gvmd's dependency %s is %q %q in the override, want !reset null", n.Content[i].Value, v.Tag, v.Value)
		}
		reset = append(reset, n.Content[i].Value)
	}
	slices.Sort(reset)
	if want := []string{"cert-bund-data", "dfn-cert-data", "scap-data"}; !slices.Equal(reset, want) {
		t.Errorf("the override resets gvmd's dependencies %q, want %q", reset, want)
	}
	for _, d := range reset {
		if !slices.Contains(upstream, d) {
			t.Errorf("Greenbone's gvmd does not depend on %s any more: take its !reset out", d)
		}
	}
	return reset
}

// gvmd takes Vedette's GMP login at the creation of its admin user. The override gives gvmd the host's password file
// as its only secret, and its command reads it and runs the image's own start-gvmd; a missing or empty file never reaches start-gvmd
// (which would create admin/admin). The command runs here under /bin/sh as compose hands it over ($$ → $), with the two paths moved
// into a temporary directory and a start-gvmd that prints what it got.
func TestOverrideGivesGvmdTheLoginAtItsCreation(t *testing.T) {
	t.Parallel()
	dec := yaml.NewDecoder(strings.NewReader(string(read(t, "compose.vedette.yaml"))))
	dec.KnownFields(true)
	var ov override
	if err := dec.Decode(&ov); err != nil {
		t.Fatal(err)
	}
	const secret, file = "vedette-gmp-password", "/var/lib/vedette-host/greenbone/gvmd-admin-password" //nolint:gosec // G101: the secret's name and path (host/ops gbPasswordFile), not a credential
	if len(ov.Secrets) != 1 || ov.Secrets[secret].File != file {
		t.Fatalf("secrets %+v, want only %s from %s", ov.Secrets, secret, file)
	}
	gvmd := ov.Services["gvmd"]
	if !slices.Equal(gvmd.Secrets, []string{secret}) {
		t.Fatalf("gvmd's secrets %v", gvmd.Secrets)
	}
	if len(gvmd.Command) != 3 || gvmd.Command[0] != "/bin/sh" || gvmd.Command[1] != "-c" {
		t.Fatalf("gvmd's command %q, want /bin/sh -c <script>", gvmd.Command)
	}
	script := strings.ReplaceAll(gvmd.Command[2], "$$", "$")
	for _, want := range []string{"/run/secrets/" + secret, "USER=" + api.GreenboneUser, "exec /usr/local/bin/start-gvmd"} {
		if !strings.Contains(script, want) {
			t.Fatalf("gvmd's command %q lacks %q", script, want)
		}
	}
	if strings.Contains(script, "echo") || strings.Contains(script, "set -x") {
		t.Fatalf("gvmd's command prints something: %q", script)
	}
	dir := t.TempDir()
	start := filepath.Join(dir, "start-gvmd")
	if err := os.WriteFile(start, []byte("#!/bin/sh\nprintf '%s|%s' \"$USER\" \"$PASSWORD\"\n"), 0o700); err != nil { //nolint:gosec // a fake start-gvmd that must run
		t.Fatal(err)
	}
	pw := filepath.Join(dir, "secret")
	script = strings.NewReplacer("/run/secrets/"+secret, pw, "/usr/local/bin/start-gvmd", start).Replace(script)
	run := func() (string, error) {
		out, err := exec.CommandContext(t.Context(), "/bin/sh", "-c", script).Output() //nolint:gosec // the override's own command, run as compose would
		return string(out), err
	}
	const want = "0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(pw, []byte(want+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err != nil || out != api.GreenboneUser+"|"+want {
		t.Fatalf("with the file: %q, %v; want start-gvmd to get %s and the password", out, err, api.GreenboneUser)
	}
	if err := os.Remove(pw); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err == nil || out != "" {
		t.Fatalf("without the file: %q, %v; want the container to end before start-gvmd", out, err)
	}
	if err := os.WriteFile(pw, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err == nil || out != "" {
		t.Fatalf("with an empty file: %q, %v; want the container to end before start-gvmd", out, err)
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
