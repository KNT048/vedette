// Package compose checks the text of the container-only compose files (D-168). It starts nothing: the effect (the stack runs, refuses a
// wrong Host, keeps its data) is the smoke of a later slice and the lab. These tests keep the hardening of DEPLOYMENT.md (Hardening) true
// of the files a customer is given.
package compose

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var files = []string{"compose.yaml", "compose.sensors.yaml", "compose.syslog.yaml"}

const dir = "container-only"

type service struct {
	Image         string         `yaml:"image"`
	ContainerName string         `yaml:"container_name"`
	Hostname      string         `yaml:"hostname"`
	User          string         `yaml:"user"`
	ReadOnly      bool           `yaml:"read_only"`
	Privileged    bool           `yaml:"privileged"`
	CapDrop       []string       `yaml:"cap_drop"`
	CapAdd        []string       `yaml:"cap_add"`
	SecurityOpt   []string       `yaml:"security_opt"`
	NetworkMode   string         `yaml:"network_mode"`
	Restart       string         `yaml:"restart"`
	Ports         []string       `yaml:"ports"`
	Volumes       []string       `yaml:"volumes"`
	Command       []string       `yaml:"command"`
	Healthcheck   map[string]any `yaml:"healthcheck"`
	MemLimit      string         `yaml:"mem_limit"`
	PidsLimit     int            `yaml:"pids_limit"`
	// The rest are the keys in use. The files are decoded with KnownFields(true): a key that is not here (pid, ipc, userns_mode, devices,
	// volumes_from, extra_hosts, sysctls ...) fails the test until someone adds it on purpose.
	Tmpfs        []string          `yaml:"tmpfs"`
	MemswapLimit string            `yaml:"memswap_limit"`
	Cpus         any               `yaml:"cpus"`
	CPUShares    int               `yaml:"cpu_shares"`
	Init         bool              `yaml:"init"`
	Environment  map[string]string `yaml:"environment"`
	DependsOn    map[string]any    `yaml:"depends_on"`
	Logging      map[string]any    `yaml:"logging"`
}

type file struct {
	Name     string             `yaml:"name"`
	Services map[string]service `yaml:"services"`
	Volumes  map[string]any     `yaml:"volumes"`
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // test: fixed file names of this directory
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func load(t *testing.T, name string) file {
	t.Helper()
	var f file
	dec := yaml.NewDecoder(strings.NewReader(read(t, name)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

var imageRef = regexp.MustCompile(`^\$\{VEDETTE_(CORE|SENSOR|SCAN)_IMAGE:\?[^}]+\}$`)

// The syslog file is an add-on of core's ports and nothing else: merged over compose.yaml, any other key of it (read_only: false, a
// command without -hosts, pid: host ...) would silently change core. It is read as raw maps, so even an absent-versus-false key shows.
func TestSyslogFileHoldsOnlyCorePorts(t *testing.T) {
	t.Parallel()
	var raw map[string]map[string]map[string]any
	if err := yaml.Unmarshal([]byte(read(t, "compose.syslog.yaml")), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 || raw["services"] == nil || len(raw["services"]) != 1 || raw["services"]["core"] == nil {
		t.Fatalf("compose.syslog.yaml: only services.core, got %v", raw)
	}
	core := raw["services"]["core"]
	if _, ok := core["ports"]; !ok || len(core) != 1 {
		t.Errorf("compose.syslog.yaml: the keys of core must be exactly [ports], got %v", core)
	}
	for _, p := range load(t, "compose.syslog.yaml").Services["core"].Ports {
		if !strings.HasPrefix(p, "${VEDETTE_BIND_IP:?") {
			t.Errorf("compose.syslog.yaml: port %q must name an address", p)
		}
	}
}

// Every service of the two main files: an image that only a release can fill (the variable of its own service), no root (the one
// exception below), no privilege, nothing but NET_RAW and only on the host network of the sensor, no docker socket (no bind mount at
// all), ports only on an address, a restart policy, bounded logs.
func TestEveryServiceIsHardenedLikeTheAppliance(t *testing.T) {
	t.Parallel()
	seen := 0
	for _, name := range files[:2] {
		for sname, s := range load(t, name).Services {
			where := name + " " + sname
			seen++
			if m := imageRef.FindStringSubmatch(s.Image); m == nil || !strings.EqualFold(m[1], sname) {
				t.Errorf("%s: image %q must be ${VEDETTE_%s_IMAGE:?message}: the release fills the digest, the repository copy refuses to start (D-166 (2))", where, s.Image, strings.ToUpper(sname))
			}
			// uid 0 only for the host-network sensor with exactly NET_RAW: Docker gives an added capability only to root, Podman to any user
			// (measured, D-168 (3)); D-114 (3) planned this fallback. Everything else runs as a non-root uid.
			rootSensor := sname == "sensor" && s.NetworkMode == "host" && slices.Equal(s.CapAdd, []string{"NET_RAW"})
			u, g, _ := strings.Cut(s.User, ":")
			if u == "" || ((u == "0" || u == "root") && !rootSensor) {
				t.Errorf("%s: user %q must be a non-root uid (only the host-network sensor with cap_add [NET_RAW] may be 0)", where, s.User)
			}
			// uid 0 with every capability dropped has no DAC override: it reads core's sensor credentials (0640, 65532:65532) only through group 65532
			if (u == "0" || u == "root") && g != "65532" {
				t.Errorf("%s: user %q: the root sensor must run with group 65532 to read core's credentials (0640), got group %q", where, s.User, g)
			}
			if sname == "scan" && len(s.CapAdd) > 0 {
				t.Errorf("%s: the scan worker has no nmap here and needs no capability, got cap_add %v", where, s.CapAdd)
			}
			if len(s.Tmpfs) == 0 || s.Healthcheck == nil {
				t.Errorf("%s: tmpfs and healthcheck are set", where)
			}
			if s.Logging["driver"] != "json-file" {
				t.Errorf("%s: logging driver must be json-file with a bound (the appliance's journald bounds itself), got %v", where, s.Logging)
			} else if o, _ := s.Logging["options"].(map[string]any); o["max-size"] == nil || o["max-file"] == nil {
				t.Errorf("%s: logging needs max-size and max-file, got %v", where, s.Logging)
			}
			if !s.ReadOnly {
				t.Errorf("%s: read_only must be true", where)
			}
			if s.Privileged {
				t.Errorf("%s: privileged", where)
			}
			if !slices.Equal(s.CapDrop, []string{"ALL"}) {
				t.Errorf("%s: cap_drop must be [ALL], got %v", where, s.CapDrop)
			}
			if !slices.Equal(s.SecurityOpt, []string{"no-new-privileges:true"}) {
				t.Errorf("%s: security_opt must be exactly [no-new-privileges:true] (no seccomp=unconfined, no apparmor opt-out), got %v", where, s.SecurityOpt)
			}
			if s.Restart != "unless-stopped" {
				t.Errorf("%s: restart must be unless-stopped (a purge makes core exit and expects a supervisor, D-154), got %q", where, s.Restart)
			}
			if s.MemLimit == "" || s.PidsLimit == 0 {
				t.Errorf("%s: mem_limit and pids_limit are set (DEPLOYMENT.md 2.5)", where)
			}
			for _, c := range s.CapAdd {
				if c != "NET_RAW" || s.NetworkMode != "host" {
					t.Errorf("%s: cap_add %q: only NET_RAW, only on the host network (D-114)", where, c)
				}
			}
			if s.NetworkMode != "" && (s.NetworkMode != "host" || (sname != "sensor" && sname != "scan")) {
				t.Errorf("%s: network_mode %q: only sensor and scan use the host network", where, s.NetworkMode)
			}
			for _, v := range s.Volumes {
				src, _, _ := strings.Cut(v, ":")
				if strings.ContainsAny(src, "/.~") || strings.Contains(v, "docker.sock") || strings.Contains(v, "podman.sock") {
					t.Errorf("%s: volume %q must be a named volume (no bind mount, no engine socket)", where, v)
				}
			}
			for _, p := range s.Ports {
				if !strings.HasPrefix(p, "${VEDETTE_BIND_IP:?") && !strings.HasPrefix(p, "127.0.0.1:") {
					t.Errorf("%s: port %q must name an address (Docker -p goes around the firewall)", where, p)
				}
			}
		}
	}
	if seen != 3 {
		t.Errorf("expected core, sensor and scan, found %d services", seen)
	}
}

func TestCoreServiceIsTheOneThingTheCustomerMustSet(t *testing.T) {
	t.Parallel()
	core := load(t, "compose.yaml").Services["core"]
	if core.Healthcheck == nil || !strings.Contains(strings.Join(toStrings(core.Healthcheck["test"]), " "), "/vedette healthcheck") {
		t.Errorf("core healthcheck must run /vedette healthcheck, got %v", core.Healthcheck)
	}
	cmd := strings.Join(core.Command, " ")
	for _, want := range []string{"-host-socket= ", "-hosts=${VEDETTE_HOSTS:?", "-sensor-listen=:8444", "-syslog-port=5514"} {
		if !strings.Contains(cmd+" ", want) {
			t.Errorf("core command lacks %q: %s", want, cmd)
		}
	}
	if len(core.Ports) != 2 || !strings.HasSuffix(core.Ports[0], ":8443:8443") || core.Ports[1] != "127.0.0.1:8444:8444" {
		t.Errorf("core publishes 8443 on the address given and 8444 on loopback only, got %v", core.Ports)
	}
	// the name of the appliance's unit, so one log command is true on both installs; the name "This box" gets in the inventory
	if core.ContainerName != "vedette-core" || core.Hostname != "vedette" {
		t.Errorf("core container_name %q and hostname %q must be vedette-core and vedette", core.ContainerName, core.Hostname)
	}
	sys := load(t, "compose.syslog.yaml").Services["core"]
	if len(sys.Ports) != 3 || !strings.HasSuffix(sys.Ports[0], ":514:5514/udp") || !strings.HasSuffix(sys.Ports[1], ":514:5514/tcp") ||
		!strings.HasSuffix(sys.Ports[2], ":6514:5515/tcp") {
		t.Errorf("compose.syslog.yaml publishes 514 udp and tcp to core's 5514 and TLS 6514 tcp to 5515 (D-214), got %v", sys.Ports)
	}
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// Every flag of core's command is a flag the binary has (the names are read from cmd/vedette/main.go: the package main cannot be imported).
func TestCoreFlagsExist(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "vedette", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, m := range regexp.MustCompile(`flags\.\w+Var\(&o\.\w+, "([a-z-]+)"`).FindAllStringSubmatch(string(src), -1) {
		have[m[1]] = true
	}
	if len(have) < 8 {
		t.Fatalf("found only %d flags in cmd/vedette/main.go: the pattern is stale", len(have))
	}
	for _, a := range load(t, "compose.yaml").Services["core"].Command {
		name, _, _ := strings.Cut(strings.TrimPrefix(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || !have[name] {
			t.Errorf("core command argument %q is not a flag of cmd/vedette", a)
		}
	}
}

var variable = regexp.MustCompile(`\$\{(VEDETTE_[A-Z_]+)`)

// vedette.env names every variable the compose files use, and in the repository every value is empty: a release fills the three images
// and the customer the other two, so a copy of the repository starts nothing.
func TestEnvFileNamesEveryVariableAndIsEmptyInTheRepository(t *testing.T) {
	t.Parallel()
	env := map[string]string{}
	for _, l := range strings.Split(read(t, "vedette.env"), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			t.Fatalf("vedette.env line %q: KEY=VALUE", l)
		}
		env[k] = v
	}
	used := map[string]bool{}
	for _, name := range files {
		for _, m := range variable.FindAllStringSubmatch(read(t, name), -1) {
			used[m[1]] = true
		}
	}
	for k := range used {
		if _, ok := env[k]; !ok {
			t.Errorf("%s is used by the compose files and missing from vedette.env", k)
		}
	}
	for k, v := range env {
		if !used[k] {
			t.Errorf("%s is in vedette.env and used by no compose file", k)
		}
		if v != "" {
			t.Errorf("%s=%q: the repository copy is empty (a release or the customer fills it)", k, v)
		}
	}
}

// The backup and restore commands of the install guide run the Debian image the project pins for its builds, by the same digest
// (no floating tag may read the key of the box).
func TestInstallGuideUsesThePinnedDebianImage(t *testing.T) {
	t.Parallel()
	pins, err := os.ReadFile(filepath.Join("..", "containers", "pins.env"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^DEBIAN_IMAGE=(\S+)$`).FindSubmatch(pins)
	if m == nil {
		t.Fatal("DEBIAN_IMAGE not found in deploy/containers/pins.env")
	}
	guide, err := os.ReadFile(filepath.Join("..", "..", "docs", "INSTALL-CONTAINER.md"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(guide), string(m[1])); n < 2 {
		t.Errorf("docs/INSTALL-CONTAINER.md must name %s in the backup and in the restore command, found %d", m[1], n)
	}
	if strings.Contains(string(guide), "alpine") {
		t.Error("docs/INSTALL-CONTAINER.md: no unpinned third-party image")
	}
}
