// Package systemd checks the text of vedette-host.service (D-150). It starts nothing: whether systemd restarts the host and kills a stray child
// is checked in the lab. The unit must carry no filesystem-namespace option (D-121): `ip netns add vedette-hp` bind-mounts on /run/netns/vedette-hp
// and the honeypot container, started by podman outside the unit, must see that mount. Drop-ins under vedette-host.service.d/ are not covered.
package systemd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const unitPath = "vedette-host.service"

// forbidden are the options that make a mount namespace (DEPLOYMENT.md section 12) or another namespace the host must not live in. They give
// a clear message; the allowlist below is what actually keeps every other key out.
var forbidden = []string{
	"PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
	"ProtectControlGroups", "ProtectProc", "ProcSubset", "ReadOnlyPaths", "ReadWritePaths", "InaccessiblePaths", "ExecPaths", "NoExecPaths",
	"BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "PrivateMounts", "MountAPIVFS", "MountImages", "RootDirectory", "RootImage",
	"RootEphemeral", "DynamicUser", "ProtectHostname", "PrivateUsers", "PrivateNetwork", "NetworkNamespacePath", "PrivateIPC", "PrivatePIDs",
	"MountFlags", "ExtensionImages", "ExtensionDirectories", "RootHash", "RootVerity", "LogNamespace", "BindLogSockets",
}

// allowed is every key the unit may have, per section. A new option is a decision: add it here on purpose (like `known` in TestContract_INV17).
var allowed = map[string][]string{
	"Unit":    {"Description", "After", "Wants", "ConditionPathExists", "StartLimitIntervalSec"},
	"Service": {"Type", "ExecStart", "Restart", "RestartSec", "RestartSteps", "RestartMaxDelaySec", "KillMode", "TimeoutStartSec", "RestrictAddressFamilies", "LockPersonality", "RestrictRealtime", "SystemCallArchitectures"},
	"Install": {"WantedBy"},
}

type entry struct{ section, key, value string }

func unitText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// parse reads the lines the way systemd does for our purposes: whitespace around a line, a key and a value is ignored, and a line that starts
// with # or ; is a comment. Keys stay case-sensitive.
func parse(text string) []entry {
	var out []entry
	section := ""
	for l := range strings.SplitSeq(text, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "" || l[0] == '#' || l[0] == ';':
		case l[0] == '[' && strings.HasSuffix(l, "]"):
			section = l[1 : len(l)-1]
		default:
			k, v, _ := strings.Cut(l, "=")
			out = append(out, entry{section, strings.TrimSpace(k), strings.TrimSpace(v)})
		}
	}
	return out
}

func options(text string) map[string][]string {
	m := map[string][]string{}
	for _, e := range parse(text) {
		m[e.key] = append(m[e.key], e.value)
	}
	return m
}

// problems lists what is wrong with the namespace and key rules of a unit text.
func problems(text string) []string {
	var out []string
	for _, e := range parse(text) {
		switch {
		case slices.Contains(forbidden, e.key):
			out = append(out, e.key+"= is set: it makes a namespace and hides /run/netns/vedette-hp from podman (D-121)")
		case !slices.Contains(allowed[e.section], e.key):
			out = append(out, "["+e.section+"] "+e.key+"= is not in the allowed list of deploy/systemd/unit_test.go: add it there on purpose")
		}
		if e.key == "RestrictNamespaces" && !namespacesAllowNetAndMnt(e.value) {
			out = append(out, "RestrictNamespaces="+e.value+" must allow net and mnt (ip netns calls unshare and setns)")
		}
	}
	return out
}

// namespacesAllowNetAndMnt reports whether a RestrictNamespaces= value still lets `ip netns` unshare/setns net and mnt.
func namespacesAllowNetAndMnt(v string) bool {
	switch v {
	case "", "no", "false", "0", "off":
		return true
	case "yes", "true", "1", "on":
		return false
	}
	deny := strings.HasPrefix(v, "~")
	set := strings.Fields(strings.TrimPrefix(v, "~"))
	for _, ns := range []string{"net", "mnt"} {
		if slices.Contains(set, ns) == deny {
			return false
		}
	}
	return true
}

func TestUnitHasNoFilesystemNamespaceOptionAndNoUnknownKey(t *testing.T) {
	t.Parallel()
	for _, p := range problems(unitText(t)) {
		t.Error(p)
	}
}

func TestProblemsCatchesWhatSystemdWouldAccept(t *testing.T) {
	t.Parallel()
	const head = "[Unit]\nDescription=x\n[Service]\nType=notify\n"
	for name, tc := range map[string]struct {
		text string
		want int
	}{
		"clean":                    {head, 0},
		"spaces around =":          {head + "PrivateTmp = yes\n", 1},
		"leading space":            {head + "  PrivateTmp=yes\n", 1},
		"leading tab":              {head + "\tProtectSystem=strict\n", 1},
		"trailing space":           {head + "ProtectHome=yes  \n", 1},
		"new forbidden key":        {head + "PrivateIPC=yes\n", 1},
		"unknown key":              {head + "CPUWeight=10\n", 1},
		"key in the wrong section": {head + "[Install]\nRestart=always\n", 1},
		"a comment is not a key":   {head + "# PrivateTmp=yes\n; ProtectHome=yes\n", 0},
		"namespaces too narrow":    {head + "RestrictNamespaces=yes\n", 2}, // also not in the allowed list
		"namespaces allowed":       {head + "RestrictNamespaces=net mnt\n", 1},
	} {
		if got := len(problems(tc.text)); got != tc.want {
			t.Errorf("%s: %d problems %q, want %d", name, got, problems(tc.text), tc.want)
		}
	}
}

func TestNamespacesAllowNetAndMnt(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{
		"": true, "no": true, "yes": false, "net mnt": true, "mnt net user": true, "net": false, "mnt": false, "~user": true, "~net": false, "~mnt pid": false,
	} {
		if got := namespacesAllowNetAndMnt(v); got != want {
			t.Errorf("%q: %t, want %t", v, got, want)
		}
	}
}

func TestUnitKeepsWhatTheHostNeeds(t *testing.T) {
	t.Parallel()
	opts := options(unitText(t))
	for k, want := range map[string]string{
		"Type":                  "notify",
		"Restart":               "always",
		"KillMode":              "control-group",
		"ExecStart":             "/usr/lib/vedette/vedette-host", // where the .deb installs the binary (DEPLOYMENT.md section 6.1)
		"WantedBy":              "multi-user.target",
		"ConditionPathExists":   "/etc/vedette/host.conf", // enabled by the package, skipped (not crash-looping) until the installer writes host.conf (D-155)
		"StartLimitIntervalSec": "0",                      // with Restart=always the default limit would stop a crash loop for good
		"TimeoutStartSec":       "16min",
	} {
		if got := opts[k]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want exactly %q", k, got, want)
		}
	}
	// No RuntimeDirectory* (D-157, WP-31 L10): systemd would make /run/vedette root:root at every start and the host
	// (Listen) refuses a directory that is not owned by root and socket_gid; the host creates and checks it itself.
	for _, k := range []string{"RuntimeDirectory", "RuntimeDirectoryMode", "RuntimeDirectoryPreserve", "User", "Group"} {
		if len(opts[k]) != 0 {
			t.Errorf("%s is set: /run/vedette is the host's to create, not systemd's (D-157)", k)
		}
	}
	// Crash-loop back-off (systemd 254 or newer): the keys must be there, with a value.
	for _, k := range []string{"RestartSec", "RestartSteps", "RestartMaxDelaySec"} {
		if len(opts[k]) != 1 || opts[k][0] == "" {
			t.Errorf("%s is missing", k)
		}
	}
	families := ""
	if v := opts["RestrictAddressFamilies"]; len(v) == 1 {
		families = v[0]
	}
	for _, f := range []string{"AF_PACKET", "AF_NETLINK", "AF_UNIX", "AF_INET", "AF_INET6"} {
		if !slices.Contains(strings.Fields(families), f) {
			t.Errorf("RestrictAddressFamilies=%q lacks %s (ARP probe, netlink addresses, host socket)", families, f)
		}
	}
}

// DEPLOYMENT.md section 6.1 shows the file itself: the first ini block after the line that names the installed path.
func TestDeploymentShowsTheSameText(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "DEPLOYMENT.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(doc), "`/usr/lib/systemd/system/vedette-host.service`")
	if !ok {
		t.Fatal("DEPLOYMENT.md does not name /usr/lib/systemd/system/vedette-host.service")
	}
	_, block, ok := strings.Cut(after, "```ini\n")
	if !ok {
		t.Fatal("no ini block after the unit path in DEPLOYMENT.md")
	}
	block, _, ok = strings.Cut(block, "```")
	if !ok {
		t.Fatal("the ini block of the unit is not closed")
	}
	if want := unitText(t); block != want {
		t.Errorf("DEPLOYMENT.md section 6.1 differs from deploy/systemd/vedette-host.service; paste the file between the fences.\ndoc:\n%s\nfile:\n%s", block, want)
	}
}
