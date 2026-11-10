// Package systemd checks the text of vedette-host.service (D-150). It starts nothing: whether systemd restarts the host and kills a stray child
// is checked in the lab. The unit must carry no filesystem-namespace option (D-121): `ip netns add vedette-hp` bind-mounts on /run/netns/vedette-hp
// and the honeypot container, started by podman outside the unit, must see that mount.
package systemd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const unitPath = "vedette-host.service"

// forbidden are the options of DEPLOYMENT.md section 12 that make a mount namespace (the first group), plus the ones that imply one.
var forbidden = []string{
	"PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
	"ProtectControlGroups", "ProtectProc", "ProcSubset", "ReadOnlyPaths", "ReadWritePaths", "InaccessiblePaths", "ExecPaths", "NoExecPaths",
	"BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "PrivateMounts", "MountAPIVFS", "MountImages", "RootDirectory", "RootImage",
	"RootEphemeral", "DynamicUser",
}

func unitText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// options maps each key to its values, from lines that start with the key (systemd is case-sensitive and does not indent keys we care about).
func options(text string) map[string][]string {
	m := map[string][]string{}
	for l := range strings.SplitSeq(text, "\n") {
		if l == "" || l[0] == '#' || l[0] == ';' || l[0] == '[' {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = append(m[k], strings.TrimSpace(v))
		}
	}
	return m
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

func TestUnitHasNoFilesystemNamespaceOption(t *testing.T) {
	t.Parallel()
	opts := options(unitText(t))
	for _, k := range forbidden {
		if _, ok := opts[k]; ok {
			t.Errorf("%s= is set: it makes a mount namespace and hides /run/netns/vedette-hp from podman (D-121)", k)
		}
	}
	for _, v := range opts["RestrictNamespaces"] {
		if !namespacesAllowNetAndMnt(v) {
			t.Errorf("RestrictNamespaces=%s must allow net and mnt (ip netns calls unshare and setns)", v)
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
		"Type":                     "notify",
		"Restart":                  "always",
		"KillMode":                 "control-group",
		"RuntimeDirectory":         "vedette",
		"RuntimeDirectoryMode":     "0750",
		"RuntimeDirectoryPreserve": "yes",
		"ExecStart":                "/usr/lib/vedette/vedette-host", // where the .deb installs the binary (DEPLOYMENT.md section 6.1)
		"WantedBy":                 "multi-user.target",
	} {
		if got := opts[k]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want exactly %q", k, got, want)
		}
	}
	for _, k := range []string{"TimeoutStartSec", "RestartSec"} {
		if len(opts[k]) != 1 || opts[k][0] == "" {
			t.Errorf("%s is missing", k)
		}
	}
	if v := opts["TimeoutStartSec"]; len(v) == 1 && v[0] != "16min" {
		t.Errorf("TimeoutStartSec = %s: it bounds the Start steps of D-121/D-123 (16 min)", v[0])
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
