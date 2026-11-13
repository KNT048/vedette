package ops_test

import (
	"os"
	"os/exec" //nolint:depguard // the test runs install.sh's own sh functions with a fixed argv; SYS-1 is about the product
	"path/filepath"
	"strings"
	"testing"
)

// runInstallShFns runs install.sh's functions fns, then call, with the fake programs of bin first on PATH; it returns stdout+stderr.
func runInstallShFns(t *testing.T, bin string, env []string, fns []string, call string) (string, error) {
	t.Helper()
	script := "set -eu\nhave() { command -v \"$1\" >/dev/null 2>&1; }\n" +
		"say() { printf 'vedette-install: %s\\n' \"$*\"; }\nwarn() { printf 'vedette-install: WARNING: %s\\n' \"$*\" >&2; }\n"
	for _, f := range fns {
		script += installShFunc(t, f)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "-c", script+call) //nolint:gosec // the sh functions of install.sh under test
	cmd.Env = append(append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH")), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func fakeProgram(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // a fake program of the test
		t.Fatal(err)
	}
}

// D-409 (L7 of D-267's review): --uninstall removes Vedette's images by their exact names only. A customer's own
// localhost/vedette-foo (or a name that merely starts like ours) is never removed, and an image of ours that the customer
// also tagged is left in place with a warning: rmi -f by ID would take the customer's name and its containers with it.
func TestInstallSh_UninstallRemovesOnlyVedettesImages(t *testing.T) {
	dir := t.TempDir()
	images := strings.Join([]string{
		"aaa ghcr.io/knt048/vedette-core",
		"aaa localhost/vedette-core",
		"bbb localhost/vedette-scan-nmap",
		"ccc localhost/vedette-foo",
		"ddd localhost/vedette-core-custom",
		"eee localhost/vedette-sensor",
		"eee localhost/mytag",
		"fff ghcr.io/knt048/vedette-honeypot",
		"ggg docker.io/library/nginx",
		"hhh ghcr.io/knt048/vedette-coreX",
		"iii <none>",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "images"), []byte(images), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeProgram(t, dir, "podman", `case "$1" in
images) [ "$2" = -a ] && exit 0; cat "$FAKE/images" ;;
rmi) echo "$*" >>"$FAKE/calls" ;;
*) exit 1 ;;
esac
`)
	out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir}, []string{"remove_images"}, "remove_images")
	if err != nil {
		t.Fatalf("remove_images: %v\n%s", err, out)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
	if got, want := string(calls), "rmi -f aaa\nrmi -f bbb\nrmi -f fff\n"; got != want {
		t.Fatalf("rmi calls:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(out, "WARNING: image eee is Vedette's but also has a name that is not Vedette's") {
		t.Fatalf("no warning for the shared image eee:\n%s", out)
	}
}

// D-409 (Opus r2 N4 of D-267): forward_check warns when the bridge vedette0 is not there although the network file names it
// (a network vedette-int left by an earlier install keeps its old bridge, the DOCKER-USER rules never match), instead of
// reporting the rules as in place; with the bridge there it goes on to the rules as before.
func TestInstallSh_ForwardCheckNeedsTheBridge(t *testing.T) {
	for name, tc := range map[string]struct {
		ipExit   string
		wantWarn bool
	}{"no vedette0": {"1", true}, "vedette0 there": {"0", false}} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			nf := filepath.Join(dir, "vedette-int.network")
			if err := os.WriteFile(nf, []byte("[Network]\nSubnet=172.30.77.0/24\nPodmanArgs=--interface-name=vedette0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fakeProgram(t, dir, "iptables", "exit 0\n")
			fakeProgram(t, dir, "ip", `echo "$*" >>"$FAKE/ip.calls"; exit `+tc.ipExit+"\n")
			out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "NETWORK_FILE=" + nf},
				[]string{"forward_check", "fwd_rules_present"}, "forward_check")
			if err != nil {
				t.Fatalf("forward_check: %v\n%s", err, out)
			}
			ipArgs, _ := os.ReadFile(filepath.Join(dir, "ip.calls")) //nolint:gosec // G304: a file of the test's own temp dir
			if string(ipArgs) != "-o link show dev vedette0\n" {
				t.Fatalf("ip was called with %q", ipArgs)
			}
			warned := strings.Contains(out, "WARNING: the container network vedette-int has no bridge named vedette0")
			if warned != tc.wantWarn || strings.Contains(out, "Docker is on this box") == tc.wantWarn {
				t.Fatalf("output:\n%s", out)
			}
		})
	}
}

// D-463: --uninstall wipes podman's storage and runtime files, and removes the folders podman made, only when the script added
// podman and apt then purged it. A podman that apt kept is the administrator's: nothing of it is wiped, not even by --keep-data.
func TestInstallSh_UninstallWipesPodmanOnlyWhenPodmanIsGone(t *testing.T) {
	body := installShFunc(t, "do_uninstall")
	const gate = "\tif grep -qx podman \"$STATE/asked-packages\" 2>/dev/null && ! installed_pkg podman; then\n"
	i := strings.Index(body, gate)
	if i < 0 {
		t.Fatalf("do_uninstall has no gate %q", gate)
	}
	j := strings.Index(body[i:], "\n\tfi\n")
	if j < 0 {
		t.Fatal("the gate has no end")
	}
	inside, outside := body[i:i+j], ""
	for l := range strings.Lines(body[:i] + body[i+j:]) {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") { // the commands, not the comments that name the folders
			outside += l
		}
	}
	for _, w := range []string{"find /var/lib/containers -mindepth 1 -delete", "rm -rf /run/containers", "/etc/containers/networks", "/var/lib/cni", "dpkg-query -S"} {
		if !strings.Contains(inside, w) {
			t.Errorf("%q is not inside the gate", w)
		}
	}
	for _, w := range []string{"/var/lib/containers", "/run/containers", "rm -rf /etc/containers", "/var/lib/cni"} {
		if strings.Contains(outside, w) {
			t.Errorf("%q is outside the gate", w)
		}
	}
	if strings.Contains(inside, "rm -rf /etc") || strings.Contains(inside, "rm -rf /var/lib/cni") {
		t.Error("a folder of /etc/containers or /var/lib/cni is removed with rm -r, not rmdir")
	}
}
