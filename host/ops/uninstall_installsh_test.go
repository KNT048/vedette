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

// D-463, D-508: --uninstall wipes podman's storage and runtime files, and removes the folders podman made, only when the script added
// podman, nothing decided to keep it (KEEP_PODMAN: someone else's containers, no answer, --keep-data) and apt then purged it. A podman
// that apt kept is the administrator's: nothing of it is wiped, not even by --keep-data.
func TestInstallSh_UninstallWipesPodmanOnlyWhenPodmanIsGone(t *testing.T) {
	body := installShFunc(t, "do_uninstall")
	const gate = "\tif [ -z \"$KEEP_PODMAN\" ] && grep -qx podman \"$STATE/asked-packages\" 2>/dev/null && ! installed_pkg podman; then\n"
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
		// the commands, not the comments or the messages (say) that name the folders
		if !strings.HasPrefix(strings.TrimSpace(l), "#") && !strings.Contains(l, "say \"") {
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

// installShLine is the one-line sh function name of install.sh ("name() { ...; }").
func installShLine(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for l := range strings.Lines(string(raw)) {
		if strings.HasPrefix(l, name+"() { ") {
			return l
		}
	}
	t.Fatalf("no one-line %s in install.sh", name)
	return ""
}

// fakeDpkgQuery answers installed_pkg from $FAKE/installed (one package per line).
const fakeDpkgQuery = `p=; for a; do p=$a; done
grep -qx "$p" "$FAKE/installed" && printf installed
exit 0
`

// W4-1, D-508: on kien's N100 an uninstall with --keep-data purged the podman the installer had added and wiped /var/lib/containers
// with 21 Greenbone containers in it. podman_stays reads what the rootful podman holds after Vedette's own things are gone: anything
// that is not Vedette's (a stopped container, a pod, a network, a volume, a named image) keeps podman and says why, with at most five
// names and a count; a podman that cannot be asked is kept (fail closed); --keep-data always keeps it; only a podman that holds nothing
// else, without --keep-data, is left to the purge as before (D-463). Names from podman are cut to printable characters and 64 bytes.
func TestInstallSh_UninstallKeepsAPodmanThatHoldsOthers(t *testing.T) {
	var greenbone []string
	for i := range 21 {
		greenbone = append(greenbone, "greenbone-"+string(rune('a'+i)))
	}
	vedetteOnly := map[string]string{
		"ctr": "vedette-core\n", "pod": "", "net": "podman\nvedette-int\n", "vol": "vedette-hp-log\n",
		"img": "ghcr.io/knt048/vedette-core\nlocalhost/vedette-scan-nmap\n<none>\nlocalhost/podman-pause\n",
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range vedetteOnly {
			m[a] = b
		}
		m[k] += v
		return m
	}
	for name, tc := range map[string]struct {
		lists     map[string]string
		psExit    string
		keepData  string
		wantKeep  string // a part of KEEP_PODMAN; empty: podman is left to the purge
		wantInUse bool
	}{
		"greenbone next to vedette": {
			lists: map[string]string{
				"ctr": "vedette-core\n" + strings.Join(greenbone, "\n") + "\n", "pod": "",
				"net": "podman\nvedette-int\ngreenbone-community-edition_default\n", "vol": "vedette-hp-log\ngvmd_data_vol\n",
				"img": "ghcr.io/knt048/vedette-core\nregistry.community.greenbone.net/community/gvmd\nregistry.community.greenbone.net/community/gvmd\n<none>\n",
			},
			wantKeep:  "kept? 21 containers, 1 network, 1 volume and 1 image that are not Vedette's use it (greenbone-a, greenbone-b, greenbone-c, greenbone-d, greenbone-e, and 19 more)",
			wantInUse: true,
		},
		"one stopped container": {lists: with("ctr", "mydb\n"), wantKeep: "1 container that is not Vedette's uses it (mydb)", wantInUse: true},
		"a pod":                 {lists: with("pod", "web\n"), wantKeep: "1 pod that is not Vedette's uses it (web)", wantInUse: true},
		"only an image":         {lists: with("img", "docker.io/library/nginx\n"), wantKeep: "1 image that is not Vedette's uses it (docker.io/library/nginx)"},
		"only a volume":         {lists: with("vol", "pgdata\n"), wantKeep: "1 volume that is not Vedette's uses it (pgdata)"},
		"a hostile name": {
			lists:     with("ctr", "x\x1b[31m"+strings.Repeat("a", 100)+"\n"),
			wantKeep:  "1 container that is not Vedette's uses it (x??31m" + strings.Repeat("a", 58) + "...)",
			wantInUse: true,
		},
		"podman does not answer":         {lists: vedetteOnly, psExit: "125", wantKeep: "could not check what else uses it", wantInUse: true},
		"nothing else, --keep-data":      {lists: vedetteOnly, keepData: "1", wantKeep: "--keep-data was given"},
		"nothing else, a full uninstall": {lists: vedetteOnly},
	} {
		t.Run(name, func(t *testing.T) {
			dir, state, tmp := t.TempDir(), t.TempDir(), t.TempDir()
			for k, v := range tc.lists {
				if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(state, "asked-packages"), []byte("chrony\npodman\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "installed"), []byte("podman\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fakeProgram(t, dir, "dpkg-query", fakeDpkgQuery)
			fakeProgram(t, dir, "podman", `case "$1 $2" in
"ps -a") cat "$FAKE/ctr"; exit ${PS_EXIT:-0} ;;
"pod ps") cat "$FAKE/pod" ;;
"network ls") cat "$FAKE/net" ;;
"volume ls") cat "$FAKE/vol" ;;
"images --format") cat "$FAKE/img" ;;
*) exit 1 ;;
esac
`)
			// the names of the hostile case hold an ESC: printf in the fake, not in the file
			if name == "a hostile name" {
				if err := os.WriteFile(filepath.Join(dir, "ctr"), []byte("vedette-core\nx\x1b[31m"+strings.Repeat("a", 100)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runInstallShFns(t, dir,
				[]string{"FAKE=" + dir, "STATE=" + state, "HOST_STATE=" + t.TempDir(), "TMP=" + tmp, "KEEP_DATA=" + tc.keepData,
					"KEEP_PODMAN=", "PODMAN_IN_USE=", "PODMAN_OURS=", "PS_EXIT=" + tc.psExit, "LC_ALL=C"},
				[]string{"podman_stays", "podman_others", "others_text", "by_us_packages"},
				installShLine(t, "installed_pkg")+`podman_stays
printf 'keep=%s\nuse=%s\nours=%s\n' "$KEEP_PODMAN" "$PODMAN_IN_USE" "$PODMAN_OURS"
`)
			if err != nil {
				t.Fatalf("podman_stays: %v\n%s", err, out)
			}
			keep := strings.TrimPrefix(strings.SplitN(out, "\n", 2)[0], "keep=")
			if want := strings.TrimPrefix(tc.wantKeep, "kept? "); (tc.wantKeep == "") != (keep == "") || !strings.Contains(keep, want) {
				t.Errorf("KEEP_PODMAN %q, want %q", keep, want)
			}
			if inUse := strings.Contains(out, "\nuse=1\n"); inUse != tc.wantInUse {
				t.Errorf("PODMAN_IN_USE %v, want %v\n%s", inUse, tc.wantInUse, out)
			}
			if !strings.Contains(out, "\nours=1\n") {
				t.Errorf("podman is in asked-packages but PODMAN_OURS is not set\n%s", out)
			}
		})
	}
}

// W4-1, D-508: purge_added_packages with a podman that stays purges none of the packages podman runs with (by name, its Depends down
// the tree as apt-cache gives them), marks the ones the script asked for manual again, and still purges what else the script added;
// with nothing keeping podman it purges podman and its dependencies as before (D-463). apt is a small fake: autoremove offers an
// auto-marked package that no installed package needs, a purge also removes what needs the package.
func TestInstallSh_PurgeKeepsThePackagesOfAPodmanThatStays(t *testing.T) {
	for name, tc := range map[string]struct {
		keep          string
		wantInstalled string
		wantManual    string
	}{
		"podman stays":         {keep: "21 containers that are not Vedette's use it", wantInstalled: "aardvark-dns conmon crun libgpgme11 netavark podman", wantManual: "manual netavark podman"},
		"nothing keeps podman": {keep: "", wantInstalled: "", wantManual: ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir, state, tmp := t.TempDir(), t.TempDir(), t.TempDir()
			files := map[string]string{
				"installed": "aardvark-dns\nchrony\nconmon\ncrun\nlibgpgme11\nnetavark\npodman\n",
				"auto":      "aardvark-dns\nconmon\ncrun\nlibgpgme11\n",
				// aardvark-dns: only recommended (by netavark), so nothing in apt stops its purge; only the keep list does
				// needs.<p>: the packages that need p
				"needs.conmon": "podman\n", "needs.crun": "podman\n", "needs.libgpgme11": "podman\n", "needs.netavark": "podman\n",
			}
			for k, v := range files {
				if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for k, v := range map[string]string{"asked-packages": "chrony\nnetavark\npodman\n", "installed-by-us": "aardvark-dns\nchrony\nconmon\ncrun\nlibgpgme11\nnetavark\npodman\n"} {
				if err := os.WriteFile(filepath.Join(state, k), []byte(v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fakeProgram(t, dir, "dpkg-query", fakeDpkgQuery)
			fakeProgram(t, dir, "apt-cache", `printf 'podman\n  Depends: conmon\n |Depends: crun\n  Depends: libgpgme11\n  Recommends: netavark\nconmon\ncrun\nlibgpgme11\n'
`)
			fakeProgram(t, dir, "apt-mark", `case $1 in
showmanual) grep -vxFf "$FAKE/auto" "$FAKE/installed" || true ;;
auto) shift; for p; do echo "$p" >>"$FAKE/auto"; done ;;
manual) echo "$*" >>"$FAKE/calls"; shift; for p; do grep -vx "$p" "$FAKE/auto" >"$FAKE/a.new" || true; mv "$FAKE/a.new" "$FAKE/auto"; done ;;
esac
`)
			fakeProgram(t, dir, "apt-get", `sim=; words=
for a; do case $a in -s) sim=1 ;; -*|*::*) ;; *) words="$words $a" ;; esac; done
set -- $words
cmd=$1; shift
needed() { [ -f "$FAKE/needs.$1" ] || return 1; for u in $(cat "$FAKE/needs.$1"); do grep -qx "$u" "$FAKE/installed" && return 0; done; return 1; }
case $cmd in
autoremove) for p in $(cat "$FAKE/installed"); do if grep -qx "$p" "$FAKE/auto" && ! needed "$p"; then echo "Purg $p"; fi; done ;;
purge)
	for p; do
		echo "Purg $p"
		[ ! -f "$FAKE/needs.$p" ] || for u in $(cat "$FAKE/needs.$p"); do grep -qx "$u" "$FAKE/installed" && echo "Purg $u"; done
	done
	[ -n "$sim" ] && exit 0
	for p; do grep -vx "$p" "$FAKE/installed" >"$FAKE/i.new" || true; mv "$FAKE/i.new" "$FAKE/installed"; done >/dev/null ;;
*) exit 1 ;;
esac
exit 0
`)
			out, err := runInstallShFns(t, dir,
				[]string{"FAKE=" + dir, "STATE=" + state, "HOST_STATE=" + t.TempDir(), "TMP=" + tmp, "KEEP_PODMAN=" + tc.keep, "LC_ALL=C"},
				[]string{"purge_added_packages", "podman_pkgs", "by_us_packages", "apt_run"},
				installShLine(t, "installed_pkg")+installShLine(t, "apt_sim")+"purge_added_packages\n")
			if err != nil {
				t.Fatalf("purge_added_packages: %v\n%s", err, out)
			}
			installed, _ := os.ReadFile(filepath.Join(dir, "installed")) //nolint:gosec // G304: a file of the test's own temp dir
			if got := strings.Join(strings.Fields(string(installed)), " "); got != tc.wantInstalled {
				t.Errorf("installed after the purge: %q, want %q\n%s", got, tc.wantInstalled, out)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
			if got := strings.TrimSpace(string(calls)); got != tc.wantManual {
				t.Errorf("apt-mark calls %q, want %q", got, tc.wantManual)
			}
		})
	}
}
