package ops_test

import (
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the test runs install.sh's own sh functions with a fixed argv; SYS-1 is about the product
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/internal/release"
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
ps) ;;
*) exit 1 ;;
esac
`)
	out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "TMP=" + t.TempDir()}, []string{"remove_images", "rmi_ours", "others_use", "pm"}, "remove_images")
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
// names and a count (images counted by ID); a podman that cannot be asked, or that hung, is kept (fail closed); --keep-data always
// keeps it, also its storage when podman is not installed (review M3); only a podman that holds nothing else, without --keep-data, is
// left to the purge as before (D-463). Nothing is read through a file, so a $TMP that cannot be written changes nothing (review M2).
// Names from podman are cut to printable characters and 64 bytes.
func TestInstallSh_UninstallKeepsAPodmanThatHoldsOthers(t *testing.T) {
	var greenbone []string
	for i := range 21 {
		greenbone = append(greenbone, "greenbone-"+string(rune('a'+i)))
	}
	vedetteOnly := map[string]string{
		"ctr": "vedette-core\n", "pod": "", "net": "podman\nvedette-int\n", "vol": "vedette-hp-log\n",
		"img": "a1 ghcr.io/knt048/vedette-core\nb2 localhost/vedette-scan-nmap\nc3 <none>\nd4 localhost/podman-pause\n",
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
		absent    bool   // podman is not installed
		tmpFile   bool   // $TMP is a regular file: nothing can be written under it
		wantKeep  string // a part of KEEP_PODMAN; empty: podman is left to the purge
		wantInUse bool
	}{
		"greenbone next to vedette": {
			lists: map[string]string{
				"ctr": "vedette-core\n" + strings.Join(greenbone, "\n") + "\n", "pod": "",
				"net": "podman\nvedette-int\ngreenbone-community-edition_default\n", "vol": "vedette-hp-log\ngvmd_data_vol\n",
				"img": "a1 ghcr.io/knt048/vedette-core\ne5 registry.community.greenbone.net/community/gvmd\ne5 registry.community.greenbone.net/community/gvmd\nc3 <none>\n",
			},
			wantKeep:  "kept? 21 containers, 1 network, 1 volume and 1 image that are not Vedette's use it (greenbone-a, greenbone-b, greenbone-c, greenbone-d, greenbone-e, and 19 more)",
			wantInUse: true,
		},
		"one stopped container": {lists: with("ctr", "mydb\n"), wantKeep: "1 container that is not Vedette's uses it (mydb)", wantInUse: true},
		"a pod":                 {lists: with("pod", "web\n"), wantKeep: "1 pod that is not Vedette's uses it (web)", wantInUse: true},
		"only an image":         {lists: with("img", "f6 docker.io/library/nginx\n"), wantKeep: "1 image that is not Vedette's uses it (docker.io/library/nginx)"},
		"images by ID":          {lists: with("img", "g1 r.example/gvmd\ng1 r.example/gvmd\ng2 r.example/gvmd\n"), wantKeep: "2 images that are not Vedette's use it (r.example/gvmd)"},
		"only a volume":         {lists: with("vol", "pgdata\n"), wantKeep: "1 volume that is not Vedette's uses it (pgdata)"},
		"a hostile name": {
			lists:     with("ctr", "x\x1b[31m"+strings.Repeat("a", 100)+"\n"),
			wantKeep:  "1 container that is not Vedette's uses it (x??31m" + strings.Repeat("a", 58) + "...)",
			wantInUse: true,
		},
		"TMP cannot be written":          {lists: with("ctr", "mydb\n"), tmpFile: true, wantKeep: "1 container that is not Vedette's uses it (mydb)", wantInUse: true},
		"podman does not answer":         {lists: vedetteOnly, psExit: "125", wantKeep: "could not check what else uses it", wantInUse: true},
		"podman hangs":                   {lists: vedetteOnly, psExit: "124", wantKeep: "could not check what else uses it", wantInUse: true},
		"nothing else, --keep-data":      {lists: vedetteOnly, keepData: "1", wantKeep: "--keep-data was given"},
		"no podman, --keep-data":         {lists: vedetteOnly, keepData: "1", absent: true, wantKeep: "--keep-data was given"},
		"no podman":                      {lists: vedetteOnly, absent: true},
		"nothing else, a full uninstall": {lists: vedetteOnly},
	} {
		t.Run(name, func(t *testing.T) {
			dir, state, tmp := t.TempDir(), t.TempDir(), t.TempDir()
			for k, v := range tc.lists {
				if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.tmpFile {
				tmp = filepath.Join(dir, "tmp-is-a-file")
				if err := os.WriteFile(tmp, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(state, "asked-packages"), []byte("chrony\npodman\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			installed, have := "podman\n", ""
			if tc.absent {
				// podman may be on the PATH of the machine that runs the test
				installed, have = "", "have() { [ \"$1\" != podman ] && command -v \"$1\" >/dev/null 2>&1; }\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "installed"), []byte(installed), 0o600); err != nil {
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
					"KEEP_PODMAN=", "PODMAN_IN_USE=", "PODMAN_OURS=", "OTHERS=", "PS_EXIT=" + tc.psExit, "LC_ALL=C"},
				[]string{"podman_stays", "podman_others", "others_text", "by_us_packages", "pm"},
				installShLine(t, "installed_pkg")+have+`podman_stays
printf 'keep=%s\nuse=%s\nours=%s\n' "$KEEP_PODMAN" "$PODMAN_IN_USE" "$PODMAN_OURS"
`)
			if err != nil {
				t.Fatalf("podman_stays: %v\n%s", err, out)
			}
			_, rest, _ := strings.Cut(out, "keep=")
			keep, _, _ := strings.Cut(rest, "\n")
			if want := strings.TrimPrefix(tc.wantKeep, "kept? "); (tc.wantKeep == "") != (keep == "") || !strings.Contains(keep, want) {
				t.Errorf("KEEP_PODMAN %q, want %q\n%s", keep, want, out)
			}
			if inUse := strings.Contains(out, "\nuse=1\n"); inUse != tc.wantInUse {
				t.Errorf("PODMAN_IN_USE %v, want %v\n%s", inUse, tc.wantInUse, out)
			}
			if !strings.Contains(out, "\nours=1\n") {
				t.Errorf("podman is in asked-packages but PODMAN_OURS is not set\n%s", out)
			}
			if hung := strings.Contains(out, "did not answer in 60 s"); hung != (tc.psExit == "124") {
				t.Errorf("hang warning %v, want %v\n%s", hung, tc.psExit == "124", out)
			}
		})
	}
}

// W4-1, D-508: purge_added_packages with a podman that stays purges none of the packages podman runs with (by name, and its Depends
// and Recommends down the tree as apt-cache gives them: netavark Recommends nftables, which it drives; review H1), marks the ones the
// script asked for manual again, and still purges what else the script added. The same holds for the administrator's own podman, which
// the script did not add (D-463). With nothing keeping podman it purges podman and its dependencies as before. apt is a small fake:
// apt-cache honours --recurse, --installed and --no-recommends; autoremove offers an auto-marked package that no installed package
// Depends on, a purge also removes what Depends on the package.
func TestInstallSh_PurgeKeepsThePackagesOfAPodmanThatStays(t *testing.T) {
	const all = "aardvark-dns chrony conmon crun libgpgme11 libnftables1 netavark nftables podman"
	for name, tc := range map[string]struct {
		keep          string
		asked, byUs   string
		auto          string
		wantInstalled string
		wantManual    string
	}{
		"podman stays": {
			keep: "21 containers that are not Vedette's use it", asked: "chrony netavark nftables podman", byUs: all,
			auto:          "aardvark-dns conmon crun libgpgme11 libnftables1",
			wantInstalled: "aardvark-dns conmon crun libgpgme11 libnftables1 netavark nftables podman", wantManual: "manual netavark nftables podman",
		},
		"the administrator's own podman": {
			asked: "chrony nftables", byUs: "chrony nftables",
			wantInstalled: "aardvark-dns conmon crun libgpgme11 libnftables1 netavark nftables podman", wantManual: "manual nftables",
		},
		"nothing keeps podman": {
			asked: "chrony netavark nftables podman", byUs: all, auto: "aardvark-dns conmon crun libgpgme11 libnftables1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, state, tmp := t.TempDir(), t.TempDir(), t.TempDir()
			lines := func(w string) string { return strings.Join(strings.Fields(w), "\n") + "\n" }
			files := map[string]string{
				"installed": lines(all),
				"auto":      lines(tc.auto),
				// deps.<p> / recs.<p>: what p Depends on / Recommends; needs.<p>: the packages that Depend on p
				// libnftables1 is reached only through a Recommends (podman > netavark > nftables > libnftables1), so only a keep list
				// that follows Recommends down the tree has it
				"deps.podman": "conmon\ncrun\nlibgpgme11\n", "recs.podman": "netavark\n", "recs.netavark": "aardvark-dns\nnftables\n",
				"deps.nftables": "libnftables1\n",
				"needs.conmon":  "podman\n", "needs.crun": "podman\n", "needs.libgpgme11": "podman\n", "needs.libnftables1": "nftables\n",
			}
			for k, v := range files {
				if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for k, v := range map[string]string{"asked-packages": lines(tc.asked), "installed-by-us": lines(tc.byUs)} {
				if err := os.WriteFile(filepath.Join(state, k), []byte(v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fakeProgram(t, dir, "dpkg-query", fakeDpkgQuery)
			fakeProgram(t, dir, "apt-cache", `[ "$1" = depends ] || exit 1
shift; rec=1; recurse=; inst=; root=
for a; do case $a in --no-recommends) rec= ;; --recurse) recurse=1 ;; --installed) inst=1 ;; -*) ;; *) root=$a ;; esac; done
seen=" "; queue=$root
while [ -n "$queue" ]; do
	set -- $queue; p=$1; shift; queue="$*"
	case $seen in *" $p "*) continue ;; esac
	seen="$seen$p "
	[ -z "$inst" ] || grep -qx "$p" "$FAKE/installed" || continue
	echo "$p"
	for d in $(cat "$FAKE/deps.$p" 2>/dev/null); do echo "  Depends: $d"; [ -z "$recurse" ] || queue="$queue $d"; done
	[ -z "$rec" ] || for d in $(cat "$FAKE/recs.$p" 2>/dev/null); do echo "  Recommends: $d"; [ -z "$recurse" ] || queue="$queue $d"; done
done
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
			keep, _ := os.ReadFile(filepath.Join(tmp, "keep")) //nolint:gosec // G304: a file of the test's own temp dir
			for _, p := range []string{"podman", "netavark", "aardvark-dns", "nftables", "iptables", "libnftables1", "conmon"} {
				if got := strings.Contains("\n"+string(keep), "\n"+p+"\n"); got != (tc.wantInstalled != "") {
					t.Errorf("%s on the keep list: %v, want %v\n%s", p, got, tc.wantInstalled != "", keep)
				}
			}
		})
	}
}

// fakePodmanUsers is a podman that logs every call to $FAKE/calls and answers "ps -a --filter <f>" from $FAKE/users.<f> (the filter
// with = and / as _), exists with yes, and images from $FAKE/images.
const fakePodmanUsers = `echo "$*" >>"$FAKE/calls"
case "$1 $2" in
"ps -a") f=$(printf '%s' "$4" | tr '=/' '__'); cat "$FAKE/users.$f" 2>/dev/null; exit 0 ;;
"network exists" | "volume exists") exit 0 ;;
"container exists") exit 1 ;; # no ZAP container (D-521)
"images --format") cat "$FAKE/images" ;;
"images -a") ;;
esac
exit 0
`

// D-508 review M1: Vedette's network and volumes are removed without -f, and an image of ours only when no container runs it: a
// container that is not Vedette's and is attached to vedette-int, mounts one of our volumes or runs one of our images keeps that thing
// (with a warning), so podman_others still sees the container and podman stays. A leftover container of Vedette's is not a reason to
// keep anything. This runs do_uninstall's own lines, from the network up to podman_stays.
func TestInstallSh_UninstallNeverForcesOutSomeoneElsesContainer(t *testing.T) {
	dir := t.TempDir()
	for k, v := range map[string]string{ //nolint:gosec // G101: the answers of the fake podman (a volume name has "creds" in it), no secret
		"users.network_vedette-int":         "caddy\n",
		"users.volume_vedette-hp-log":       "logship\n",
		"users.volume_vedette-creds-active": "vedette-core\n",
		"users.ancestor_aaa":                "web\nvedette-sensor\n",
		"users.ancestor_bbb":                "vedette-sensor\n",
		"images":                            "aaa ghcr.io/knt048/vedette-core\nbbb localhost/vedette-sensor\nccc ghcr.io/knt048/vedette-honeypot\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fakeProgram(t, dir, "podman", fakePodmanUsers)
	fakeProgram(t, dir, "nft", `echo "nft $*" >>"$FAKE/calls"
`) // the ZAP fence of D-521 (never the real nft)
	body := installShFunc(t, "do_uninstall")
	i := strings.Index(body, "\tif have podman; then\n\t\tremove_ours network vedette-int\n")
	j := strings.Index(body, "\tpodman_stays\n")
	if i < 0 || j < i {
		t.Fatalf("do_uninstall has no removal of the network and volumes before podman_stays:\n%s", body)
	}
	out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "TMP=" + t.TempDir(), "ZAP_IMAGE=" + ops.ZapImage},
		[]string{"remove_ours", "rmi_ours", "others_use", "remove_images", "pm", "remove_zap", "remove_zap_fence"}, body[i:j])
	if err != nil {
		t.Fatalf("removal: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
	var removed []string
	for l := range strings.Lines(string(raw)) {
		if f := strings.Fields(l); len(f) > 1 && (f[0] == "rmi" || f[1] == "rm") {
			removed = append(removed, strings.TrimSpace(l))
		}
	}
	if got, want := strings.Join(removed, "; "), "volume rm vedette-creds-passive; volume rm vedette-creds-active; rmi -f bbb; rmi -f ccc"; got != want {
		t.Errorf("removals:\n%s\nwant:\n%s", got, want)
	}
	for _, w := range []string{"the network vedette-int is Vedette's but a container that is not Vedette's uses it",
		"the volume vedette-hp-log is Vedette's but a container that is not Vedette's uses it", "image aaa is Vedette's but a container"} {
		if !strings.Contains(out, "WARNING: "+w) {
			t.Errorf("no warning %q:\n%s", w, out)
		}
	}
}

// D-508 review M4 and LOW: every podman call of the uninstall goes through pm: the variables that point podman at another instance or
// store are unset, and a call that hangs (timeout's 124 or 137) makes every later call fail at once and keeps podman, while the
// uninstall goes on. Here the first rm hangs: nothing else reaches podman, and podman_stays keeps it.
func TestInstallSh_UninstallKeepsAPodmanThatHangs(t *testing.T) {
	dir, tmp, state := t.TempDir(), t.TempDir(), t.TempDir()
	fakeProgram(t, dir, "podman", `echo "$* host=${CONTAINER_HOST-unset} conn=${CONTAINER_CONNECTION-unset} storage=${CONTAINERS_STORAGE_CONF-unset} conf=${CONTAINERS_CONF-unset}" >>"$FAKE/calls"
[ "$1" = rm ] && exit 124
exit 0
`)
	fakeProgram(t, dir, "dpkg-query", fakeDpkgQuery)
	if err := os.WriteFile(filepath.Join(dir, "installed"), []byte("podman\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runInstallShFns(t, dir,
		[]string{"FAKE=" + dir, "TMP=" + tmp, "STATE=" + state, "HOST_STATE=" + t.TempDir(), "KEEP_DATA=", "KEEP_PODMAN=", "PODMAN_IN_USE=",
			"PODMAN_OURS=", "OTHERS=", "CONTAINER_HOST=tcp://198.51.100.7:8888", "CONTAINER_CONNECTION=elsewhere",
			"CONTAINERS_STORAGE_CONF=/x/storage.conf", "CONTAINERS_CONF=/x/containers.conf", "LC_ALL=C"},
		[]string{"pm", "remove_ours", "others_use", "remove_images", "rmi_ours", "podman_stays", "podman_others", "others_text", "by_us_packages"},
		installShLine(t, "installed_pkg")+`for c in vedette-core vedette-sensor; do pm rm -f -t 5 "$c" >/dev/null || true; done
remove_ours network vedette-int
remove_images
podman_stays
printf 'keep=%s\nuse=%s\n' "$KEEP_PODMAN" "$PODMAN_IN_USE"
`)
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
	if got, want := string(calls), "rm -f -t 5 vedette-core host=unset conn=unset storage=unset conf=unset\n"; got != want {
		t.Errorf("podman calls:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(out, "keep=could not check what else uses it") || !strings.Contains(out, "\nuse=1\n") {
		t.Errorf("podman is not kept after a hang:\n%s", out)
	}
	if strings.Count(out, "did not answer in 60 s") != 1 {
		t.Errorf("want one hang warning:\n%s", out)
	}
}

// D-508 review: do_uninstall removes Vedette's own things first, then decides about podman (podman_stays), and only then restores the
// runtime and purges packages, so KEEP_PODMAN and PODMAN_IN_USE are known when they are read; the D-463 wipe comes last. Every podman
// call of the uninstall goes through pm (timeout, no environment), and nothing of ours is removed with -f but an image after its check.
func TestInstallSh_UninstallDecidesAboutPodmanBeforeThePurge(t *testing.T) {
	body := installShFunc(t, "do_uninstall")
	last := -1
	for _, step := range []string{
		"\t\t\tpm rm -f -t 5 \"$c\"", "\t\tremove_ours network vedette-int\n", "\t\t\tremove_ours volume \"$v\"\n", "\t\tremove_images\n",
		"\tpodman_stays\n", "\trestore_runtime\n", "\tpurge_added_packages\n", "\tif [ -z \"$KEEP_PODMAN\" ] && grep -qx podman",
	} {
		i := strings.Index(body, step)
		if i < 0 || strings.Count(body, step) != 1 {
			t.Fatalf("do_uninstall has %d of %q", strings.Count(body, step), step)
		}
		if i < last {
			t.Errorf("%q comes too early in do_uninstall", step)
		}
		last = i
	}
	direct := regexp.MustCompile(`(^|[;&|(]\s*|\$\(\s*|\bthen\s+|\bdo\s+)podman\s`)
	for _, fn := range []string{"do_uninstall", "remove_ours", "rmi_ours", "others_use", "remove_images", "podman_others", "forwarding_needed_elsewhere"} {
		for l := range strings.Lines(installShFunc(t, fn)) {
			c := strings.TrimSpace(l)
			if strings.HasPrefix(c, "#") || strings.HasPrefix(c, "say ") || strings.HasPrefix(c, "warn ") || strings.HasPrefix(c, "[ -n \"$KEEP_DATA\" ] || say") {
				continue
			}
			if direct.MatchString(c) {
				t.Errorf("%s calls podman without pm: %s", fn, c)
			}
			if strings.Contains(c, " rm -f vedette-int") || strings.Contains(c, "volume rm -f") || (strings.Contains(c, "rmi -f") && fn != "rmi_ours") {
				t.Errorf("%s removes with -f: %s", fn, c)
			}
		}
	}
}

// D-508 review LOW: the names install.sh --uninstall treats as Vedette's (the containers it removes by name, the network and volumes,
// the images, and the lists of podman_others and others_use that do not keep podman) are the ones the host makes: every service of
// host/api.Services, every volume and network the units mount, the registry and local image names and the scan build's. A new name in
// Go that the script does not know would keep podman on every box (a silent D-463 regression), so it fails here.
func TestInstallSh_UninstallKnowsVedettesPodmanNames(t *testing.T) {
	var ctrs, vols, imgs []string
	nets := []string{ops.IntNetwork}
	for _, s := range api.Services {
		ctrs = append(ctrs, "vedette-"+s)
		imgs = append(imgs, release.RegistryPrefix+s, ops.LocalPrefix+s)
		unit, err := ops.RenderUnit(s, "sha256:"+strings.Repeat("ab", 32), true, 1000, 1000, 1001, 1001)
		if err != nil {
			continue // greenbone has no unit (D-123 (2))
		}
		for l := range strings.Lines(string(unit)) {
			l = strings.TrimSpace(l)
			if v, ok := strings.CutPrefix(l, "Volume="); ok {
				if name, _, ok := strings.Cut(v, ".volume:"); ok && !slices.Contains(vols, name) {
					vols = append(vols, name)
				}
			}
			if v, ok := strings.CutPrefix(l, "Network="); ok {
				if name, ok := strings.CutSuffix(v, ".network"); ok && !slices.Contains(nets, name) {
					nets = append(nets, name)
				}
			}
		}
	}
	imgs = append(imgs, strings.TrimSuffix(ops.NmapTagPrefix, ":"))
	if len(vols) < 3 {
		t.Fatalf("the units mount only %v", vols)
	}
	dir := t.TempDir()
	var imgLines strings.Builder
	for i, n := range imgs {
		fmt.Fprintf(&imgLines, "id%02d %s\n", i, n)
	}
	for k, v := range map[string]string{
		"ctr": strings.Join(ctrs, "\n") + "\n", "net": "podman\n" + strings.Join(nets, "\n") + "\n", "vol": strings.Join(vols, "\n") + "\n",
		"img": imgLines.String(), "pod": "",
	} {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fakeProgram(t, dir, "podman", `case "$1 $2" in
"ps -a") cat "$FAKE/ctr" ;;
"pod ps") cat "$FAKE/pod" ;;
"network ls") cat "$FAKE/net" ;;
"volume ls") cat "$FAKE/vol" ;;
"images --format") cat "$FAKE/img" ;;
"images -a") ;;
"image inspect") [ "$5" = "$ZAP_IMAGE" ] && echo "zapimg 0" ;;
rmi*) echo "$*" >>"$FAKE/calls" ;;
esac
exit 0
`)
	out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "TMP=" + t.TempDir(), "OTHERS=", "LC_ALL=C", "ZAP_IMAGE=" + ops.ZapImage},
		[]string{"pm", "podman_others", "others_use", "rmi_ours", "remove_images"},
		`podman_others
printf 'others=[%s]\n' "$OTHERS"
if others_use ancestor=x; then echo "others_use=yes"; fi
remove_images
`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "others=[]\n") || strings.Contains(out, "others_use=yes") {
		t.Errorf("a name of Vedette's counts as someone else's:\n%s", out)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
	for i, n := range imgs {
		if !strings.Contains(string(calls), fmt.Sprintf("rmi -f id%02d\n", i)) {
			t.Errorf("remove_images leaves %s:\n%s", n, calls)
		}
	}
	if !strings.Contains(string(calls), "rmi -f zapimg\n") {
		t.Errorf("remove_images leaves the ZAP image (D-521):\n%s", calls)
	}
	body := installShFunc(t, "do_uninstall")
	for _, c := range ctrs {
		if !regexp.MustCompile(`\n\t\tfor c in ([^\n]* )?` + regexp.QuoteMeta(c) + `[ ;]`).MatchString(body) {
			t.Errorf("do_uninstall does not remove the container %s by name", c)
		}
	}
	for _, v := range vols {
		if !regexp.MustCompile(`\n\t\tfor v in ([^\n]* )?` + regexp.QuoteMeta(v) + `[ ;]`).MatchString(body) {
			t.Errorf("do_uninstall does not remove the volume %s", v)
		}
	}
	for _, n := range nets {
		if !strings.Contains(body, "remove_ours network "+n+"\n") {
			t.Errorf("do_uninstall does not remove the network %s", n)
		}
	}
	if !strings.Contains(body, "\t\tremove_zap\n") { // the container and network of zap.baseline, by their label (D-521)
		t.Error("do_uninstall does not call remove_zap")
	}
}

// D-521 (review L3, L11): --uninstall removes the container and the network vedette-zap only when they carry the label vedette-host
// gives them; one of that name without it is someone else's and stays, with a warning.
func TestInstallSh_RemoveZapOnlyTakesWhatCarriesTheLabel(t *testing.T) {
	for name, tc := range map[string]struct {
		label string
		want  string
	}{
		"ours":    {"vedette-host", "rm -f -t 5 " + ops.ZapContainer + "\nnetwork rm " + ops.ZapNetwork + "\n"},
		"foreign": {"", ""},
	} {
		dir := t.TempDir()
		fakeProgram(t, dir, "podman", `case "$1 $2" in
"container inspect"|"network inspect") [ -n "$LABEL" ] && echo "$LABEL" ;;
"container exists"|"network exists") exit 0 ;;
"ps -a") ;;
rm*|"network rm") echo "$*" >>"$FAKE/calls" ;;
*) exit 1 ;;
esac
exit 0
`)
		out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "TMP=" + t.TempDir(), "LABEL=" + tc.label},
			[]string{"pm", "others_use", "remove_ours", "remove_zap"}, "remove_zap")
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		calls, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
		if string(calls) != tc.want {
			t.Errorf("%s: calls %q, want %q", name, calls, tc.want)
		}
		if tc.label == "" && strings.Count(out, "is not Vedette's") != 2 {
			t.Errorf("%s: no warning for the container and the network:\n%s", name, out)
		}
	}
}

// Review 2 N1: --uninstall deletes the nft table of the passive web scan only when podman says plainly that the container is gone
// (exit 1 of "container exists") and was not found hung; any other answer keeps the fence, with a warning.
func TestInstallSh_TheZapFenceGoesOnlyWhenPodmanSaysTheContainerIsGone(t *testing.T) {
	for name, tc := range map[string]struct {
		rc     string
		hung   bool
		delete bool
	}{
		"gone":         {"1", false, true},
		"still there":  {"0", false, false},
		"podman error": {"125", false, false},
		"podman hung":  {"1", true, false},
	} {
		dir, tmp := t.TempDir(), t.TempDir()
		fakeProgram(t, dir, "podman", `[ "$1 $2" = "container exists" ] && exit "$RC"; exit 1
`)
		fakeProgram(t, dir, "nft", `echo "$*" >>"$FAKE/nft"; exit 0
`)
		if tc.hung {
			if err := os.WriteFile(filepath.Join(tmp, "podman.hung"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "TMP=" + tmp, "RC=" + tc.rc}, []string{"pm", "remove_zap_fence"}, "remove_zap_fence")
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		calls, _ := os.ReadFile(filepath.Join(dir, "nft")) //nolint:gosec // G304: a file of the test's own temp dir
		deleted := strings.Contains(string(calls), "delete table inet vedette_zap")
		if deleted != tc.delete {
			t.Errorf("%s: nft calls %q, delete wanted: %v", name, calls, tc.delete)
		}
		if !tc.delete && !strings.Contains(out, "kept the nft table inet vedette_zap") {
			t.Errorf("%s: no warning:\n%s", name, out)
		}
	}
}

// Review 2 L2: Vedette's own ZAP container that podman cannot remove is named as Vedette's, and its network is not then reported as
// used by "a container that is not Vedette's".
func TestInstallSh_RemoveZapSaysWhenItsOwnContainerIsStuck(t *testing.T) {
	dir := t.TempDir()
	fakeProgram(t, dir, "podman", `case "$1 $2" in
"container inspect"|"network inspect") echo vedette-host ;;
"ps -a") ;;
rm*) exit 125 ;;
"network rm") echo "$*" >>"$FAKE/calls" ;;
*) exit 0 ;;
esac
exit 0
`)
	out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "TMP=" + t.TempDir()}, []string{"pm", "others_use", "remove_ours", "remove_zap"},
		`remove_zap
echo "stuck=[$ZAP_STUCK]"`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Vedette's ZAP container vedette-zap could not be removed") || !strings.Contains(out, "stuck=[1]") || strings.Contains(out, "not Vedette's") {
		t.Fatalf("%s", out)
	}
	if calls, _ := os.ReadFile(filepath.Join(dir, "calls")); len(calls) != 0 { //nolint:gosec // G304: a file of the test's own temp dir
		t.Fatalf("the network was removed under a container that still runs: %q", calls)
	}
}
