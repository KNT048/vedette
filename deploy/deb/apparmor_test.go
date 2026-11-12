package deb

import (
	"os"
	"os/exec" //nolint:depguard // the test runs apparmor_parser and the postinst's own shell functions: fixed argv, no product code
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// The AppArmor profile of the Vedette containers (D-458): deploy/deb/vedette-container.apparmor, installed as
// /etc/apparmor.d/vedette-container and selected by every unit through ops.AppArmorConfModule. The rules that matter are pinned
// line for line: Podman's own signal and ptrace rules, with the peer of this profile also matched stacked with any other profile in
// any position (the kernel orders a stack by name, so crun's stack is "crun//&vedette-container").

const profileFile = "vedette-container.apparmor"

// codeLines are the profile's lines without comments and blanks, trimmed.
func codeLines(t *testing.T) []string {
	t.Helper()
	var out []string
	for l := range strings.SplitSeq(string(repoFile(t, "deploy/deb/"+profileFile)), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "#include") {
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		out = append(out, l)
	}
	return out
}

func TestAppArmorProfile_NameAndRules(t *testing.T) {
	t.Parallel()
	lines := codeLines(t)
	var heads, rules []string
	for _, l := range lines {
		if strings.HasPrefix(l, "profile ") {
			heads = append(heads, l)
		}
		if strings.HasPrefix(l, "signal") || strings.HasPrefix(l, "ptrace") {
			rules = append(rules, l)
		}
	}
	if want := []string{"profile " + ops.AppArmorProfile + " flags=(attach_disconnected,mediate_deleted) {"}; !slices.Equal(heads, want) {
		t.Errorf("profile lines %q, want %q", heads, want)
	}
	stacked := "peer={,**//&}" + ops.AppArmorProfile + "{,//&**},"
	want := []string{
		"signal (receive) peer=unconfined,",
		"signal (send,receive) " + stacked,
		"signal (receive) peer={/usr/bin/,/usr/sbin/,}runc,",
		"signal (receive) peer={/usr/bin/,/usr/sbin/,}crun*,",
		"signal (receive) peer={/usr/bin/,/usr/sbin/,}podman,",
		"ptrace (trace,read) " + stacked,
	}
	if !slices.Equal(rules, want) {
		t.Errorf("signal and ptrace rules\n%q\nwant exactly\n%q", rules, want)
	}
	// Podman's denials stay (a sample of each kind), and nothing loosens the profile
	for _, need := range []string{"#include <tunables/global>", "#include <abstractions/base>", "deny mount,", "deny @{PROC}/sysrq-trigger rwklx,",
		"deny @{PROC}/kcore rwklx,", "deny /sys/firmware/** rwklx,", "deny /sys/kernel/security/** rwklx,", "deny @{PROC}/* w,"} {
		if !slices.Contains(lines, need) {
			t.Errorf("the profile lacks %q", need)
		}
	}
	for _, l := range lines {
		if regexp.MustCompile(`unconfined\)|complain|change_profile|\b[uUpPcC]x\b|^pivot_root|^mount\b`).MatchString(l) {
			t.Errorf("the profile loosens confinement: %q", l)
		}
	}
}

// The profile compiles with the machine's apparmor_parser (without loading it: no root needed). Skipped where AppArmor's tools or
// its include files are missing; the lab loads it on Ubuntu 24.04, 26.04 and Debian 13 (.ai/deferred).
func TestAppArmorProfile_Compiles(t *testing.T) {
	t.Parallel()
	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		for _, p := range []string{"/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"} {
			if _, e := os.Stat(p); e == nil {
				parser, err = p, nil
			}
		}
	}
	if err != nil {
		t.Skip("apparmor_parser is not installed")
	}
	if _, err := os.Stat("/etc/apparmor.d/abstractions/base"); err != nil {
		t.Skip("no /etc/apparmor.d/abstractions/base")
	}
	out, err := exec.CommandContext(t.Context(), parser, "--skip-kernel-load", "--skip-cache", "--skip-read-cache", profileFile).CombinedOutput() //nolint:gosec // test: fixed argv
	if err != nil {
		t.Fatalf("apparmor_parser: %v\n%s", err, out)
	}
}

// shFunc is the text of a shell function of the postinst, from "name() {" to its closing brace.
func shFunc(t *testing.T, text, name string) string {
	t.Helper()
	i := strings.Index(text, name+"() {")
	if i < 0 {
		t.Fatalf("the postinst has no %s", name)
	}
	j := strings.Index(text[i:], "\n}\n")
	if j < 0 {
		t.Fatalf("%s has no end", name)
	}
	return text[i : i+j+3]
}

// The postinst checks that the profile compiles before it creates anything, and loads it (then reads the kernel's list) only where
// AppArmor can be managed, as dh_apparmor does; a failure stops the package. This runs its real functions with aa-enabled,
// apparmor_parser and grep replaced by recorders on PATH.
func TestPostinst_LoadsTheAppArmorProfile(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("postinst")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "\nAA_PROFILE=/etc/apparmor.d/"+ops.AppArmorProfile+"\n") {
		t.Fatalf("the postinst does not name /etc/apparmor.d/%s", ops.AppArmorProfile)
	}
	// order: compiled in step 1 (before the accounts), loaded before the unit is enabled and the host restarted
	conf := text[strings.Index(text, "\nconfigure)"):]
	if c, a, l, e := strings.Index(conf, "\tcheck_profile\n"), strings.Index(conf, "# 2. accounts"), strings.Index(conf, "\tload_profile\n"), strings.Index(conf, "\tenable_unit\n"); c < 0 || a < 0 || l < 0 || e < 0 || c > a || l > e {
		t.Errorf("configure must call check_profile before the accounts and load_profile before enable_unit (%d %d %d %d)", c, a, l, e)
	}
	fns := shFunc(t, text, "fail") + shFunc(t, text, "aa_on") + shFunc(t, text, "check_profile") + shFunc(t, text, "load_profile")
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	// run: enabled is the exit code of aa-enabled ("" = not installed), parserRC and grepRC those of the other two; files is how
	// the profile and the disable link are: "ok" (file, no link), "missing" (no file), "disabled" (a link), "dangling" (a broken link)
	type result struct {
		calls string
		out   string
		ok    bool
	}
	run := func(t *testing.T, enabled, parserRC, grepRC, files string) result {
		t.Helper()
		bin := t.TempDir()
		etc := t.TempDir()
		prof, dis := filepath.Join(etc, "vedette-container"), filepath.Join(etc, "disable", "vedette-container")
		if files != "missing" {
			if err := os.WriteFile(prof, []byte("profile vedette-container {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if files == "disabled" || files == "dangling" {
			target := prof
			if files == "dangling" {
				target = filepath.Join(etc, "gone")
			}
			if err := os.MkdirAll(filepath.Dir(dis), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dis); err != nil {
				t.Fatal(err)
			}
		}
		log := filepath.Join(bin, "calls")
		put := func(name, rc string) {
			if rc == "" {
				return
			}
			s := "#!" + sh + "\necho \"${0##*/} $*\" >> " + log + "\nexit " + rc + "\n"
			if err := os.WriteFile(filepath.Join(bin, name), []byte(s), 0o755); err != nil { //nolint:gosec // test: a recorder script in a temp dir
				t.Fatal(err)
			}
		}
		put("aa-enabled", enabled)
		put("apparmor_parser", parserRC)
		put("grep", grepRC)
		cmd := exec.CommandContext(t.Context(), sh, "-c", "set -eu\nAA_PROFILE="+prof+"\nAA_DISABLE="+dis+"\n"+fns+"check_profile\nload_profile\necho DONE\n") //nolint:gosec // test: the postinst's own functions
		cmd.Env = []string{"PATH=" + bin}
		out, _ := cmd.CombinedOutput()
		got, _ := os.ReadFile(log) //nolint:gosec // test: the recorder file this test created
		return result{calls: strings.ReplaceAll(string(got), prof, "<profile>"), out: string(out), ok: strings.Contains(string(out), "DONE")}
	}
	if r := run(t, "", "0", "0", "missing"); !r.ok || r.calls != "" {
		t.Errorf("without aa-enabled nothing runs (not even the file check): %+v", r)
	}
	if r := run(t, "1", "0", "0", "disabled"); !r.ok || r.calls != "aa-enabled --quiet\naa-enabled --quiet\n" {
		t.Errorf("AppArmor off: only the question: %+v", r)
	}
	want := "aa-enabled --quiet\napparmor_parser --skip-kernel-load --skip-cache <profile>\n" +
		"aa-enabled --quiet\napparmor_parser --replace --skip-read-cache --write-cache <profile>\n" +
		"grep -Eq ^vedette-container \\((enforce|complain)\\)$ /sys/kernel/security/apparmor/profiles\n"
	if r := run(t, "0", "0", "0", "ok"); !r.ok || r.calls != want {
		t.Errorf("AppArmor on: compile, load, read the kernel's list: %+v\nwant\n%q", r, want)
	}
	if r := run(t, "0", "1", "0", "ok"); r.ok {
		t.Error("a profile that does not compile must stop the postinst")
	}
	if r := run(t, "0", "0", "1", "ok"); r.ok {
		t.Error("a profile the kernel does not list must stop the postinst")
	}
	if r := run(t, "0", "", "0", "ok"); r.ok {
		t.Error("AppArmor on without apparmor_parser must stop the postinst")
	}
	// a deleted conffile (dpkg never restores it on upgrade): refused before the parser, with the command that brings it back
	if r := run(t, "0", "0", "0", "missing"); r.ok || strings.Contains(r.calls, "apparmor_parser") ||
		!strings.Contains(r.out, "is missing") || !strings.Contains(r.out, "apt-get install --reinstall -o Dpkg::Options::=--force-confmiss vedette-host") {
		t.Errorf("a missing profile file: %+v", r)
	}
	// an administrator's disable link (aa-disable), even a broken one: refused, never loaded anyway
	for _, f := range []string{"disabled", "dangling"} {
		if r := run(t, "0", "0", "0", f); r.ok || strings.Contains(r.calls, "apparmor_parser") || !strings.Contains(r.out, "disables the AppArmor profile vedette-container") {
			t.Errorf("%s: %+v", f, r)
		}
	}
	// the kernel-list pattern accepts the profile in enforce and complain mode and nothing else
	m := regexp.MustCompile(`grep -Eq '([^']+)' /sys/kernel/security/apparmor/profiles`).FindStringSubmatch(text)
	if m == nil {
		t.Fatal("the postinst has no grep of the kernel's profile list")
	}
	re := regexp.MustCompile(m[1])
	for line, want := range map[string]bool{
		"vedette-container (enforce)": true, "vedette-container (complain)": true, "vedette-container (kill)": false,
		"vedette-container-x (enforce)": false, "crun//&vedette-container (enforce)": false,
	} {
		if re.MatchString(line) != want {
			t.Errorf("%q matched = %t, want %t", line, !want, want)
		}
	}
}
