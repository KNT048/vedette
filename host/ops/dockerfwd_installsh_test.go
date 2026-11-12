package ops_test

import (
	"context"
	"os"
	"os/exec" //nolint:depguard // the test runs install.sh's own sh functions with a fixed argv; SYS-1 is about the product
	"strings"
	"testing"
)

// installShFunc is the text of the sh function name of install.sh.
func installShFunc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "\n"+name+"() {\n")
	if i < 0 {
		t.Fatalf("no %s in install.sh", name)
	}
	j := strings.Index(s[i+1:], "\n}\n")
	if j < 0 {
		t.Fatalf("%s has no end", name)
	}
	return s[i+1:i+1+j+2] + "\n"
}

// D-267, D-396: what install.sh checks (fwd_rules_present) and removes (remove_forward_rules, --uninstall) is what the
// host writes. The host fills the fake DOCKER-USER chain (an uplink br-lan, an administrator's rules), then install.sh's
// own sh functions run against the same fake iptables: -C in the host's words finds all five fixed rules, the DROP among
// them; -D removes every rule of ours, the DROP and a gone bridge's ACCEPT too, and nothing of the administrator's.
func TestInstallSh_ForwardRulesOfTheHost(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	uplink(t, m, "br-lan")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	// rules of the administrator: below our block, one with our comment but not bound to vedette0, and one above
	admin := []string{"-s 192.0.2.0/24 -j RETURN", "-i eth0 -o eth1 -m comment --comment vedette-int -j DROP"}
	for _, r := range admin {
		m.DockerAdminRule(r)
	}
	m.DockerAdminRuleFirst("-s 198.51.100.0/24 -j DROP")
	// the ACCEPT of a bridge that is gone (the host never deletes; --uninstall must)
	m.DockerAdminRule(accTo("br-old"))
	rulesAre(t, m, append(append([]string{"-s 198.51.100.0/24 -j DROP", accTo("br-lan")}, fixedRules...), append(admin, accTo("br-old"))...)...)

	fns := "set -eu\nhave() { command -v \"$1\" >/dev/null 2>&1; }\n" + installShFunc(t, "fwd_rules_present") + installShFunc(t, "remove_forward_rules")
	run := func(call string) error {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "sh", "-c", fns+call) //nolint:gosec // the sh functions of install.sh under test; the subnet is fixed
		cmd.Env = append(os.Environ(), "PATH="+m.Bin+":"+os.Getenv("PATH"), "TMP="+t.TempDir())
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			t.Logf("%s: %s", call, out)
		}
		return err
	}

	if err := run("fwd_rules_present 172.30.77.0/24"); err != nil {
		t.Fatalf("fwd_rules_present does not find the five rules the host wrote: %v", err)
	}
	m.DockerDelete(drop)
	if run("fwd_rules_present 172.30.77.0/24") == nil {
		t.Fatal("fwd_rules_present says present without the DROP of D-396")
	}
	m.DockerAdminRule(drop) // back, below the administrator's rules: remove_forward_rules finds ours wherever they stand

	if err := run("remove_forward_rules"); err != nil {
		t.Fatalf("remove_forward_rules: %v", err)
	}
	rulesAre(t, m, append([]string{"-s 198.51.100.0/24 -j DROP"}, admin...)...)
	if run("fwd_rules_present 172.30.77.0/24") == nil {
		t.Fatal("fwd_rules_present says present after the uninstall removed the rules")
	}
	var deleted []string
	for _, c := range calls(m) {
		if strings.Contains(c, " -D ") {
			deleted = append(deleted, c)
		}
	}
	want := []string{"-w 5 -D DOCKER-USER " + accTo("br-lan")}
	for _, r := range fixedRules[:4] {
		want = append(want, "-w 5 -D DOCKER-USER "+r)
	}
	want = append(want, "-w 5 -D DOCKER-USER "+accTo("br-old"), "-w 5 -D DOCKER-USER "+drop)
	if strings.Join(deleted, "\n") != strings.Join(want, "\n") {
		t.Fatalf("deletes:\n%s\nwant:\n%s", strings.Join(deleted, "\n"), strings.Join(want, "\n"))
	}

	// no DOCKER-USER chain (no Docker, or Docker gone): nothing to do, no failure
	m.DockerChain(false)
	if err := run("remove_forward_rules"); err != nil {
		t.Fatalf("remove_forward_rules without the chain: %v", err)
	}
}
