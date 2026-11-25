package ops_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// install.sh --uninstall without --keep-data deletes the box CA with the data. An osquery agent set up on the box itself with Vedette's
// install command would pin a CA no box has any more: remove_box_agent stops it and removes what that command wrote (the osquery package
// and osquery.conf stay), the same files as vedette-host's box_agent.check. An agent that reports to another box is left alone.
func TestInstallSh_UninstallRemovesTheBoxsOwnStaleAgent(t *testing.T) {
	files := []string{"etc/osquery/vedette-ca.pem", "etc/osquery/enroll.secret", "etc/osquery/osquery.flags", "etc/osquery/osquery.conf",
		"etc/systemd/system/osqueryd.service.d/vedette-restart.conf", "var/osquery/osquery.db/CURRENT"}
	setup := func(t *testing.T, tlsHost string) (bin, root string) {
		t.Helper()
		bin, root = t.TempDir(), t.TempDir()
		for _, f := range files {
			body := "x\n"
			if strings.HasSuffix(f, "osquery.flags") {
				body = "--tls_server_certs=/etc/osquery/vedette-ca.pem\n--tls_hostname=" + tlsHost + "\n"
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, f), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		fakeProgram(t, bin, "hostname", `case "$1" in -s) echo vedette-box ;; -f) echo vedette-box.lan.example ;; *) echo vedette-box ;; esac`)
		fakeProgram(t, bin, "ip", `echo "2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n2: eth0    inet6 2001:db8::10/64 scope global"`)
		fakeProgram(t, bin, "getent", `[ "$2" = box.lan.example ] && echo "192.0.2.10      STREAM box.lan.example"; exit 0`)
		fakeProgram(t, bin, "systemctl", `echo "systemctl $*" >>"$FAKE/calls"`)
		return bin, root
	}
	left := func(root string) []string {
		var out []string
		for _, f := range files {
			if _, err := os.Lstat(filepath.Join(root, f)); err == nil {
				out = append(out, f)
			}
		}
		return out
	}
	for _, host := range []string{"192.0.2.10:8443", "vedette-box:8443", "VEDETTE-BOX.lan.example:8443", "box.lan.example:8443", "[2001:db8::10]:8443", "127.0.0.1:8443"} {
		t.Run(host, func(t *testing.T) {
			bin, root := setup(t, host)
			out, err := runInstallShFns(t, bin, []string{"OSQ_ROOT=" + root, "FAKE=" + bin}, []string{"names_this_machine", "remove_box_agent"}, "remove_box_agent")
			if err != nil {
				t.Fatalf("remove_box_agent: %v\n%s", err, out)
			}
			if got := left(root); !slices.Equal(got, []string{"etc/osquery/osquery.conf"}) {
				t.Fatalf("left: %q, want only osquery.conf\n%s", got, out)
			}
			if !strings.Contains(out, "run the install command from Devices › Setup › Agents on the box") {
				t.Fatalf("the message must say how to enrol it again:\n%s", out)
			}
		})
	}
	for _, host := range []string{"203.0.113.5:8443", "other-box.example:8443", "", "vedette-box;reboot:8443"} {
		t.Run("elsewhere "+host, func(t *testing.T) {
			bin, root := setup(t, host)
			out, err := runInstallShFns(t, bin, []string{"OSQ_ROOT=" + root, "FAKE=" + bin}, []string{"names_this_machine", "remove_box_agent"}, "remove_box_agent")
			if err != nil {
				t.Fatalf("remove_box_agent: %v\n%s", err, out)
			}
			if got := left(root); len(got) != len(files) {
				t.Fatalf("an agent of another box lost %q\n%s", got, out)
			}
		})
	}
	t.Run("no agent", func(t *testing.T) {
		bin, root := t.TempDir(), t.TempDir()
		out, err := runInstallShFns(t, bin, []string{"OSQ_ROOT=" + root, "FAKE=" + bin}, []string{"names_this_machine", "remove_box_agent"}, "remove_box_agent")
		if err != nil || out != "" {
			t.Fatalf("no agent: %v %q", err, out)
		}
	})
}
