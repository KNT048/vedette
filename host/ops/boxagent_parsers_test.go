package ops_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// vedette-host (box_agent.check) and install.sh (--uninstall) decide from the same files whether the osquery on the box is Vedette's
// agent. Both fail closed, and they must agree byte for byte: the same inputs go through the Go parsers and install.sh's, and each case
// says what both must answer. Anything osquery would read differently from the plain form (an indent is fine: osquery trims it too)
// is a doubt.
func TestBoxAgentParsersAgree(t *testing.T) {
	const ca, host = "--tls_server_certs=/etc/osquery/vedette-ca.pem", "--tls_hostname=192.0.2.10:8443"
	installer := "--config_plugin=tls\n--logger_plugin=tls\n--host_identifier=specified\n--specified_identifier=vedette-box\n--enroll_secret_path=/etc/osquery/enroll.secret\n" +
		ca + "\n" + host + "\n--enroll_tls_endpoint=/api/v1/intake/osquery/enroll\n--config_tls_endpoint=/api/v1/intake/osquery/config\n--config_refresh=300\n--logger_tls_endpoint=/api/v1/intake/osquery/log\n"
	flags := []struct {
		name, in string
		ours     bool
		host     string
	}{
		{"the install command's file", installer, true, "192.0.2.10:8443"},
		{"no final newline", ca + "\n" + host, true, "192.0.2.10:8443"},
		{"CRLF line ends", ca + "\r\n" + host + "\r\n", true, "192.0.2.10:8443"},
		{"indent and trailing spaces", "  \t" + ca + " \t\n\v" + host + "\f\n\n", true, "192.0.2.10:8443"},
		{"IPv6 host", ca + "\n--tls_hostname=[2001:db8::10]:8443\n", true, "[2001:db8::10]:8443"},
		{"the last --tls_hostname counts", ca + "\n--tls_hostname=203.0.113.5:8443\n" + host + "\n", true, "192.0.2.10:8443"},
		{"an indented line repoints the CA", ca + "\n" + host + "\n   --tls_server_certs=/etc/osquery/fleet.pem\n", false, ""},
		{"the last CA line is another file", ca + "\n--tls_server_certs=/etc/fleet/ca.pem\n", false, ""},
		{"no CA line", host + "\n", false, ""},
		{"empty file", "", false, ""},
		{"single dash", ca + "\n" + host + "\n-tls_server_certs=/etc/fleet/ca.pem\n", false, ""},
		{"single dash anywhere", "-verbose=true\n" + ca + "\n", false, ""},
		{"flagfile include", ca + "\n--flagfile=/etc/fleet/osquery.flags\n", false, ""},
		{"flagfile at the end, indented", ca + "\n\t--flagfile=/dev/null\n", false, ""},
		{"space form", ca + "\n--tls_server_certs /etc/fleet/ca.pem\n", false, ""},
		{"double quotes", "--tls_server_certs=\"/etc/osquery/vedette-ca.pem\"\n", false, ""},
		{"single quotes", "--tls_server_certs='/etc/osquery/vedette-ca.pem'\n", false, ""},
		{"a comment line", "# managed by hand\n" + ca + "\n", false, ""},
		{"a boolean flag with no value", ca + "\n--disable_watchdog\n", false, ""},
		{"an upper-case name", ca + "\n--TLS_SERVER_CERTS=/etc/fleet/ca.pem\n", false, ""},
		{"a space inside the value", ca + "\n--tls_hostname=a b:8443\n", false, ""},
		{"a NUL byte", ca + "\n" + host + "\x00junk\n", false, ""},
		{"a CR in the middle", ca + "\r--tls_server_certs=/etc/fleet/ca.pem\n", false, ""},
		{"non-ASCII", ca + "\n--tls_hostname=hộp:8443\n", false, ""},
		{"a shell character", ca + "\n--tls_hostname=$(reboot):8443\n", false, ""},
	}
	bin, dir := t.TempDir(), t.TempDir()
	for i, c := range flags {
		t.Run("flags/"+c.name, func(t *testing.T) {
			gotHost, gotOurs := ops.BoxAgentFlagsOwned([]byte(c.in))
			if gotOurs != c.ours || gotHost != c.host {
				t.Errorf("Go: ours=%v host=%q, want ours=%v host=%q", gotOurs, gotHost, c.ours, c.host)
			}
			f := filepath.Join(dir, fmt.Sprintf("flags-%d", i))
			if err := os.WriteFile(f, []byte(c.in), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runInstallShFns(t, bin, nil, []string{"osq_flags_owned"}, `if h=$(osq_flags_owned "`+f+`"); then echo "ours host=$h"; else echo "not ours"; fi`)
			if err != nil {
				t.Fatalf("install.sh: %v\n%s", err, out)
			}
			want := "not ours"
			if c.ours {
				want = "ours host=" + c.host
			}
			if strings.TrimSpace(out) != want {
				t.Errorf("install.sh: %q, want %q", strings.TrimSpace(out), want)
			}
		})
	}

	exec := func(argv string) string {
		return "ExecStart={ path=/opt/osquery/bin/osqueryd ; argv[]=" + argv + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
	}
	pkg := "/opt/osquery/bin/osqueryd --flagfile $FLAG_FILE --config_path $CONFIG_FILE"
	envf := "EnvironmentFiles=/etc/default/osqueryd (ignore_errors=no)\n"
	units := []struct {
		name, show, defaults string
		ours                 bool
	}{
		{"the package's unit", exec(pkg) + "Environment=\n" + envf, pkgDefaults, true},
		{"the fixed path in the start command, no environment", exec("/usr/bin/osqueryd --flagfile=/etc/osquery/osquery.flags") + "Environment=\n", "", true},
		{"FLAG_FILE unquoted, braces, CRLF", exec("/opt/osquery/bin/osqueryd --flagfile ${FLAG_FILE}") + "Environment=\n" + envf, "FLAG_FILE=/etc/osquery/osquery.flags\r\n", true},
		{"another flag file in the start command", exec("/opt/osquery/bin/osqueryd --flagfile /etc/fleet/osquery.flags --config_path $CONFIG_FILE") + "Environment=\n" + envf, pkgDefaults, false},
		{"a flag on the command line", exec(pkg+" --tls_server_certs=/etc/fleet/ca.pem") + "Environment=\n" + envf, pkgDefaults, false},
		{"two --flagfile", exec("/opt/osquery/bin/osqueryd --flagfile /etc/osquery/osquery.flags --flagfile /etc/fleet/x.flags") + "Environment=\n", "", false},
		{"no --flagfile", exec("/opt/osquery/bin/osqueryd --config_path $CONFIG_FILE") + "Environment=\n" + envf, pkgDefaults, false},
		{"not osqueryd", exec("/usr/local/bin/fleetd --flagfile /etc/osquery/osquery.flags") + "Environment=\n", "", false},
		{"two start commands", strings.TrimSuffix(exec(pkg), "\n") + " { path=/x ; argv[]=/opt/osquery/bin/osqueryd --flagfile /etc/osquery/osquery.flags ; }\n" + "Environment=\n" + envf, pkgDefaults, false},
		{"no unit", "Environment=\n", pkgDefaults, false},
		{"Environment sets FLAG_FILE", exec(pkg) + "Environment=FLAG_FILE=/etc/fleet/osquery.flags\n" + envf, pkgDefaults, false},
		{"another environment file", exec(pkg) + "Environment=\nEnvironmentFiles=/etc/fleet/env (ignore_errors=no)\n", pkgDefaults, false},
		{"two environment files", exec(pkg) + "Environment=\n" + envf + "EnvironmentFiles=/etc/fleet/env (ignore_errors=no)\n", pkgDefaults, false},
		{"the defaults name another flag file", exec(pkg) + "Environment=\n" + envf, "FLAG_FILE=\"/etc/fleet/osquery.flags\"\n", false},
		{"the defaults name it, then another", exec(pkg) + "Environment=\n" + envf, pkgDefaults + "FLAG_FILE=/etc/fleet/osquery.flags\n", false},
		{"the defaults export it", exec(pkg) + "Environment=\n" + envf, "export FLAG_FILE=/etc/osquery/osquery.flags\n", false},
		{"single quotes in the defaults", exec(pkg) + "Environment=\n" + envf, "FLAG_FILE='/etc/osquery/osquery.flags'\n", false},
		{"no defaults file", exec(pkg) + "Environment=\n" + envf, "", false},
	}
	for i, c := range units {
		t.Run("unit/"+c.name, func(t *testing.T) {
			if got := ops.BoxAgentUnitUsesFlags(c.show, []byte(c.defaults)); got != c.ours {
				t.Errorf("Go: %v, want %v", got, c.ours)
			}
			show, def := filepath.Join(dir, fmt.Sprintf("show-%d", i)), filepath.Join(dir, fmt.Sprintf("def-%d", i))
			if err := os.WriteFile(show, []byte(c.show), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(def, []byte(c.defaults), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runInstallShFns(t, bin, nil, []string{"osq_unit_parse"}, `if osq_unit_parse "`+def+`" <"`+show+`"; then echo ours; else echo "not ours"; fi`)
			if err != nil {
				t.Fatalf("install.sh: %v\n%s", err, out)
			}
			want := map[bool]string{true: "ours", false: "not ours"}[c.ours]
			if strings.TrimSpace(out) != want {
				t.Errorf("install.sh: %q, want %q", strings.TrimSpace(out), want)
			}
		})
	}
}
