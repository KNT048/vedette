package host_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

func testCAPEM(t *testing.T, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// writeBoxAgent writes what Vedette's Linux install command leaves on a machine: the pinned CA, the flags, the secret, the restart
// drop-in and osquery's database.
func writeBoxAgent(e *sysEnv, ca, tlsHost string) {
	e.m.WriteRoot("etc/osquery/vedette-ca.pem", ca)
	e.m.WriteRoot("etc/osquery/enroll.secret", "vdt_osquery_0123456789abcdef0123456789abcdef")
	e.m.WriteRoot("etc/osquery/osquery.conf", "{}\n")
	e.m.WriteRoot("etc/osquery/osquery.flags", "--config_plugin=tls\n--logger_plugin=tls\n--host_identifier=specified\n--specified_identifier=vedette-box\n"+
		"--enroll_secret_path=/etc/osquery/enroll.secret\n--tls_server_certs=/etc/osquery/vedette-ca.pem\n--tls_hostname="+tlsHost+"\n--config_refresh=300\n")
	e.m.WriteRoot("etc/systemd/system/osqueryd.service.d/vedette-restart.conf", "[Service]\nRestart=on-failure\nRestartSec=10\n")
	e.m.WriteRoot("var/osquery/osquery.db/CURRENT", "MANIFEST-000001\n")
}

func boxAgentLeft(e *sysEnv) []string {
	var left []string
	for _, rel := range []string{"etc/osquery/vedette-ca.pem", "etc/osquery/enroll.secret", "etc/osquery/osquery.flags", "etc/osquery/osquery.conf",
		"etc/systemd/system/osqueryd.service.d/vedette-restart.conf", "etc/systemd/system/osqueryd.service.d", "var/osquery/osquery.db"} {
		if _, err := os.Lstat(filepath.Join(e.m.Root, rel)); err == nil {
			left = append(left, rel)
		}
	}
	return left
}

// After a reinstall or a data purge the box has a new CA, and the osquery agent someone installed on the box itself still pins the old
// one: box_agent.check stops and disables it with the one fixed systemctl argv and removes its Vedette settings; the osquery package
// and osquery.conf stay. An agent that pins the CA in use, or reports to another box, is left as it is; a box with no agent has nothing.
func TestContract_BoxAgent_AStaleAgentOnTheBoxIsStoppedAndItsSettingsRemoved(t *testing.T) {
	t.Parallel()
	lan := func(_ *ops.Config, d *ops.Deps) {
		d.Interfaces = func() ([]ops.HostIface, error) {
			return []ops.HostIface{{Name: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}}}, nil
		}
	}
	current, old := testCAPEM(t, "vedette-selfsigned-ca"), testCAPEM(t, "vedette-selfsigned-ca")

	t.Run("no agent", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, lan)
		if res := result[api.BoxAgentCheckResult](t, e.ok(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current})); res.State != api.BoxAgentNone {
			t.Fatalf("state = %q", res.State)
		}
		if n := len(e.m.Calls("systemctl")); n != 0 {
			t.Fatalf("systemctl ran %d times", n)
		}
	})
	t.Run("the agent pins the CA in use", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, lan)
		writeBoxAgent(e, current, "192.0.2.10:8443")
		if res := result[api.BoxAgentCheckResult](t, e.ok(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: old + current})); res.State != api.BoxAgentCurrent {
			t.Fatalf("state = %q", res.State)
		}
		if left := boxAgentLeft(e); len(left) != 7 || len(e.m.Calls("systemctl")) != 0 {
			t.Fatalf("a current agent was touched: left %q, systemctl %q", left, e.m.Calls("systemctl"))
		}
	})
	for name, host := range map[string]string{"by address": "192.0.2.10:8443", "by host name": "vedette-box:8443", "by full name": "VEDETTE-BOX.:8443", "on loopback": "[::1]:8443"} {
		t.Run("a stale agent reporting to the box "+name, func(t *testing.T) {
			t.Parallel()
			e := startSys(t, lan)
			writeBoxAgent(e, old, host)
			r := e.ok(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current})
			if res := result[api.BoxAgentCheckResult](t, r); res.State != api.BoxAgentRemoved {
				t.Fatalf("state = %q", res.State)
			}
			if got := e.m.Calls("systemctl"); !slices.EqualFunc(got, [][]string{{"disable", "--now", "osqueryd.service"}, {"daemon-reload"}}, slices.Equal) {
				t.Fatalf("systemctl argv = %q", got)
			}
			assertEnvClean(t, e.m.Envs("systemctl"))
			if left := boxAgentLeft(e); !slices.Equal(left, []string{"etc/osquery/osquery.conf"}) {
				t.Fatalf("left after the removal: %q, want only osquery.conf", left)
			}
			// the next start finds nothing to do
			if res := result[api.BoxAgentCheckResult](t, e.ok(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current})); res.State != api.BoxAgentNone {
				t.Fatalf("second check = %q", res.State)
			}
		})
	}
	t.Run("an agent of this machine that reports to another box", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, lan)
		writeBoxAgent(e, old, "203.0.113.5:8443")
		if res := result[api.BoxAgentCheckResult](t, e.ok(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current})); res.State != api.BoxAgentElsewhere {
			t.Fatalf("state = %q", res.State)
		}
		if left := boxAgentLeft(e); len(left) != 7 || len(e.m.Calls("systemctl")) != 0 {
			t.Fatalf("an agent of another box was touched: left %q, systemctl %q", left, e.m.Calls("systemctl"))
		}
	})
	t.Run("an osquery of this machine that pins another file reports to another server and is not touched", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, lan)
		writeBoxAgent(e, old, "127.0.0.1:8412")
		// someone pointed this osquery at a server of their own (here through a local port) and left the old vedette-ca.pem behind
		e.m.WriteRoot("etc/osquery/osquery.flags", "--enroll_secret_path=/etc/osquery/enroll.secret\n--tls_server_certs=/etc/osquery/fleet.pem\n--tls_hostname=127.0.0.1:8412\n")
		if res := result[api.BoxAgentCheckResult](t, e.ok(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current})); res.State != api.BoxAgentNone {
			t.Fatalf("state = %q", res.State)
		}
		if left := boxAgentLeft(e); len(left) != 7 || len(e.m.Calls("systemctl")) != 0 {
			t.Fatalf("an osquery set up for another server was touched: left %q, systemctl %q", left, e.m.Calls("systemctl"))
		}
	})
	for name, body := range map[string]string{"empty (being written)": "", "cut short": old[:len(old)/2], "not a certificate": "garbage\n"} {
		t.Run("a pinned CA that is "+name+" is a doubt: nothing is removed", func(t *testing.T) {
			t.Parallel()
			e := startSys(t, lan)
			writeBoxAgent(e, old, "192.0.2.10:8443")
			e.m.WriteRoot("etc/osquery/vedette-ca.pem", body)
			e.final(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current}, api.StatusFailed, api.CodeEffectNotVerified)
			if left := boxAgentLeft(e); len(left) != 7 || len(e.m.Calls("systemctl")) != 0 {
				t.Fatalf("an agent whose CA could not be read was touched: left %q, systemctl %q", left, e.m.Calls("systemctl"))
			}
		})
	}
	t.Run("a link in place of the pinned CA is not what the install command writes", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, lan)
		writeBoxAgent(e, old, "192.0.2.10:8443")
		e.m.RemoveRoot("etc/osquery/vedette-ca.pem")
		e.m.WriteRoot("elsewhere.pem", old)
		if err := os.Symlink("../../elsewhere.pem", filepath.Join(e.m.Root, "etc/osquery/vedette-ca.pem")); err != nil {
			t.Fatal(err)
		}
		e.final(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: current}, api.StatusFailed, api.CodeEffectNotVerified)
		if len(e.m.Calls("systemctl")) != 0 {
			t.Fatalf("systemctl ran: %q", e.m.Calls("systemctl"))
		}
	})
}

// The one argument is the anchor core gives: anything but PEM certificates of at most 16 KiB is 400 invalid_args and never reaches
// the system.
func TestContract_BoxAgent_TheAnchorIsChecked(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	ca := testCAPEM(t, "x")
	for _, bad := range []string{"", "not pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		strings.Repeat(ca, api.MaxBoxAgentCA/len(ca)+1)} {
		e.refused(t, api.CmdBoxAgentCheck, api.BoxAgentCheckArgs{CA: bad}, http.StatusBadRequest, api.CodeInvalidArgs)
	}
	if n := len(e.m.Calls("systemctl")); n != 0 {
		t.Fatalf("systemctl ran %d times", n)
	}
}
