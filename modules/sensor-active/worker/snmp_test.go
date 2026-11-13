package worker_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/internal/snmptest"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// No test here sends a packet off the machine: the targets are pointed at fake agents on loopback (snmptest).

const junosDescr = "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9, Build date: 2019-08-30 12:00:00 UTC Copyright (c) 1996-2019 Juniper Networks, Inc."

func juniper() map[string]any {
	return map[string]any{snmptest.SysDescr: junosDescr, snmptest.SysObjectID: snmptest.Object(".1.3.6.1.4.1.2636.1.1.1.2.31"), snmptest.SysName: "SW-CORE-01"}
}

func fortigate() map[string]any {
	return map[string]any{snmptest.SysDescr: "", snmptest.SysObjectID: snmptest.Object(".1.3.6.1.4.1.12356.101.1.15000"), snmptest.SysName: "FGT-HQ",
		snmptest.EntClass: 3, snmptest.EntModel: "FGT_1500D", snmptest.EntSoftware: "FortiGate-1500D v6.4.8,build1914,211117 (GA)", snmptest.EntSerial: "FG1K5D3I00000000"}
}

// startSNMP runs a worker whose SNMP requests go to the agents by target address; an address without an agent goes to a closed
// port. A request waits 50 ms for its answer, so "no answer" takes 100 ms.
func startSNMP(t *testing.T, agents map[string]*snmptest.Agent) *rig {
	t.Helper()
	ports := map[netip.Addr]uint16{}
	for ip, a := range agents {
		ports[netip.MustParseAddr(ip)] = a.Start(t)
	}
	closed := (&snmptest.Agent{}).Start(t) // an agent that serves nothing: no v2c, no v3
	return start(t, writeNmap(t, printXML), func(c *worker.Config) {
		c.SNMPTimeout = 50 * time.Millisecond
		c.SNMPDial = func(ip netip.Addr) (string, uint16) {
			if p, ok := ports[ip]; ok {
				return "127.0.0.1", p
			}
			return "127.0.0.1", closed
		}
	})
}

func snmpJob(id string, creds []sensorlink.SNMPCredential, targets ...sensorlink.SNMPTarget) sensorlink.Job {
	return sensorlink.Job{ID: id, Kind: sensorlink.KindSNMP, TimeoutS: 60, SNMP: &sensorlink.SNMPJob{Rate: 1000, Credentials: creds, Targets: targets}}
}

func v2c(c string) sensorlink.SNMPCredential {
	return sensorlink.SNMPCredential{Version: sensorlink.SNMPv2c, Community: c}
}

// D-512: the worker tries the credentials of a target in order until one is answered, reads the fixed objects with one GET and
// reports what the agent said; a target whose only community is wrong is "no answer", since an agent drops it without a word.
func TestSNMPReadsTheAgentWithTheCredentialThatAnswers(t *testing.T) {
	t.Parallel()
	sw := &snmptest.Agent{Community: "s3cret-community", Values: juniper()}
	fw := &snmptest.Agent{Community: "s3cret-community", Values: fortigate()}
	r := startSNMP(t, map[string]*snmptest.Agent{"192.168.10.20": sw, "192.168.10.21": fw, "192.168.10.22": {Community: "other"}})
	id := strings.Repeat("5", 32)
	r.core.push(snmpJob(id, []sensorlink.SNMPCredential{v2c("public"), v2c("s3cret-community")},
		sensorlink.SNMPTarget{IP: "192.168.10.20", Credentials: []int{0, 1}},
		sensorlink.SNMPTarget{IP: "192.168.10.21", Credentials: []int{1}},
		sensorlink.SNMPTarget{IP: "192.168.10.22", Credentials: []int{0, 1}}))
	got := r.core.next(t)
	if got.id != id || got.res.Status != "done" || len(got.res.SNMP) != 3 {
		t.Fatalf("result %+v", got.res)
	}
	a := got.res.SNMP[0]
	if a.Target != "192.168.10.20" || a.Status != sensorlink.SNMPStatusOK || a.Credential != 1 || a.Values.SysDescr != junosDescr ||
		a.Values.SysObjectID != ".1.3.6.1.4.1.2636.1.1.1.2.31" || a.Values.SysName != "SW-CORE-01" || a.Values.EntModel != "" {
		t.Errorf("the switch: %+v", a)
	}
	if f := got.res.SNMP[1]; f.Status != sensorlink.SNMPStatusOK || f.Values.EntClass != "3" || f.Values.EntModel != "FGT_1500D" ||
		!strings.HasPrefix(f.Values.EntSoftware, "FortiGate-1500D v6.4.8") || f.Values.EntSerial == "" {
		t.Errorf("the firewall: %+v", f)
	}
	if n := got.res.SNMP[2]; n.Status != sensorlink.SNMPStatusNoAnswer || n.Credential != 1 || n.Values != (sensorlink.SNMPValues{}) {
		t.Errorf("the wrong community: %+v", n)
	}
	if sw.Requests() != 3 { // public twice (the retry), then the right one once
		t.Errorf("the switch got %d requests, want 3", sw.Requests())
	}
}

// D-512: SNMPv3 authPriv (SHA, AES-128) and authNoPriv (SHA-256) are read; a user the agent does not know and a wrong password
// are told apart from no answer (both are "auth_failed": gosnmp takes no unauthenticated report after the discovery).
func TestSNMPv3(t *testing.T) {
	t.Parallel()
	priv := func() *snmptest.Agent {
		return &snmptest.Agent{Values: juniper(), V3: &gosnmp.UsmSecurityParameters{UserName: "vedette", AuthenticationProtocol: gosnmp.SHA,
			AuthenticationPassphrase: "auth-pass-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-1"}}
	}
	auth := &snmptest.Agent{Values: fortigate(), V3: &gosnmp.UsmSecurityParameters{UserName: "ro", AuthenticationProtocol: gosnmp.SHA256, //nolint:gosec // G101: a test password of a fake agent
		AuthenticationPassphrase: "auth-pass-2", PrivacyProtocol: gosnmp.NoPriv}}
	r := startSNMP(t, map[string]*snmptest.Agent{"10.0.0.1": priv(), "10.0.0.2": auth, "10.0.0.3": priv(), "10.0.0.4": priv()})
	good := sensorlink.SNMPCredential{Version: sensorlink.SNMPv3, User: "vedette", Auth: sensorlink.SNMPAuthSHA, AuthPass: "auth-pass-1", Priv: sensorlink.SNMPPrivAES128, PrivPass: "priv-pass-1"}
	sha256 := sensorlink.SNMPCredential{Version: sensorlink.SNMPv3, User: "ro", Auth: sensorlink.SNMPAuthSHA256, AuthPass: "auth-pass-2"} //nolint:gosec // G101: a test password of a fake agent
	stranger := good
	stranger.User = "nobody"
	wrong := good
	wrong.AuthPass = "auth-pass-X"
	id := strings.Repeat("6", 32)
	r.core.push(snmpJob(id, []sensorlink.SNMPCredential{good, sha256, stranger, wrong},
		sensorlink.SNMPTarget{IP: "10.0.0.1", Credentials: []int{0}},
		sensorlink.SNMPTarget{IP: "10.0.0.2", Credentials: []int{1}},
		sensorlink.SNMPTarget{IP: "10.0.0.3", Credentials: []int{2}},
		sensorlink.SNMPTarget{IP: "10.0.0.4", Credentials: []int{3}}))
	got := r.core.next(t)
	if len(got.res.SNMP) != 4 {
		t.Fatalf("result %+v", got.res)
	}
	for i, want := range []string{sensorlink.SNMPStatusOK, sensorlink.SNMPStatusOK, sensorlink.SNMPStatusAuthFailed, sensorlink.SNMPStatusAuthFailed} {
		if a := got.res.SNMP[i]; a.Status != want {
			t.Errorf("%s: %s, want %s", a.Target, a.Status, want)
		}
	}
	if got.res.SNMP[0].Values.SysName != "SW-CORE-01" || got.res.SNMP[1].Values.EntModel != "FGT_1500D" {
		t.Errorf("values: %+v", got.res.SNMP[:2])
	}
}

// An agent that refuses the whole request (an error status for one object it does not have) is asked again for the system
// group alone.
func TestSNMPAgentThatRefusesTheEntityObjects(t *testing.T) {
	t.Parallel()
	old := &snmptest.Agent{Community: "c0mmunity", Values: juniper(), ErrorStatus: gosnmp.NoSuchName}
	r := startSNMP(t, map[string]*snmptest.Agent{"192.168.1.9": old})
	r.core.push(snmpJob(strings.Repeat("7", 32), []sensorlink.SNMPCredential{v2c("c0mmunity")}, sensorlink.SNMPTarget{IP: "192.168.1.9", Credentials: []int{0}}))
	got := r.core.next(t)
	if len(got.res.SNMP) != 1 || got.res.SNMP[0].Status != sensorlink.SNMPStatusOK || got.res.SNMP[0].Values.SysName != "SW-CORE-01" || old.Requests() != 2 {
		t.Fatalf("result %+v, %d requests", got.res, old.Requests())
	}
}

// The worker checks the job again: a public address, a credential it does not know or a timeout over the hour is refused and
// nothing is sent.
func TestSNMPRefusesWhatTheGrammarForbids(t *testing.T) {
	t.Parallel()
	a := &snmptest.Agent{Community: "c", Values: juniper()}
	r := startSNMP(t, map[string]*snmptest.Agent{"8.8.8.8": a, "192.168.1.9": a})
	bad := []sensorlink.Job{
		snmpJob(strings.Repeat("1", 32), []sensorlink.SNMPCredential{v2c("c")}, sensorlink.SNMPTarget{IP: "8.8.8.8", Credentials: []int{0}}),
		snmpJob(strings.Repeat("2", 32), []sensorlink.SNMPCredential{{Version: "v1", Community: "c"}}, sensorlink.SNMPTarget{IP: "192.168.1.9", Credentials: []int{0}}),
		snmpJob(strings.Repeat("3", 32), []sensorlink.SNMPCredential{v2c("c")}, sensorlink.SNMPTarget{IP: "127.0.0.1", Credentials: []int{0}}),
	}
	long := snmpJob(strings.Repeat("4", 32), []sensorlink.SNMPCredential{v2c("c")}, sensorlink.SNMPTarget{IP: "192.168.1.9", Credentials: []int{0}})
	long.TimeoutS = sensorlink.MaxSNMPSeconds + 1
	for _, j := range append(bad, long) {
		r.core.push(j)
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" {
			t.Errorf("%s: %+v", j.ID, got.res)
		}
	}
	if a.Requests() != 0 {
		t.Errorf("%d requests were sent", a.Requests())
	}
}

// D-512: the heartbeat of this worker says it runs snmp jobs.
func TestHeartbeatSaysSNMP(t *testing.T) {
	t.Parallel()
	r := startSNMP(t, nil)
	select {
	case hb := <-r.core.beats:
		if !hb.SNMP {
			t.Errorf("heartbeat %+v", hb)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no heartbeat")
	}
}
