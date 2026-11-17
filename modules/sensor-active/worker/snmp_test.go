package worker_test

import (
	"net/netip"
	"strings"
	"sync"
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
		c.SNMPDial = func(ip netip.Addr, port uint16) (string, uint16) {
			if p, ok := ports[ip]; ok && port == sensorlink.SNMPPort {
				return "127.0.0.1", p
			}
			return "127.0.0.1", closed
		}
	})
}

func snmpJob(id string, targets ...sensorlink.SNMPTarget) sensorlink.Job {
	return sensorlink.Job{ID: id, Kind: sensorlink.KindSNMP, TimeoutS: 60, SNMP: &sensorlink.SNMPJob{Rate: 1000, Targets: targets}}
}

func tgt(ip string, c sensorlink.SNMPCredential) sensorlink.SNMPTarget {
	return sensorlink.SNMPTarget{IP: ip, Credential: c}
}

func v2c(c string) sensorlink.SNMPCredential {
	return sensorlink.SNMPCredential{Version: sensorlink.SNMPv2c, Community: c}
}

// the worker sends each target its own credential, to the target's address and to no other, reads the fixed objects
// with one GET and reports what the agent said; a target whose community is wrong is "no answer", since an agent drops it without a
// word. Every request goes to a target's own address: the switch's community never reaches the firewall, nor the reverse.
func TestSNMPSendsEachTargetItsOwnCredentialOnly(t *testing.T) {
	t.Parallel()
	sw := &snmptest.Agent{Community: "switch-community", Values: juniper()}
	fw := &snmptest.Agent{Community: "firewall-community", Values: fortigate()}
	other := &snmptest.Agent{Community: "other"}
	agents := map[string]*snmptest.Agent{"192.168.10.20": sw, "192.168.10.21": fw, "192.168.10.22": other}
	ports := map[netip.Addr]uint16{}
	for ip, a := range agents {
		ports[netip.MustParseAddr(ip)] = a.Start(t)
	}
	var mu sync.Mutex
	var dialled []string
	r := start(t, writeNmap(t, printXML), func(c *worker.Config) {
		c.SNMPTimeout = 50 * time.Millisecond
		c.SNMPDial = func(ip netip.Addr, _ uint16) (string, uint16) {
			mu.Lock()
			dialled = append(dialled, ip.String())
			mu.Unlock()
			return "127.0.0.1", ports[ip]
		}
	})
	id := strings.Repeat("5", 32)
	r.core.push(snmpJob(id, tgt("192.168.10.20", v2c("switch-community")), tgt("192.168.10.21", v2c("firewall-community")),
		tgt("192.168.10.22", v2c("switch-community"))))
	got := r.core.next(t)
	if got.id != id || got.res.Status != "done" || len(got.res.SNMP) != 3 {
		t.Fatalf("result %+v", got.res)
	}
	a := got.res.SNMP[0]
	if a.Target != "192.168.10.20" || a.Status != sensorlink.SNMPStatusOK || a.Values.SysDescr != junosDescr ||
		a.Values.SysObjectID != ".1.3.6.1.4.1.2636.1.1.1.2.31" || a.Values.SysName != "SW-CORE-01" || a.Values.EntModel != "" {
		t.Errorf("the switch: %+v", a)
	}
	if f := got.res.SNMP[1]; f.Status != sensorlink.SNMPStatusOK || f.Values.EntClass != "3" || f.Values.EntModel != "FGT_1500D" ||
		!strings.HasPrefix(f.Values.EntSoftware, "FortiGate-1500D v6.4.8") || f.Values.EntSerial == "" {
		t.Errorf("the firewall: %+v", f)
	}
	if n := got.res.SNMP[2]; n.Status != sensorlink.SNMPStatusNoAnswer || n.Values != (sensorlink.SNMPValues{}) {
		t.Errorf("the wrong community: %+v", n)
	}
	if sw.Requests() != 1 || fw.Requests() != 1 || other.Requests() != 2 { // one each, the unanswered one sent twice (the retry)
		t.Errorf("requests: switch %d, firewall %d, other %d; want 1, 1, 2", sw.Requests(), fw.Requests(), other.Requests())
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(dialled, " ") != "192.168.10.20 192.168.10.21 192.168.10.22" {
		t.Errorf("dialled %v: a credential went to an address other than its target's", dialled)
	}
}

// A device that serves SNMP on another UDP port is read on the port its credential names; a credential without a
// port goes to 161 as before (here no agent listens there: no answer).
func TestSNMPReadsTheCredentialsPort(t *testing.T) {
	t.Parallel()
	agent := (&snmptest.Agent{Community: "s3cret-community", Values: juniper()}).Start(t)
	closed := (&snmptest.Agent{}).Start(t)
	var mu sync.Mutex
	var asked []uint16
	r := start(t, writeNmap(t, printXML), func(c *worker.Config) {
		c.SNMPTimeout = 50 * time.Millisecond
		c.SNMPDial = func(_ netip.Addr, port uint16) (string, uint16) {
			mu.Lock()
			asked = append(asked, port)
			mu.Unlock()
			if port == 1161 {
				return "127.0.0.1", agent
			}
			return "127.0.0.1", closed
		}
	})
	custom, plain := v2c("s3cret-community"), v2c("s3cret-community")
	custom.Port = 1161
	id := strings.Repeat("7", 32)
	r.core.push(snmpJob(id, tgt("192.168.10.30", plain), tgt("192.168.10.31", custom)))
	got := r.core.next(t)
	if len(got.res.SNMP) != 2 {
		t.Fatalf("result %+v", got.res)
	}
	if a := got.res.SNMP[0]; a.Status != sensorlink.SNMPStatusNoAnswer {
		t.Errorf("port 161: %+v", a)
	}
	if a := got.res.SNMP[1]; a.Status != sensorlink.SNMPStatusOK || a.Values.SysName != "SW-CORE-01" {
		t.Errorf("port 1161: %+v", a)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0] != 161 || asked[1] != 1161 {
		t.Errorf("ports asked %v, want [161 1161]", asked)
	}
}

// SNMPv3 authPriv (SHA, AES-128) and authNoPriv (SHA-256) are read; a user the agent does not know and a wrong password
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
	r.core.push(snmpJob(id, tgt("10.0.0.1", good), tgt("10.0.0.2", sha256), tgt("10.0.0.3", stranger), tgt("10.0.0.4", wrong)))
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
	r.core.push(snmpJob(strings.Repeat("7", 32), tgt("192.168.1.9", v2c("c0mmunity"))))
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
		snmpJob(strings.Repeat("1", 32), tgt("8.8.8.8", v2c("c"))),
		snmpJob(strings.Repeat("2", 32), tgt("192.168.1.9", sensorlink.SNMPCredential{Version: "v1", Community: "c"})),
		snmpJob(strings.Repeat("3", 32), tgt("127.0.0.1", v2c("c"))),
	}
	long := snmpJob(strings.Repeat("4", 32), tgt("192.168.1.9", v2c("c")))
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

// The heartbeat of this worker says it runs snmp jobs.
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

// #910, #919: MikroTik's sysDescr names the board only; the same one GET reads MIKROTIK-MIB mtxrLicVersion.0, the
// RouterOS version. An agent without the object (the Juniper here) answers noSuchObject: "", and the rest of its answer is kept.
func TestSNMPReadsTheMikroTikVersionInTheSameGet(t *testing.T) {
	t.Parallel()
	mt := &snmptest.Agent{Community: "c0mmunity-mt", Values: map[string]any{snmptest.SysDescr: "RouterOS RB4011iGS+",
		snmptest.SysObjectID: snmptest.Object(".1.3.6.1.4.1.14988.1"), snmptest.SysName: "gw1", snmptest.MikroTikVer: "6.49.10"}}
	sw := &snmptest.Agent{Community: "c0mmunity-mt", Values: juniper()}
	r := startSNMP(t, map[string]*snmptest.Agent{"192.168.10.30": mt, "192.168.10.31": sw})
	id := strings.Repeat("6", 32)
	r.core.push(snmpJob(id, tgt("192.168.10.30", v2c("c0mmunity-mt")), tgt("192.168.10.31", v2c("c0mmunity-mt"))))
	got := r.core.next(t)
	if got.id != id || got.res.Status != "done" || len(got.res.SNMP) != 2 {
		t.Fatalf("result %+v", got.res)
	}
	if a := got.res.SNMP[0]; a.Status != sensorlink.SNMPStatusOK || a.Values.OSVersion != "6.49.10" || a.Values.SysDescr != "RouterOS RB4011iGS+" {
		t.Errorf("the MikroTik: %+v", a)
	}
	if a := got.res.SNMP[1]; a.Status != sensorlink.SNMPStatusOK || a.Values.OSVersion != "" || a.Values.SysDescr != junosDescr {
		t.Errorf("the switch: %+v", a)
	}
}
