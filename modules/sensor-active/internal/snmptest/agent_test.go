package snmptest

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// The fake agent itself answers a v3 client: the discovery, then an authenticated and encrypted GET.
func TestAgentAnswersV3(t *testing.T) {
	t.Parallel()
	a := &Agent{Values: map[string]any{SysName: "sw"}, V3: &gosnmp.UsmSecurityParameters{UserName: "u", AuthenticationProtocol: gosnmp.SHA,
		AuthenticationPassphrase: "auth-pass-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-1"}}
	port := a.Start(t)
	g := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: port, Version: gosnmp.Version3, Timeout: 200 * time.Millisecond, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "u", AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "auth-pass-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-1"}}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Conn.Close() }()
	p, err := g.Get([]string{SysName})
	if err != nil || len(p.Variables) != 1 || string(p.Variables[0].Value.([]byte)) != "sw" {
		t.Fatalf("%v %+v (%d requests, last error %v)", err, p, a.Requests(), a.lastErr)
	}
}
