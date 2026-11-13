// Package snmptest is a fake SNMP agent on loopback for the tests of the worker and of core's SNMP round (D-512): no test sends a
// packet to a real device. It answers GET requests from a table of values, built and parsed with gosnmp itself; a v2c request with
// another community is dropped without a word, as a real agent drops it (RFC 1157 4.1). A v3 user, when set, is served with the USM
// exchange a real agent has: the engine discovery report, then authenticated (and encrypted) answers; an unknown user or a message
// whose digest does not check out gets the report a real agent sends.
package snmptest

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// The objects of the worker's read, for building tables.
const (
	SysDescr     = ".1.3.6.1.2.1.1.1.0"
	SysObjectID  = ".1.3.6.1.2.1.1.2.0"
	SysName      = ".1.3.6.1.2.1.1.5.0"
	EntClass     = ".1.3.6.1.2.1.47.1.1.1.1.5.1"
	EntModel     = ".1.3.6.1.2.1.47.1.1.1.1.13.1"
	EntSoftware  = ".1.3.6.1.2.1.47.1.1.1.1.10.1"
	EntSerial    = ".1.3.6.1.2.1.47.1.1.1.1.11.1"
	engineID     = "\x80\x00\x1f\x88\x80\x76\x65\x64\x65\x74\x74\x65"
	unknownUsers = ".1.3.6.1.6.3.15.1.1.3.0"
	unknownEng   = ".1.3.6.1.6.3.15.1.1.4.0"
	wrongDigests = ".1.3.6.1.6.3.15.1.1.5.0"
)

// Agent is one fake agent. Set its fields before Start; Values maps an object identifier (with the leading dot) to its value: a
// string is an OCTET STRING, an int an INTEGER, and Object(...) an OBJECT IDENTIFIER.
type Agent struct {
	Community string // v2c; "" serves no v2c
	// V3 serves one USM user (nil: none). AuthoritativeEngineID and the boots and time are the agent's own.
	V3     *gosnmp.UsmSecurityParameters
	Values map[string]any
	// ErrorStatus, when set, answers every request that names more than the three system objects with this error status (an agent
	// that refuses the whole PDU for one unknown object).
	ErrorStatus gosnmp.SNMPError

	requests atomic.Int64
	conn     *net.UDPConn
	mu       sync.Mutex
	lastErr  error // why the latest message got no answer, for a failing test to print
}

// Object marks a value as an OBJECT IDENTIFIER.
type Object string

// Start listens on a loopback port and serves until the test ends; it returns the port.
func (a *Agent) Start(t testing.TB) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	a.conn = c
	t.Cleanup(func() { _ = c.Close() })
	go a.serve()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // a port number
}

// Requests is how many messages the agent has received.
func (a *Agent) Requests() int { return int(a.requests.Load()) }

func (a *Agent) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.requests.Add(1)
		if out := a.answer(append([]byte(nil), buf[:n]...)); out != nil {
			_, _ = a.conn.WriteToUDP(out, from)
		}
	}
}

func (a *Agent) answer(msg []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(msg) > 4 && msg[4] == byte(gosnmp.Version3) || len(msg) > 5 && msg[5] == byte(gosnmp.Version3) {
		return a.answerV3(msg)
	}
	if a.Community == "" {
		return nil
	}
	req, err := (&gosnmp.GoSNMP{Version: gosnmp.Version2c}).SnmpDecodePacket(msg)
	if err != nil || req.Community != a.Community || req.PDUType != gosnmp.GetRequest {
		return nil // a wrong community is dropped, never answered
	}
	resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: a.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID}
	a.fill(resp, req.Variables)
	out, err := resp.MarshalMsg()
	if err != nil {
		return nil
	}
	return out
}

// fill sets the variables (or the error status) of an answer to the objects asked.
func (a *Agent) fill(resp *gosnmp.SnmpPacket, asked []gosnmp.SnmpPDU) {
	if a.ErrorStatus != gosnmp.NoError && len(asked) > 3 {
		resp.Error, resp.ErrorIndex = a.ErrorStatus, 4
		resp.Variables = asked
		for i := range resp.Variables {
			resp.Variables[i].Type, resp.Variables[i].Value = gosnmp.Null, nil
		}
		return
	}
	for _, v := range asked {
		pdu := gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject}
		switch x := a.Values[v.Name].(type) {
		case string:
			pdu.Type, pdu.Value = gosnmp.OctetString, []byte(x)
		case []byte:
			pdu.Type, pdu.Value = gosnmp.OctetString, x
		case int:
			pdu.Type, pdu.Value = gosnmp.Integer, x
		case Object:
			pdu.Type, pdu.Value = gosnmp.ObjectIdentifier, string(x)
		}
		resp.Variables = append(resp.Variables, pdu)
	}
}

func (a *Agent) answerV3(msg []byte) []byte {
	if a.V3 == nil {
		return nil
	}
	// The header and the user name come out of a decode without keys; a message that is authenticated needs the user's keys.
	head, err := (&gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "?"}}).SnmpDecodePacket(msg)
	var usm *gosnmp.UsmSecurityParameters
	if head != nil {
		usm, _ = head.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	}
	if usm == nil {
		a.lastErr = errors.Join(errors.New("v3 header"), err)
		return nil
	}
	if usm.AuthoritativeEngineID == "" { // discovery: tell the engine id, boots and time (RFC 3414 4)
		return a.report(head, unknownEng)
	}
	if usm.UserName != a.V3.UserName {
		return a.report(head, unknownUsers)
	}
	keys := a.params()
	if err := keys.InitSecurityKeys(); err != nil {
		a.lastErr = err
		return nil
	}
	req, err := (&gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: head.MsgFlags, SecurityParameters: keys}).SnmpDecodePacket(msg)
	if err != nil { // the digest does not check out, or the message does not decrypt: the password is not the user's
		a.lastErr = err
		return a.report(head, wrongDigests)
	}
	if req.MsgFlags&gosnmp.AuthPriv != a.flags()&gosnmp.AuthPriv {
		return a.report(head, wrongDigests)
	}
	resp := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: a.flags(), SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: a.params(),
		MsgID: req.MsgID, MsgMaxSize: 65507, ContextEngineID: engineID, PDUType: gosnmp.GetResponse, RequestID: req.RequestID}
	a.fill(resp, req.Variables)
	if err := resp.SecurityParameters.InitSecurityKeys(); err != nil {
		a.lastErr = err
		return nil
	}
	if err := resp.SecurityParameters.InitPacket(resp); err != nil {
		a.lastErr = err
		return nil
	}
	out, err := resp.MarshalMsg()
	if err != nil {
		a.lastErr = err
		return nil
	}
	return out
}

func (a *Agent) flags() gosnmp.SnmpV3MsgFlags {
	if a.V3.PrivacyProtocol != gosnmp.NoPriv && a.V3.PrivacyProtocol != 0 {
		return gosnmp.AuthPriv
	}
	return gosnmp.AuthNoPriv
}

// params is the user's security parameters with the agent's engine.
func (a *Agent) params() *gosnmp.UsmSecurityParameters {
	return &gosnmp.UsmSecurityParameters{UserName: a.V3.UserName, AuthenticationProtocol: a.V3.AuthenticationProtocol, AuthenticationPassphrase: a.V3.AuthenticationPassphrase,
		PrivacyProtocol: a.V3.PrivacyProtocol, PrivacyPassphrase: a.V3.PrivacyPassphrase, AuthoritativeEngineID: engineID, AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 100}
}

// report is the unauthenticated report a real agent sends for a discovery, an unknown user or a wrong digest.
func (a *Agent) report(req *gosnmp.SnmpPacket, counter string) []byte {
	resp := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.NoAuthNoPriv, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{AuthoritativeEngineID: engineID, AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 100},
		MsgID:              req.MsgID, MsgMaxSize: 65507, ContextEngineID: engineID, PDUType: gosnmp.Report, RequestID: req.RequestID,
		Variables: []gosnmp.SnmpPDU{{Name: counter, Type: gosnmp.Counter32, Value: uint32(1)}}}
	out, err := resp.MarshalMsg()
	if err != nil {
		a.lastErr = err
		return nil
	}
	return out
}
