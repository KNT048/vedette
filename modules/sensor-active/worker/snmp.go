package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/core/sensorlink"
)

// The SNMP reads of D-512: for each target of an snmp job, in order and one at a time, the worker tries the credentials the target
// names until one gets an answer, with one read-only GET of a fixed list of objects (snmpObjects). Nothing is ever set, walked or
// bulk-read, and no object identifier comes from core. A request waits 2 s for its answer and is sent once more (SNMPTimeout,
// SNMPRetries); the next request leaves at most rate packets a second behind it (a v3 read is two exchanges: the engine discovery
// and the GET). Credentials live in the job, in memory, for the job only: they are never logged (sensorlink.SNMPCredential
// redacts itself) and never sent back.
const (
	SNMPTimeout = 2 * time.Second
	SNMPRetries = 1
	snmpPort    = 161
	// snmpValueMax is the longest value kept: an SNMP DisplayString is at most 255 octets (RFC 2579); a longer one is cut.
	snmpValueMax = 255
	// packetsPerRead is what one read may cost on the wire, the base of the pace: a v3 engine discovery and the GET.
	packetsPerRead = 2
)

// The objects read from every agent: MIB-2 system (RFC 3418) and ENTITY-MIB entPhysicalEntry (RFC 6933) of index 1, which is the
// chassis or the stack on the devices that have the table (core checks the class before it believes the model).
var snmpObjects = []string{
	".1.3.6.1.2.1.1.1.0",           // sysDescr
	".1.3.6.1.2.1.1.2.0",           // sysObjectID
	".1.3.6.1.2.1.1.5.0",           // sysName
	".1.3.6.1.2.1.47.1.1.1.1.5.1",  // entPhysicalClass.1
	".1.3.6.1.2.1.47.1.1.1.1.13.1", // entPhysicalModelName.1
	".1.3.6.1.2.1.47.1.1.1.1.10.1", // entPhysicalSoftwareRev.1
	".1.3.6.1.2.1.47.1.1.1.1.11.1", // entPhysicalSerialNum.1
}

// systemObjects is the first three: what an agent that refuses the whole request (an error status, as SNMPv1-style agents do for
// one unknown object) is asked again for.
var systemObjects = snmpObjects[:3]

// SNMPDialer says where the request for a target goes; tests point it at a fake agent on loopback. nil means the target itself on
// port 161.
type SNMPDialer func(ip netip.Addr) (host string, port uint16)

// executeSNMP re-checks an snmp job (the grammar of sensorlink.CheckSNMPJob, every target local by core/localnet like nmap's, the
// timeout) and runs it. Its result is done with one answer per target it got to, or stopped when core cancelled it; a job cut by
// its deadline still reports the targets it finished.
func (w *Worker) executeSNMP(ctx, jctx context.Context, cur *activeJob) *sensorlink.JobResult {
	j := cur.job
	targets, err := snmpTargets(j)
	if err != nil {
		w.log.ErrorContext(ctx, "sensor_active_job_refused", "id", j.ID, "error", err) // core and worker disagree on the grammar
		return &sensorlink.JobResult{Status: "refused", Reason: "invalid_job", ExitCode: -1}
	}
	rctx, cancel := context.WithTimeout(jctx, time.Duration(j.TimeoutS)*time.Second)
	defer cancel()
	gap := time.Duration(packetsPerRead) * time.Second / time.Duration(j.SNMP.Rate)
	answers := make([]sensorlink.SNMPAnswer, 0, len(targets))
	for i, t := range targets {
		if i > 0 && gap > 0 && w.sleep(rctx, gap) != nil {
			break
		}
		a, ok := w.readTarget(rctx, t, j.SNMP)
		if !ok {
			break
		}
		answers = append(answers, a)
	}
	if context.Cause(jctx) != nil {
		return stopped()
	}
	res := &sensorlink.JobResult{Status: "done", SNMP: answers}
	if rctx.Err() != nil && len(answers) < len(targets) {
		res.Reason = "deadline" // done with what it got: the targets it did not reach are not in the answer
	}
	return res
}

// snmpTargets checks the job and returns its targets as addresses.
func snmpTargets(j sensorlink.Job) ([]netip.Addr, error) {
	if j.TimeoutS < 1 || j.TimeoutS > sensorlink.MaxSNMPSeconds {
		return nil, fmt.Errorf("timeout %d s is outside 1..%d", j.TimeoutS, sensorlink.MaxSNMPSeconds)
	}
	if err := sensorlink.CheckSNMPJob(j.SNMP); err != nil {
		return nil, err
	}
	out := make([]netip.Addr, len(j.SNMP.Targets))
	for i, t := range j.SNMP.Targets {
		a, err := netip.ParseAddr(t.IP)
		if err != nil || !localnet.Addr(a) {
			return nil, fmt.Errorf("target %q is not a local IPv4 address", t.IP)
		}
		out[i] = a
	}
	return out, nil
}

// readTarget tries the target's credentials in order until one is answered. ok is false when ctx ended before a status was known.
func (w *Worker) readTarget(ctx context.Context, ip netip.Addr, job *sensorlink.SNMPJob) (sensorlink.SNMPAnswer, bool) {
	var tries []int
	for _, t := range job.Targets {
		if t.IP == ip.String() {
			tries = t.Credentials
		}
	}
	a := sensorlink.SNMPAnswer{Target: ip.String(), Status: sensorlink.SNMPStatusNoAnswer}
	for _, ci := range tries {
		if ctx.Err() != nil {
			return a, false
		}
		a.Credential = ci
		a.Status, a.Values = w.read(ctx, ip, job.Credentials[ci])
		if a.Status == sensorlink.SNMPStatusOK {
			break
		}
	}
	if ctx.Err() != nil && a.Status != sensorlink.SNMPStatusOK {
		return a, false // a timeout cut short by the job's end says nothing about the device
	}
	return a, true
}

// read is one credential against one target: the GET of snmpObjects, and of the system group alone when the agent refuses that.
func (w *Worker) read(ctx context.Context, ip netip.Addr, c sensorlink.SNMPCredential) (string, sensorlink.SNMPValues) {
	host, port := ip.String(), uint16(snmpPort)
	if w.snmpDial != nil {
		host, port = w.snmpDial(ip)
	}
	g, err := client(ctx, host, port, w.snmpWait, c)
	if err != nil {
		return sensorlink.SNMPStatusError, sensorlink.SNMPValues{}
	}
	if err := g.Connect(); err != nil {
		return sensorlink.SNMPStatusNoAnswer, sensorlink.SNMPValues{}
	}
	defer func() { _ = g.Conn.Close() }()
	pkt, err := g.Get(snmpObjects)
	if err == nil && pkt.Error != gosnmp.NoError {
		pkt, err = g.Get(systemObjects)
	}
	if st := statusOf(err); st != sensorlink.SNMPStatusOK {
		return st, sensorlink.SNMPValues{}
	}
	if pkt.Error != gosnmp.NoError {
		return sensorlink.SNMPStatusError, sensorlink.SNMPValues{}
	}
	return sensorlink.SNMPStatusOK, valuesOf(pkt.Variables)
}

// client builds the gosnmp client of one credential. Its logger is gosnmp's default, which writes nothing.
func client(ctx context.Context, host string, port uint16, wait time.Duration, c sensorlink.SNMPCredential) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{Target: host, Port: port, Transport: "udp", Context: ctx, Timeout: wait, Retries: SNMPRetries, MaxOids: len(snmpObjects)}
	switch c.Version {
	case sensorlink.SNMPv2c:
		g.Version, g.Community = gosnmp.Version2c, c.Community
		return g, nil
	case sensorlink.SNMPv3:
		usm := &gosnmp.UsmSecurityParameters{UserName: c.User, AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: c.AuthPass, PrivacyProtocol: gosnmp.NoPriv}
		if c.Auth == sensorlink.SNMPAuthSHA256 {
			usm.AuthenticationProtocol = gosnmp.SHA256
		}
		g.Version, g.SecurityModel, g.MsgFlags, g.SecurityParameters = gosnmp.Version3, gosnmp.UserSecurityModel, gosnmp.AuthNoPriv, usm
		if c.Priv == sensorlink.SNMPPrivAES128 {
			usm.PrivacyProtocol, usm.PrivacyPassphrase, g.MsgFlags = gosnmp.AES, c.PrivPass, gosnmp.AuthPriv
		}
		return g, nil
	}
	return nil, errors.New("unknown version") // CheckSNMPJob already refused it
}

// statusOf names what an error of gosnmp means for the person: no answer at all (no agent, a firewall, a wrong v2c community: the
// agent drops those without a word, RFC 1157 4.1), a v3 user the agent does not know, a v3 password that does not check out.
func statusOf(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return sensorlink.SNMPStatusOK
	case errors.Is(err, gosnmp.ErrUnknownUsername):
		return sensorlink.SNMPStatusUnknownUser
	case errors.Is(err, gosnmp.ErrWrongDigest), errors.Is(err, gosnmp.ErrDecryption),
		// After the engine discovery gosnmp takes no unauthenticated report: the usmStatsUnknownUserNames or usmStatsWrongDigests
		// report an agent sends for a user it does not know or a password that does not check out ends here, without a sentinel.
		strings.Contains(err.Error(), "not authentic"):
		return sensorlink.SNMPStatusAuthFailed
	case errors.Is(err, gosnmp.ErrMaxRetriesExceeded), errors.As(err, &ne), errors.Is(err, context.DeadlineExceeded),
		strings.Contains(err.Error(), "connection refused"): // an ICMP port unreachable read back on the UDP socket
		return sensorlink.SNMPStatusNoAnswer
	}
	return sensorlink.SNMPStatusError
}

// valuesOf turns the variables of an answer into the values of the protocol, by object; an object the agent does not have
// (noSuchObject, noSuchInstance) or one of an unexpected type is "". The text is the agent's and untrusted: it is made valid UTF-8
// and cut to 255 bytes here, and core cleans it again.
func valuesOf(vars []gosnmp.SnmpPDU) sensorlink.SNMPValues {
	var v sensorlink.SNMPValues
	dst := map[string]*string{
		snmpObjects[0]: &v.SysDescr, snmpObjects[1]: &v.SysObjectID, snmpObjects[2]: &v.SysName, snmpObjects[3]: &v.EntClass,
		snmpObjects[4]: &v.EntModel, snmpObjects[5]: &v.EntSoftware, snmpObjects[6]: &v.EntSerial,
	}
	for _, p := range vars {
		d, ok := dst["."+strings.TrimPrefix(p.Name, ".")]
		if !ok || *d != "" {
			continue
		}
		switch p.Type {
		case gosnmp.OctetString:
			if b, ok := p.Value.([]byte); ok {
				*d = cut(strings.ToValidUTF8(string(b), "�"))
			}
		case gosnmp.ObjectIdentifier:
			if s, ok := p.Value.(string); ok {
				*d = cut(s)
			}
		case gosnmp.Integer:
			*d = strconv.FormatInt(gosnmp.ToBigInt(p.Value).Int64(), 10)
		}
	}
	return v
}

// cut keeps at most snmpValueMax bytes of s, on a rune boundary.
func cut(s string) string {
	if len(s) <= snmpValueMax {
		return s
	}
	s = s[:snmpValueMax]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
