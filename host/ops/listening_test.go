package ops

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// GET /v1/state/ports (inventory INV-3, host INV-9b): only sockets another machine can reach, one entry per port and protocol, named by
// the Vedette service or the process that holds them.
func TestReadPortsListsWhatTheBoxServes(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	p := newFakeProc(t)
	p.table("tcp", procRow("00000000:20FB", "0A", "10")+ // 0.0.0.0:8443 LISTEN: core's port, kept open by its conmon
		procRow("0100007F:2234", "0A", "11")+ // 127.0.0.1:8756 LISTEN: loopback, not listed
		procRow("00000000:0016", "0A", "12")+ // 0.0.0.0:22 LISTEN
		procRow("0A12A8C0:0016", "01", "13")+ // 192.168.18.10:22 ESTABLISHED: a connection, not a listener
		procRow("0A12A8C0:1F90", "0A", "14")) // 192.168.18.10:8080 LISTEN, no process found
	p.table("tcp6", "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15 1 0 100 0 0 10 0\n"+ // [::]:22, the same port again
		"   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 16 1 0 100 0 0 10 0\n") // [::1]:80
	p.table("udp", procRow("00000000:0202", "07", "20")+ // 0.0.0.0:514: core's syslog
		"   1: 0A12A8C0:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 21 1 0 100 0 0 10 0\n") // a DNS client socket with a peer
	p.process("900", "conmon", cgCore, "10", "20")
	p.process("700", "sshd", "0::/system.slice/ssh.service\n", "12", "15")
	p.process("800", "python3", cgUser, "11")
	got, err := p.ops(t).readPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []api.ListenPort{
		{Port: 22, Proto: "tcp", Process: "sshd"},
		{Port: 8080, Proto: "tcp"},
		{Port: 8443, Proto: "tcp", Process: "vedette-core"},
		{Port: 514, Proto: "udp", Process: "vedette-core"},
	}
	if ps := got.(api.PortsState).Ports; !slices.Equal(ps, want) {
		t.Fatalf("ports %+v", ps)
	}
}

// A container of a unit that runs in the host's network holds its port itself: it is named by its Vedette unit, not its program.
func TestReadPortsNamesAContainerByItsUnit(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	p := newFakeProc(t)
	p.table("tcp", procRow("00000000:20FB", "0A", "10"))
	p.process("901", "vedette", cgCtr, "10")
	got, err := p.ops(t).readPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ps := got.(api.PortsState).Ports; len(ps) != 1 || ps[0].Process != "vedette-core" {
		t.Fatalf("ports %+v", ps)
	}
}

// No IPv4 socket table: the read fails, so core keeps the list it has rather than emptying the box's.
func TestReadPortsFailsWithoutTheSocketTable(t *testing.T) {
	t.Parallel()
	p := newFakeProc(t)
	if err := os.RemoveAll(filepath.Join(p.root, "proc", "net")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ops(t).readPorts(t.Context()); err == nil {
		t.Fatal("no error")
	}
}
