package ops

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		procRow("0A8EA8C0:0016", "01", "13")+ // 192.168.142.10:22 ESTABLISHED: a connection, not a listener
		procRow("0A8EA8C0:1F90", "0A", "14")+ // 192.168.142.10:8080 LISTEN on the card, no process found
		procRow("0100590A:0035", "0A", "17")) // 10.89.0.1:53 LISTEN: aardvark-dns on Podman's bridge, not on a card
	p.table("tcp6", "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15 1 0 100 0 0 10 0\n"+ // [::]:22, the same port again
		"   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 16 1 0 100 0 0 10 0\n"+ // [::1]:80
		"   2: 00000000000000000000000000000000:2382 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18 1 0 100 0 0 10 0\n") // [::]:9090 only, no IPv4 socket
	p.table("udp", procRow("00000000:0202", "07", "20")+ // 0.0.0.0:514: core's syslog
		"   1: 0A8EA8C0:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 21 1 0 100 0 0 10 0\n") // a DNS client socket with a peer
	p.process("900", "conmon", cgCore, "10", "20")
	p.process("700", "sshd", "0::/system.slice/ssh.service\n", "12", "15")
	p.process("800", "python3", cgUser, "11")
	p.process("850", "aardvark-dns", cgUser, "17")
	p.process("860", "cockpit-ws", "0::/system.slice/cockpit.service\n", "18")
	o := p.ops(t)
	if err := os.MkdirAll(filepath.Join(p.root, "sys", "class", "net", "eth0", "device"), 0o750); err != nil {
		t.Fatal(err)
	}
	o.d.Interfaces = func() ([]HostIface, error) {
		return []HostIface{
			{Name: "lo", Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
			{Name: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.142.10/24")}},
			{Name: "podman1", Addrs: []netip.Prefix{netip.MustParsePrefix("10.89.0.1/24")}},
		}, nil
	}
	got, err := o.readPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []api.ListenPort{
		{Port: 22, Proto: "tcp", Process: "sshd"},
		{Port: 8080, Proto: "tcp"},
		{Port: 8443, Proto: "tcp", Process: "vedette-core"},
		{Port: 9090, Proto: "tcp", Process: "cockpit-ws"}, // bound to [::] only (dual stack): listed
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

// #933 review r2 L2: a socket table that exists but cannot be read to its end fails the read, so core keeps the box's list rather
// than replacing it with part of one (the ports of that table would be deleted).
func TestReadPortsFailsOnATableItCannotReadWhole(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	p := newFakeProc(t)
	p.table("tcp", procRow("00000000:0016", "0A", "12"))
	p.table("udp6", "   0: "+strings.Repeat("0", 5000)+"\n") // a line over the scanner's bound
	if _, err := p.ops(t).readPorts(t.Context()); err == nil {
		t.Fatal("a table read in part gave a list")
	}
}

// n82: sshd socket-activated by systemd (Ubuntu's ssh.socket) is listed as what serves 22/tcp, not "systemd". When sshd runs it
// holds the socket systemd passed it; when only systemd holds it, the port is named by the service the socket unit activates, read
// from the unit files and their drop-ins (no program runs). A port no unit or two units claim stays "systemd": never a guess.
func TestReadPortsNamesASocketActivatedService(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	p := newFakeProc(t)
	p.table("tcp", procRow("00000000:0016", "0A", "12")+ // 0.0.0.0:22, systemd and sshd hold it
		procRow("00000000:2382", "0A", "18")+ // 0.0.0.0:9090, systemd alone: cockpit.socket, service not started
		procRow("00000000:0050", "0A", "19")+ // 0.0.0.0:80, systemd alone: claimed by two socket units
		procRow("00000000:1F90", "0A", "20")) // 0.0.0.0:8080, systemd alone: an old ListenStream reset by a drop-in
	p.table("udp", procRow("00000000:14E9", "07", "21")) // 0.0.0.0:5353, systemd alone, no unit
	p.process("1", "systemd", "0::/init.scope\n", "12", "18", "19", "20", "21")
	p.process("700", "sshd", "0::/system.slice/ssh.service\n", "12")
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(p.root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/lib/systemd/system/cockpit.socket", "[Unit]\nDescription=Cockpit\n\n[Socket]\nListenStream=8080\n")
	write("etc/systemd/system/cockpit.socket.d/listen.conf", "[Socket]\nListenStream=\nListenStream=[::]:9090\n") // moves it to 9090
	write("usr/lib/systemd/system/web-a.socket", "[Socket]\nListenStream=80\nService=nginx.service\n")
	write("usr/lib/systemd/system/web-b.socket", "[Socket]\nListenStream=0.0.0.0:80\n")
	write("usr/lib/systemd/system/old.socket", "[Socket]\nListenStream=/run/old.sock\n")
	got, err := p.ops(t).readPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []api.ListenPort{
		{Port: 22, Proto: "tcp", Process: "sshd"},
		{Port: 80, Proto: "tcp", Process: "systemd"},
		{Port: 8080, Proto: "tcp", Process: "systemd"},
		{Port: 9090, Proto: "tcp", Process: "cockpit"},
		{Port: 5353, Proto: "udp", Process: "systemd"},
	}
	if ps := got.(api.PortsState).Ports; !slices.Equal(ps, want) {
		t.Fatalf("ports %+v", ps)
	}
}

// The service a socket unit activates: Service= wins over the unit's own name; an instance template (Accept=yes) is named without "@".
func TestParseSocketUnit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.socket")
	if err := os.WriteFile(path, []byte("[Socket]\nListenStream=22\nListenDatagram=[::]:53\nAccept=yes\nService=sshd@.service\n[Install]\nListenStream=99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, service := parseSocketUnit([]string{path})
	if want := []socketKey{{22, false}, {53, true}}; !slices.Equal(keys, want) || service != "sshd" {
		t.Fatalf("keys %v service %q", keys, service)
	}
}
