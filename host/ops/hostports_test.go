package ops

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The socket-table rows below are written as a little-endian kernel prints them.
func littleEndianOnly(t *testing.T) {
	t.Helper()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the /proc/net fixtures are little-endian")
	}
}

// Every PublishPort= line of every template, current and earlier, is read: a form the parser skipped would never be checked (D-455).
func TestPublishedPortsReadsEveryLineOfEveryTemplate(t *testing.T) {
	t.Parallel()
	f := goldFill(true)
	n := 0
	for svc, s := range services {
		texts := [][]byte{mustRender(t, svc, f)}
		for _, tmpl := range legacyTemplates[svc] {
			b, err := s.render(tmpl, f)
			if err != nil {
				t.Fatal(err)
			}
			texts = append(texts, b)
		}
		for _, b := range texts {
			want := strings.Count(string(b), "\nPublishPort=")
			if got := publishedPorts(b); len(got) != want {
				t.Errorf("%s: %d of %d PublishPort lines read: %v", svc, len(got), want, got)
			}
			n += want
		}
	}
	if n == 0 {
		t.Fatal("no template publishes a port")
	}
}

func TestPublishedPortsForms(t *testing.T) {
	t.Parallel()
	lo := netip.MustParseAddr("127.0.0.1")
	cases := []struct {
		line string
		want []hostPort
	}{
		{"PublishPort=8443:8443", []hostPort{{port: 8443}}},
		{"PublishPort=127.0.0.1:8765:8765", []hostPort{{addr: lo, port: 8765}}},
		{"PublishPort=514:5514/udp", []hostPort{{port: 514, udp: true}}},
		{"PublishPort=6514:5515/tcp", []hostPort{{port: 6514}}},
		{"PublishPort=0.0.0.0:80:80", []hostPort{{port: 80}}},
		{"PublishPort=[::1]:9000:9000", []hostPort{{addr: netip.MustParseAddr("::1"), port: 9000}}},
		{"PublishPort=[::ffff:127.0.0.1]:9000:9000", []hostPort{{addr: lo, port: 9000}}},
		{"PublishPort=8000", nil},                // no host port: Podman picks one
		{"PublishPort=127.0.0.1::8000", nil},     // the same with an address
		{"PublishPort=8000-8010:8000-8010", nil}, // a range: the host writes none
		{"PublishPort=nope:1:1", nil},
		{"PublishPort=0:80", nil},
		{"PublishPort=70000:80", nil},
		{"#PublishPort=80:80", nil},
		{"PublishPort = 8765:8765 ", []hostPort{{port: 8765}}}, // spaces around "=" and after the value
		{"PublishPort=8765:8765/sctp", nil},                    // another protocol: never treated as tcp
		{"PublishPort=8765:8765/tcp,udp", nil},
		{"PublishPort=8765:8765/", nil},
		{"PublishPorts=80:80", nil},
	}
	for _, c := range cases {
		if got := publishedPorts([]byte("[Container]\n" + c.line + "\n")); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.line, got, c.want)
		}
	}
}

// The ports a change adds: core-3 (#489) → current adds 127.0.0.1:8765 (D-395); core-1 (D-318) adds 6514 too; the same template
// adds nothing; no unit at all adds every port. The address of a port already published does not make it new.
func TestAddedPortsBetweenTemplates(t *testing.T) {
	t.Parallel()
	f := goldFill(true)
	cur := mustRender(t, api.ServiceCore, f)
	legacy := func(i int) []byte {
		b, err := services[api.ServiceCore].render(legacyTemplates[api.ServiceCore][i], f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	names := func(ps []hostPort) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.String())
		}
		return out
	}
	if got := names(addedPorts(legacy(2), cur)); !slices.Equal(got, []string{"8765/tcp"}) {
		t.Errorf("core-3 → current: %v", got)
	}
	if got := addedPorts(legacy(2), cur); got[0].addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("8765 is published on %v, want 127.0.0.1", got[0].addr)
	}
	if got := names(addedPorts(legacy(0), cur)); !slices.Equal(got, []string{"8765/tcp", "6514/tcp"}) {
		t.Errorf("core-1 → current: %v", got)
	}
	if got := addedPorts(cur, cur); len(got) != 0 {
		t.Errorf("the same unit adds %v", got)
	}
	if got := addedPorts(nil, cur); len(got) != 6 {
		t.Errorf("no unit → current adds %v", got)
	}
	if got := addedPorts([]byte("PublishPort=8765:8765\n"), []byte("PublishPort=127.0.0.1:8765:8765\n")); len(got) != 0 {
		t.Errorf("a port that only changes its address is not new: %v", got)
	}
	if got := names(addedPorts([]byte("PublishPort=514:5514/tcp\n"), []byte("PublishPort=514:5514/udp\n"))); !slices.Equal(got, []string{"514/udp"}) {
		t.Errorf("another protocol is new: %v", got)
	}
	if got := addedPorts(mustRender(t, api.ServiceSensor, f), mustRender(t, api.ServiceSensor, f)); len(got) != 0 {
		t.Errorf("sensor (host network) publishes %v", got)
	}
}

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func procRow(local, state, inode string) string {
	return "   0: " + local + " 00000000:0000 " + state + " 00000000:00000000 00:00000000 00000000     0        0 " + inode + " 1 0000000000000000 100 0 0 10 0\n"
}

func TestParseProcNet(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	tcp := procNetHeader +
		procRow("0100007F:223D", "0A", "11") + // 127.0.0.1:8765 LISTEN
		procRow("00000000:1972", "0A", "12") + // 0.0.0.0:6514 LISTEN
		procRow("0A01A8C0:223D", "0A", "13") + // 192.168.1.10:8765 LISTEN
		procRow("0100007F:223D", "01", "14") + // ESTABLISHED: not a listener
		procRow("0100007F:0000", "0A", "15") + // port 0
		procRow("XYZ:223D", "0A", "16") + // not an address
		procRow("0100007F:223D", "0A", "-1") + // not an inode
		"garbage\n"
	got, err := parseProcNet(strings.NewReader(tcp), false)
	if err != nil {
		t.Fatal(err)
	}
	want := []sockEntry{
		{addr: netip.MustParseAddr("127.0.0.1"), port: 8765, inode: 11},
		{addr: netip.MustParseAddr("0.0.0.0"), port: 6514, inode: 12},
		{addr: netip.MustParseAddr("192.168.1.10"), port: 8765, inode: 13},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tcp: %v", got)
	}
	tcp6 := procNetHeader +
		procRow("00000000000000000000000000000000:223D", "0A", "21") + // [::]:8765
		procRow("00000000000000000000000001000000:223D", "0A", "22") + // [::1]:8765
		procRow("0000000000000000FFFF00000100007F:223D", "0A", "23") // [::ffff:127.0.0.1]:8765
	got, err = parseProcNet(strings.NewReader(tcp6), false)
	if err != nil {
		t.Fatal(err)
	}
	want = []sockEntry{
		{addr: netip.MustParseAddr("::"), port: 8765, inode: 21},
		{addr: netip.MustParseAddr("::1"), port: 8765, inode: 22},
		{addr: netip.MustParseAddr("127.0.0.1"), port: 8765, inode: 23},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tcp6: %v", got)
	}
	// UDP: a bound socket holds its port in any state.
	udp := procNetHeader + procRow("00000000:0202", "07", "31") + procRow("0100007F:0202", "01", "32")
	if got, err := parseProcNet(strings.NewReader(udp), true); err != nil || len(got) != 2 || !got[0].udp || got[0].port != 514 || got[1].inode != 32 {
		t.Fatalf("udp: %v %v", got, err)
	}
	// A read error is returned with what came before it; so is a line longer than any the kernel prints.
	got, err = parseProcNet(io.MultiReader(strings.NewReader(procNetHeader+procRow("0100007F:223D", "0A", "11")), iotest.ErrReader(errors.New("boom"))), false)
	if err == nil || len(got) != 1 {
		t.Fatalf("read error: %v %v", got, err)
	}
	if got, err = parseProcNet(strings.NewReader(procRow("0100007F:223D", "0A", "11")+strings.Repeat("x", 5000)+"\n"), false); err == nil || len(got) != 1 {
		t.Fatalf("long line: %v %v", got, err)
	}
}

func TestClashes(t *testing.T) {
	t.Parallel()
	lo, any4, any6 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::")
	lan := netip.MustParseAddr("192.168.1.10")
	p := hostPort{addr: lo, port: 8765}
	all := hostPort{port: 6514}
	cases := []struct {
		p    hostPort
		s    sockEntry
		want bool
	}{
		{p, sockEntry{addr: lo, port: 8765}, true},
		{p, sockEntry{addr: any4, port: 8765}, true},
		{p, sockEntry{addr: any6, port: 8765}, true}, // dual stack is the default
		{p, sockEntry{addr: lan, port: 8765}, false}, // another address of the box
		{p, sockEntry{addr: netip.MustParseAddr("::1"), port: 8765}, false},
		{p, sockEntry{addr: lo, port: 8766}, false},
		{p, sockEntry{addr: lo, port: 8765, udp: true}, false},
		{all, sockEntry{addr: lan, port: 6514}, true},
		{all, sockEntry{addr: netip.MustParseAddr("::1"), port: 6514}, true},
		{hostPort{port: 514, udp: true}, sockEntry{addr: any4, port: 514, udp: true}, true},
	}
	for _, c := range cases {
		if got := clashes(c.p, c.s); got != c.want {
			t.Errorf("%v %+v: %t", c.p, c.s, got)
		}
	}
}

// fakeProc is a /proc under a temp root: socket tables and processes that hold sockets.
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc", "net"), 0o750); err != nil {
		t.Fatal(err)
	}
	return &fakeProc{t: t, root: root}
}

func (f *fakeProc) table(name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, "proc", "net", name), []byte(procNetHeader+body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// process adds /proc/<pid> with comm, cgroup and one fd link per socket inode.
func (f *fakeProc) process(pid, comm, cgroup string, inodes ...string) {
	f.t.Helper()
	dir := filepath.Join(f.root, "proc", pid)
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o750); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o600); err != nil {
		f.t.Fatal(err)
	}
	_ = os.Symlink("/dev/null", filepath.Join(dir, "fd", "0"))
	_ = os.Symlink("pipe:[99]", filepath.Join(dir, "fd", "1"))
	for i, ino := range inodes {
		if err := os.Symlink("socket:["+ino+"]", filepath.Join(dir, "fd", string(rune('3'+i)))); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fakeProc) ops(t *testing.T) *Ops {
	t.Helper()
	o := legacyOps(t)
	o.d.Root = f.root
	o.log = slog.New(slog.DiscardHandler)
	return o
}

const (
	cgUser = "0::/user.slice/user-1000.slice/session-3.scope\n"
	cgCore = "0::/system.slice/vedette-core.service\n"
	cgCtr  = "0::/system.slice/vedette-core.service/libpod-payload-0123abcd\n"
	cgFake = "0::/system.slice/vedette-core.service.d\n" // not below the unit: a prefix is not enough
)

// busyPorts over core-3 → current (adds 127.0.0.1:8765): which listeners refuse the change and how they are named.
func TestBusyPortsNamesTheProgramAndSparesTheServiceItself(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	f := goldFill(true)
	old, err := services[api.ServiceCore].render(legacyTemplates[api.ServiceCore][2], f)
	if err != nil {
		t.Fatal(err)
	}
	want := mustRender(t, api.ServiceCore, f)
	cases := []struct {
		name  string
		setup func(*fakeProc)
		want  []string
	}{
		{"no socket tables", func(*fakeProc) {}, nil},
		{"nothing on 8765", func(p *fakeProc) { p.table("tcp", procRow("00000000:20FB", "0A", "40")) }, nil}, // 8443 is in both units
		{"python3 on 127.0.0.1", func(p *fakeProc) {
			p.table("tcp", procRow("0100007F:223D", "0A", "41"))
			p.process("4242", "python3", cgUser, "41")
		}, []string{"8765/tcp (python3, pid 4242)"}},
		{"a program on every address", func(p *fakeProc) {
			p.table("tcp", procRow("00000000:223D", "0A", "42"))
			p.process("77", "node", cgUser, "42")
		}, []string{"8765/tcp (node, pid 77)"}},
		{"a program on [::] (tcp6)", func(p *fakeProc) {
			p.table("tcp6", procRow("00000000000000000000000000000000:223D", "0A", "43"))
			p.process("78", "nginx", cgFake, "43")
		}, []string{"8765/tcp (nginx, pid 78)"}},
		{"a program on the LAN address only", func(p *fakeProc) {
			p.table("tcp", procRow("0A01A8C0:223D", "0A", "44"))
			p.process("79", "python3", cgUser, "44")
		}, nil},
		{"core's own conmon", func(p *fakeProc) {
			p.table("tcp", procRow("0100007F:223D", "0A", "45"))
			p.process("900", "conmon", cgCore, "45")
		}, nil},
		{"core's own container", func(p *fakeProc) {
			p.table("tcp", procRow("0100007F:223D", "0A", "46"))
			p.process("901", "vedette", cgCtr, "46")
		}, nil},
		{"no process holds it", func(p *fakeProc) { p.table("tcp", procRow("0100007F:223D", "0A", "47")) }, []string{"8765/tcp"}},
		{"a connection, not a listener", func(p *fakeProc) {
			p.table("tcp", procRow("0100007F:223D", "01", "48"))
			p.process("80", "curl", cgUser, "48")
		}, nil},
		{"udp on 8765", func(p *fakeProc) {
			p.table("udp", procRow("0100007F:223D", "07", "49"))
			p.process("81", "dnsmasq", cgUser, "49")
		}, nil},
		{"a hostile process name", func(p *fakeProc) {
			p.table("tcp", procRow("0100007F:223D", "0A", "50"))
			p.process("82", "a\x1b[31mb\tc-very-long-name", cgUser, "50")
		}, []string{"8765/tcp (a?[31mb?c-very-, pid 82)"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := newFakeProc(t)
			c.setup(p)
			got := busyList(p.ops(t).busyPorts(context.Background(), api.ServiceCore, old, want))
			if len(got) == 0 {
				got = nil
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("%q, want %q", got, c.want)
			}
		})
	}
}

// The refusal is 412 port_in_use, names the port and the program, and says nothing was changed. A change that adds no port reads
// nothing at all (an unreadable socket table cannot matter then).
func TestPortsFreeRefusesWith412PortInUse(t *testing.T) {
	t.Parallel()
	littleEndianOnly(t)
	f := goldFill(true)
	old, err := services[api.ServiceCore].render(legacyTemplates[api.ServiceCore][0], f) // core-1: no 6514, no 8765
	if err != nil {
		t.Fatal(err)
	}
	want := mustRender(t, api.ServiceCore, f)
	p := newFakeProc(t)
	p.table("tcp", procRow("0100007F:223D", "0A", "41")+procRow("00000000:1972", "0A", "51"))
	p.process("4242", "python3", cgUser, "41")
	p.process("600", "rsyslogd", cgUser, "51")
	o := p.ops(t)
	ctx := context.Background()
	err = o.portsFree(ctx, api.ServiceCore, old, want)
	var ref *server.Refusal
	if !errors.As(err, &ref) || ref.Status != 412 || ref.Code != api.CodePortInUse {
		t.Fatalf("%v", err)
	}
	for _, s := range []string{"Ports 8765/tcp (python3, pid 4242), 6514/tcp (rsyslogd, pid 600) are in use", "Nothing was changed."} {
		if !strings.Contains(ref.Message, s) {
			t.Errorf("message %q lacks %q", ref.Message, s)
		}
	}
	// core reads the ports and programs out of the message to show them (D-412)
	if list, plural, ok := api.PortsInUse(ref.Message); !ok || !plural || list != "8765/tcp (python3, pid 4242), 6514/tcp (rsyslogd, pid 600)" {
		t.Errorf("api.PortsInUse(%q) = %q %v %v", ref.Message, list, plural, ok)
	}
	if err := o.portsFree(ctx, api.ServiceCore, want, want); err != nil {
		t.Fatalf("the same unit: %v", err)
	}
	// A stopped service (no old unit to compare with): every port is looked at, 8443 included.
	r := newFakeProc(t)
	r.table("tcp", procRow("00000000:20FB", "0A", "61"))
	r.process("70", "nginx", cgUser, "61")
	if err := r.ops(t).portsFree(ctx, api.ServiceCore, nil, want); !errors.As(err, &ref) || !strings.Contains(ref.Message, "Port 8443/tcp (nginx, pid 70) is in use") {
		t.Fatalf("every port of a stopped service: %v", err)
	}
	if list, plural, ok := api.PortsInUse(ref.Message); !ok || plural || list != "8443/tcp (nginx, pid 70)" {
		t.Errorf("api.PortsInUse(%q) = %q %v %v", ref.Message, list, plural, ok)
	}
	if err := r.ops(t).portsFree(ctx, api.ServiceCore, old, want); err != nil {
		t.Fatalf("a running service's own port: %v", err)
	}
	// A table that is there but cannot be read (a directory: the read fails): logged, no refusal (the check never blocks on its
	// own misreading).
	q := newFakeProc(t)
	if err := os.Mkdir(filepath.Join(q.root, "proc", "net", "tcp"), 0o750); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	qo := q.ops(t)
	qo.log = slog.New(slog.NewTextHandler(&logged, nil))
	if err := qo.portsFree(ctx, api.ServiceCore, old, want); err != nil {
		t.Fatalf("an unreadable table refused: %v", err)
	}
	if !strings.Contains(logged.String(), "could not read a socket table to its end") || !strings.Contains(logged.String(), "table=proc/net/tcp") {
		t.Fatalf("the unreadable table was not logged: %s", logged.String())
	}
}
