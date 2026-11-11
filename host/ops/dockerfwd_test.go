package ops_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

const netFile = "etc/containers/systemd/vedette-int.network"

func networkText(subnet string) string {
	return "[Network]\nNetworkName=vedette-int\nSubnet=" + subnet + "\nGateway=172.30.77.1\n"
}

const (
	rule1 = "-d 172.30.77.0/24 -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -m comment --comment vedette-int -j ACCEPT"
	rule2 = "-s 172.30.77.0/24 -m comment --comment vedette-int -j ACCEPT"
)

// safeBuf is a log sink two goroutines may write.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fwdBox is a machine with the network file, an Ops that logs into the returned buffer and whose timer never fires.
func fwdBox(t *testing.T, subnet string) (*opstest.Machine, *ops.Ops, *safeBuf) {
	t.Helper()
	m := opstest.NewMachine(t)
	if subnet != "" {
		m.WriteRoot(netFile, networkText(subnet))
	}
	buf := &safeBuf{}
	o := m.Ops(nil, func(c *ops.Config, d *ops.Deps) {
		c.Logger = slog.New(slog.NewTextHandler(buf, nil))
		d.FwdAfter = func(time.Duration, func()) func() bool { return func() bool { return true } }
	})
	t.Cleanup(o.Close)
	return m, o, buf
}

func calls(m *opstest.Machine) []string {
	var out []string
	for _, c := range m.Calls(ops.BinIptables) {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func TestDockerFwd_ChainAbsentChangesNothing(t *testing.T) {
	m, o, buf := fwdBox(t, "172.30.77.0/24")
	o.DockerFwdTick(context.Background())
	if got := calls(m); len(got) != 1 || got[0] != "-w 5 -S DOCKER-USER" {
		t.Fatalf("calls: %q", got)
	}
	if len(m.DockerRules()) != 0 {
		t.Fatalf("rules: %q", m.DockerRules())
	}
	if !strings.Contains(buf.String(), "no DOCKER-USER chain") {
		t.Fatalf("log: %s", buf)
	}
}

func TestDockerFwd_ChainPresentRulesAbsentInsertsTwoWithExactArgv(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	want := []string{
		"-w 5 -S DOCKER-USER",
		"-w 5 -C DOCKER-USER " + rule1,
		"-w 5 -I DOCKER-USER 1 " + rule1,
		"-w 5 -C DOCKER-USER " + rule2,
		"-w 5 -I DOCKER-USER 1 " + rule2,
	}
	if got := calls(m); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := m.DockerRules(); len(got) != 2 || got[0] != rule1 || got[1] != rule2 {
		t.Fatalf("rules: %q", got)
	}
}

func TestDockerFwd_RulesPresentOnlyChecks(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	before := len(calls(m))
	o.DockerFwdTick(context.Background())
	o.DockerFwdTick(context.Background())
	for _, c := range calls(m)[before:] {
		if strings.Contains(c, " -I ") {
			t.Fatalf("an insert on a repeated tick: %q", c)
		}
	}
	if got := m.DockerRules(); len(got) != 2 {
		t.Fatalf("rules are not idempotent: %q", got)
	}
}

func TestDockerFwd_DockerRestartPutsTheRulesBack(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	m.DockerFlush()
	o.DockerFwdTick(context.Background())
	if got := m.DockerRules(); len(got) != 2 {
		t.Fatalf("rules after a flush: %q", got)
	}
}

func TestDockerFwd_BadSubnetRunsNothing(t *testing.T) {
	for _, s := range []string{"8.8.8.0/24", "0.0.0.0/0", "172.30.77.5/24", "172.30.0.0/8", "172.30.77.0/29", "fd00::/64", "garbage", "10.0.0.0/24; x", ""} {
		m, o, _ := fwdBox(t, "")
		m.WriteRoot(netFile, networkText(s))
		m.DockerChain(true)
		o.DockerFwdTick(context.Background())
		if got := calls(m); len(got) != 0 {
			t.Errorf("subnet %q: ran %q", s, got)
		}
	}
}

func TestDockerFwd_NetworkFileProblemsRunNothing(t *testing.T) {
	two := networkText("172.30.77.0/24") + "Subnet=172.30.78.0/24\n"
	none := "[Network]\nNetworkName=vedette-int\n"
	for name, text := range map[string]string{"two Subnet lines": two, "no Subnet line": none} {
		m, o, _ := fwdBox(t, "")
		m.WriteRoot(netFile, text)
		m.DockerChain(true)
		o.DockerFwdTick(context.Background())
		if got := calls(m); len(got) != 0 {
			t.Errorf("%s: ran %q", name, got)
		}
	}
	// a file others can write, and a symlink
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	if err := os.Chmod(filepath.Join(m.Root, netFile), 0o666); err != nil { //nolint:gosec // the test makes a file others can write
		t.Fatal(err)
	}
	o.DockerFwdTick(context.Background())
	if got := calls(m); len(got) != 0 {
		t.Errorf("writable file: ran %q", got)
	}
	m2, o2, _ := fwdBox(t, "")
	m2.WriteRoot("elsewhere", networkText("172.30.77.0/24"))
	if err := os.MkdirAll(filepath.Dir(filepath.Join(m2.Root, netFile)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(m2.Root, "elsewhere"), filepath.Join(m2.Root, netFile)); err != nil {
		t.Fatal(err)
	}
	m2.DockerChain(true)
	o2.DockerFwdTick(context.Background())
	if got := calls(m2); len(got) != 0 {
		t.Errorf("symlink: ran %q", got)
	}
}

func TestDockerFwd_NoNetworkFileRunsNothing(t *testing.T) {
	m, o, _ := fwdBox(t, "")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	if got := calls(m); len(got) != 0 {
		t.Fatalf("ran %q", got)
	}
}

func TestDockerFwd_LogsOnlyOnAStateChange(t *testing.T) {
	m, o, buf := fwdBox(t, "172.30.77.0/24")
	ctx := context.Background()
	for range 3 {
		o.DockerFwdTick(ctx)
	}
	if n := strings.Count(buf.String(), "no DOCKER-USER chain"); n != 1 {
		t.Fatalf("chain-absent logged %d times:\n%s", n, buf)
	}
	m.DockerChain(true)
	for range 3 {
		o.DockerFwdTick(ctx)
	}
	if n := strings.Count(buf.String(), "added to DOCKER-USER"); n != 1 {
		t.Fatalf("added logged %d times:\n%s", n, buf)
	}
	if n := strings.Count(buf.String(), "already has both rules"); n != 0 {
		t.Fatalf("the quiet ticks after an add logged %d times:\n%s", n, buf)
	}
	m.DockerFlush()
	o.DockerFwdTick(ctx)
	if n := strings.Count(buf.String(), "added to DOCKER-USER"); n != 2 {
		t.Fatalf("a flush must log again, added logged %d times:\n%s", n, buf)
	}
}

func TestDockerFwd_StartLooksOnceAndArmsTheTimerUntilClose(t *testing.T) {
	m := opstest.NewMachine(t)
	m.WriteRoot(netFile, networkText("172.30.77.0/24"))
	m.DockerChain(true)
	var fire func()
	armed := 0
	o := m.Ops(nil, func(_ *ops.Config, d *ops.Deps) {
		d.FwdAfter = func(dur time.Duration, f func()) func() bool {
			if dur != 30*time.Second {
				t.Errorf("interval %v", dur)
			}
			fire = f
			armed++
			return func() bool { return true }
		}
	})
	o.Start(context.Background(), nil)
	if len(m.DockerRules()) != 2 {
		t.Fatalf("Start did not put the rules: %q", m.DockerRules())
	}
	if fire == nil {
		t.Fatal("no 30 s timer armed")
	}
	m.DockerFlush()
	fire()
	if len(m.DockerRules()) != 2 {
		t.Fatalf("the timer did not put the rules back: %q", m.DockerRules())
	}
	if armed != 2 {
		t.Fatalf("armed %d times, want 2 (Start, then the fire)", armed)
	}
	o.Close()
	fire() // a look that was already running when Close came: it ends and arms nothing
	if armed != 2 {
		t.Fatalf("a look after Close armed another timer (%d)", armed)
	}
}

func TestValidateIptables(t *testing.T) {
	t.Parallel()
	good := [][]string{
		{"-w", "5", "-S", "DOCKER-USER"},
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(rule1)...),
		append([]string{"-w", "5", "-I", "DOCKER-USER", "1"}, strings.Fields(rule2)...),
	}
	for _, a := range good {
		if err := ops.ValidateIptables(a); err != nil {
			t.Errorf("%q refused: %v", a, err)
		}
	}
	bad := [][]string{
		nil,
		{"-S", "DOCKER-USER"},
		{"-w", "5", "-S", "FORWARD"},
		{"-w", "5", "-S", "DOCKER-USER", "-v"},
		{"-w", "5", "-F", "DOCKER-USER"},
		{"-w", "5", "-D", "DOCKER-USER", "1"},
		{"-w", "5", "-P", "FORWARD", "ACCEPT"},
		{"-w", "5", "-I", "DOCKER-USER"},
		{"-w", "5", "-I", "DOCKER-USER", "2", "-s", "172.30.77.0/24", "-m", "comment", "--comment", "vedette-int", "-j", "ACCEPT"},
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule2, "ACCEPT", "DROP", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule2, "172.30.77.0/24", "0.0.0.0/0", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule2, "172.30.77.0/24", "8.8.8.0/24", 1))...),
		append(append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(rule2)...), "-j", "ACCEPT"),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule2, "-s", "-i", 1))...),
	}
	for _, a := range bad {
		if err := ops.ValidateIptables(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}
