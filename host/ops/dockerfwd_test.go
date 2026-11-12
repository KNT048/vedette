package ops_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

const netFile = "etc/containers/systemd/vedette-int.network"

func networkText(subnet string) string {
	return "[Network]\nNetworkName=vedette-int\nSubnet=" + subnet + "\nGateway=172.30.77.1\nPodmanArgs=--interface-name=vedette0\n"
}

// The five fixed rules, in the order the host keeps them; the ACCEPT of each bridge of the box named br-… goes above them.
const (
	ret1  = "-i vedette0 -o docker0 -m comment --comment vedette-int -j RETURN"
	ret2  = "-i vedette0 -o br-+ -m comment --comment vedette-int -j RETURN"
	rule1 = "-o vedette0 -d 172.30.77.0/24 -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -m comment --comment vedette-int -j ACCEPT"
	rule2 = "-i vedette0 -s 172.30.77.0/24 -m comment --comment vedette-int -j ACCEPT"
	drop  = "! -i vedette0 -o vedette0 -m comment --comment vedette-int -j DROP"
)

var fixedRules = []string{ret1, ret2, rule1, rule2, drop}

// accTo is the ACCEPT for a bridge of the box, in the words iptables -S prints.
func accTo(br string) string {
	return "-s 172.30.77.0/24 -i vedette0 -o " + br + " -m comment --comment vedette-int -j ACCEPT"
}

// iface makes the interface name under <root>/sys/class/net.
func iface(t *testing.T, m *opstest.Machine, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.MkdirAll(filepath.Join(m.Root, "sys/class/net", n), 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

// uplink makes br a bridge of the box with a network card as its port.
func uplink(t *testing.T, m *opstest.Machine, brs ...string) {
	t.Helper()
	for _, br := range brs {
		iface(t, m, br+"/brif/eth9", "eth9/device")
	}
}

func rulesAre(t *testing.T, m *opstest.Machine, want ...string) {
	t.Helper()
	if got := m.DockerRules(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func changes(m *opstest.Machine, from int) []string {
	var out []string
	for _, c := range calls(m)[from:] {
		if !strings.Contains(c, " -C ") && !strings.Contains(c, " -S ") {
			out = append(out, c)
		}
	}
	return out
}

// D-396 (a): the br-+ RETURN also matches a bridge of the box itself (an uplink br-lan): such a bridge gets an ACCEPT
// above the RETURNs, so the containers keep the internet through it. A bridge whose ports are only veths (Docker's, by
// ID or by a custom name such as br-app; review r2 M1), one without ports, or with a name the host never writes, gets none.
func TestDockerFwd_OnlyTheBoxsUplinkBridgesGetAnAccept(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	iface(t, m, "eth0/device", "bond0/bonding", "eth0.10/lower_eth0", "veth1a2b", "veth3c4d", "docker0", "vedette0", "xbr-lan")
	iface(t, m, "br-lan/brif/veth3c4d", "br-lan/brif/eth0") // a card beside a veth
	iface(t, m, "br-ex/brif/bond0", "br-vlan/brif/eth0.10")
	iface(t, m, "br-app/brif/veth1a2b", "br-empty", "br-0123456789ab/brif/eth0", "br-l+n/brif/eth0")
	o.DockerFwdTick(context.Background())
	rulesAre(t, m, accTo("br-ex"), accTo("br-lan"), accTo("br-vlan"), ret1, ret2, rule1, rule2, drop)
}

// A bridge of the box made later gets its ACCEPT above the RETURNs, below an administrator's rule; one that is gone keeps
// it (it matches nothing); the host never deletes.
func TestDockerFwd_ANewBridgeOfTheBoxGoesAboveTheReturns(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	m.DockerAdminRuleFirst("-s 192.0.2.0/24 -j DROP")
	uplink(t, m, "br-lan")
	o.DockerFwdTick(context.Background())
	rulesAre(t, m, "-s 192.0.2.0/24 -j DROP", accTo("br-lan"), ret1, ret2, rule1, rule2, drop)
	if err := os.RemoveAll(filepath.Join(m.Root, "sys/class/net/br-lan")); err != nil {
		t.Fatal(err)
	}
	uplink(t, m, "br-wan")
	o.DockerFwdTick(context.Background())
	rulesAre(t, m, "-s 192.0.2.0/24 -j DROP", accTo("br-wan"), accTo("br-lan"), ret1, ret2, rule1, rule2, drop)
	before := len(calls(m))
	o.DockerFwdTick(context.Background())
	if c := changes(m, before); len(c) != 0 {
		t.Fatalf("a quiet tick changed %q", c)
	}
}

// A box with the four rules of D-267 (and Docker's own trailing RETURN) gets the DROP (D-396 (b)) at the end of our block
// and the ACCEPT of its uplink bridge at the top; nothing is moved.
func TestDockerFwd_TheFourRulesOfD267GetTheDropAndTheUplinkAccept(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	for _, r := range []string{ret1, ret2, rule1, rule2, "-j RETURN"} {
		m.DockerAdminRule(r)
	}
	uplink(t, m, "br-lan", "br-0123456789ab")
	o.DockerFwdTick(context.Background())
	rulesAre(t, m, accTo("br-lan"), ret1, ret2, rule1, rule2, drop, "-j RETURN")
}

// Review M2: positions are counted inside our block; with someone else's rule inside it the DROP would land above the
// ACCEPT of replies, so nothing is inserted and the log says so once.
func TestDockerFwd_AForeignRuleInsideOurBlockStopsTheInserts(t *testing.T) {
	m, o, buf := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	for _, r := range []string{ret1, ret2, "-s 192.0.2.0/24 -j DROP", rule1, rule2} {
		m.DockerAdminRule(r)
	}
	for range 3 {
		o.DockerFwdTick(context.Background())
	}
	if c := changes(m, 0); len(c) != 0 {
		t.Fatalf("inserted %q", c)
	}
	if n := strings.Count(buf.String(), "with another rule between them"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, buf)
	}
}

// A duplicate ACCEPT of a bridge is a form the host did not write: nothing is added.
func TestDockerFwd_ADuplicateBridgeAcceptStopsTheInserts(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	for _, r := range []string{accTo("br-lan"), accTo("br-lan"), ret1, ret2, rule1, rule2} {
		m.DockerAdminRule(r)
	}
	uplink(t, m, "br-lan")
	o.DockerFwdTick(context.Background())
	if c := changes(m, 0); len(c) != 0 {
		t.Fatalf("inserted %q", c)
	}
}

func TestDockerFwd_TooManyBridgesOfTheBoxChangesNothingAndSaysSoOnce(t *testing.T) {
	m, o, buf := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	for i := range 33 {
		uplink(t, m, fmt.Sprintf("br-%02d", i))
	}
	for range 3 {
		o.DockerFwdTick(context.Background())
	}
	if got := calls(m); len(got) != 0 {
		t.Fatalf("ran %q", got)
	}
	if n := strings.Count(buf.String(), "more than 32 bridges"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, buf)
	}
}

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

func TestDockerFwd_ChainPresentRulesAbsentInsertsFiveInOrderWithExactArgv(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	want := []string{"-w 5 -S DOCKER-USER"}
	for _, r := range fixedRules {
		want = append(want, "-w 5 -C DOCKER-USER "+r)
	}
	for i, r := range fixedRules {
		want = append(want, "-w 5 -I DOCKER-USER "+strconv.Itoa(i+1)+" "+r)
	}
	if got := calls(m); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := m.DockerRules(); strings.Join(got, "\n") != strings.Join(fixedRules, "\n") {
		t.Fatalf("rules: %q", got)
	}
}

// An administrator's rule stands above ours and stays there; a missing rule of ours goes back at its place in our block.
func TestDockerFwd_AMissingRuleGoesBackInPlaceBelowTheAdminsRule(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	m.DockerAdminRule("-s 192.0.2.0/24 -j DROP")
	o.DockerFwdTick(context.Background())
	// the admin's rule was there first and ours went in at the top: the host does not know what an unrelated rule means
	got := m.DockerRules()
	if len(got) != 6 || got[5] != "-s 192.0.2.0/24 -j DROP" {
		t.Fatalf("rules: %q", got)
	}
	// the admin puts a rule above ours, and the host deletes nothing and moves nothing
	m2, o2, _ := fwdBox(t, "172.30.77.0/24")
	m2.DockerChain(true)
	o2.DockerFwdTick(context.Background())
	m2.DockerAdminRuleFirst("-s 192.0.2.0/24 -j DROP")
	o2.DockerFwdTick(context.Background())
	if got := m2.DockerRules(); len(got) != 6 || got[0] != "-s 192.0.2.0/24 -j DROP" || strings.Join(got[1:], "\n") != strings.Join(fixedRules, "\n") {
		t.Fatalf("rules after the admin's rule on top: %q", got)
	}
	// one of ours is deleted (the third): it returns between the second and the fourth, below the admin's rule
	m2.DockerDelete(rule1)
	o2.DockerFwdTick(context.Background())
	if got := m2.DockerRules(); len(got) != 6 || got[0] != "-s 192.0.2.0/24 -j DROP" || strings.Join(got[1:], "\n") != strings.Join(fixedRules, "\n") {
		t.Fatalf("rules after a deleted rule: %q", got)
	}
	// the first of ours is deleted: it returns above the second
	m2.DockerDelete(ret1)
	o2.DockerFwdTick(context.Background())
	if got := m2.DockerRules(); len(got) != 6 || got[0] != "-s 192.0.2.0/24 -j DROP" || strings.Join(got[1:], "\n") != strings.Join(fixedRules, "\n") {
		t.Fatalf("rules after the first was deleted: %q", got)
	}
}

// A vedette-int rule in a form the host does not write (or a duplicate) stops every insert, and the log says so once.
func TestDockerFwd_UnexpectedRulesOfOursStopTheInserts(t *testing.T) {
	m, o, buf := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	m.DockerAdminRule("-s 172.30.77.0/24 -m comment --comment vedette-int -j ACCEPT") // the old two-rule form
	for range 3 {
		o.DockerFwdTick(context.Background())
	}
	for _, c := range calls(m) {
		if strings.Contains(c, " -I ") {
			t.Fatalf("an insert beside a rule of an unknown form: %q", c)
		}
	}
	if n := strings.Count(buf.String(), "in a form this host does not know"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, buf)
	}
	if len(m.DockerRules()) != 1 {
		t.Fatalf("rules: %q", m.DockerRules())
	}
}

func TestDockerFwd_ANetworkFileWithoutTheBridgeNameChangesNothingAndSaysSoOnce(t *testing.T) {
	m, o, buf := fwdBox(t, "")
	m.WriteRoot(netFile, "[Network]\nNetworkName=vedette-int\nSubnet=172.30.77.0/24\nGateway=172.30.77.1\n")
	m.DockerChain(true)
	for range 3 {
		o.DockerFwdTick(context.Background())
	}
	if got := calls(m); len(got) != 0 {
		t.Fatalf("ran %q", got)
	}
	if n := strings.Count(buf.String(), "run the installer again"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, buf)
	}
	// another bridge name is a refusal too
	m2, o2, _ := fwdBox(t, "")
	m2.WriteRoot(netFile, strings.Replace(networkText("172.30.77.0/24"), "vedette0", "docker0", 1))
	m2.DockerChain(true)
	o2.DockerFwdTick(context.Background())
	if got := calls(m2); len(got) != 0 {
		t.Fatalf("another bridge: ran %q", got)
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
	if got := m.DockerRules(); len(got) != 5 {
		t.Fatalf("rules are not idempotent: %q", got)
	}
}

func TestDockerFwd_DockerRestartPutsTheRulesBack(t *testing.T) {
	m, o, _ := fwdBox(t, "172.30.77.0/24")
	m.DockerChain(true)
	o.DockerFwdTick(context.Background())
	m.DockerFlush()
	o.DockerFwdTick(context.Background())
	if got := m.DockerRules(); len(got) != 5 {
		t.Fatalf("rules after a flush: %q", got)
	}
}

func TestDockerFwd_BadSubnetRunsNothing(t *testing.T) {
	for _, s := range []string{"8.8.8.0/24", "0.0.0.0/0", "172.30.77.5/24", "172.30.0.0/8", "172.30.77.0/29", "fd00::/64", "192.168.0.0/24", "10.0.0.0/24", "172.30.0.0/16", "172.31.77.0/24", "172.30.77.0/25", "garbage", "10.0.0.0/24; x", ""} {
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
	if len(m.DockerRules()) != 5 {
		t.Fatalf("Start did not put the rules: %q", m.DockerRules())
	}
	if fire == nil {
		t.Fatal("no 30 s timer armed")
	}
	m.DockerFlush()
	fire()
	if len(m.DockerRules()) != 5 {
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
	good := [][]string{{"-w", "5", "-S", "DOCKER-USER"}}
	for i, r := range fixedRules {
		good = append(good, append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(r)...),
			append([]string{"-w", "5", "-I", "DOCKER-USER", strconv.Itoa(i + 1)}, strings.Fields(r)...))
	}
	for _, a := range good {
		if err := ops.ValidateIptables(a); err != nil {
			t.Errorf("%q refused: %v", a, err)
		}
	}
	for _, br := range []string{"br-lan", "br-ex", "br-0123456789AB", "br-a.b_c-d"} {
		good = append(good, append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo(br))...),
			append([]string{"-w", "5", "-I", "DOCKER-USER", "1"}, strings.Fields(accTo(br))...))
	}
	bad := [][]string{
		nil,
		append([]string{"-w", "5", "-I", "DOCKER-USER", "1"}, strings.Fields(accTo("br-0123456789ab"))...), // Docker's own bridge
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo("br-+"))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo("br-l+n"))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo("br-"))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo("br-1234567890123"))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo("eth0"))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(accTo("docker0"))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(accTo("br-lan"), "172.30.77.0/24", "0.0.0.0/0", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(accTo("br-lan"), "-i vedette0", "-i eth0", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(accTo("br-lan"), "ACCEPT", "RETURN", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(accTo("br-lan"), "-s 172.30.77.0/24 ", "", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(ret2, "br-+", "br-lan", 1))...),
		append([]string{"-w", "5", "-D", "DOCKER-USER"}, strings.Fields(ret2)...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(drop, "! ", "", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(drop, "-o vedette0", "-o eth0", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(drop, "DROP", "ACCEPT", 1))...),
		{"-w", "5", "-C", "DOCKER-USER", "-s"},
		{"-S", "DOCKER-USER"},
		{"-w", "5", "-S", "FORWARD"},
		{"-w", "5", "-S", "DOCKER-USER", "-v"},
		{"-w", "5", "-F", "DOCKER-USER"},
		{"-w", "5", "-D", "DOCKER-USER", "1"},
		{"-w", "5", "-P", "FORWARD", "ACCEPT"},
		{"-w", "5", "-I", "DOCKER-USER"},
		{"-w", "5", "-I", "DOCKER-USER", "2", "-s", "172.30.77.0/24", "-m", "comment", "--comment", "vedette-int", "-j", "ACCEPT"}, // the old, interface-less form
		append([]string{"-w", "5", "-I", "DOCKER-USER", "0"}, strings.Fields(rule2)...),
		append([]string{"-w", "5", "-I", "DOCKER-USER", "1001"}, strings.Fields(rule2)...),
		append([]string{"-w", "5", "-I", "DOCKER-USER", "01"}, strings.Fields(rule2)...),
		append([]string{"-w", "5", "-I", "DOCKER-USER", "-1"}, strings.Fields(rule2)...),
		append([]string{"-w", "5", "-I", "DOCKER-USER"}, strings.Fields(rule2)...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(ret1, "docker0", "eth0", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(ret1, "RETURN", "ACCEPT", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule2, "vedette0", "eth0", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule1, "172.30.77.0/24", "192.168.0.0/24", 1))...),
		append([]string{"-w", "5", "-C", "DOCKER-USER"}, strings.Fields(strings.Replace(rule1, "172.30.77.0/24", "172.30.0.0/16", 1))...),
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
