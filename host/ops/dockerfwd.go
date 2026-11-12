package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Docker's FORWARD drop (D-267). When Docker enables IP forwarding it sets the iptables filter FORWARD
// policy to DROP; netavark (Podman, nftables driver) keeps its rules in its own table, and an accept in
// one nftables table is not final, so the packets of Vedette's own network are still dropped: the GUI on
// 8443 and syslog on 514 are unreachable from the LAN and the containers cannot reach the internet.
// Docker's answer is the DOCKER-USER chain (the place for rules of the administrator, never touched by
// Docker); LXD and Fedora's Podman notes say the same. So the host keeps four rules in DOCKER-USER, bound
// to Vedette's bridge vedette0 (install.sh names it) and its subnet, and only while that chain exists (no
// Docker, or Docker's nftables backend: nothing is done). In the order they keep:
//
//	-i vedette0 -o docker0 -j RETURN       Docker keeps protecting its own networks from Vedette's containers:
//	-i vedette0 -o br-+    -j RETURN       the packet goes on to Docker's own chains, which decide as before
//	-o vedette0 -d <subnet> -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -j ACCEPT   published ports, replies
//	-i vedette0 -s <subnet> -j ACCEPT                                                    the containers' traffic out
//
// All four carry the comment vedette-int. They accept only packets that enter or leave through vedette0
// from or to the subnet of vedette-int, and apart from the two RETURNs they accept those wherever they go
// (an administrator's own DOCKER-USER rules must stand above them). A stop leaves them; install.sh
// --uninstall removes them.
//
// The subnet and the bridge name are read from the Quadlet network file install.sh wrote, never from a
// request. A file without the bridge name (an older install) is left alone: a re-install is needed.

const (
	netFileRel     = unitsRel + "/vedette-int.network"
	maxNetFileSize = 4 << 10
	fwdChain       = "DOCKER-USER"
	fwdComment     = "vedette-int"
	fwdBridge      = "vedette0"
	fwdBridgeLine  = "PodmanArgs=--interface-name=" + fwdBridge
	dockerFwdEvery = 30 * time.Second
	dockerFwdLimit = 20 * time.Second
	maxFwdPosition = 1000
)

// binIptables is iptables (the nft or the legacy flavour, whichever the alternatives point at).
const binIptables = "iptables"

// fwdNet is the only range install.sh picks the subnet from (172.30.x.0/24).
var fwdNet = netip.MustParsePrefix("172.30.0.0/16")

// fwdPrefix says whether p is a subnet the host will write rules for: 172.30.x.0/24.
func fwdPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && p.Bits() == 24 && p == p.Masked() && fwdNet.Contains(p.Addr())
}

// fwdRules are the four rules in the order they keep, as the words after the chain name.
func fwdRules(p netip.Prefix) [4][]string {
	s := p.String()
	c := []string{"-m", "comment", "--comment", fwdComment}
	cat := func(parts ...[]string) []string { return slices.Concat(parts...) }
	return [4][]string{
		cat([]string{"-i", fwdBridge, "-o", "docker0"}, c, []string{"-j", "RETURN"}),
		cat([]string{"-i", fwdBridge, "-o", "br-+"}, c, []string{"-j", "RETURN"}),
		cat([]string{"-o", fwdBridge, "-d", s, "-m", "conntrack", "--ctstate", "DNAT,ESTABLISHED,RELATED"}, c, []string{"-j", "ACCEPT"}),
		cat([]string{"-i", fwdBridge, "-s", s}, c, []string{"-j", "ACCEPT"}),
	}
}

// validateIptables accepts exactly three shapes: list the chain (-S DOCKER-USER), check one of the four
// rules (-C DOCKER-USER <rule>) and insert one at a position (-I DOCKER-USER <1..1000> <rule>); every
// shape starts with "-w 5" (wait for the xtables lock). The rule must be one fwdRules builds, for a
// subnet that passes fwdPrefix.
func validateIptables(args []string) error {
	bad := errors.New("not one of the fixed iptables command lines")
	if len(args) < 4 || args[0] != "-w" || args[1] != "5" || args[3] != fwdChain {
		return bad
	}
	rest := args[4:]
	switch args[2] {
	case "-S":
		if len(rest) == 0 {
			return nil
		}
		return bad
	case "-I":
		if len(rest) < 2 {
			return bad
		}
		pos, err := strconv.Atoi(rest[0])
		if err != nil || pos < 1 || pos > maxFwdPosition || strconv.Itoa(pos) != rest[0] {
			return bad
		}
		rest = rest[1:]
	case "-C":
	default:
		return bad
	}
	// the two RETURNs have no subnet; the other two have it as the fourth word
	if r := fwdRules(fwdNet); slices.Equal(rest, r[0]) || slices.Equal(rest, r[1]) {
		return nil
	}
	if len(rest) < 4 {
		return bad
	}
	p, err := netip.ParsePrefix(rest[3])
	if err != nil || !fwdPrefix(p) {
		return bad
	}
	if r := fwdRules(p); slices.Equal(rest, r[2]) || slices.Equal(rest, r[3]) {
		return nil
	}
	return bad
}

func argvIptables(verb string, pos int, rule []string) []string {
	a := []string{"-w", "5", verb, fwdChain}
	if verb == "-I" {
		a = append(a, strconv.Itoa(pos))
	}
	return append(a, rule...)
}

// errNoBridge says the network file is from an install that did not name the bridge.
var errNoBridge = errors.New("the network file does not name the bridge vedette0")

// vedetteIntSubnet reads Subnet= and the bridge name from the network file under the root. The file
// must be a regular file (no symlink) of the host's owner that nobody else can write.
func (o *Ops) vedetteIntSubnet() (netip.Prefix, error) {
	f, st, err := openRegularNoFollow(filepath.Join(o.d.Root, netFileRel))
	if err != nil {
		return netip.Prefix{}, err
	}
	defer func() { _ = f.Close() }()
	if !o.ownedByHost(st) || st.Mode().Perm()&0o022 != 0 {
		return netip.Prefix{}, errors.New("the network file is not the host's own or can be written by others")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxNetFileSize+1))
	if err != nil || len(b) > maxNetFileSize {
		return netip.Prefix{}, errors.New("the network file cannot be read or is too large")
	}
	var subnets []string
	bridge := 0
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "Subnet="); ok {
			subnets = append(subnets, v)
		}
		if strings.Contains(l, "--interface-name") && !strings.HasPrefix(l, "#") {
			if l != fwdBridgeLine {
				return netip.Prefix{}, errors.New("the network file names a bridge other than vedette0")
			}
			bridge++
		}
	}
	if len(subnets) != 1 {
		return netip.Prefix{}, fmt.Errorf("the network file has %d Subnet= lines, want 1", len(subnets))
	}
	p, err := netip.ParsePrefix(subnets[0])
	if err != nil || !fwdPrefix(p) {
		return netip.Prefix{}, errors.New("the Subnet= of the network file is not a 172.30.x.0/24 prefix")
	}
	if bridge != 1 {
		return netip.Prefix{}, errNoBridge
	}
	return p, nil
}

// dockerFwdSync makes the four rules exist, in order, when DOCKER-USER does. It returns the state it
// found, a short word, and how many rules it had to add.
func (o *Ops) dockerFwdSync(ctx context.Context) (state string, added int) {
	p, err := o.vedetteIntSubnet()
	switch {
	case errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT):
		return "no_network_file", 0
	case errors.Is(err, errNoBridge):
		return "no_bridge", 0
	case err != nil:
		o.log.WarnContext(ctx, "docker forward rules: the vedette-int network file is unusable; nothing is changed", "error", err.Error())
		return "subnet_unusable", 0
	}
	res, code, err := o.exec(ctx, binIptables, argvIptables("-S", 0, nil)...)
	if err != nil {
		return "iptables_unavailable", 0
	}
	if code != 0 {
		return "chain_absent", 0
	}
	// Where our block starts (the position of the first line that carries our comment) and how many such lines there are.
	base, ours, n := 1, 0, 0
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if !strings.HasPrefix(l, "-A "+fwdChain+" ") {
			continue
		}
		n++
		if strings.Contains(l, "--comment "+fwdComment+" ") || strings.HasSuffix(l, "--comment "+fwdComment) {
			if ours == 0 {
				base = n
			}
			ours++
		}
	}
	rules := fwdRules(p)
	var missing []int
	for k, r := range rules {
		_, code, err := o.exec(ctx, binIptables, argvIptables("-C", 0, r)...)
		if err != nil || (code != 0 && code != 1) {
			return "failed", 0
		}
		if code == 1 {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return "present", 0
	}
	// Never insert beside rules of ours in a form the host does not know (or duplicates): an odd iptables, or a person, did that.
	if ours > len(rules)-len(missing) {
		return "unexpected", 0
	}
	for _, k := range missing {
		if _, code, err := o.exec(ctx, binIptables, argvIptables("-I", base+k, rules[k])...); err != nil || code != 0 {
			return "failed", added
		}
		added++
	}
	return "present", added
}

// dockerFwdTick is one look: sync, and log when the state changed or rules were added.
func (o *Ops) dockerFwdTick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, dockerFwdLimit)
	defer cancel()
	state, added := o.dockerFwdSync(ctx)
	o.mu.Lock()
	changed := state != o.fwdLast
	o.fwdLast = state
	o.mu.Unlock()
	switch {
	case added > 0:
		o.log.InfoContext(ctx, "docker forward rules: added to DOCKER-USER for the vedette-int bridge (D-267)", "rules", added)
	case !changed:
	case state == "present":
		o.log.InfoContext(ctx, "docker forward rules: DOCKER-USER already has the rules for the vedette-int bridge")
	case state == "chain_absent":
		o.log.InfoContext(ctx, "docker forward rules: no DOCKER-USER chain (no Docker, or its nftables backend); nothing to do")
	case state == "no_bridge":
		o.log.WarnContext(ctx, "docker forward rules: the vedette-int network was made by an install that did not name its bridge (vedette0); run the installer again (--uninstall --yes, then install). Nothing is changed")
	case state == "unexpected":
		o.log.WarnContext(ctx, "docker forward rules: DOCKER-USER holds vedette-int rules in a form this host does not know (or more than it writes); nothing is changed")
	case state == "failed" || state == "iptables_unavailable":
		o.log.WarnContext(ctx, "docker forward rules: iptables did not accept the rules; will try again", "state", state)
	}
}

// armDockerFwd looks now and then every dockerFwdEvery, each look arming the next, until Close.
func (o *Ops) armDockerFwd(ctx context.Context) {
	o.dockerFwdTick(ctx)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fwdOff != nil {
		o.fwdOff()
	}
	if o.closed {
		return
	}
	o.fwdOff = o.d.FwdAfter(dockerFwdEvery, func() { o.armDockerFwd(context.WithoutCancel(ctx)) })
}
