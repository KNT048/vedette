package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Docker's FORWARD drop (D-267, D-396). When Docker enables IP forwarding it sets the iptables filter FORWARD
// policy to DROP; netavark (Podman, nftables driver) keeps its rules in its own table, and an accept in
// one nftables table is not final, so the packets of Vedette's own network are still dropped: the GUI on
// 8443 and syslog on 514 are unreachable from the LAN and the containers cannot reach the internet.
// Docker's answer is the DOCKER-USER chain (the place for rules of the administrator, never touched by
// Docker); LXD and Fedora's Podman notes say the same. So the host keeps its rules in DOCKER-USER, bound
// to Vedette's bridge vedette0 (install.sh names it) and its subnet, and only while that chain exists (no
// Docker, or Docker's nftables backend: nothing is done). In the order they keep:
//
//	-s <subnet> -i vedette0 -o br-lan -j ACCEPT   one per bridge of the box named br-… that is not Docker's (D-396)
//	-i vedette0 -o docker0 -j RETURN              Docker keeps protecting its own networks from Vedette's containers:
//	-i vedette0 -o br-+    -j RETURN              the packet goes on to Docker's own chains, which decide as before
//	-o vedette0 -d <subnet> -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -j ACCEPT   published ports, replies
//	-i vedette0 -s <subnet> -j ACCEPT                                                    the containers' traffic out
//	! -i vedette0 -o vedette0 -j DROP             nothing else reaches Vedette's containers (D-396)
//
// The br-+ RETURN covers Docker's user-defined networks (Docker names their bridges "br-" and 12 hex digits
// of the network ID) from the moment Docker makes one; iptables matches an interface name only exactly or by
// a "+" prefix, so it also matches a bridge of the box itself such as an uplink br-lan, and the containers
// lost the internet through it. The host lists /sys/class/net and keeps, above the RETURNs, an ACCEPT for
// every interface named br-… that is not of Docker's form (D-396). Fail closed: a new uplink bridge has no
// internet for at most one look (30 s); a new Docker network is never open to Vedette's containers. An
// ACCEPT of a bridge that is gone stays (it matches nothing; install.sh --uninstall removes it).
//
// The DROP mirrors what Docker 28 does for its own networks: a port of a container that is not published
// is not reachable from outside its network. Without it, Docker's own accept for traffic leaving its
// bridges let a customer's Docker container open any port of Vedette's containers on vedette-int;
// published ports (DNAT) and replies are accepted above it.
//
// All rules carry the comment vedette-int. An administrator's own DOCKER-USER rules must stand above them.
// The host only checks (-C) and inserts (-I); it never deletes or moves a rule. A stop leaves them;
// install.sh --uninstall removes them.
//
// The subnet and the bridge name are read from the Quadlet network file install.sh wrote, never from a
// request. A file without the bridge name (an older install) is left alone: a re-install is needed.

const (
	// intNetwork is NetworkName= of the network file (install.sh writes it): the containers' network, and the scan build's (#467).
	intNetwork     = "vedette-int"
	netFileRel     = unitsRel + "/" + intNetwork + ".network"
	maxNetFileSize = 4 << 10
	fwdChain       = "DOCKER-USER"
	fwdComment     = "vedette-int"
	fwdBridge      = "vedette0"
	fwdBridgeLine  = "PodmanArgs=--interface-name=" + fwdBridge
	dockerFwdEvery = 30 * time.Second
	dockerFwdLimit = 20 * time.Second
	maxFwdPosition = 1000
	// maxBoxBridges caps the ACCEPTs for bridges of the box named br-… (an appliance has one or two).
	// ponytail: past it nothing is changed and the log says so; raise it if a real box needs more.
	maxBoxBridges = 32
)

// binIptables is iptables (the nft or the legacy flavour, whichever the alternatives point at).
const binIptables = "iptables"

// fwdNet is the only range install.sh picks the subnet from (172.30.x.0/24).
var fwdNet = netip.MustParsePrefix("172.30.0.0/16")

var (
	// dockerBridgeName is the name Docker gives the bridge of a user-defined network: "br-" + id[:12] (moby's bridge driver).
	dockerBridgeName = regexp.MustCompile(`^br-[0-9a-f]{12}$`)
	// brName is a name the br-+ RETURN matches that the host will write into a rule: at most 15 bytes (IFNAMSIZ),
	// and never "+" (iptables' wildcard) or "!".
	brName = regexp.MustCompile(`^br-[A-Za-z0-9_.-]{1,12}$`)
)

// boxBridge says whether name is a bridge of the box (not Docker's) that the br-+ RETURN would catch.
func boxBridge(name string) bool {
	return brName.MatchString(name) && !dockerBridgeName.MatchString(name)
}

// fwdPrefix says whether p is a subnet the host will write rules for: 172.30.x.0/24.
func fwdPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && p.Bits() == 24 && p == p.Masked() && fwdNet.Contains(p.Addr())
}

// fwdReturn is the RETURN for packets of vedette0 that leave through out (docker0 or br-+).
func fwdReturn(out string) []string {
	return []string{"-i", fwdBridge, "-o", out, "-m", "comment", "--comment", fwdComment, "-j", "RETURN"}
}

// fwdBoxAccept is the ACCEPT for the containers' packets that leave through the box's own bridge out, in the
// words "iptables -S" prints it (source first), so the host can read it back.
func fwdBoxAccept(p netip.Prefix, out string) []string {
	return []string{"-s", p.String(), "-i", fwdBridge, "-o", out, "-m", "comment", "--comment", fwdComment, "-j", "ACCEPT"}
}

// fwdRules are the five fixed rules in the order they keep, as the words after the chain name; the ACCEPTs
// of fwdBoxAccept stand above them.
func fwdRules(p netip.Prefix) [5][]string {
	s := p.String()
	c := []string{"-m", "comment", "--comment", fwdComment}
	cat := func(parts ...[]string) []string { return slices.Concat(parts...) }
	return [5][]string{
		fwdReturn("docker0"),
		fwdReturn("br-+"),
		cat([]string{"-o", fwdBridge, "-d", s, "-m", "conntrack", "--ctstate", "DNAT,ESTABLISHED,RELATED"}, c, []string{"-j", "ACCEPT"}),
		cat([]string{"-i", fwdBridge, "-s", s}, c, []string{"-j", "ACCEPT"}),
		cat([]string{"!", "-i", fwdBridge, "-o", fwdBridge}, c, []string{"-j", "DROP"}),
	}
}

// validateIptables accepts exactly three shapes: list the chain (-S DOCKER-USER), check one rule (-C
// DOCKER-USER <rule>) and insert one at a position (-I DOCKER-USER <1..1000> <rule>); every shape starts
// with "-w 5" (wait for the xtables lock). The rule must be one fwdRules builds, or fwdBoxAccept of a name
// boxBridge accepts, for a subnet that passes fwdPrefix.
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
	// the two RETURNs and the DROP have no subnet
	if r := fwdRules(fwdNet); slices.Equal(rest, r[0]) || slices.Equal(rest, r[1]) || slices.Equal(rest, r[4]) {
		return nil
	}
	// an ACCEPT for a bridge of the box has the subnet as the second word, the two others as the fourth
	at := 3
	if len(rest) > 1 && rest[0] == "-s" {
		at = 1
	}
	if len(rest) <= at {
		return bad
	}
	p, err := netip.ParsePrefix(rest[at])
	if err != nil || !fwdPrefix(p) {
		return bad
	}
	if at == 1 {
		if len(rest) == 12 && boxBridge(rest[5]) && slices.Equal(rest, fwdBoxAccept(p, rest[5])) {
			return nil
		}
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

// errTooManyBridges says the box has more than maxBoxBridges bridges named br-… that are not Docker's.
var errTooManyBridges = errors.New("too many bridges named br-")

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

// boxBridges are the interfaces of the box (<root>/sys/class/net, names only) that the br-+ RETURN would
// catch and that are not Docker's, sorted. A directory that cannot be read gives none: fail closed (such
// a bridge then has no internet for Vedette's containers, as before D-396).
func (o *Ops) boxBridges() ([]string, error) {
	ents, err := os.ReadDir(o.path("sys/class/net"))
	if err != nil {
		return nil, nil // fail closed, see above
	}
	var out []string
	for _, e := range ents {
		if boxBridge(e.Name()) {
			out = append(out, e.Name())
		}
	}
	if len(out) > maxBoxBridges {
		return nil, errTooManyBridges
	}
	return out, nil
}

// fwdView is what "iptables -S DOCKER-USER" shows of ours: the positions of the first and the last line
// that carry our comment, how many such lines there are, and the ACCEPTs for bridges of the box among
// them, as the number of lines per bridge.
type fwdView struct {
	base, last, ours int
	box              map[string]int
}

func parseFwdChain(out string, p netip.Prefix) fwdView {
	v := fwdView{base: 1, box: map[string]int{}}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "-A "+fwdChain+" ") {
			continue
		}
		n++
		if !strings.Contains(l, "--comment "+fwdComment+" ") && !strings.HasSuffix(l, "--comment "+fwdComment) {
			continue
		}
		if v.ours == 0 {
			v.base = n
		}
		v.last = n
		v.ours++
		if f := strings.Fields(l)[2:]; len(f) == 12 && boxBridge(f[5]) && slices.Equal(f, fwdBoxAccept(p, f[5])) {
			v.box[f[5]]++
		}
	}
	return v
}

// dockerFwdSync makes the rules exist, in order, when DOCKER-USER does: an ACCEPT for every bridge of the
// box named br-… that is not Docker's, then the five fixed rules. It returns the state it found, a short
// word, and how many rules it added.
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
	want, err := o.boxBridges()
	if err != nil {
		return "too_many_bridges", 0
	}
	res, code, err := o.exec(ctx, binIptables, argvIptables("-S", 0, nil)...)
	if err != nil {
		return "iptables_unavailable", 0
	}
	if code != 0 {
		return "chain_absent", 0
	}
	v := parseFwdChain(string(res.Stdout), p)
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
	// Never insert beside rules of ours in a form the host does not know (or duplicates): an odd iptables, or a person, did that.
	if v.ours > len(rules)-len(missing)+len(v.box) {
		return "unexpected", 0
	}
	var newBox []string
	for _, br := range want {
		if v.box[br] > 0 {
			continue
		}
		// -S did not show it: make sure it is really absent, so an iptables that prints our rules in other words never gets a new copy every 30 s.
		_, code, err := o.exec(ctx, binIptables, argvIptables("-C", 0, fwdBoxAccept(p, br))...)
		switch {
		case err != nil || (code != 0 && code != 1):
			return "failed", 0
		case code == 0:
			return "unexpected", 0
		}
		newBox = append(newBox, br)
	}
	if len(missing) == 0 && len(newBox) == 0 {
		return "present", 0
	}
	// Positions are counted inside our block, so it must be one run of lines: a rule of someone else inside it would put a
	// rule of ours at a wrong place (the DROP above the ACCEPT of replies).
	if v.ours > 0 && v.last-v.base+1 != v.ours {
		return "unexpected", 0
	}
	for i, br := range newBox {
		if _, code, err := o.exec(ctx, binIptables, argvIptables("-I", v.base+i, fwdBoxAccept(p, br))...); err != nil || code != 0 {
			return "failed", added
		}
		added++
	}
	// the fixed rules go in order, so the ones before k are in place when k goes in
	box := len(v.box) + len(newBox)
	for _, k := range missing {
		if _, code, err := o.exec(ctx, binIptables, argvIptables("-I", v.base+box+k, rules[k])...); err != nil || code != 0 {
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
		o.log.InfoContext(ctx, "docker forward rules: added to DOCKER-USER for the vedette-int bridge (D-267, D-396)", "rules", added)
	case !changed:
	case state == "present":
		o.log.InfoContext(ctx, "docker forward rules: DOCKER-USER already has the rules for the vedette-int bridge")
	case state == "chain_absent":
		o.log.InfoContext(ctx, "docker forward rules: no DOCKER-USER chain (no Docker, or its nftables backend); nothing to do")
	case state == "no_bridge":
		o.log.WarnContext(ctx, "docker forward rules: the vedette-int network was made by an install that did not name its bridge (vedette0); run the installer again (--uninstall --yes, then install). Nothing is changed")
	case state == "unexpected":
		o.log.WarnContext(ctx, "docker forward rules: DOCKER-USER holds vedette-int rules in a form this host does not know, more than it writes, or with another rule between them; nothing is changed")
	case state == "too_many_bridges":
		o.log.WarnContext(ctx, "docker forward rules: more than 32 bridges named br-… that are not Docker's on this box; nothing is changed")
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
