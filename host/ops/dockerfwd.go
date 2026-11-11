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
	"strings"
	"syscall"
	"time"
)

// Docker's FORWARD drop (D-267). When Docker enables IP forwarding it sets the iptables filter FORWARD
// policy to DROP; netavark (Podman, nftables driver) keeps its rules in its own table, and an accept in
// one nftables table is not final, so the packets of Vedette's own network are still dropped: the GUI on
// 8443 and syslog on 514 are unreachable from the LAN and the containers cannot reach the internet.
// Docker's own answer is the DOCKER-USER chain (the place for rules of the administrator, never touched
// by Docker); LXD and Fedora's Podman notes say the same. So the host keeps two rules in DOCKER-USER for
// the subnet of vedette-int, and only while that chain exists (no Docker, or Docker's nftables backend:
// nothing is done). They accept nothing but Vedette's own subnet, so a stop leaves them; install.sh
// --uninstall removes them (they carry the comment vedette-int).
//
// The subnet is read from the Quadlet network file install.sh wrote, never from a request.

const (
	netFileRel      = unitsRel + "/vedette-int.network"
	maxNetFileSize  = 4 << 10
	fwdChain        = "DOCKER-USER"
	fwdComment      = "vedette-int"
	dockerFwdEvery  = 30 * time.Second
	dockerFwdLimit  = 20 * time.Second
	minFwdPrefixLen = 16
	maxFwdPrefixLen = 28
)

// binIptables is iptables (the nft or the legacy flavour, whichever the alternatives point at).
const binIptables = "iptables"

// fwdPrefix says whether p is a subnet the host will write rules for: a private IPv4 prefix, in its
// canonical (masked) form, 16 to 28 bits long.
func fwdPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && p.Addr().IsPrivate() && p == p.Masked() &&
		p.Bits() >= minFwdPrefixLen && p.Bits() <= maxFwdPrefixLen
}

// fwdRules are the two rules, as the words after the chain name: R1 admits what goes to the subnet
// (published ports after DNAT, and the replies to what the containers opened), R2 what leaves it.
func fwdRules(p netip.Prefix) [2][]string {
	s := p.String()
	return [2][]string{
		{"-d", s, "-m", "conntrack", "--ctstate", "DNAT,ESTABLISHED,RELATED", "-m", "comment", "--comment", fwdComment, "-j", "ACCEPT"},
		{"-s", s, "-m", "comment", "--comment", fwdComment, "-j", "ACCEPT"},
	}
}

// validateIptables accepts exactly three shapes: list the chain (-S DOCKER-USER), check one of the two
// rules (-C DOCKER-USER <rule>) and insert one at position 1 (-I DOCKER-USER 1 <rule>); every shape
// starts with "-w 5" (wait for the xtables lock). The rule must be one fwdRules builds, for a subnet
// that passes fwdPrefix.
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
		if len(rest) == 0 || rest[0] != "1" {
			return bad
		}
		rest = rest[1:]
	case "-C":
	default:
		return bad
	}
	if len(rest) < 2 {
		return bad
	}
	p, err := netip.ParsePrefix(rest[1])
	if err != nil || !fwdPrefix(p) {
		return bad
	}
	if r := fwdRules(p); slices.Equal(rest, r[0]) || slices.Equal(rest, r[1]) {
		return nil
	}
	return bad
}

func argvIptables(verb string, rule []string) []string {
	a := []string{"-w", "5", verb, fwdChain}
	if verb == "-I" {
		a = append(a, "1")
	}
	return append(a, rule...)
}

// vedetteIntSubnet reads Subnet= from the network file under the root. The file must be a regular file
// (no symlink) of the host's owner that nobody else can write.
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
	var got []string
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Subnet="); ok {
			got = append(got, v)
		}
	}
	if len(got) != 1 {
		return netip.Prefix{}, fmt.Errorf("the network file has %d Subnet= lines, want 1", len(got))
	}
	p, err := netip.ParsePrefix(got[0])
	if err != nil || !fwdPrefix(p) {
		return netip.Prefix{}, errors.New("the Subnet= of the network file is not a private IPv4 prefix of 16 to 28 bits")
	}
	return p, nil
}

// dockerFwdSync makes the two rules exist when DOCKER-USER does. It returns the state it found, a
// short word, and how many rules it had to add.
func (o *Ops) dockerFwdSync(ctx context.Context) (state string, added int) {
	p, err := o.vedetteIntSubnet()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return "no_network_file", 0
		}
		o.log.WarnContext(ctx, "docker forward rules: the vedette-int subnet is unusable; nothing is changed", "error", err.Error())
		return "subnet_unusable", 0
	}
	_, code, err := o.exec(ctx, binIptables, argvIptables("-S", nil)...)
	if err != nil {
		return "iptables_unavailable", 0
	}
	if code != 0 {
		return "chain_absent", 0
	}
	for _, r := range fwdRules(p) {
		_, code, err := o.exec(ctx, binIptables, argvIptables("-C", r)...)
		if err != nil {
			return "failed", added
		}
		if code == 0 {
			continue
		}
		if code != 1 {
			return "failed", added
		}
		if _, code, err := o.exec(ctx, binIptables, argvIptables("-I", r)...); err != nil || code != 0 {
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
		o.log.InfoContext(ctx, "docker forward rules: added to DOCKER-USER for the vedette-int subnet (D-267)", "rules", added)
	case !changed:
	case state == "present":
		o.log.InfoContext(ctx, "docker forward rules: DOCKER-USER already has both rules for the vedette-int subnet")
	case state == "chain_absent":
		o.log.InfoContext(ctx, "docker forward rules: no DOCKER-USER chain (no Docker, or its nftables backend); nothing to do")
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
