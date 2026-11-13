package ops

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// decoy_ip.add and decoy_ip.remove (spec 6.6, D-102) and the re-apply that follows every network
// change and every start. A decoy is a macvlan link on the management card, moved into the namespace
// vedette-hp, with its address, its own routing table (100 to 131, kept with the decoy) and a rule
// "from <ip> lookup <table>". The honeypot container joins the namespace, so a decoy added later
// is seen without a restart.

const (
	maxNSLinks       = 1024
	decoyReapplyTime = 2 * time.Minute
)

// fieldIP names the ip argument in errors, logs and audit lines; a reviewed exception of the network-literal guard (FORBID-2).
const fieldIP = "ip"

var errNoMgmt = errors.New("ops: the box has no management network yet")

// mgmtNet is the box's own network as far as decoys care: the card the macvlans sit on, the box's
// address with its prefix, and the gateway (invalid when there is none).
type mgmtNet struct {
	Iface   string
	Prefix  netip.Prefix
	Gateway netip.Addr
}

func (m mgmtNet) subnet() netip.Prefix { return m.Prefix.Masked() }

// mgmtNow finds the management network. With hint (the configuration a net.apply is just applying)
// the card and a static address come from it; otherwise from the host's netplan file, or, before the
// host has configured anything, from the card of the default route. A DHCP card has no address in
// any file: it is read from the card, and with wait the host gives the lease up to NetWait.
func (o *Ops) mgmtNow(ctx context.Context, hint *NetplanConfig, wait bool) (mgmtNet, error) {
	var cfg NetplanConfig
	ok := false
	if hint != nil {
		cfg, ok = *hint, true
	} else {
		cfg, ok = o.readNetplanConfig()
	}
	m := mgmtNet{}
	route := o.defaultRoute()
	static := false
	switch {
	case ok:
		m.Iface = cfg.Mgmt.Iface
		if cfg.Mgmt.Mode == api.NetModeStatic && cfg.Mgmt.Address.IsValid() && cfg.Mgmt.Address.Addr().Is4() {
			static, m.Prefix, m.Gateway = true, cfg.Mgmt.Address, cfg.Mgmt.Gateway
		}
	case route != nil:
		m.Iface = route.Iface
	}
	if !validIfaceName(m.Iface) {
		return mgmtNet{}, errNoMgmt
	}
	if !static {
		m.Prefix = o.waitIPv4(ctx, m.Iface, wait)
		if !m.Prefix.IsValid() {
			return mgmtNet{}, errNoMgmt
		}
		if route != nil && route.Iface == m.Iface {
			m.Gateway, _ = netip.ParseAddr(route.Gateway)
		}
	}
	if m.Gateway.IsValid() && !m.Gateway.Is4() {
		m.Gateway = netip.Addr{}
	}
	if b := m.Prefix.Bits(); b < minMgmtBits || b > maxMgmtBits {
		return mgmtNet{}, errNoMgmt
	}
	return m, nil
}

// waitIPv4 returns the first global IPv4 address of the card, waiting for it when wait is set.
func (o *Ops) waitIPv4(ctx context.Context, iface string, wait bool) netip.Prefix {
	end := time.Now().Add(o.d.NetWait)
	for {
		if p := o.firstIPv4(iface); p.IsValid() {
			return p
		}
		if !wait || time.Now().After(end) || !sleepCtx(ctx, o.d.NetPoll) {
			return netip.Prefix{}
		}
	}
}

func (o *Ops) firstIPv4(iface string) netip.Prefix {
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return netip.Prefix{}
	}
	for _, h := range ifaces {
		if h.Name != iface {
			continue
		}
		for _, p := range h.Addrs {
			if p.Addr().Is4() && unicast4(p.Addr()) {
				return p
			}
		}
	}
	return netip.Prefix{}
}

// hostAddrs lists every IPv4 address the box holds on any card.
func (o *Ops) hostAddrs() []netip.Addr {
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, h := range ifaces {
		for _, p := range h.Addrs {
			if p.Addr().Is4() {
				out = append(out, p.Addr())
			}
		}
	}
	return out
}

// refusalFor says why ip cannot be a decoy of this network, or "" when it can (spec 6.6 order:
// the subnet, then network, broadcast, gateway, the box).
func (m mgmtNet) refusalFor(ip netip.Addr, host []netip.Addr) (code, msg string) {
	sub := m.subnet()
	switch {
	case !sub.Contains(ip):
		return api.CodeIPNotInMgmtSubnet, "A decoy address must be inside the box's own subnet (" + sub.String() + ")."
	}
	mask := ^uint32(0) << (32 - sub.Bits())
	switch n := ipv4Num(ip); {
	case n&^mask == 0:
		return api.CodeIPIsNetwork, "That is the network address of the subnet."
	case n&^mask == ^mask:
		return api.CodeIPIsBroadcast, "That is the broadcast address of the subnet."
	case m.Gateway.IsValid() && ip == m.Gateway:
		return api.CodeIPIsGateway, "That is the address of the gateway."
	case slices.Contains(host, ip) || ip == m.Prefix.Addr():
		return api.CodeIPIsHost, "That is an address of this box."
	}
	return "", ""
}

func decoyArgs(a api.DecoyAddArgs) (netip.Addr, *[3]byte, error) {
	ip, err := parseDecoyIP(a.IP)
	if err != nil {
		return netip.Addr{}, nil, server.Invalid(fieldIP, err.Error())
	}
	oui, has, err := parseOUI(a.OUI)
	if err != nil {
		return netip.Addr{}, nil, server.Invalid("oui", err.Error())
	}
	if _, err := portsArg(a.Ports); err != nil {
		return netip.Addr{}, nil, err
	}
	if !has {
		return ip, nil, nil
	}
	return ip, &oui, nil
}

// parseDecoyIP accepts one canonical, usable unicast IPv4 address (IPv6 decoys are not built yet).
func parseDecoyIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() || ip.String() != s {
		return netip.Addr{}, errors.New("must be an IPv4 address in dotted form")
	}
	if !unicast4(ip) {
		return netip.Addr{}, errors.New("must be a usable unicast address")
	}
	return ip, nil
}

func (o *Ops) cmdDecoyAdd() server.Command {
	return server.Define(server.Spec[api.DecoyAddArgs]{
		Name: api.CmdDecoyAdd, Write: true, Timeout: 30 * time.Second,
		Validate: func(a *api.DecoyAddArgs) error { _, _, err := decoyArgs(*a); return err },
		Check:    o.checkDecoyAdd,
		Run:      o.runDecoyAdd,
	})
}

func (o *Ops) cmdDecoyRemove() server.Command {
	return server.Define(server.Spec[api.DecoyRemoveArgs]{
		Name: api.CmdDecoyRemove, Write: true, Timeout: 30 * time.Second,
		Validate: func(a *api.DecoyRemoveArgs) error {
			_, err := parseDecoyIP(a.IP)
			if err != nil {
				return server.Invalid(fieldIP, err.Error())
			}
			return nil
		},
		Run: o.runDecoyRemove,
	})
}

// addRefusal runs the refusals of decoy_ip.add in the order of spec 6.6 (after the arguments, which
// Validate has checked): not_appliance, the subnet, network/broadcast/gateway/host, a duplicate, the
// limit. The ARP probe is not here: it takes four seconds and belongs to the run.
func (o *Ops) addRefusal(ctx context.Context, ip netip.Addr, list []decoyEntry) (mgmtNet, error) {
	if _, err := o.platform(); err != nil {
		return mgmtNet{}, err
	}
	m, err := o.mgmtNow(ctx, nil, false)
	if err != nil {
		return mgmtNet{}, refuse412(api.CodeIPNotInMgmtSubnet, "The box has no management network yet, so there is no subnet for a decoy.")
	}
	if code, msg := m.refusalFor(ip, o.hostAddrs()); code != "" {
		return mgmtNet{}, refuse412(code, msg)
	}
	if slices.ContainsFunc(list, func(e decoyEntry) bool { return e.IP == ip.String() }) {
		return mgmtNet{}, refuse412(api.CodeDuplicateDecoy, "That address is already a decoy. Remove it first to change it.")
	}
	if len(list) >= api.MaxDecoys {
		return mgmtNet{}, refuse412(api.CodeLimitReached, fmt.Sprintf("The box holds %d decoy addresses already, the most it allows.", api.MaxDecoys))
	}
	return m, nil
}

func (o *Ops) checkDecoyAdd(ctx context.Context, a api.DecoyAddArgs) error {
	ip, _, err := decoyArgs(a)
	if err != nil {
		return err
	}
	if o.hpDirErr != nil {
		return nil // the run answers with hp_state_unusable
	}
	list, _ := o.readDecoys() // an invalid file is set aside by the run
	_, err = o.addRefusal(ctx, ip, list)
	return err
}

func (o *Ops) runDecoyAdd(ctx context.Context, rc *server.RunContext, a api.DecoyAddArgs) (any, error) {
	ip, oui, err := decoyArgs(a)
	if err != nil {
		return nil, err
	}
	if o.hpDirErr != nil {
		return nil, fail(api.CodeHPStateUnusable, hpUnusableMsg)
	}
	o.hpMu.Lock()
	defer o.hpMu.Unlock()
	list, err := o.loadDecoysNoted()
	if err != nil {
		return nil, fail(api.CodeDecoysStateInvalid, "The decoy state file could not be read or set aside.")
	}
	m, err := o.addRefusal(ctx, ip, list)
	if err != nil {
		return nil, err
	}
	rc.Log("Checking that " + ip.String() + " is free (ARP probe).")
	res, err := o.d.Probe.Probe(ctx, m.Iface, ip)
	switch {
	case err != nil:
		o.log.WarnContext(ctx, "the ARP probe failed", "error", err.Error())
		return nil, fail(api.CodeARPProbeFailed, "The host could not check whether the address is free, so nothing was added.")
	case res.Conflict:
		return nil, refuse412(api.CodeIPInUse, "Another device on the network already answers for "+ip.String()+" ("+res.MAC+").")
	}
	key, err := o.loadMACKey()
	if err != nil {
		o.log.ErrorContext(ctx, "the MAC key is not usable", "error", err.Error())
		return nil, fail(api.CodeMACKeyInvalid, "The host's MAC key is missing or damaged, so it will not invent MAC addresses.")
	}
	mac := deriveMAC(key, ip, oui).String()
	if slices.ContainsFunc(list, func(e decoyEntry) bool { return e.MAC == mac }) {
		return nil, refuse412(api.CodeMACInUse, "The MAC address this IP would get is already a decoy's. Use another address or another OUI.")
	}
	name := linkName(ip)
	if exists, err := o.hostHasLink(name); err != nil || exists {
		return nil, refuse412(api.CodeLinkNameInUse, "A network link called "+name+" already exists on this machine and the host did not make it, so it is left alone.")
	}
	if err := o.ensureHP(ctx, false); err != nil {
		o.log.ErrorContext(ctx, "the honeypot namespace is not usable", "error", err.Error())
		return nil, fail(api.CodeHPNamespaceUnavailable, "The honeypot network namespace is not usable, so nothing was added.")
	}
	links, err := o.listNS(ctx)
	if err != nil {
		return nil, fail(api.CodeDecoyFailed, "The host could not list the honeypot namespace.")
	}
	o.dropOrphans(ctx, links, list) // leftovers of an interrupted run, never a link of a decoy in the state
	table, ok := freeTable(list)
	if !ok {
		return nil, refuse412(api.CodeLimitReached, "No routing table is free.")
	}
	ports, err := portsArg(a.Ports)
	if err != nil {
		return nil, err
	}
	d := decoyEntry{IP: ip.String(), MAC: mac, Table: table, Iface: m.Iface, Ports: ports}
	next := append(slices.Clone(list), d)
	rc.Log("Creating the link " + name + " in the honeypot namespace.")
	if err := o.buildDecoy(ctx, d, m); err != nil {
		o.log.ErrorContext(ctx, "could not build the decoy", fieldIP, d.IP, "error", err.Error())
		return nil, fail(api.CodeDecoyFailed, "The decoy could not be created; nothing was kept.")
	}
	if err := o.saveDecoys(next); err != nil {
		o.log.ErrorContext(ctx, "could not write hp/decoys.json", "error", err.Error())
		o.removeDecoyNS(ctx, d)
		return nil, fail(api.CodeDecoyFailed, "The decoy could not be recorded; it was removed again.")
	}
	undo := func() {
		o.removeDecoyNS(ctx, d)
		if serr := o.saveDecoys(list); serr != nil {
			o.log.ErrorContext(ctx, "could not take the decoy out of hp/decoys.json", "error", serr.Error())
		}
	}
	if err := o.verifyDecoy(ctx, d, m); err != nil {
		o.log.ErrorContext(ctx, "the decoy is not in the namespace as it should be", fieldIP, d.IP, "error", err.Error())
		undo()
		return nil, fail(api.CodeDecoyFailed, "The decoy was created but the link in the namespace does not have the right MAC and address; it was removed again.")
	}
	// The address answers only once the ruleset that lets it (its allow-list, or the open set) is in
	// force and proven (D-466); until then the input chain refuses every port of it.
	if err := o.applyRuleset(ctx, next); err != nil {
		o.log.ErrorContext(ctx, "the ruleset with the new decoy could not be proven", fieldIP, d.IP, "error", err.Error())
		undo()
		if rerr := o.applyRuleset(ctx, list); rerr != nil {
			o.closeUnproven(ctx, rerr)
		}
		return nil, fail(api.CodeDecoyFailed, "The ports of the decoy could not be put in force; it was removed again.")
	}
	return api.DecoyAddResult{IP: d.IP, MAC: d.MAC}, nil
}

func (o *Ops) runDecoyRemove(ctx context.Context, rc *server.RunContext, a api.DecoyRemoveArgs) (any, error) {
	ip, err := parseDecoyIP(a.IP)
	if err != nil {
		return nil, server.Invalid(fieldIP, err.Error())
	}
	if o.hpDirErr != nil {
		return nil, fail(api.CodeHPStateUnusable, hpUnusableMsg)
	}
	o.hpMu.Lock()
	defer o.hpMu.Unlock()
	list, err := o.loadDecoysNoted()
	if err != nil {
		return nil, fail(api.CodeDecoysStateInvalid, "The decoy state file could not be read or set aside.")
	}
	i := slices.IndexFunc(list, func(e decoyEntry) bool { return e.IP == ip.String() })
	if i < 0 {
		rc.Log(ip.String() + " is not a decoy; nothing to do.")
		return api.DecoyRemoveResult{}, nil
	}
	d := list[i]
	present, err := o.checkNSFile()
	if err != nil {
		return nil, fail(api.CodeHPNamespaceUnavailable, "The honeypot network namespace is not usable, so nothing was removed.")
	}
	// The state first: a crash after it leaves a link no entry owns, which the next reconcile
	// removes; the other order would bring a removed decoy back.
	rest := slices.Delete(slices.Clone(list), i, i+1)
	if err := o.saveDecoys(rest); err != nil {
		o.log.ErrorContext(ctx, "could not write hp/decoys.json", "error", err.Error())
		return nil, fail(api.CodeDecoyFailed, "The decoy list could not be written; nothing was removed.")
	}
	if present {
		rc.Log("Removing the rule, the routes and the link of " + ip.String() + ".")
		o.removeDecoyNS(ctx, d)
		links, err := o.listNS(ctx)
		if err != nil || slices.ContainsFunc(links, func(l nsLink) bool { return l.Name == linkName(ip) }) {
			return nil, fail(api.CodeDecoyFailed, "The decoy is out of the list but its link is still in the namespace; the next start removes it.")
		}
		// Its ports leave the ruleset too (D-466): the sets hold exactly the decoys of the state.
		if err := o.applyRuleset(ctx, rest); err != nil {
			o.closeUnproven(ctx, err)
			return nil, fail(api.CodeDecoyFailed, "The decoy is removed but the ruleset of the honeypot namespace could not be proven; the decoys are off until the host proves it again.")
		}
	}
	return api.DecoyRemoveResult{Removed: true}, nil
}

// loadDecoysNoted is loadDecoys that audits an invalid file it set aside.
func (o *Ops) loadDecoysNoted() ([]decoyEntry, error) {
	list, q, err := o.loadDecoys()
	if q {
		o.log.Error("hp/decoys.json was not valid; it was set aside as decoys.json.invalid")
		o.note("decoy_ip", "decoys_state_invalid", map[string]any{})
	}
	return list, err
}

// hostHasLink reports whether a link of that name exists in the host's own namespace (where
// macvlans are created); an error is "yes", the safe answer.
func (o *Ops) hostHasLink(name string) (bool, error) {
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return true, err
	}
	return slices.ContainsFunc(ifaces, func(h HostIface) bool { return h.Name == name }), nil
}

// ipRun runs one ip command line and reports success; a non-zero exit is an error naming the verb.
func (o *Ops) ipRun(ctx context.Context, args []string) error {
	res, code, err := o.exec(ctx, binIP, args...)
	return ipErr(args, res.Stderr, code, err)
}

// fibTableMissingRE is the kernel's answer (through iproute2 6.19 and later, exit 2, then "Flush terminated") to
// "route flush table N" for a table the namespace does not have; older iproute2 exits 0 there (#475).
var fibTableMissingRE = regexp.MustCompile(`(?m)^Error: ipv4: FIB table does not exist\.$`)

// routeFlush empties a decoy's table. The table does not exist until its first route (a new decoy, a namespace made
// again after a reboot), and a table that does not exist has nothing to flush: exit 2 with the kernel's "FIB table does
// not exist" is success. Every other answer is a failure, as with ipRun. Asking first ("route show table N") would not
// avoid it: the same kernel check refuses the dump of a missing table.
func (o *Ops) routeFlush(ctx context.Context, table int) error {
	args := argvRouteFlush(table)
	res, code, err := o.exec(ctx, binIP, args...)
	if err == nil && code == 2 && fibTableMissingRE.Match(res.Stderr) {
		return nil
	}
	return ipErr(args, res.Stderr, code, err)
}

// ipErr is the error of one ip call. A non-zero exit carries the first line of ip's stderr (quoted, at most
// maxStderrHead bytes) so the host's log says why. These errors go to the host's log only: the API and the audit lines
// get fixed sentences and codes, never this text.
func ipErr(args []string, stderr []byte, code int, err error) error {
	if err != nil {
		return fmt.Errorf("ops: ip %s: %w", strings.Join(args[:min(len(args), 4)], " "), err)
	}
	if code != 0 {
		if h := stderrHead(stderr); h != "" {
			return fmt.Errorf("ops: ip %s failed (exit %d): %q", strings.Join(args[:min(len(args), 4)], " "), code, h)
		}
		return fmt.Errorf("ops: ip %s failed (exit %d)", strings.Join(args[:min(len(args), 4)], " "), code)
	}
	return nil
}

const maxStderrHead = 200

// stderrHead is the first non-empty line of a program's stderr, cut to maxStderrHead bytes and to valid UTF-8.
func stderrHead(b []byte) string {
	line, _, _ := bytes.Cut(bytes.TrimSpace(b), []byte("\n"))
	return strings.ToValidUTF8(string(line[:min(len(line), maxStderrHead)]), "")
}

// buildDecoy makes the link, moves it into the namespace and configures it. It deletes only what
// this call created: a failure of "link add" (the name taken by someone else) deletes nothing.
func (o *Ops) buildDecoy(ctx context.Context, d decoyEntry, m mgmtNet) error {
	ip := d.addr()
	name := linkName(ip)
	if err := o.ipRun(ctx, argvLinkAdd(m.Iface, name, d.MAC)); err != nil {
		return err
	}
	if err := o.ipRun(ctx, argvLinkToNS(name)); err != nil {
		_ = o.ipRun(ctx, argvHostLinkDel(name)) // we made it a moment ago and it never left
		return err
	}
	steps := [][]string{argvAddrAdd(netip.PrefixFrom(ip, m.Prefix.Bits()), name), argvUp(name)}
	for _, s := range steps {
		if err := o.ipRun(ctx, s); err != nil {
			o.removeDecoyNS(ctx, d)
			return err
		}
	}
	if err := o.configureRouting(ctx, d, m); err != nil {
		o.removeDecoyNS(ctx, d)
		return err
	}
	return nil
}

// configureRouting (re)sets the decoy's own table and rule: the table is flushed, holds the subnet
// and, when the box has a gateway, the default route; the rule sends what the decoy's address
// sends through that table. It is the part a gateway change needs.
func (o *Ops) configureRouting(ctx context.Context, d decoyEntry, m mgmtNet) error {
	ip, name := d.addr(), linkName(d.addr())
	if err := o.routeFlush(ctx, d.Table); err != nil {
		return err
	}
	if err := o.ipRun(ctx, argvRouteSubnet(m.subnet(), name, ip, d.Table)); err != nil {
		return err
	}
	if m.Gateway.IsValid() {
		if err := o.ipRun(ctx, argvRouteDefault(m.Gateway, name, d.Table)); err != nil {
			return err
		}
	}
	_ = o.ipRun(ctx, argvRule("del", ip, d.Table)) // absent is the usual case; add refuses a duplicate
	return o.ipRun(ctx, argvRule("add", ip, d.Table))
}

// removeDecoyNS takes a decoy out of the namespace: its rule, its table, its link (the addresses
// and routes of the link go with it). Failures are not errors here; callers check the effect.
func (o *Ops) removeDecoyNS(ctx context.Context, d decoyEntry) {
	ip := d.addr()
	_ = o.ipRun(ctx, argvRule("del", ip, d.Table))
	_ = o.ipRun(ctx, argvRouteFlush(d.Table))
	_ = o.ipRun(ctx, argvNSLinkDel(linkName(ip)))
}

// nsLink is one link of the namespace as "ip -j addr show" reports it.
type nsLink struct {
	Name  string
	MAC   string
	Up    bool
	Addrs []netip.Prefix
}

type ipJSONLink struct {
	IfName   string   `json:"ifname"`
	Address  string   `json:"address"`
	Flags    []string `json:"flags"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

// listNS reads the links of the namespace. The text is the kernel's through iproute2: it is
// bounded, and a link whose name is not a plain interface name is left out.
func (o *Ops) listNS(ctx context.Context) ([]nsLink, error) {
	res, code, err := o.exec(ctx, binIP, argvList()...)
	if err != nil || code != 0 || res.Truncated {
		return nil, errors.New("ops: ip addr show in vedette-hp failed")
	}
	return parseNSLinks(res.Stdout)
}

func parseNSLinks(b []byte) ([]nsLink, error) {
	var raw []ipJSONLink
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) > maxNSLinks {
		return nil, errors.New("ops: ip addr show gave an answer the host cannot read")
	}
	out := make([]nsLink, 0, len(raw))
	for _, r := range raw {
		if !validIfaceName(r.IfName) {
			continue
		}
		l := nsLink{Name: r.IfName, MAC: strings.ToLower(r.Address), Up: slices.Contains(r.Flags, "UP")}
		for _, ai := range r.AddrInfo {
			if a, err := netip.ParseAddr(ai.Local); ai.Family == "inet" && err == nil && a.Is4() && ai.PrefixLen >= 0 && ai.PrefixLen <= 32 {
				l.Addrs = append(l.Addrs, netip.PrefixFrom(a, ai.PrefixLen))
			}
		}
		out = append(out, l)
	}
	return out, nil
}

// linkOK: the link is there with the decoy's MAC, up, holding the decoy's address with the
// management prefix length.
func (l nsLink) matches(d decoyEntry, m mgmtNet) bool {
	return l.MAC == d.MAC && l.Up && slices.Contains(l.Addrs, netip.PrefixFrom(d.addr(), m.Prefix.Bits()))
}

// verifyDecoy is the effect check of decoy_ip.add: the link exists in the namespace with the right
// MAC and address.
func (o *Ops) verifyDecoy(ctx context.Context, d decoyEntry, m mgmtNet) error {
	links, err := o.listNS(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(links, func(l nsLink) bool { return l.Name == linkName(d.addr()) })
	if i < 0 || !links[i].matches(d, m) {
		return errors.New("the link is missing or differs")
	}
	return nil
}

// dropOrphans deletes the links called vdh<8 hex> that no entry of the list owns. The namespace is
// the host's own, and the name is the host's own scheme: what is there is a leftover of a run that
// was interrupted, or of a state file that was set aside.
func (o *Ops) dropOrphans(ctx context.Context, links []nsLink, list []decoyEntry) {
	for _, l := range links {
		if !linkNameRE.MatchString(l.Name) || slices.ContainsFunc(list, func(e decoyEntry) bool { return linkName(e.addr()) == l.Name }) {
			continue
		}
		if err := o.ipRun(ctx, argvNSLinkDel(l.Name)); err != nil {
			o.log.WarnContext(ctx, "could not remove a leftover link of vedette-hp", "link", l.Name)
		}
	}
}

// reapplyDecoys is the hook of net.apply, net.confirm's revert and every start (D-100, D-102 (6)):
// it brings the namespace in line with hp/decoys.json for the network the box has now. hint is the
// configuration being applied (nil: read it). It never fails a network change for a decoy: a decoy
// that is outside the subnet now, or that cannot be built, is removed from the state and reported
// (log and an audit line; it is missing from GET /v1/state/net, so core sees it and the honeypot
// shows "conflict"). It returns an error only when the state itself cannot be kept true.
func (o *Ops) reapplyDecoys(ctx context.Context, hint *NetplanConfig) error {
	if o.hpDirErr != nil {
		return nil
	}
	o.hpMu.Lock()
	defer o.hpMu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, decoyReapplyTime)
		defer cancel()
	}
	return o.reconcile(ctx, hint, false)
}

type droppedDecoy struct {
	d      decoyEntry
	reason string
}

// reconcile does the work of reapplyDecoys with hpMu held. ensured says the namespace was just
// made ready by Start.
func (o *Ops) reconcile(ctx context.Context, hint *NetplanConfig, ensured bool) error {
	list, err := o.loadDecoysNoted()
	if err != nil {
		o.log.ErrorContext(ctx, "the decoy state could not be read", "error", err.Error())
		return nil
	}
	if len(list) == 0 && !ensured {
		return nil // nothing to put back; the start removes leftovers
	}
	if len(list) == 0 {
		// No decoys: only what no entry owns is left to remove, and no management network is needed.
		if links, err := o.listNS(ctx); err == nil {
			o.dropOrphans(ctx, links, nil)
		}
		return nil
	}
	if !ensured {
		if err := o.ensureHP(ctx, false); err != nil {
			o.log.ErrorContext(ctx, "the honeypot namespace is not usable; decoys were not re-applied", "error", err.Error())
			o.note("decoy_ip", "decoy_reapply_failed", map[string]any{"why": "namespace"})
			return nil
		}
	}
	m, err := o.mgmtNow(ctx, hint, true)
	if err != nil {
		o.log.WarnContext(ctx, "the management network is not known; decoys were left as they are")
		o.note("decoy_ip", "decoy_reapply_failed", map[string]any{"why": "no_management_network"})
		return nil
	}
	links, err := o.listNS(ctx)
	if err != nil {
		o.log.ErrorContext(ctx, "could not list the honeypot namespace; decoys were not re-applied", "error", err.Error())
		o.note("decoy_ip", "decoy_reapply_failed", map[string]any{"why": "list"})
		return nil
	}
	o.dropOrphans(ctx, links, list)
	host := o.hostAddrs()
	var keep []decoyEntry
	var dropped []droppedDecoy
	cancelled := func() bool {
		if ctx.Err() == nil {
			return false
		}
		// A cancelled context is not a verdict on any decoy: stop, keep every entry and report nothing;
		// the next reconcile starts from the same state (D-121).
		o.log.WarnContext(context.WithoutCancel(ctx), "the re-apply of the decoys was cancelled; the entries were kept")
		return true
	}
	for _, d := range list {
		if cancelled() {
			return nil
		}
		if code, _ := m.refusalFor(d.addr(), host); code != "" {
			o.removeDecoyNS(ctx, d)
			dropped = append(dropped, droppedDecoy{d, code})
			continue
		}
		name := linkName(d.addr())
		i := slices.IndexFunc(links, func(l nsLink) bool { return l.Name == name })
		if i >= 0 && d.Iface == m.Iface && links[i].matches(d, m) && o.configureRouting(ctx, d, m) == nil {
			keep = append(keep, d)
			continue
		}
		if i >= 0 {
			o.removeDecoyNS(ctx, d)
		}
		if exists, err := o.hostHasLink(name); err != nil || exists {
			dropped = append(dropped, droppedDecoy{d, api.CodeLinkNameInUse})
			continue
		}
		d.Iface = m.Iface
		if err := o.buildDecoy(ctx, d, m); err != nil {
			if cancelled() {
				return nil
			}
			o.log.ErrorContext(ctx, "could not rebuild a decoy", fieldIP, d.IP, "error", err.Error())
			dropped = append(dropped, droppedDecoy{d, "apply_failed"})
			continue
		}
		keep = append(keep, d)
	}
	if cancelled() {
		return nil
	}
	if len(dropped) > 0 || !slices.EqualFunc(keep, list, sameEntry) {
		if err := o.saveDecoys(keep); err != nil {
			return err
		}
		// A dropped decoy leaves the sets of the ruleset as well (D-466).
		if !sameSets(keep, list) {
			if err := o.applyRuleset(ctx, keep); err != nil {
				o.closeUnproven(ctx, err)
			}
		}
	}
	for _, x := range dropped {
		o.log.WarnContext(ctx, "a decoy was removed because it no longer fits the network", fieldIP, x.d.IP, "reason", x.reason)
		o.note("decoy_ip", "decoy_dropped", map[string]any{fieldIP: x.d.IP, "reason": x.reason})
	}
	return nil
}

// startHP makes the namespace ready before the server listens (and before a revert at start may
// need it); it reports whether it worked. A failure is logged and audited and the host serves
// anyway: the network commands must still work, and decoy_ip.add tries again.
func (o *Ops) startHP(ctx context.Context) bool {
	if o.hpDirErr != nil {
		o.note("decoy_ip", "hp_namespace_failed", map[string]any{"why": "hp_state_unusable"})
		return false
	}
	hctx, cancel := context.WithTimeout(ctx, decoyReapplyTime)
	defer cancel()
	if err := o.ensureHP(hctx, true); err != nil {
		o.log.ErrorContext(ctx, "the honeypot namespace could not be made ready", "error", err.Error())
		o.note("decoy_ip", "hp_namespace_failed", map[string]any{})
		return false
	}
	return true
}

// reconcileAtStart is the re-apply of Start, once the network is final.
func (o *Ops) reconcileAtStart(ctx context.Context, ensured bool) {
	if o.hpDirErr != nil {
		return
	}
	o.hpMu.Lock()
	defer o.hpMu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, decoyReapplyTime)
	defer cancel()
	o.reclaimHostLinks(rctx)
	if err := o.reconcile(rctx, nil, ensured); err != nil {
		o.log.ErrorContext(ctx, "the decoys could not be re-applied", "error", err.Error())
	}
}

const hpUnusableMsg = "The decoy state directory is not usable (not a plain directory of the host, or open to others), so decoys are off."

// reclaimHostLinks deletes, at Start, a link vdh<8 hex> that a crash left in the host's own namespace
// (between "link add" and "link set netns") when it is provably the host's: its MAC is the one the
// key gives the IP in its name, or carries the HMAC tail an OUI-based MAC has. Any other link of that
// name is somebody else's and stays (decoy_ip.add then refuses it as link_name_in_use).
func (o *Ops) reclaimHostLinks(ctx context.Context) {
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return
	}
	var key []byte
	for _, h := range ifaces {
		if !linkNameRE.MatchString(h.Name) {
			continue
		}
		raw, err := hex.DecodeString(h.Name[len(linkNamePre):])
		hw, merr := net.ParseMAC(h.MAC)
		if err != nil || len(raw) != 4 || merr != nil || len(hw) != 6 {
			continue
		}
		if key == nil {
			if _, err := os.Lstat(o.stateFile("hp", "mac.key")); err != nil {
				return // no key was ever made: the host never made a decoy
			}
			if key, err = o.loadMACKey(); err != nil {
				return
			}
		}
		ip := netip.AddrFrom4([4]byte(raw))
		if !ownMAC(key, ip, hw) {
			continue
		}
		if err := o.ipRun(ctx, argvHostLinkDel(h.Name)); err != nil {
			o.log.WarnContext(ctx, "could not delete a leftover link of the host", "link", h.Name)
			continue
		}
		o.note("decoy_ip", "host_link_reclaimed", map[string]any{"link": h.Name})
	}
}

// readDecoyState is the decoys of GET /v1/state/net, by address.
func (o *Ops) readDecoyState() []api.NetDecoy {
	out := []api.NetDecoy{}
	if o.hpDirErr != nil || !o.hpOK.Load() {
		// Only decoys that are live after a namespace that was proven are listed: when egress is not
		// proven the links are deleted (failClosed), and hp/decoys.json keeps the intent.
		return out
	}
	list, err := o.readDecoys()
	if err != nil {
		o.log.Error("hp/decoys.json is not valid; state/net lists no decoys")
		return out
	}
	slices.SortFunc(list, func(a, b decoyEntry) int { return a.addr().Compare(b.addr()) })
	for _, e := range list {
		out = append(out, api.NetDecoy{IP: e.IP, MAC: e.MAC, Ports: portsOf(e)})
	}
	return out
}
