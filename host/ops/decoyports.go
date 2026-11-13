package ops

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// Per-address ports of the decoys (D-466). OpenCanary is one process that listens on every address of
// the namespace (D-90 (1)); the host keeps each address to its own services with the input chain of
// the namespace's ruleset: an address with an allow-list answers only the (protocol, port) pairs of
// its list, an address without one (nil, a decoy an older core added) answers everything, and an
// address in neither set answers no TCP or UDP port (fail closed). The ruleset is rendered from
// hp/decoys.json and loaded whole ("flush ruleset" in the same nft transaction); after every load the
// host lists it back and checks the egress part, the input chain and both sets' elements.

// fieldPorts names the ports argument in errors.
const fieldPorts = "ports"

// canonicalPorts checks an allow-list (at most api.MaxDecoyPorts, tcp or udp, 1 to 65535, no
// duplicate) and returns it sorted by protocol, then port; never nil.
func canonicalPorts(in []api.DecoyPort) ([]api.DecoyPort, error) {
	if len(in) > api.MaxDecoyPorts {
		return nil, fmt.Errorf("at most %d ports", api.MaxDecoyPorts)
	}
	out := make([]api.DecoyPort, 0, len(in))
	for _, p := range in {
		if p.Proto != api.ProtoTCP && p.Proto != api.ProtoUDP {
			return nil, errors.New("proto must be tcp or udp")
		}
		if p.Port < 1 || p.Port > 65535 {
			return nil, errors.New("port must be 1 to 65535")
		}
		if slices.Contains(out, p) {
			return nil, errors.New("a port is listed twice")
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b api.DecoyPort) int {
		return cmp.Or(cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Port, b.Port))
	})
	return out, nil
}

// portsArg is canonicalPorts for an optional argument: nil stays nil (no allow-list).
func portsArg(p *[]api.DecoyPort) (*[]api.DecoyPort, error) {
	if p == nil {
		return nil, nil
	}
	c, err := canonicalPorts(*p)
	if err != nil {
		return nil, server.Invalid(fieldPorts, err.Error())
	}
	return &c, nil
}

// The fixed lines of the ruleset (D-102 (4), D-121, D-466). Output: replies and loopback go out,
// every new connection is dropped. Forward: nothing. Input: see the comment at the top.
var (
	hpOutputRules = []string{"ct state established,related accept", "oif lo accept", "ct state new drop"}
	hpInputRules  = []string{
		"iif lo accept",
		"ct state established,related accept",
		"ip daddr @open accept",
		"ip daddr . meta l4proto . th dport @allow accept",
		"meta l4proto tcp reject with tcp reset",
		"meta l4proto udp reject",
	}
)

const (
	hpOpenType  = "ipv4_addr"
	hpAllowType = "ipv4_addr . inet_proto . inet_service"
)

// wantedSets are the elements of the two sets for a decoy list: the addresses without an allow-list,
// and "ip . proto . port" of every allowed port.
func wantedSets(list []decoyEntry) (open, allow []string) {
	for _, e := range list {
		if e.Ports == nil {
			open = append(open, e.IP)
			continue
		}
		for _, p := range *e.Ports {
			allow = append(allow, e.IP+" . "+p.Proto+" . "+strconv.Itoa(p.Port))
		}
	}
	slices.Sort(open)
	slices.Sort(allow)
	return open, allow
}

// renderRuleset is the text nft -f loads for a decoy list. Every value in it is a validated address,
// protocol word or number from decoys.json (parseDecoys checks them all).
func renderRuleset(list []decoyEntry) string {
	open, allow := wantedSets(list)
	var b strings.Builder
	set := func(name, typ string, elems []string) {
		b.WriteString("\tset " + name + " {\n\t\ttype " + typ + "\n")
		if len(elems) > 0 {
			b.WriteString("\t\telements = { " + strings.Join(elems, ", ") + " }\n")
		}
		b.WriteString("\t}\n")
	}
	chain := func(name, hdr string, rules []string) {
		b.WriteString("\tchain " + name + " {\n\t\t" + hdr + "\n")
		for _, r := range rules {
			b.WriteString("\t\t" + r + "\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("flush ruleset\ntable inet vedette_hp {\n")
	set("open", hpOpenType, open)
	set("allow", hpAllowType, allow)
	chain("input", "type filter hook input priority 0; policy accept;", hpInputRules)
	chain("output", "type filter hook output priority 0; policy accept;", hpOutputRules)
	chain("forward", "type filter hook forward priority 0; policy drop;", nil)
	b.WriteString("}\n")
	return b.String()
}

// nftChain and nftSet are a chain and a set of the table as "nft list ruleset" prints them, every
// line normalised (no spaces, tabs, braces or quotes).
type nftChain struct {
	hdr   string
	rules []string
}

type nftSet struct {
	typ   string
	elems []string // as printed, trimmed, not normalised
	other []string // any other line (flags, timeouts...): our sets have none
}

type nftTable struct {
	found, dormant bool
	chains         map[string]*nftChain
	sets           map[string]*nftSet
}

func nftNorm(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "{", "", "}", "", `"`, "").Replace(s)
}

// parseHPTable reads the table inet vedette_hp out of "nft list ruleset". Other tables are skipped.
// Element lists may span lines ("elements = { a,\n b }").
func parseHPTable(out []byte) nftTable {
	t := nftTable{chains: map[string]*nftChain{}, sets: map[string]*nftSet{}}
	var (
		inTable  bool
		chain    *nftChain
		set      *nftSet
		inElems  bool
		elemText strings.Builder
	)
	for _, raw := range bytes.Split(out, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if inElems { // a continuation of a multi-line element list
			before, _, closed := strings.Cut(line, "}")
			elemText.WriteString(" " + before)
			if closed {
				inElems = false
				set.elems = splitElems(elemText.String())
			}
			continue
		}
		switch {
		case line == "":
		case strings.HasPrefix(line, "table ") && strings.HasSuffix(line, "{"):
			inTable, chain, set = nftNorm(line) == "tableinetvedette_hp", nil, nil
			t.found = t.found || inTable
		case !inTable:
		case strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{"):
			name := strings.TrimPrefix(nftNorm(line), "chain")
			chain, set = &nftChain{}, nil
			if _, dup := t.chains[name]; dup {
				name += "#dup" // a second chain of the same name never matches what we want
			}
			t.chains[name] = chain
		case strings.HasPrefix(line, "set ") && strings.HasSuffix(line, "{"):
			name := strings.TrimPrefix(nftNorm(line), "set")
			set, chain = &nftSet{}, nil
			if _, dup := t.sets[name]; dup {
				name += "#dup"
			}
			t.sets[name] = set
		case line == "}":
			if chain != nil || set != nil {
				chain, set = nil, nil
			} else {
				inTable = false
			}
		case chain == nil && set == nil:
			if strings.HasPrefix(nftNorm(line), "flagsdormant") {
				t.dormant = true
			}
		case set != nil && strings.HasPrefix(line, "type "):
			set.typ = strings.Join(strings.Fields(strings.TrimPrefix(line, "type ")), " ")
		case set != nil && strings.HasPrefix(line, "elements = {"):
			rest := strings.TrimPrefix(line, "elements = {")
			before, _, closed := strings.Cut(rest, "}")
			if closed {
				set.elems = splitElems(before)
			} else {
				inElems = true
				elemText.Reset()
				elemText.WriteString(before)
			}
		case set != nil:
			set.other = append(set.other, line)
		case strings.HasPrefix(line, "type "):
			chain.hdr = nftNorm(line)
		default:
			chain.rules = append(chain.rules, nftNorm(line))
		}
	}
	return t
}

func splitElems(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.Join(strings.Fields(e), " "); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// normElem reads one printed element of a set back into the form wantedSets writes: an address, or
// "ip . proto . port" with the protocol as a word (nft prints tcp, or 6 when asked for numbers).
func normElem(e string, concat bool) (string, bool) {
	if !concat {
		a, err := netip.ParseAddr(e)
		return e, err == nil && a.Is4() && a.String() == e
	}
	f := strings.Split(e, " . ")
	if len(f) != 3 {
		return "", false
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil || !a.Is4() || a.String() != f[0] {
		return "", false
	}
	proto := map[string]string{api.ProtoTCP: api.ProtoTCP, "6": api.ProtoTCP, api.ProtoUDP: api.ProtoUDP, "17": api.ProtoUDP}[f[1]]
	port, err := strconv.Atoi(f[2])
	if proto == "" || err != nil || strconv.Itoa(port) != f[2] || port < 1 || port > 65535 {
		return "", false
	}
	return f[0] + " . " + proto + " . " + f[2], true
}

// setIs reports whether the printed set has exactly the type and the elements wanted.
func setIs(s *nftSet, typ string, want []string, concat bool) bool {
	if s == nil || s.typ != typ || len(s.other) > 0 || len(s.elems) != len(want) {
		return false
	}
	got := make([]string, 0, len(s.elems))
	for _, e := range s.elems {
		n, ok := normElem(e, concat)
		if !ok {
			return false
		}
		got = append(got, n)
	}
	slices.Sort(got)
	return slices.Equal(got, want)
}

func normAll(rules []string) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = nftNorm(r)
	}
	return out
}

// rejectUDPForms are the ways nft may print "meta l4proto udp reject": the default reject of the
// inet family is an ICMPx port unreachable, which some versions spell out.
var rejectUDPForms = []string{"metal4protoudpreject", "metal4protoudprejectwithicmpxport-unreachable", "metal4protoudprejectwithicmpxtypeport-unreachable"}

// egressOK is the check of D-102 (4) on a parsed table: not dormant; the output chain (hook output,
// policy accept) holds exactly the three rules in order, so no broader accept comes before the drop;
// the forward chain has policy drop and no rule.
func (t nftTable) egressOK() bool {
	out, fwd := t.chains["output"], t.chains["forward"]
	return t.found && !t.dormant && out != nil && fwd != nil &&
		strings.HasPrefix(out.hdr, "typefilterhookoutput") && strings.Contains(out.hdr, "policyaccept") &&
		strings.HasPrefix(fwd.hdr, "typefilterhookforward") && strings.Contains(fwd.hdr, "policydrop") &&
		len(fwd.rules) == 0 && slices.Equal(out.rules, normAll(hpOutputRules))
}

// inputOK: the input chain (hook input, policy accept) holds exactly the rules of hpInputRules, in order.
func (t nftTable) inputOK() bool {
	in := t.chains["input"]
	if in == nil || !strings.HasPrefix(in.hdr, "typefilterhookinput") || !strings.Contains(in.hdr, "policyaccept") || len(in.rules) != len(hpInputRules) {
		return false
	}
	want := normAll(hpInputRules)
	for i, r := range in.rules {
		udpReject := i == len(want)-1 && slices.Contains(rejectUDPForms, r)
		if r != want[i] && !udpReject {
			return false
		}
	}
	return true
}

// hasEgressDrop reads the text of "nft list ruleset" and accepts only the egress part of the host's
// ruleset (see egressOK). The text is compared without spaces, braces and quotes ("oif "lo"" is how
// nft prints the interface).
func hasEgressDrop(out []byte) bool { return parseHPTable(out).egressOK() }

// rulesetIs reports whether the printed ruleset is the one the host wants for list: the egress part,
// the input chain, the two sets with exactly the wanted elements, and no other chain or set in the
// table (one could hold a hook of its own).
func rulesetIs(out []byte, list []decoyEntry) bool {
	t := parseHPTable(out)
	open, allow := wantedSets(list)
	return t.egressOK() && t.inputOK() && len(t.chains) == 3 && len(t.sets) == 2 &&
		setIs(t.sets["open"], hpOpenType, open, false) && setIs(t.sets["allow"], hpAllowType, allow, true)
}

// wantedDecoys is the list the ruleset is rendered from when a caller has none at hand (ensureHP):
// the state file; one that cannot be read gives no address at all (fail closed), and the writer
// that reads it next sets it aside and loads the ruleset again.
func (o *Ops) wantedDecoys() []decoyEntry {
	list, err := o.readDecoys()
	if err != nil {
		return nil
	}
	return list
}

// rulesetLoaded lists the ruleset from inside the namespace and compares it with the one wanted.
func (o *Ops) rulesetLoaded(ctx context.Context, list []decoyEntry) (bool, error) {
	res, code, err := o.exec(ctx, binIP, argvNftList()...)
	if err != nil || code != 0 || res.Truncated {
		return false, fmt.Errorf("ops: listing the ruleset of vedette-hp failed (exit %d)", code)
	}
	return rulesetIs(res.Stdout, list), nil
}

// applyRuleset loads the ruleset for list and proves it (the effect check). It changes nothing else:
// the caller decides what a failure means.
func (o *Ops) applyRuleset(ctx context.Context, list []decoyEntry) error {
	if err := o.loadRuleset(ctx, list); err != nil {
		return err
	}
	ok, err := o.rulesetLoaded(ctx, list)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("ops: the ruleset of vedette-hp is not the one the host loaded")
	}
	return nil
}

// closeUnproven is what a ruleset that cannot be proven means for the namespace: not usable (state/net
// lists no decoy) and its links deleted (failClosed); hp/decoys.json keeps the intent, so the next
// ensureHP that proves a ruleset rebuilds them at the next reconcile.
func (o *Ops) closeUnproven(ctx context.Context, err error) {
	o.log.ErrorContext(ctx, "the ruleset of vedette-hp could not be proven", "error", err.Error())
	o.hpOK.Store(false)
	o.failClosed(ctx)
}

func (o *Ops) cmdDecoySetPorts() server.Command {
	return server.Define(server.Spec[api.DecoySetPortsArgs]{
		Name: api.CmdDecoySetPorts, Write: true, Timeout: 30 * time.Second,
		Validate: func(a *api.DecoySetPortsArgs) error { _, _, err := setPortsArgs(*a); return err },
		Check:    o.checkDecoySetPorts,
		Run:      o.runDecoySetPorts,
	})
}

func setPortsArgs(a api.DecoySetPortsArgs) (netip.Addr, []api.DecoyPort, error) {
	ip, err := parseDecoyIP(a.IP)
	if err != nil {
		return netip.Addr{}, nil, server.Invalid(fieldIP, err.Error())
	}
	if a.Ports == nil {
		return netip.Addr{}, nil, server.Invalid(fieldPorts, "is required (an empty list closes every port)")
	}
	p, err := canonicalPorts(a.Ports)
	if err != nil {
		return netip.Addr{}, nil, server.Invalid(fieldPorts, err.Error())
	}
	return ip, p, nil
}

const notADecoyMsg = "That address is not a decoy. Add it first."

func (o *Ops) checkDecoySetPorts(_ context.Context, a api.DecoySetPortsArgs) error {
	ip, _, err := setPortsArgs(a)
	if err != nil {
		return err
	}
	if o.hpDirErr != nil {
		return nil // the run answers with hp_state_unusable
	}
	if _, err := o.platform(); err != nil {
		return err
	}
	list, err := o.readDecoys()
	if err != nil {
		return nil // the run sets an invalid file aside and answers
	}
	if !slices.ContainsFunc(list, func(e decoyEntry) bool { return e.IP == ip.String() }) {
		return refuse412(api.CodeNotADecoy, notADecoyMsg)
	}
	return nil
}

// runDecoySetPorts replaces the allow-list of one decoy: the state first, then the ruleset, proven.
// A ruleset that cannot be loaded or proven puts the old entry and ruleset back; when even that
// cannot be proven, the namespace is closed (closeUnproven). Setting the same list again succeeds and
// changes nothing.
func (o *Ops) runDecoySetPorts(ctx context.Context, rc *server.RunContext, a api.DecoySetPortsArgs) (any, error) {
	ip, ports, err := setPortsArgs(a)
	if err != nil {
		return nil, err
	}
	if o.hpDirErr != nil {
		return nil, fail(api.CodeHPStateUnusable, hpUnusableMsg)
	}
	if _, err := o.platform(); err != nil {
		return nil, err
	}
	o.hpMu.Lock()
	defer o.hpMu.Unlock()
	list, err := o.loadDecoysNoted()
	if err != nil {
		return nil, fail(api.CodeDecoysStateInvalid, "The decoy state file could not be read or set aside.")
	}
	i := slices.IndexFunc(list, func(e decoyEntry) bool { return e.IP == ip.String() })
	if i < 0 {
		return nil, refuse412(api.CodeNotADecoy, notADecoyMsg)
	}
	result := api.DecoySetPortsResult{IP: ip.String(), Ports: ports}
	if err := o.ensureHP(ctx, false); err != nil {
		o.log.ErrorContext(ctx, "the honeypot namespace is not usable", "error", err.Error())
		return nil, fail(api.CodeHPNamespaceUnavailable, "The honeypot network namespace is not usable, so nothing was changed.")
	}
	if list[i].Ports != nil && slices.Equal(*list[i].Ports, ports) {
		rc.Log("The ports of " + ip.String() + " are already these; nothing to do.")
		return result, nil
	}
	next := slices.Clone(list)
	next[i].Ports = &ports
	if err := o.saveDecoys(next); err != nil {
		o.log.ErrorContext(ctx, "could not write hp/decoys.json", "error", err.Error())
		return nil, fail(api.CodeDecoyFailed, "The decoy list could not be written; nothing was changed.")
	}
	rc.Log(fmt.Sprintf("Allowing %d ports on %s.", len(ports), ip))
	if err := o.applyRuleset(ctx, next); err != nil {
		o.log.ErrorContext(ctx, "the new ports of a decoy could not be put in force", fieldIP, ip.String(), "error", err.Error())
		if serr := o.saveDecoys(list); serr != nil {
			o.log.ErrorContext(ctx, "could not put the old entry back in hp/decoys.json", "error", serr.Error())
		}
		if rerr := o.applyRuleset(ctx, list); rerr != nil {
			o.closeUnproven(ctx, rerr)
		}
		return nil, fail(api.CodeDecoyFailed, "The new ports could not be put in force; the old ones were put back.")
	}
	return result, nil
}

// sameSets reports whether two lists give the ruleset the same set elements.
func sameSets(a, b []decoyEntry) bool {
	ao, aa := wantedSets(a)
	bo, ba := wantedSets(b)
	return slices.Equal(ao, bo) && slices.Equal(aa, ba)
}

// portsOf is the allow-list of an entry for GET /v1/state/net (a copy).
func portsOf(e decoyEntry) *[]api.DecoyPort {
	if e.Ports == nil {
		return nil
	}
	p := slices.Clone(*e.Ports)
	return &p
}
