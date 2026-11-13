package ops

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
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
		hpTouchRule,
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
	// hpTouchedType is the set of (source, decoy) pairs that tried a new TCP or UDP connection to a decoy address in the last
	// hpTouchTimeout, allowed port or not (B2 review M2: a SYN scan completes no connection, so OpenCanary logs nothing). The
	// packet path adds to it; "add" keeps the first time, so an element's age is the time since that source first touched
	// that decoy. Bounded: past hpTouchedSize new pairs are not added (the oldest expire within the timeout).
	hpTouchedType  = "ipv4_addr . ipv4_addr"
	hpTouchedSize  = 1024
	hpTouchTimeout = 2 * time.Minute
	// Only unicast to the namespace (pkttype host): broadcast and multicast UDP (NetBIOS, mDNS, SSDP) would fill the set and
	// hide a real scan (B2 review M1).
	hpTouchRule = "meta l4proto { tcp, udp } meta pkttype host ct state new add @touched { ip saddr . ip daddr }"
)

// touchRuleForms are the ways nft may print hpTouchRule back, normalised: protocols as names or numbers, pkttype with or
// without "meta" (nft prints unqualified meta keys bare), with or without the implicit "meta nfproto ipv4" of the inet family.
// A form none of these matches is not fatal: applyRuleset then loads the ruleset without the set (loadProven).
var touchRuleForms = func() []string {
	var out []string
	for _, nf := range []string{"", "meta nfproto ipv4 "} {
		for _, proto := range []string{"tcp, udp", "6, 17"} {
			for _, pt := range []string{"meta pkttype host ", "pkttype host ", ""} { // "": the rule of 7712c63f, printed by nft 1.1.6 in the lab
				out = append(out, nftNorm(nf+"meta l4proto { "+proto+" } "+pt+"ct state new add @touched { ip saddr . ip daddr }"))
			}
		}
	}
	return out
}()

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
func renderRuleset(list []decoyEntry) string { return renderRulesetMode(list, true) }

// inputRules are the rules of the input chain, with or without the touch rule.
func inputRules(touch bool) []string {
	if touch {
		return hpInputRules
	}
	return slices.DeleteFunc(slices.Clone(hpInputRules), func(r string) bool { return r == hpTouchRule })
}

// renderRulesetMode is renderRuleset with (touch) or without the set touched and its rule: the ruleset of before B2 review M2,
// what the host falls back to when nft prints the touch part in a form the effect check does not know (loadProven).
func renderRulesetMode(list []decoyEntry, touch bool) string {
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
	if touch {
		b.WriteString("\tset touched {\n\t\ttype " + hpTouchedType + "\n\t\tsize " + strconv.Itoa(hpTouchedSize) +
			"\n\t\tflags dynamic,timeout\n\t\ttimeout " + strconv.Itoa(int(hpTouchTimeout/time.Second)) + "s\n\t}\n")
	}
	chain("input", "type filter hook input priority 0; policy accept;", inputRules(touch))
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
	// foreign counts the other tables of the namespace's ruleset: the host loads it whole ("flush ruleset"), so any other
	// table is one the host did not write, and the ruleset is not the one it wants.
	foreign int
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
			if !inTable {
				t.foreign++
			}
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

// inputOK: the input chain (hook input, policy accept) holds exactly the rules of inputRules(touch), in order.
func (t nftTable) inputOK(touch bool) bool {
	rules := inputRules(touch)
	in := t.chains["input"]
	if in == nil || !strings.HasPrefix(in.hdr, "typefilterhookinput") || !strings.Contains(in.hdr, "policyaccept") || len(in.rules) != len(rules) {
		return false
	}
	want := normAll(rules)
	for i, r := range in.rules {
		udpReject := i == len(want)-1 && slices.Contains(rejectUDPForms, r)
		touch := want[i] == nftNorm(hpTouchRule) && slices.Contains(touchRuleForms, r)
		if r != want[i] && !udpReject && !touch {
			return false
		}
	}
	return true
}

// touchedOK is the check of the dynamic set: its type, the flags dynamic and timeout, its size and timeout as loaded (the timeout
// as nft prints it, 2m, or as loaded, 120s), and no other line. Its elements are the traffic of the moment and are not compared.
func touchedOK(s *nftSet) bool {
	if s == nil || s.typ != hpTouchedType {
		return false
	}
	flags, size, timeout := false, false, false
	for _, l := range s.other {
		l, _, _ = strings.Cut(l, "#") // nft 1.1 prints "size 1024\t# count 6"
		n := nftNorm(l)
		switch {
		case strings.HasPrefix(n, "flags"):
			f := strings.Split(strings.TrimPrefix(n, "flags"), ",")
			flags = len(f) == 2 && slices.Contains(f, "dynamic") && slices.Contains(f, "timeout")
		case n == "size"+strconv.Itoa(hpTouchedSize):
			size = true
		case n == "timeout2m" || n == "timeout"+strconv.Itoa(int(hpTouchTimeout/time.Second))+"s":
			timeout = true
		default:
			return false
		}
	}
	return flags && size && timeout
}

// hasEgressDrop reads the text of "nft list ruleset" and accepts only the egress part of the host's
// ruleset (see egressOK). The text is compared without spaces, braces and quotes ("oif "lo"" is how
// nft prints the interface).
func hasEgressDrop(out []byte) bool { return parseHPTable(out).egressOK() }

// rulesetIs reports whether the printed ruleset is the one the host wants for list: the egress part,
// the input chain, the two sets with exactly the wanted elements (so every address it names is a
// decoy's), no other chain or set in the table (one could hold a hook of its own), and no other table
// in the namespace.
func rulesetIs(out []byte, list []decoyEntry) bool { return rulesetIsMode(out, list, true) }

// rulesetIsMode is rulesetIs for the ruleset with (touch) or without the set touched and its rule.
func rulesetIsMode(out []byte, list []decoyEntry, touch bool) bool {
	t := parseHPTable(out)
	open, allow := wantedSets(list)
	sets := 2
	if touch {
		sets = 3
		if !touchedOK(t.sets["touched"]) {
			return false
		}
	}
	return t.foreign == 0 && t.egressOK() && t.inputOK(touch) && len(t.chains) == 3 && len(t.sets) == sets &&
		setIs(t.sets["open"], hpOpenType, open, false) && setIs(t.sets["allow"], hpAllowType, allow, true)
}

// withTouch says whether the host loads the set touched and its rule: until nft printed them in a form the effect check does not
// know (loadProven), for the life of the process.
func (o *Ops) withTouch() bool { return !o.touchOff.Load() }

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
	return rulesetIsMode(res.Stdout, list, o.withTouch()), nil
}

// applyRuleset loads the ruleset for list and proves it (the effect check). It changes nothing else:
// the caller decides what a failure means.
func (o *Ops) applyRuleset(ctx context.Context, list []decoyEntry) error {
	return o.loadProven(ctx, list)
}

// loadProven loads the ruleset for list and proves it. When the ruleset with the set touched cannot be proven but the same
// ruleset without it can, the touch part is what nft printed in a form the check does not know (B2 review H1): the host keeps
// the decoys up without it, for the life of the process, says so (log, audit line, hp-touches "recording": false), and a SYN
// scan is then seen only by its completed connections. When neither can be proven the touch part is kept and the error stands
// (the caller decides: undo, close the namespace).
func (o *Ops) loadProven(ctx context.Context, list []decoyEntry) error {
	if err := o.loadRuleset(ctx, list); err != nil {
		return err
	}
	ok, err := o.rulesetLoaded(ctx, list)
	if err != nil || ok {
		return err
	}
	if o.withTouch() {
		o.touchOff.Store(true)
		if err := o.loadRuleset(ctx, list); err == nil {
			if ok, err := o.rulesetLoaded(ctx, list); err == nil && ok {
				o.log.ErrorContext(ctx, "the ruleset of vedette-hp could not be proven with the set touched; loaded without it: SYN scans of the decoys are not recorded")
				o.note("decoy_ip", "touch_record_off", map[string]any{})
				return nil
			}
		}
		o.touchOff.Store(false) // the touch part was not the trouble
	}
	return errors.New("ops: the ruleset of vedette-hp is not the one the host loaded")
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
	if err := o.ensureHPLinks(ctx); err != nil {
		o.log.ErrorContext(ctx, "the honeypot namespace is not usable", "error", err.Error())
		return nil, fail(api.CodeHPNamespaceUnavailable, "The honeypot network namespace is not usable, so nothing was changed.")
	}
	if list, err = o.loadDecoysNoted(); err != nil { // a rebuild may have dropped a decoy that no longer fits
		return nil, fail(api.CodeDecoysStateInvalid, "The decoy state file could not be read or set aside.")
	}
	if i = slices.IndexFunc(list, func(e decoyEntry) bool { return e.IP == ip.String() }); i < 0 {
		return nil, refuse412(api.CodeNotADecoy, notADecoyMsg)
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
			// The file keeps the new ports, which the ruleset could not prove: the file and the ruleset
			// would disagree, and the next ensureHP would load the file. Close the namespace instead
			// (fail closed); the next write proves it from the file and builds the links again.
			o.log.ErrorContext(ctx, "could not put the old entry back in hp/decoys.json", "error", serr.Error())
			o.closeUnproven(ctx, serr)
			return nil, fail(api.CodeDecoyFailed, "The new ports could not be put in force and the old ones could not be written back; the decoys are off until the host proves the namespace again.")
		}
		if rerr := o.applyRuleset(ctx, list); rerr != nil {
			o.closeUnproven(ctx, rerr)
			return nil, fail(api.CodeDecoyFailed, "The new ports could not be put in force and the old ruleset could not be proven; the decoys are off until the host proves the namespace again.")
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

// readHPTouches is GET /v1/state/hp-touches: the elements of the touched set, from "nft -j list set" inside the namespace
// (no shell, a fixed argv). Only pairs whose destination is a decoy of hp/decoys.json and whose source is no decoy, loopback,
// multicast or the limited broadcast are kept; the host's own addresses never reach the namespace (macvlan bridge mode). A
// namespace that is not proven answers no touch. Anything nft prints that does not parse is an error (fail closed: no touch is
// made up).
func (o *Ops) readHPTouches(ctx context.Context) (any, error) {
	out := api.HPTouchesState{Touches: []api.HPTouch{}, Recording: o.withTouch()}
	if o.hpDirErr != nil || !o.hpOK.Load() || !out.Recording {
		return out, nil
	}
	list, err := o.readDecoys()
	if err != nil {
		return out, nil
	}
	res, code, err := o.exec(ctx, binIP, argvNftTouched()...)
	if err != nil || code != 0 || res.Truncated {
		return nil, fmt.Errorf("ops: listing the touched set of vedette-hp failed (exit %d)", code)
	}
	touches, err := parseTouched(res.Stdout)
	if err != nil {
		return nil, err
	}
	if len(touches) >= api.HPTouchesFull {
		out.Full = true
		o.log.WarnContext(ctx, "the set touched of vedette-hp is (nearly) full: new attempts to the decoys may not be recorded", "elements", len(touches))
	}
	decoys := map[string]bool{}
	for _, e := range list {
		decoys[e.IP] = true
	}
	for _, t := range touches {
		src, _ := netip.ParseAddr(t.Src)
		if !decoys[t.Dst] || decoys[t.Src] || src.IsLoopback() || src.IsMulticast() || src.IsUnspecified() || t.Src == "255.255.255.255" {
			continue
		}
		out.Touches = append(out.Touches, t)
	}
	return out, nil
}

// parseTouched reads "nft -j list set inet vedette_hp touched". An element is {"elem": {"val": {"concat": [src, dst]},
// "timeout": s, "expires": s}} (or a bare {"concat": [...]} when nft gives no times: age 0). Both addresses must be plain IPv4.
func parseTouched(b []byte) ([]api.HPTouch, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name    string            `json:"name"`
				Timeout int               `json:"timeout"`
				Elem    []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("ops: the touched set is not nft JSON: %w", err)
	}
	type concat struct {
		Concat []string `json:"concat"`
	}
	var out []api.HPTouch
	found := false
	for _, n := range doc.Nftables {
		if n.Set == nil || n.Set.Name != "touched" {
			continue
		}
		found = true
		for _, raw := range n.Set.Elem {
			var e struct {
				Elem *struct {
					Val     concat `json:"val"`
					Timeout int    `json:"timeout"`
					Expires int    `json:"expires"`
				} `json:"elem"`
				concat
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf("ops: an element of the touched set: %w", err)
			}
			pair, age := e.Concat, 0
			if e.Elem != nil {
				pair = e.Elem.Val.Concat
				timeout := e.Elem.Timeout
				if timeout == 0 {
					timeout = n.Set.Timeout
				}
				age = max(0, timeout-e.Elem.Expires)
			}
			if len(pair) != 2 || !plainIP4(pair[0]) || !plainIP4(pair[1]) {
				return nil, errors.New("ops: an element of the touched set is not two IPv4 addresses")
			}
			out = append(out, api.HPTouch{Src: pair[0], Dst: pair[1], AgeS: age})
		}
	}
	if !found {
		return nil, errors.New("ops: nft printed no touched set")
	}
	return out, nil
}
