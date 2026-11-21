package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/ai/provider"
)

// The brief is the small door the mitigation module uses (`mitigation.AI`): the AI explains a finding or drafts a
// recommendation for it, and the answer is a few paragraphs and steps. Like every AI output it is a suggestion: mitigation stores
// it as an AI result and the page labels it as AI-generated, never as a confirmed recommendation (INV-5).

// BriefRequest is one such call. Data holds the device and feed text of the finding; it is untrusted and goes into the prompt only
// as fenced data.
type BriefRequest struct {
	Job      Job // JobExplainFinding or JobMitigationConfig
	Actor    string
	Target   string // the CVE, for the activity summary
	Question string
	Data     []DataBlock
	// Trusted are the addresses the box itself knows for this finding, read from structured fields (the device's IP, the IPs of the
	// firewalls sent), never from a banner, a name or free text. A config line that names any other address is flagged on the page for
	// the person to check (#897 r2: warn, not filter).
	Trusted []netip.Addr
}

// BriefAnswer is the checked answer. Citations are not part of it: the caller builds them from the feed entry.
type BriefAnswer struct {
	Model      string
	Profile    string
	TokensIn   int
	TokensOut  int
	Paragraphs []string
	Steps      []string
	// Configs are the ready configuration blocks of a mitigation-config answer (none for explain-finding).
	Configs []BriefConfig
	// NoConfigReason is why no network rule (or no config at all) applies, in the model's words: a local or user-interaction flaw, or
	// no open port of the device serves the vulnerable part (r1 H1 of #897). An answer may have no config only when it says why.
	NoConfigReason string
	// Shortened is set when a part of the answer was longer than the box keeps: a text was cut at a sentence end (never mid-sentence)
	// or a config block was left out whole (a cut config could be pasted half), so the page can say so (M2-2).
	Shortened  bool
	ActivityID string
}

// BriefConfig is one configuration block a person can paste as it is: the device-side workaround, or a rule for one firewall.
type BriefConfig struct {
	Title      string // the target: "Juniper EX4200-48T (Junos)", "FortiGate 60F"
	Code       string // the lines, joined with line breaks
	SideEffect string // what it can break, shown before the person copies it
	BasedOn    string // the source the change follows ("the vendor advisory linked in the entry")
	// Check lists the addresses the block names that are not Trusted (netmasks, wildcards and 0.0.0.0 / :: aside), as written: the page
	// asks the person to check them before pasting. Nothing is dropped for an address (#897 r2).
	Check []string
}

type briefBody struct {
	Paragraphs []string        `json:"paragraphs"`
	Steps      []string        `json:"steps"`
	Configs    []briefConfigIn `json:"configs"`
	NoConfig   string          `json:"no_config_reason"`
}

type briefConfigIn struct {
	Title      string   `json:"title"`
	Lines      []string `json:"lines"`
	SideEffect string   `json:"side_effect"`
	BasedOn    string   `json:"based_on"`
}

const briefSchema = `{"type":"object","properties":{"paragraphs":{"type":"array","items":{"type":"string"}},"steps":{"type":"array","items":{"type":"string"}}},"required":["paragraphs","steps"],"additionalProperties":false}`

// briefConfigSchema is the mitigation-config answer: the explanation and the order of work, plus the config blocks themselves. Each
// line of a block is its own string, so every line goes through the after_ai hooks in the form that is kept (INV-12).
const briefConfigSchema = `{"type":"object","properties":{"paragraphs":{"type":"array","items":{"type":"string"}},"steps":{"type":"array","items":{"type":"string"}},"configs":{"type":"array","items":{"type":"object","properties":{"title":{"type":"string"},"lines":{"type":"array","items":{"type":"string"}},"side_effect":{"type":"string"},"based_on":{"type":"string"}},"required":["title","lines","side_effect","based_on"],"additionalProperties":false}},"no_config_reason":{"type":"string"}},"required":["paragraphs","steps","configs","no_config_reason"],"additionalProperties":false}`

// briefFixRule is the part of both finding tasks about the fix. The finding page states the fix from the box's own reading of the affected
// versions (the data's "Fixed version" line); an answer that names another one contradicts the page. The end of an affected range
// ("before 20.4") is not a fix: the vendor may list releases of 20.4 itself as affected, and then the line says so.
const briefFixRule = `The "Fixed version" line of the device block is what the finding page tells the person about the fix: name as the fix only a release that line names as fixed, in its words. When it says a release is not a fix, names no fixed release, or says the fix is not known, say exactly that and point to the vendor advisory in the links; never call that release (or "that release or later") the fix and never tell the person to upgrade to it. Never work out a fixed release from an affected range, such as the "before" end of the range in the Evidence.`

const (
	briefExplainTask = `Explain one finding for this company's network: a device the box matched to a known vulnerability. The device block's Urgency line says why it matters now; call the vulnerability exploited only when that line says attackers use it, never otherwise. Use only the facts in the data blocks. In "paragraphs" write at most 4 short paragraphs of plain English: what the vulnerability is, whether it touches this device and why, and what an attacker could do. In "steps" write the steps a person should take, in order. ` + briefFixRule + ` Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`
	briefConfigTask  = `Write ready-to-paste configuration that reduces the risk of one vulnerability on this device until it is patched, when configuration can do that. Use only the facts in the data blocks: the device block gives the device, its installed software and version, the affected range and the fixed releases, the CVSS attack vector, its open ports and the ports of the vulnerable product (the ports that run it, the ones most likely the same server, the ones that run another product); the network block lists the firewalls and routers of the company's inventory a rule may be written for, each with its place on the path to this device. In "paragraphs" write at most 3 short paragraphs of plain English: whether the installed version is inside the affected range and what the data says about the fix (when the data names a fixed release, give it, do not ask the person to look it up), what the configuration below does, and what it can break. When you write a firewall or router rule, say which traffic it stops, as the network block gives it: a rule on a gateway or firewall filters only the traffic routed through it, so it protects the device only from other networks, hosts on the device's own network still reach the device directly, and only the change on the device itself protects it from them. ` + briefFixRule + ` In "configs" give the configuration blocks, each a "title" naming the target (vendor and model), its "lines" exactly as a person pastes them into that product's command line, one command per string and never a line break inside a string, its "side_effect" (what stops working, and how not to lock yourself out), and "based_on" (which source in the data the change follows, or "general practice, no source in the data names it" when none does). First one block for the device itself in its own configuration language: the vendor's known workaround for this vulnerability, such as turning off or restricting the vulnerable service, a policy or a registry setting. Then, only when the vulnerability is reached over the network (attack vector network or adjacent) and an open port of this device serves the vulnerable component, one block for each firewall or router the network block lists, in that vendor's own syntax, that blocks or limits access from other networks to the ports of the vulnerable product on this device (its IP address from the data), as the "Ports of the vulnerable product" line gives them: the ports that run it and the ones it calls most likely the same server, plain and TLS alike (a web interface's HTTP and HTTPS ports, never only one of them), and never a port it calls another product (when such a port may be a reverse proxy in front of the vulnerable product, say so in "no_config_reason"). Choose such a rule's action by where the blocked traffic comes from and by each port's protocol. Traffic from the company's own internal networks is refused, so a blocked client fails at once instead of hanging and the person sees the block when verifying: TCP ports with a TCP reset (nftables "reject with tcp reset", iptables "-p tcp -j REJECT --reject-with tcp-reset", a Junos firewall filter term "then reject tcp-reset", a pfSense or OPNsense Reject rule, a FortiGate deny policy with "set send-deny-packet enable"); UDP ports with an ICMP reject (nftables plain "reject", iptables "-p udp -j REJECT") in a rule of their own, never a TCP reset, and never TCP and UDP ports in one match with a TCP reset. Traffic that arrives from the Internet (the device is reachable through a port forward or a public address) is dropped silently in a rule of its own placed before the reject, matched on the Internet side with a placeholder such as <WAN_INTERFACE>, so the device does not answer scanners. When a product can only drop, use its deny as it is (a FortiGate deny policy drops unless send-deny-packet is enabled; a pfSense Block rule drops). Of the ports it calls not known which product, cover the ones of the same service as a port that runs it, and the ones of other services only when the vulnerability is reached through that service (such as the product's web front end); say in "no_config_reason" which of them you covered and why. When that line says the ports are not known, choose from its candidates only the ones that serve the vulnerable component (from the product the scan read on each and what the vulnerability is), with the ports it calls most likely the same server, never every web port of the device, and say in "no_config_reason" which ports you chose and why. When it says the vulnerability is in the device's own platform, choose the interface the vulnerability names (such as the web interface) and cover every port it lists for that service, plain and TLS alike, never only one of them and never the ports of the device's other interfaces. Write a rule only for a firewall or router the network block lists, never for one it says is not on the path to this device. When the network block says Vedette does not know which firewall is on the device's path, a rule for a listed one is an assumption: put "(assumed)" in the block's "title", and in "no_config_reason" name each firewall you assumed is in front of the device, why (its place as the network block gives it), and that Vedette does not know the device's path. When the network block says this device is the network edge (the default gateway of its network), write no firewall block and no Linux gateway example: nothing of the company stands in front of it, so the device's own block restricts the vulnerable service (its management or VPN access, a local-in policy), and "no_config_reason" says that no other firewall is in front of this device. For a listed firewall or router whose vendor is not known, write its block for a Linux gateway with nftables, titled with its name. When the network block lists no firewall or router a rule can be written for, one block for a Linux gateway with nftables instead, titled for the gateway the network block names when it names one, and in "no_config_reason" say that Vedette does not know which firewall is in front of the device, so this rule is an example for whatever gateway it is. Never write a firewall rule for ports unrelated to the vulnerable service. When the data gives a target a safe apply (a way to apply that undoes the change by itself when it is not confirmed, such as Junos "commit confirmed"), that target's change is applied that way: a command it calls a separate step goes in "steps", never in "lines"; its "side_effect" says what to confirm, by when, and what happens when it is not confirmed (some platforms restart); "steps" say how to confirm it; never end such a block with a plain commit alone. For a remote change to a network device or firewall the data gives no safe apply, never name an automatic rollback: its "side_effect" says to keep a second session open while applying. Use only IP addresses that are in the data; write a named placeholder such as <ADMIN_NETWORK> for what the data cannot know. In "no_config_reason" say in one or two sentences why a firewall rule, or any configuration, does not help when you give none (for example: the attack is local or needs a user to open a file, or no open port serves the vulnerable part), or which firewall a rule assumes as asked above, else an empty string. In "steps" write at most 8 short steps: back up the current configuration, apply, verify, and how to undo; when no configuration helps, the steps to patch or turn the component off. Every verify step says where to test from and the result the person sees, matching the action of the rule it checks and the network tested from: a silent drop or deny (nftables "drop", a FortiGate deny without send-deny-packet, a pfSense Block, a Junos "discard") makes the connection time out with no answer; a TCP reset makes a TCP connection refused at once; an ICMP reject makes it fail at once as unreachable or prohibited (a UDP port is never "refused": an ICMP error or no answer). Never call a timeout refused, or a refusal a timeout. Test a firewall or router rule from a host whose traffic crosses that firewall, as its line in the network block says, never from the device's own network: from there the port still answers, which is expected, and the step says so. When the network block says the device's network is assumed or not known, the step says to pick the test host by its route to the device (a traceroute or tracert lists the firewall as a hop), not by an address range. When the network block says a scan from the box does not show a gateway rule, never tell the person to check that rule with a scan from Vedette. Test the device's own change from a host it is meant to block: a service turned off answers no host, so it is refused from any host, the device's own network included; an access restriction on the device (an allowed admin network, trusted hosts, a local-in policy, a host firewall rule) is tested from a host outside the allowed sources, with the result its action gives (refused for a reset, a timeout for a drop), and from an allowed host the port still answers, as expected. Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`
)

// briefMaxTokens is the output limit of an explanation. The answer itself (4 paragraphs and a list of steps, as JSON) runs to about
// 900 tokens, but the limit also covers what a model thinks before it answers (Claude Haiku 5.5 thinks by default; OpenAI reasoning
// models and Gemini count it the same way), which can be a few thousand. The meter counts what is really used, not this limit; a cut
// answer is asked again once with twice the limit (Router.retryCut). briefConfigMaxTokens is the same for mitigation-config, whose
// config blocks (the device's own and one per firewall vendor) add about 1,500 tokens.
const (
	briefMaxTokens       = 6000
	briefConfigMaxTokens = 8000
)

// Limits on what a brief keeps (the model's text is untrusted). A text over its limit is cut at the end of a sentence, never in the
// middle of one (M2-2: "No confirmed recommendation exists yet, and a" was a paragraph cut at 500 characters); a config block over its
// limits is left out whole. Either sets BriefAnswer.Shortened.
const (
	briefMaxParagraphs = 6
	briefParagraphRune = 1500
	briefMaxSteps      = 12
	briefStepRunes     = 600
	briefMaxConfigs    = 8
	briefMaxLines      = 80
	briefLineRunes     = 400
	briefTitleRunes    = 200
	briefSideRunes     = 800
)

func parseBrief(text string, job Job) (briefBody, error) {
	var b briefBody
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return briefBody{}, ErrBadOutput
	}
	keys := []string{"paragraphs", "steps"}
	if job == JobMitigationConfig {
		keys = append(keys, "configs")
	}
	if !hasKeys(text, keys...) {
		return briefBody{}, ErrBadOutput
	}
	if len(cleanList(b.Paragraphs)) == 0 {
		return briefBody{}, ErrBadOutput
	}
	if job == JobMitigationConfig { // the job is the config: an answer without one must say why none helps (M2-2, r1 H1)
		found := strings.TrimSpace(b.NoConfig) != ""
		for _, c := range b.Configs {
			for _, l := range c.Lines {
				found = found || strings.TrimSpace(l) != ""
			}
		}
		if !found {
			return briefBody{}, ErrBadOutput
		}
	} else {
		b.Configs, b.NoConfig = nil, ""
	}
	return b, nil
}

// keptBrief is the answer as it is kept: texts within their limits, cut at a sentence end, and the config blocks that fit whole, each
// with the addresses it names that are not trusted (#897 r2: shown for checking, never dropped).
func keptBrief(b briefBody, trusted []netip.Addr) (a BriefAnswer) {
	a.Paragraphs, a.Shortened = sentenceList(b.Paragraphs, briefMaxParagraphs, briefParagraphRune)
	var cut bool
	a.Steps, cut = sentenceList(b.Steps, briefMaxSteps, briefStepRunes)
	a.Shortened = a.Shortened || cut
	for _, c := range b.Configs {
		code, ok := codeBlock(c.Lines)
		if code == "" && ok {
			continue
		}
		// a block over the limits or with a line break inside a line (a masked answer would have joined its two commands) is left out whole
		if !ok || len(a.Configs) == briefMaxConfigs {
			a.Shortened = true
			continue
		}
		title, c1 := clipSentence(cleanText(c.Title), briefTitleRunes)
		side, c2 := clipSentence(cleanText(c.SideEffect), briefSideRunes)
		basis, c3 := clipSentence(cleanText(c.BasedOn), briefTitleRunes)
		a.Shortened = a.Shortened || c1 || c2 || c3
		if title == "" {
			title = "Configuration"
		}
		a.Configs = append(a.Configs, BriefConfig{Title: title, Code: code, SideEffect: side, BasedOn: basis, Check: untrustedAddrs(code, trusted)})
	}
	var c4 bool
	a.NoConfigReason, c4 = clipSentence(cleanText(b.NoConfig), briefSideRunes)
	a.Shortened = a.Shortened || c4
	return a
}

var (
	ipv4Like = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?`)
	ipv6Like = regexp.MustCompile(`\[?[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.[0-9]{1,3}){0,3}\]?(?:/[0-9]{1,3})?`)
)

// untrustedAddrs lists, once each and in order, the IPv4 and IPv6 literals of a config that are not trusted. Not listed: a netmask
// (255.255.255.0, ones then zeros) or a wildcard (0.0.0.255, zeros then ones), 0.0.0.0 and ::, and a prefix of /16 (IPv6 /48) or
// longer that holds a trusted address. Anything that looks like an address but is not a plain one (leading zeros, which inet_aton reads
// as octal; a 4-in-6 form of an untrusted address) is listed as written. A version number (15.1R7.9, 10.0.19045.6456) is not taken for
// one: a digit or a dot touches the match.
func untrustedAddrs(code string, trusted []netip.Addr) []string {
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	isTrusted := func(a netip.Addr) bool { return slices.Contains(trusted, a) }
	trustedPrefix := func(p netip.Prefix) bool {
		if p.Addr().Is4() && p.Bits() < 16 || p.Addr().Is6() && p.Bits() < 48 {
			return false
		}
		return slices.ContainsFunc(trusted, p.Contains)
	}
	ms := ipv4Like.FindAllStringIndex(code, -1)
	for i := 0; i < len(ms); i++ {
		m := ms[i]
		if m[0] > 0 && strings.ContainsRune("0123456789.:", rune(code[m[0]-1])) || m[1] < len(code) && strings.ContainsRune("0123456789.", rune(code[m[1]])) {
			continue // part of a longer dotted number (a version) or of an IPv6 literal, not an IPv4 address
		}
		t := code[m[0]:m[1]]
		host, _, hasBits := strings.Cut(t, "/")
		a, err := netip.ParseAddr(host)
		// "<network> <mask>" (Cisco, FortiOS: 192.168.18.0 255.255.255.0 or the wildcard 0.0.0.255) is one network
		if err == nil && !hasBits && i+1 < len(ms) && strings.TrimSpace(code[m[1]:ms[i+1][0]]) == "" {
			if mask, merr := netip.ParseAddr(code[ms[i+1][0]:ms[i+1][1]]); merr == nil && isMask(mask) {
				if p, perr := a.Prefix(maskBits(mask)); perr == nil {
					if !isTrusted(a) && !trustedPrefix(p) {
						add(t)
					}
					i++ // the mask is read
					continue
				}
			}
		}
		switch {
		case err != nil: // 010.010.010.010 and the like
			add(t)
		case hasBits:
			p, err := netip.ParsePrefix(t)
			if err != nil || (!a.IsUnspecified() || p.Bits() != 0) && !trustedPrefix(p.Masked()) {
				add(t)
			}
		case isMask(a), a.IsUnspecified(), isTrusted(a):
		default:
			add(t)
		}
	}
	for _, t := range ipv6Like.FindAllString(code, -1) {
		raw := strings.Trim(t, "[]")
		host, _, hasBits := strings.Cut(raw, "/")
		if strings.Count(host, ":") < 2 {
			continue // a time (12:30:00) or a port pair
		}
		a, err := netip.ParseAddr(host)
		switch {
		case err != nil:
			if strings.Contains(host, "::") || strings.Count(host, ":") == 7 {
				add(t) // looks like an address and is not a plain one
			}
		case a.Is4In6():
			if !isTrusted(a.Unmap()) {
				add(t)
			}
		case a.IsUnspecified(), isTrusted(a):
		case hasBits:
			if p, err := netip.ParsePrefix(raw); err != nil || !trustedPrefix(p.Masked()) {
				add(t)
			}
		default:
			add(t)
		}
	}
	return out
}

// maskBits is the prefix length of a netmask (255.255.255.0: 24) or of a wildcard mask (0.0.0.255: 24).
func maskBits(m netip.Addr) int {
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if inv := ^v; inv&(inv+1) == 0 { // a netmask: ones then zeros (255.255.255.255 is /32, not the wildcard of /0)
		return bits.OnesCount32(v)
	}
	return bits.OnesCount32(^v) // a wildcard: zeros then ones
}

// isMask reports whether an IPv4 value is a netmask (ones then zeros, 255.255.255.0) or a wildcard mask (zeros then ones, 0.0.0.255),
// not a host.
func isMask(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if v == 0 {
		return false
	}
	inv := ^v
	return inv&(inv+1) == 0 || v&(v+1) == 0
}

// sentenceList cleans a list of texts, drops empty ones and keeps at most n, each cut at a sentence end within runes characters.
func sentenceList(in []string, n, runes int) ([]string, bool) {
	out, cut := []string{}, false
	for _, s := range in {
		s, c := clipSentence(cleanText(s), runes)
		if s == "" {
			continue
		}
		if len(out) == n {
			return out, true
		}
		cut = cut || c
		out = append(out, s)
	}
	return out, cut
}

// codeBlock joins the lines of a config block with line breaks. A line that holds a line break itself is refused (ok false): the
// schema asks for one command per string, and a masked answer is written out with line breaks as spaces, which would join two commands
// into one (r1 M2). ok is also false when the block is longer than the limits: it is then left out whole, because half a config can be
// pasted and do harm. The after_ai hooks see the block in this same joined form (afterHooks, the "lines" array).
func codeBlock(lines []string) (string, bool) {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return "", false
		}
		l = codeLine(l)
		if utf8.RuneCountInString(l) > briefLineRunes {
			return "", false
		}
		out = append(out, l)
	}
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if len(out) > briefMaxLines {
		return "", false
	}
	return strings.Join(out, "\n"), true
}

// codeLine is one config line as it is kept: control characters (NEL too), line and paragraph separators (U+2028, U+2029) and
// invisible format characters (bidi controls such as U+202E, zero-width spaces) go, so the line shown is the line pasted (#897 r2 M4);
// a tab becomes a space, the indentation stays, the end is trimmed.
func codeLine(l string) string {
	return strings.TrimRight(strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			return -1
		}
		return r
	}, strings.ToValidUTF8(l, "\uFFFD")), " ")
}

// clipSentence cuts s to at most n characters at the end of a sentence (a stop, possibly followed by a closing bracket or quote, then a
// space or the end; never after a short abbreviation such as "e.g."), so a kept text never stops in the middle of one; when no
// sentence ends in the last two thirds it cuts at a word, else between characters (never before a combining mark), and ends with "…".
// cut reports whether it cut.
func clipSentence(s string, n int) (string, bool) {
	r := []rune(s)
	if len(r) <= n {
		return s, false
	}
	r = r[:n]
	for i := len(r) - 1; i >= n/3; i-- {
		if r[i] != '.' && r[i] != '!' && r[i] != '?' {
			continue
		}
		end := i + 1
		for end < len(r) && strings.ContainsRune(`)"'”’`, r[end]) {
			end++
		}
		if (end == len(r) || r[end] == ' ') && !abbrevAt(r, i) {
			return string(r[:end]), true
		}
	}
	for i := len(r) - 1; i >= n/3; i-- {
		if r[i] == ' ' {
			return strings.TrimRight(string(r[:i]), " ,;:") + "…", true
		}
	}
	i := n - 1
	for i > 0 && unicode.Is(unicode.Mn, r[i]) { // keep a letter with its accent (an NFD "ă" is two runes)
		i--
	}
	return string(r[:i]) + "…", true
}

var abbrevs = []string{"e.g.", "i.e.", "etc.", "vs.", "approx.", "no.", "cf.", "incl."}

// abbrevAt reports whether the stop at r[i] ends a short abbreviation ("e.g."), which is not a sentence end.
func abbrevAt(r []rune, i int) bool {
	if r[i] != '.' {
		return false
	}
	w := i
	for w > 0 && r[w-1] != ' ' && r[w-1] != '(' {
		w--
	}
	word := strings.ToLower(string(r[w : i+1]))
	return slices.Contains(abbrevs, word)
}

// Available reports whether the ai module is on and a profile is assigned and allowed for the job.
func (s *Service) Available(job Job) bool {
	return s.moduleOn() && s.Ready(job) == nil
}

func (s *Service) moduleOn() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

// Brief runs an explain-finding or mitigation-config call for a finding. It returns the *apierr.Error of RunJob (409
// ai_unavailable, 429 budget_reached) so the caller can tell "cannot be used" from a failure.
func (s *Service) Brief(ctx context.Context, r BriefRequest) (BriefAnswer, error) {
	if !s.moduleOn() { // a door another module holds must not run the AI while the module is off
		return BriefAnswer{}, apiUnavailable("The AI assistant module is off. Turn it on in Settings, Modules.")
	}
	task, schema, limit := briefExplainTask, briefSchema, briefMaxTokens
	switch r.Job {
	case JobExplainFinding:
	case JobMitigationConfig:
		task, schema, limit = briefConfigTask, briefConfigSchema, briefConfigMaxTokens
	default:
		return BriefAnswer{}, fmt.Errorf("ai: brief: job %q is not a finding job", r.Job)
	}
	var kept BriefAnswer
	res, err := s.RunJob(ctx, JobSpec{
		Job: r.Job, Actor: r.Actor, Task: task, Question: r.Question, Data: r.Data,
		Schema: &provider.Schema{Name: "finding_brief", JSON: json.RawMessage(schema)}, MaxTokens: limit,
		Summary: fmt.Sprintf("%s for %s", strings.ToUpper(r.Job.Name()[:1])+r.Job.Name()[1:], clipRunes(cleanLine(r.Target, 40), 40)),
		// the answer is checked as it is kept (#897 r2 M1): a config answer whose every block was left out, and that gives no reason,
		// is not what the job asked for, so it is a format error, never an empty "Ask my AI"
		Check: func(text string) error {
			body, perr := parseBrief(text, r.Job)
			if perr != nil {
				return perr
			}
			kept = keptBrief(body, r.Trusted)
			if r.Job == JobMitigationConfig && len(kept.Configs) == 0 && kept.NoConfigReason == "" {
				return ErrBadOutput
			}
			return nil
		},
	})
	if err != nil {
		return BriefAnswer{}, err
	}
	a := kept
	a.Model, a.Profile, a.TokensIn, a.TokensOut, a.ActivityID = res.Model, res.Profile, res.TokensIn, res.TokensOut, res.ActivityID
	return a, nil
}

// Configured reports whether at least one AI profile can be used (a key, or a model inside the network): flow 3 of the Privacy page.
func (s *Service) Configured() bool {
	for _, p := range s.snap.Load().profiles {
		if p.Usable() {
			return true
		}
	}
	return false
}
