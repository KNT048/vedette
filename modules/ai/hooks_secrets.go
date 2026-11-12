package ai

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Device secrets (D-220, INV-12). Text that comes from a device (a configuration, a log line, the output of a read tool of a
// connection) can carry passwords, hashes, SNMP communities and keys. The block-pii hook masks the value and keeps the keyword,
// so the AI still sees that a password is set, not what it is.
//
// Every pattern is RE2 (linear in the text, no backtracking), runs on the normalised text like the other finders, and every capture
// group is a value to mask. A value is a quoted string without a line break (a backslash escapes the next character), or the run of
// characters up to the next space. Patterns never cross a line, except the private-key block, which is masked whole (or to the end of
// the text when it has no end line).
//
// A pattern needs a marker prose does not have: a keyword followed by a value of the shape of a secret (hex after type 7, a crypt hash),
// an algorithm word (md5, sha1), `=`, a JSON field, a hash prefix, ENC, or a configuration line (cfgLine: a lower-case command at the
// start of the line, such as `username`, `enable`, `set`). "Change your password 3 times" and "the psk is weak" are left alone.
// ponytail: only secrets that carry such a marker or sit where the vendor's syntax puts them (` password x` under `line vty|con|aux`,
// a YAML key, the body of a PuTTY key file, a FortiGate `set name` inside `config system snmp community`, an IOS `snmp-server host`
// with a version); other vendors' blocks are not recognised; upgrade path: a config-aware parser per vendor, if a customer needs it.
// Over-masking costs one word and is kept (D-428): `password 3 times` at the start of a lower-case line, `The password authentication
// encrypted`; the value shape is all a pattern can tell, and a secret that leaks costs more.
const secretValue = `("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|\S+)` //nolint:gosec // a regexp fragment, not a credential

// secretKeyStart: the keyword begins at the start of a line or after a character that cannot be part of a word.
const secretKeyStart = `(?i)(?:^|[^a-z0-9_])` //nolint:gosec // a regexp fragment, not a credential

// cfgLine: the start of a configuration line (case-sensitive: device configurations are lower case, sentences start with a capital).
const cfgLine = `(?m:^)[ \t]*(?:no[ \t]+)?`

// typeKeyword: the words a Cisco type number (0-9) follows; typeAlgo: an algorithm word between a key number and the value (NTP, OSPF).
const (
	typeKeyword = `(?:password|secret|passphrase|key-string|key|md5|authentication-key|auth-key|message-digest-key)`
	typeAlgo    = `(?:(?:md5|sha1|sha256|sha512|hmac-sha\S*)[ \t]+(?:[0-9][ \t]+)?)?`
)

// secretPattern is a pattern, the words one of which the text must hold (lower case) for the pattern to be run at all, and the values
// it must leave alone (nil: none); leaveWhole is the same for the whole match (nil: none). The words keep the cost of text without secrets (most text) to one lower-casing and a few searches.
type secretPattern struct {
	re         *regexp.Regexp
	needs      []string
	leave      *regexp.Regexp
	leaveWhole *regexp.Regexp
}

func secretRE(expr string, needs ...string) secretPattern {
	return secretPattern{re: regexp.MustCompile(expr), needs: needs}
}

// Words the patterns need, lower case.
var (
	needTyped  = []string{"pass", "secret", "key", "md5"}
	needCommun = []string{"community"}
	needNamed  = []string{"pass", "secret", "psk", "shared", "private"}
	needJSON   = []string{"pass", "secret", "psk", "shared", "private", "community"}
)

const yamlKey = `(?:(?i:[a-z0-9_-]*(?:password|passwd|passphrase|secret|psk|private[-_]?key)[a-z0-9_-]*|(?:[a-z0-9_-]*[_-])?pass)|(?:[a-z0-9_-]*[_-])?community)`

var deviceSecretPatterns = []secretPattern{
	// Cisco type 7 anywhere, when the value has its shape: two decimal digits (the offset) and hex (password 7 <hex>, key 7 <hex>,
	// md5 7 <hex>, key-string 7 <hex>).
	secretRE(secretKeyStart+typeKeyword+`[ \t]+7[ \t]+"?([0-9]{2}[0-9a-f]{2,})\b`, needTyped...),
	// A key number and an algorithm before the value (ntp authentication-key 1 md5 <key> [7], ip ospf message-digest-key 1 md5 7 <key>).
	secretRE(secretKeyStart+`(?:authentication-key|message-digest-key|auth-key)[ \t]+[0-9]+[ \t]+(?:md5|sha1|sha256|sha512|hmac-sha\S*)[ \t]+(?:[0-9][ \t]+)?`+secretValue, "-key"),
	// Any type number on a configuration line (username bob secret 0 <x>, enable secret 5 <hash>, pre-shared-key ... key 6 <x>).
	{needs: needTyped, re: regexp.MustCompile(cfgLine + `(?:(?:username|enable|line|ntp|tacacs-server|radius-server|crypto|pre-shared-key|ip|ipv6|neighbor|set|server|ikev1|ikev2|ppp|aaa|standby|vrrp|area)[ \t](?:[^\n]*?[ \t])?)?` + typeKeyword + `[ \t]+[0-9][ \t]+` + typeAlgo + secretValue),
		// `ntp server <ip> key 1 prefer`: 1 is the id of an authentication-key, not a type, and no secret follows it
		leaveWhole: regexp.MustCompile(`(?i)^[ \t]*ntp[ \t]+(?:server|peer)[ \t]`)},
	// Cleartext on a few configuration lines whose command says what follows (enable password <x>, username a [privilege 15] password <x>,
	// neighbor <ip> password <x>, ip ospf authentication-key <x>).
	secretRE(cfgLine+`(?:enable[ \t]+(?:password|secret)(?:[ \t]+level[ \t]+[0-9]+)?|username[ \t]+\S+(?:[ \t]+privilege[ \t]+[0-9]+)?[ \t]+(?:password|secret)|neighbor[ \t]+\S+[ \t]+password|ip[ \t]+ospf[ \t]+authentication-key)[ \t]+(?:[0-9][ \t]+)?`+secretValue, "enable", "username", "neighbor", "ospf"),
	// Crypt hashes: $1$ (md5), $5$ $6$ (sha), $7$ (scrypt), $8$ $9$ (Cisco), $2a$ $2b$ $2x$ $2y$ (bcrypt), $y$ $gy$ (yescrypt), $apr1$
	// (Apache), $md5$ $sha1$ (Solaris, NetBSD), $sha256$ $sha512$ (ASA pbkdf2), $argon2.., $scrypt$, $pbkdf2...
	secretRE(`(\$(?:[15-9]|2[abxy]|y|gy|apr1|md5(?:,rounds=[0-9]+)?|sha1|sha256|sha512|argon2(?:id|i|d)|scrypt|pbkdf2[a-z0-9-]*)\$[A-Za-z0-9./$+=,\-]{4,})`, "$"),
	// ASA hashes named by a word after them (enable password <x> encrypted, passwd <x> encrypted, password <x> pbkdf2|nt-encrypted): the
	// value has a digit or sign, or is 12 characters or more, so "password is encrypted" is prose.
	secretRE(secretKeyStart+`(?:password|passwd|secret)[ \t]+([a-z0-9./+=$]{12,}|[a-z0-9./+=$]*[0-9./+=$][a-z0-9./+=$]*)[ \t]+(?:encrypted|pbkdf2|nt-encrypted)\b`, "encrypted", "pbkdf2"),
	// SNMP communities: snmp-server community <x>, snmp community <x>, rocommunity <x>, read-community <x>, community=<x>, a Juniper
	// block (community <x> {), an ASA host (snmp-server host ... community <x>); MikroTik writes the name of the community, name=<x>, on the
	// same line (at most 80 bytes later). A Juniper policy-options community block (a BGP name) is masked too: harmless.
	secretRE(secretKeyStart+`(?:snmp(?:-server)?[ \t]+|(?:ro|rw|read|write|trap|snmp)[-_]?)community(?:[ \t]*[=:][ \t]*|[ \t]+)`+secretValue, needCommun...),
	secretRE(secretKeyStart+`community[ \t]*=[ \t]*`+secretValue, needCommun...),
	secretRE(secretKeyStart+`community[^\n]{0,80}?[ \t]name=`+secretValue, needCommun...),
	secretRE(secretKeyStart+`community[ \t]+("[^"\n]*"|[^\s{]+)[ \t]*\{`, needCommun...),
	secretRE(secretKeyStart+`snmp-server[ \t]+host[ \t][^\n]*?[ \t]community[ \t]+(?:[0-9][ \t]+)?`+secretValue, needCommun...),
	// set community <x> (FortiGate, Juniper set lines), but not a BGP community of a route-map (65000:100, no-export, additive).
	{
		needs: needCommun,
		re:    regexp.MustCompile(secretKeyStart + `set[ \t]+community(?:[ \t]*[=:][ \t]*|[ \t]+)` + secretValue),
		leave: regexp.MustCompile(`(?i)^(?:[0-9]+(?::[0-9]+)*|no-export|no-export-subconfed|no-advertise|local-as|internet|none|additive|no-peer|gshut|graceful-shutdown|blackhole|accept-own|llgr-stale|no-llgr|delete)$`),
	},
	// SNMPv3 users: snmp-server user ... auth md5|sha <key> [priv [aes 128] <key>].
	secretRE(secretKeyStart+`snmp-server[ \t]+user[ \t][^\n]*?[ \t]auth[ \t]+(?:md5|sha[0-9-]*)[ \t]+`+secretValue+`(?:[ \t]+priv[ \t]+(?:(?:3des|des|aes(?:-?[0-9]+)?)(?:[ \t]+[0-9]+)?[ \t]+)?`+secretValue+`)?`, "snmp-server"),
	// TACACS+ and RADIUS server keys: tacacs-server [host <ip> ...] key [7] <x>.
	secretRE(secretKeyStart+`(?:tacacs|radius)-server[ \t]+(?:host[ \t][^\n]*?[ \t])?key[ \t]+(?:[0-9][ \t]+)?`+secretValue, "-server"),
	// Key strings with the words a vendor puts before the value (ENC, ascii-text, hex, a type number): psksecret ENC <x>, key-string 7
	// <x>, isakmp key <x>. Pre-shared keys need = or : (wpa-psk: <x>) or a configuration line (wpa-psk ascii <x>, ikev1 pre-shared-key <x>,
	// pre-shared-key address <ip> key <x>).
	secretRE(secretKeyStart+`(?:psk-?secret|key-string|isakmp[ \t]+key)(?:[ \t]*[=:][ \t]*|[ \t]+)(?:(?:enc|ascii-text|ascii|hex|text|[0-9])[ \t]+)*`+secretValue, "psk", "key-string", "isakmp"),
	secretRE(secretKeyStart+`[a-z0-9_-]*(?:pre[-_]?shared[-_]?key|psk)[ \t]*:[ \t]*(?:(?:enc|ascii-text|ascii|hex|text|[0-9])[ \t]+)*`+secretValue, "psk", "shared"),
	secretRE(cfgLine+`(?:(?:set|ikev1|ikev2|ikev2[ \t]+(?:local|remote)-authentication)[ \t]+)?(?:pre-?shared-key|psk|wpa-psk|wpa2-psk)[ \t]+(?:(?:address|hostname|remote|local)[ \t]+\S+[ \t]+key[ \t]+)?(?:(?:ENC|enc|ascii-text|ascii|hex|text|[0-9])[ \t]+)*`+secretValue, "psk", "shared"),
	// key=value: password=<x>, authentication-password=<x>, wpa_passphrase=<x>, wpa_psk=<x>, client_secret=<x>, PrivateKey = <x>
	// (WireGuard), PresharedKey = <x>, private-key="<x>" (MikroTik).
	secretRE(secretKeyStart+`[a-z0-9_-]*(?:password|passwd|passphrase|secret|psk|pre[-_]?shared[-_]?key|private[-_]?key)[ \t]*=[ \t]*`+secretValue, needNamed...),
	// JSON: "password": "<x>", "wifi_passphrase": "<x>", "community": "<x>".
	secretRE(`(?i)"[a-z0-9_-]*(?:password|passwd|passphrase|secret|psk|pre[-_]?shared[-_]?key|private[-_]?key|community)"[ \t]*:[ \t]*`+secretValue, needJSON...),
	// set <...->password <x> (FortiGate, Juniper set lines), with or without ENC.
	secretRE(cfgLine+`set[ \t]+(?:[a-z0-9]+-)*(?:password|passwd|passphrase|secret|psksecret|private-key|pre-shared-key)[ \t]+(?:ENC[ \t]+)?`+secretValue, needNamed...),
	// FortiGate: an encrypted secret is ENC followed by base64 (set password ENC SH2..., set psksecret ENC ...).
	secretRE(`(?:^|[^A-Za-z0-9_])ENC[ \t]+([A-Za-z0-9+/=]{16,})`, "enc"),
	// IOS SNMP trap host: snmp-server host <host> [vrf V] [traps|informs] version 1|2c <community> [udp-port 162]; with traps|informs and
	// no version; and bare, snmp-server host <host> [vrf V] <community>. The word that can sit where the community does (version, traps,
	// an interface or an address of the ASA form) is left alone only in the slots where a keyword can sit, never after version 1|2c.
	secretRE(cfgLine+`snmp-server[ \t]+host[ \t]+\S+[ \t]+(?:vrf[ \t]+\S+[ \t]+)?(?:(?:traps|informs)[ \t]+)?version[ \t]+(?:1|2c)[ \t]+`+secretValue, "snmp-server"),
	{
		needs: []string{"snmp-server"},
		re:    regexp.MustCompile(cfgLine + `snmp-server[ \t]+host[ \t]+\S+[ \t]+(?:vrf[ \t]+\S+[ \t]+)?(?:traps|informs)[ \t]+` + secretValue),
		leave: regexp.MustCompile(`(?i)^(?:version|community|udp-port|vrf|traps|informs)$`),
	},
	{
		needs: []string{"snmp-server"},
		re:    regexp.MustCompile(cfgLine + `snmp-server[ \t]+host[ \t]+\S+[ \t]+(?:vrf[ \t]+\S+[ \t]+)?` + secretValue),
		leave: regexp.MustCompile(`(?i)^(?:version|community|udp-port|vrf|traps|informs|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-f]*:[0-9a-f:.]*)$`),
	},
	// YAML keys: password: <x>, Password: <x>, db_password: <x>, - secret: <x>, api_pass: <x>, community: <x>, password: &anchor <x>.
	// The password words are matched in any case (a ticket or a form says `Password: x`; prose that starts with them and a colon costs one
	// word), pass and community only in lower case; a block scalar (`|`, `>`; see yamlScalar), null, a flag and a ${placeholder} are
	// not values.
	{
		needs: append([]string{"community", "pass"}, needNamed...),
		re:    regexp.MustCompile(`(?m:^)[ \t]*(?:-[ \t]+)?(?:(?i:[a-z0-9_-]*(?:password|passwd|passphrase|secret|psk|private[-_]?key)[a-z0-9_-]*|(?:[a-z0-9_-]*[_-])?pass)|(?:[a-z0-9_-]*[_-])?community)[ \t]*:[ \t]+(?:(?:&|!!?)\S+[ \t]+)*` + secretValue),
		leave: regexp.MustCompile(`(?i)^(?:null|~|true|false|yes|no|none|required|[|>][-+0-9]*|\[\]|\{\}|""|''|!vault|\$\{.*)$`),
	},
	// YAML flow mapping ({user: a, password: x}) and the environment form (DB_PASS=x, SMTP_PASS=x): the value ends at a comma or a bracket.
	{
		needs: append([]string{"community", "pass"}, needNamed...),
		re:    regexp.MustCompile(`[{,][ \t]*` + yamlKey + `[ \t]*:[ \t]+(?:(?:&|!!?)\S+[ \t]+)*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\s,}\]]+)`),
		leave: regexp.MustCompile(`(?i)^(?:null|~|true|false|yes|no|none|required|\$\{.*)$`),
	},
	secretRE(secretKeyStart+`(?:[a-z0-9_-]*[_-])?pass[ \t]*=[ \t]*`+secretValue, "pass"),
	// PuTTY key file (.ppk): the lines of the Private-Lines section (indented or with trailing spaces too), up to the Private-MAC line.
	secretRE(`(?m:^)[ \t]*Private-Lines:[ \t]*[0-9]+[ \t]*\r?\n((?:[ \t]*[A-Za-z0-9+/=]+[ \t]*\r?\n)*[ \t]*[A-Za-z0-9+/=]+)[ \t]*(?:\r?\n|\z)`, "private-lines"),
	// A private key block, whole; without an end line (the text was cut) to the end of the text. The first group is the match itself.
	secretRE(`(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*)`, "private key"),
}

// findDeviceSecrets finds the values of device secrets in norm (the normalised text): every capture group of every pattern, in order,
// overlapping ones merged (maskSpans wants them in order and writes one mask per span).
func findDeviceSecrets(norm string) []span {
	out, _ := scanDeviceSecrets(context.Background(), norm) // a background context never ends
	return out
}

// scanDeviceSecrets is findDeviceSecrets that looks at the context between the patterns: one pattern on the biggest text is linear
// and short, but the deadline of the hook holds in the whole run.
func scanDeviceSecrets(ctx context.Context, norm string) ([]span, error) {
	var out []span
	lower := strings.ReplaceAll(strings.ToLower(norm), "ſ", "s") // (?i) folds U+017F to s; ToLower does not
	for _, p := range deviceSecretPatterns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(p.needs, func(w string) bool { return strings.Contains(lower, w) }) {
			continue
		}
		for _, m := range p.re.FindAllStringSubmatchIndex(norm, -1) {
			if p.leaveWhole != nil && p.leaveWhole.MatchString(norm[m[0]:m[1]]) {
				continue
			}
			for g := 2; g+1 < len(m); g += 2 {
				if a, b := m[g], m[g+1]; a >= 0 && b > a && (p.leave == nil || !p.leave.MatchString(norm[a:b])) {
					out = append(out, span{a, b})
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, b := range secretBlocks {
		if !slices.ContainsFunc(b.needs, func(w string) bool { return strings.Contains(lower, w) }) {
			continue
		}
		out = append(out, b.spans(norm)...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	merged := out[:0]
	for _, sp := range out {
		if n := len(merged); n > 0 && sp.start <= merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, sp.end)
			continue
		}
		merged = append(merged, sp)
	}
	return merged, nil
}

// secretBlock is a secret that sits in an indented block under a header line: the lines after the header that are blank or indented
// deeper than it (the next line at the header's indent, such as `end`, closes it). No line count stops it: every line is read by one header
// at most, so the work is linear and nothing after a cap would reach the provider. Each line is matched
// with line, whose first group is the value. needs are words of the lower-cased text, any one of which must be there.
type secretBlock struct {
	needs  []string
	header *regexp.Regexp // group 1: the indent of the header (with a list dash, for YAML)
	line   *regexp.Regexp
}

var secretBlocks = []secretBlock{
	// Cleartext password in a console or terminal line block (line vty 0 4 / ` password x` / ` login`): every password line of the block.
	{[]string{"password"}, regexp.MustCompile(`(?m:^)([ \t]*)line[ \t]+(?:con|console|aux|vty|tty|[0-9]+)\b[^\n]*\n`), regexp.MustCompile(`^[ \t]*password[ \t]+(?:[0-9][ \t]+)?` + secretValue)},
	// FortiGate: `set name "<community>"` in `config system snmp community`: the community is a name, with no keyword of its own.
	{[]string{"community"}, regexp.MustCompile(`(?m:^)([ \t]*)config[ \t]+system[ \t]+snmp[ \t]+community[ \t]*\r?\n`), regexp.MustCompile(`^[ \t]*set[ \t]+name[ \t]+` + secretValue)},
	// YAML block scalar of a secret key (`password: |`): the lines under it are the value.
	{[]string{"pass", "secret", "psk", "private", "community"}, regexp.MustCompile(`(?m:^)([ \t]*(?:-[ \t]+)?)` + yamlKey + `[ \t]*:[ \t]*(?:(?:&|!!?)\S+[ \t]+)*[|>][-+0-9]*[ \t]*(?:#[^\n]*)?\r?\n`), regexp.MustCompile(`^[ \t]*(\S(?:[^\r]*\S)?)`)},
}

func (b secretBlock) spans(norm string) []span {
	var out []span
	done := 0 // a header inside a block already read is read by no one again: every line is visited once (linear)
	for _, h := range b.header.FindAllStringSubmatchIndex(norm, -1) {
		if h[0] < done {
			continue
		}
		indent := h[3] - h[2]
		pos := h[1]
		for pos < len(norm) {
			end := len(norm)
			if i := strings.IndexByte(norm[pos:], '\n'); i >= 0 {
				end = pos + i + 1
			}
			line := norm[pos:end]
			if strings.TrimSpace(line) != "" {
				if len(line)-len(strings.TrimLeft(line, " \t")) <= indent {
					break
				}
				if m := b.line.FindStringSubmatchIndex(strings.TrimRight(line, "\n")); m != nil && m[3] > m[2] {
					out = append(out, span{pos + m[2], pos + m[3]})
				}
			}
			pos = end
		}
		done = pos
	}
	return out
}
