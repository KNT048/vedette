package ai

import (
	"regexp"
	"sort"
)

// Device secrets (D-220, INV-12). Text that comes from a device (a configuration, a log line, the output of a read tool of a
// connection) can carry passwords, hashes, SNMP communities and keys. The block-pii hook masks the value and keeps the keyword,
// so the AI still sees that a password is set, not what it is.
//
// Every pattern is RE2 (linear in the text, no backtracking), runs on the normalised text like the other finders, and has a
// capture group that is the value to mask. A value is a quoted string without a line break, or the run of characters up to the next
// space. Patterns never cross a line, except the private-key block, which is masked whole (or to the end of the text when it has no
// end line).
// ponytail: only secrets that carry a marker (a keyword, a type number, a hash prefix, ENC); a cleartext `enable password x` or
// `username a password b` has none a pattern can tell from prose, and a FortiGate `set name "x"` inside an SNMP community block is
// not recognised; upgrade path: a config-aware parser per vendor, if a customer needs it.
const secretValue = `("[^"\n]*"|'[^'\n]*'|\S+)`

// secretKeyStart: the keyword begins at the start of a line or after a character that cannot be part of a word.
const secretKeyStart = `(?i)(?:^|[^a-z0-9_])`

var deviceSecretPatterns = []*regexp.Regexp{
	// Cisco type 0-9 (password 7 <hex>, secret 5 $1$..., secret 8 $8$..., secret 9 $9$..., key 7 ..., md5 7 ..., key-string 7 ...).
	regexp.MustCompile(secretKeyStart + `(?:password|secret|passphrase|key-string|key|md5|authentication-key|auth-key)[ \t]+[0-9][ \t]+(?:md5[ \t]+[0-9][ \t]+)?` + secretValue),
	// Crypt hashes: $1$ (md5), $5$ and $6$ (sha), $8$ and $9$ (Cisco), $2a$ $2b$ $2x$ $2y$ (bcrypt), $argon2.., $scrypt$, $pbkdf2...
	regexp.MustCompile(`(\$(?:[1568-9]|2[abxy]|argon2(?:id|i|d)|scrypt|pbkdf2[a-z0-9-]*)\$[A-Za-z0-9./$+=,\-]{4,})`),
	// SNMP communities: snmp-server community <x>, snmp community <x>, set community <x> (FortiGate), rocommunity <x>,
	// read-community <x>, community=<x>; MikroTik writes the name of the community, name=<x>, on the same line (at most 80 bytes later).
	regexp.MustCompile(secretKeyStart + `(?:(?:snmp(?:-server)?|set)[ \t]+|(?:ro|rw|read|write|trap|snmp)[-_]?)community(?:[ \t]*[=:][ \t]*|[ \t]+)` + secretValue),
	regexp.MustCompile(secretKeyStart + `community[ \t]*[=:][ \t]*` + secretValue),
	regexp.MustCompile(secretKeyStart + `community[^\n]{0,80}?[ \t]name=` + secretValue),
	// Pre-shared keys and key strings, with the words a vendor puts before the value (ENC, ascii-text, hex, a type number):
	// pre-shared-key, wpa-psk, psksecret ENC <x>, key-string 7 <x>, isakmp key <x>.
	regexp.MustCompile(secretKeyStart + `(?:pre-?shared-key|psk-?secret|psk|key-string|isakmp[ \t]+key)(?:[ \t]*[=:][ \t]*|[ \t]+)(?:(?:enc|ascii-text|ascii|hex|text|[0-9])[ \t]+)*` + secretValue),
	// MikroTik and similar: password=<x>, authentication-password=<x>, secret=<x>, passphrase=<x>.
	regexp.MustCompile(secretKeyStart + `(?:[a-z]+-)*(?:password|passwd|passphrase|secret)=` + secretValue),
	// FortiGate: an encrypted secret is ENC followed by base64 (set password ENC SH2..., set psksecret ENC ...).
	regexp.MustCompile(`(?:^|[^A-Za-z0-9_])ENC[ \t]+([A-Za-z0-9+/=]{16,})`),
	// A private key block, whole; without an end line (the text was cut) to the end of the text. The first group is the match itself.
	regexp.MustCompile(`(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*)`),
}

// findDeviceSecrets finds the values of device secrets in norm (the normalised text).
func findDeviceSecrets(norm string) []span {
	var out []span
	for _, re := range deviceSecretPatterns {
		out = append(out, findAll(re, norm, 1)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start }) // maskSpans wants them in order
	return out
}
