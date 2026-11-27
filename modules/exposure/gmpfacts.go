package exposure

import "regexp"

// gmpFact is one NVT whose result, at any level and quality of detection, states a configuration fact a person can act on (not a
// banner guess): it becomes a Low issue under the title, with the fix line. when, when set, narrows it to results whose detection
// text says so (an NVT that logs a note on every host).
type gmpFact struct {
	oid, title, fix string
	when            *regexp.Regexp
}

// gmpFactSeverity is the severity a fact is stored with: Low (below GreenboneLowBelow), whatever CVSS the NVT carries. A fact is
// hardening, and carries no CVE, so it is never matched against the exploited-vulnerability list.
const gmpFactSeverity = 2.0

// gmpFacts is the allowlist. QoD 70 stays the cut for every other result (a version guessed from a banner is a false positive on a
// distribution package that carries backported fixes); these results are read at any QoD because each states what the scanner saw
// on the wire. Every entry needs a title and a fix (TestOpenVASFactsHaveTitleAndFix).
var gmpFacts = []gmpFact{
	{oid: "1.3.6.1.4.1.25623.1.0.10267", // SSH Server type and version: its detection text lists the authentication methods
		title: "SSH accepts password logins from the Internet",
		fix:   "Allow only key logins: set PasswordAuthentication no in sshd_config (and PermitRootLogin prohibit-password), then reload sshd.",
		when:  regexp.MustCompile(`(?i)authentication[^\n]*\bpassword\b`)},
	{oid: "1.3.6.1.4.1.25623.1.0.117839", // D(HE)ater: DHE key exchange offered
		title: "SSH offers Diffie-Hellman (DHE) key exchange",
		fix:   "Remove the diffie-hellman-group* key exchange algorithms from KexAlgorithms in sshd_config and keep curve25519 and sntrup761."},
	{oid: "1.3.6.1.4.1.25623.1.0.117414", // BREACH
		title: "HTTP compression over TLS allows the BREACH attack",
		fix:   "Turn off HTTP compression for pages that carry secrets or tokens, or mask CSRF tokens per response."},
	// HTTP Debugging Methods (TRACE/TRACK) Enabled: raised only when the scanner got the request echoed back. The methods enumeration
	// NVT (1.3.6.1.4.1.25623.1.0.153974) is not a source: it lists the methods a server did not refuse, so a port that redirects every
	// method names TRACE without supporting it.
	{oid: "1.3.6.1.4.1.25623.1.0.11213",
		title: "The web server allows TRACE",
		fix:   "Disable the TRACE method (Apache: TraceEnable off; nginx: return 405 for TRACE; most reverse proxies: block it)."},
	{oid: "1.3.6.1.4.1.25623.1.0.103140", // Self-Signed Certificate
		title: "The TLS certificate is self-signed",
		fix:   "Install a certificate from a public certificate authority (for example Let's Encrypt)."},
	{oid: "1.3.6.1.4.1.25623.1.0.103141", // Subject CN does not match the host name
		title: "The TLS certificate does not match the host name",
		fix:   "Issue a certificate whose subject alternative names include the name clients use to reach this service."},
	{oid: "1.3.6.1.4.1.25623.1.0.117764", // Untrusted Certificate
		title: "The TLS certificate is not trusted by public certificate authorities",
		fix:   "Install a certificate from a public certificate authority, with its full chain."},
}

// gmpFactOf is the allowlist entry a result is, by OID and detection text.
func gmpFactOf(oid, detection string) (gmpFact, bool) {
	for _, f := range gmpFacts {
		if f.oid == oid && (f.when == nil || f.when.MatchString(detection)) {
			return f, true
		}
	}
	return gmpFact{}, false
}

// isFactOID says the OID is on the allowlist (a stored row of it is read at any QoD).
func isFactOID(oid string) bool {
	for _, f := range gmpFacts {
		if f.oid == oid {
			return true
		}
	}
	return false
}
