package ops

import "regexp"

// The log export is a second line of defence (SYS-4): Vedette's own code does not log secrets, but
// a journal also holds what other programs print. Each rule replaces the secret and keeps the
// surrounding text. They run on the raw JSON text of a journal line, and none of them may consume a
// quote or a backslash, so a valid JSON line stays valid JSON after redaction (a fuzz target checks it).
const redactedText = "[redacted]"

type redactRule struct {
	re   *regexp.Regexp
	repl string
}

var redactRules = []redactRule{
	// PEM blocks (a private key printed in one MESSAGE); newlines are "\n" escapes in the JSON text.
	{regexp.MustCompile(`-----BEGIN [A-Z ]{1,40}-----[^"]*?-----END [A-Z ]{1,40}-----`), redactedText},
	// "Authorization: Bearer xyz" and "Authorization: Basic xyz".
	{regexp.MustCompile(`(?i)(authorization\W{1,4}(?:bearer|basic)\s+)[^\s"\\]{4,}`), "${1}" + redactedText},
	// A bare bearer token.
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`), "${1}" + redactedText},
	// Vedette's own token shapes: vdt_osquery_..., the secret path of a blocklist URL.
	{regexp.MustCompile(`vdt_[A-Za-z0-9_-]{6,}`), "vdt_" + redactedText},
	{regexp.MustCompile(`(?i)(/blocklist/)[A-Za-z0-9._~%-]{6,}`), "${1}" + redactedText},
	// Chat tokens and well-known provider prefixes.
	{regexp.MustCompile(`\b(xapp|xoxb|xoxp|xoxa|xoxs)-[A-Za-z0-9-]{6,}`), "${1}-" + redactedText},
	{regexp.MustCompile(`\b(sk|ghp|gho|ghs|ghu)[_-][A-Za-z0-9_-]{16,}`), "${1}_" + redactedText},
	{regexp.MustCompile(`\b(github_pat_|glpat-)[A-Za-z0-9_-]{16,}`), "${1}" + redactedText},
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{12,}`), "${1}" + redactedText},
	// JSON Web Tokens.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*`), redactedText},
	// password=..., passwd=..., token=..., secret=..., api_key=... (also in a URL query or a command line).
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)(=|:\s*)[^\s"&\\;,]{1,}`), "${1}${2}" + redactedText},
}

// RedactJournalLine removes the known secret shapes from one journal line. It is a pure function:
// the same line always gives the same result, and a line without a match comes back unchanged.
func RedactJournalLine(line []byte) []byte {
	for _, r := range redactRules {
		line = r.re.ReplaceAll(line, []byte(r.repl))
	}
	return line
}
