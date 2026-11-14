package ops

// The rules file of zap.baseline (D-525, plan tool-tuning §3 Z1): zap-baseline.py -c reads it from the work folder. The host writes
// this constant there before each run (0600, owned by the image's zap user); it is compiled into vedette-host and never taken from
// core, a request or the network, and the run's argv names only this file (isZapRunArgv).
//
// Format (zap-baseline.py load_config at the 2.17.0 commit 528bdf4c, docker/zap_common.py; https://www.zaproxy.org/docs/docker/baseline-scan/):
// one rule per line, "<plugin id>\t<IGNORE|INFO|WARN|FAIL>\t(<name>)", tab separated, lines starting with # skipped; a rule not
// listed is WARN. A line with another level makes zap-baseline.py stop with exit 3, so TestZapConfIsZapBaselineFormat checks each.
//
// What -c changes: the summary zap-baseline.py prints and its exit code (1 = a FAIL rule matched, 2 = a WARN rule matched), not the
// rules ZAP runs nor the JSON report (-J writes ZAP's whole alert list). Exposure decides what each level means on the page.
//
// The CONTENTS (which rule gets which level) are AI-Mlee's product call (the exposure side owns how web alerts are shown); the host
// side (AI-Trưởng) owns the file, its mode and the argv. Change the list here, in its own PR, with a line in D-525.
const (
	zapConfName = "vedette-baseline.conf"
	zapConf     = "# Vedette's ZAP baseline rule levels (D-525). A rule not listed is WARN.\n" +
		// Noise for a small business owner, or false-positive prone without context.
		"10096\tIGNORE\t(Timestamp Disclosure)\n" +
		"10027\tIGNORE\t(Information Disclosure - Suspicious Comments)\n" +
		"10109\tIGNORE\t(Modern Web Application)\n" +
		"10049\tIGNORE\t(Content Cacheability)\n" +
		"10015\tIGNORE\t(Re-examine Cache-control Directives)\n" +
		"10111\tIGNORE\t(Authentication Request Identified)\n" +
		"10112\tIGNORE\t(Session Management Response Identified)\n" +
		"10110\tIGNORE\t(Dangerous JS Functions)\n" +
		"90004\tIGNORE\t(Insufficient Site Isolation Against Spectre Vulnerability)\n" +
		"10063\tIGNORE\t(Permissions Policy Header Not Set)\n" +
		// Hardening.
		"10020\tWARN\t(Missing Anti-clickjacking Header)\n" +
		"10021\tWARN\t(X-Content-Type-Options Header Missing)\n" +
		"10035\tWARN\t(Strict-Transport-Security Header)\n" +
		"10038\tWARN\t(Content Security Policy (CSP) Header Not Set)\n" +
		"10055\tWARN\t(CSP)\n" +
		"10010\tWARN\t(Cookie No HttpOnly Flag)\n" +
		"10011\tWARN\t(Cookie Without Secure Flag)\n" +
		"10054\tWARN\t(Cookie without SameSite Attribute)\n" +
		"10098\tWARN\t(Cross-Domain Misconfiguration)\n" +
		"10202\tWARN\t(Absence of Anti-CSRF Tokens)\n" +
		"2\tWARN\t(Private IP Disclosure)\n" +
		// Fix this.
		"10003\tFAIL\t(Vulnerable JS Library)\n" +
		"10036\tFAIL\t(Server Leaks Version Information via \"Server\" HTTP Response Header Field)\n" +
		"10037\tFAIL\t(Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s))\n" +
		"90022\tFAIL\t(Application Error Disclosure)\n" +
		"10023\tFAIL\t(Information Disclosure - Debug Error Messages)\n" +
		"10062\tFAIL\t(PII Disclosure)\n" +
		"10040\tFAIL\t(Secure Pages Include Mixed Content)\n" +
		"10105\tFAIL\t(Weak Authentication Method)\n"
)

// zapConfFlag is zap-baseline.py's rules-file option. It is an argv word of the fixed run, not a shell's -c (a reviewed exception of
// the host contract's FORBID-1 test, shellLiteralExceptions).
const zapConfFlag = "-c"
