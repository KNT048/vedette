package signature

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Mine turns a log message into its template: the words that make a kind of line stay, the values that change from one line
// to the next are masked, so that a device cannot make one signature per value. Masked: IPv4 addresses (with their port) -> <ip>,
// hexadecimal values, MAC and IPv6 addresses -> <hex>, digit runs -> <n>, a long identifier or random-looking token -> <tok>, a
// host or domain name -> <dom>, an e-mail address -> <email>, a URL -> <url>, a path (a word that starts with "/") -> <path>, a
// quoted string -> <s>, the value of a key that names somebody or something (user, account, login, host, query, url, email ...,
// as key=value, key:value or "key":"value") -> <v>, any other value after "=" -> <v> unless it is a short plain word (an
// enumeration such as action=deny) or an address or number, and the name that follows "user", "login", "account", "for" or the
// Vietnamese "tài khoản" and "người dùng" -> <name> ("Invalid user oracle" and "Invalid user postgres" are one signature; a list
// of user names is not a list of signatures). The rule is fixed and has no state, so the same line has the same signature on any
// box, in any order, after a restart (Drain-style template mining without the learned tree; the alternative, masking the words
// that are rare, needs counts and would give one line different signatures on different boxes). Mine is total: any input gives a
// non-empty, valid UTF-8 text of at most MaxSignatureBytes bytes, with no control character.
func Mine(text string) string {
	text = strings.ToValidUTF8(clip(text, maxScan), "?")
	if strings.IndexByte(text, '@') >= 0 { // rare
		text = maskEmails(text)
	}
	text = maskIdentity(maskBeforeParen(maskPamName(maskBracketBeforeLogin(text))))
	text = maskQuotes(text)
	var out []string
	size, maskNext, afterName := 0, false, false
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || unicode.IsControl(r) }) {
		if size >= MaxSignatureBytes {
			break
		}
		pre := "" // "message=User bob failed": the key of a kept sentence is apart from its first word
		if i := strings.IndexByte(w, '='); i > 0 && i < len(w)-1 && keepsQuote(w[:i+1]) {
			pre, w = w[:i+1], w[i+1:]
		}
		low := lowerWord(w)
		var m string
		switch {
		case maskNext && skipWords[low]: // "login of bob", "for invalid user x": the name comes later
			m = w
		case maskNext && sentenceWords[low]: // "SSL user failed to logged in": no name here
			m, maskNext = w, false
		case maskNext && nameToken(w):
			m, maskNext = "<name>", false
			afterName = true
			out = append(out, pre+m)
			size += len(pre) + len(m) + 1
			continue
		case afterName && (w == "->" || w == "=>"): // "user [bob] -> [bob]": the second name is the first again
			m, maskNext = w, true
		default:
			m, maskNext = maskWord(w), nameKeywords[low]
		}
		afterName = false
		out = append(out, pre+m)
		size += len(pre) + len(m) + 1
	}
	maskWordPatterns(out)
	res := strings.TrimSpace(cut(strings.Join(out, " "), MaxSignatureBytes))
	if res == "" {
		return "(empty)"
	}
	return res
}

var (
	// identityKeys are the keys whose value names somebody or something: whatever the shape of the value and of the separator, it is
	// never part of a signature, enumeration or not.
	identityKeys = set("user", "username", "usr", "acct", "account", "login", "logname", "uname", "name", "uid", "host", "hostname", "rhost", "src", "dst", "query", "domain", "url", "uri", "email", "mail", "set_id", "userid", "user_id", "suser", "duser", "shost", "dhost")
	// identitySuffixes: a key that ends with one of these (client_user, targetUser, sasl_username, user_name, TargetUserName) names somebody too.
	identitySuffixes = []string{"user", "username", "name", "host", "login", "account"}
	// nameKeywords are the words after which a name comes. skipWords can stand between the keyword and the name; sentenceWords end
	// the search ("account locked after 5 failures" has no name).
	nameKeywords  = set("user", "username", "login", "account", "acct", "khoản", "dùng", "for", "пользователь", "пользователя", "логин")
	skipWords     = set("of", "for", "as", "by", "invalid", "illegal", "user", "username", "account", "name", "the", "a", "an")
	sentenceWords = set("failed", "failure", "successful", "successfully", "success", "ok", "denied", "from", "via", "at", "on", "in", "to", "with", "is", "was", "has", "not", "error", "locked", "logged", "rejected", "accepted", "closed", "opened", "started", "stopped")
	machineWords  = set("DESKTOP", "LAPTOP", "WIN", "PC", "NB", "WORKSTATION", "SERVER")
	tlds          = set("com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co", "uk", "de", "fr", "ru", "cn", "jp", "vn", "us", "ca", "au", "in", "br", "xyz", "top", "cc", "me", "tv", "app", "dev", "ai", "tk", "ml", "ga", "cf", "gq", "online", "site", "club", "shop", "cloud")
	maskTokens    = set("<v>", "<s>", "<ip>", "<n>", "<hex>", "<tok>", "<path>", "<dom>", "<url>", "<name>", "<email>")
)

// maskWordPatterns masks the name in four layouts where the name has no keyword in front of it but a fixed neighbour: the user
// column of a squid access line (the word before "HIER_..."), the "bob : user NOT in sudoers" and "bob : TTY=..." of sudo, and the
// name after "FAILED SU (to root)". It works on the words of the signature, in place.
func maskWordPatterns(out []string) {
	for i, w := range out {
		switch {
		case strings.HasPrefix(w, "HIER_") && i > 0 && out[i-1] != "-" && !maskTokens[out[i-1]]:
			out[i-1] = "<name>"
		case w == ":" && i > 0 && i+1 < len(out) && (strings.HasPrefix(out[i+1], "TTY=") || out[i+1] == "user" && i+3 < len(out) && out[i+2] == "NOT" && out[i+3] == "in") && !maskTokens[out[i-1]]:
			out[i-1] = "<name>"
		case w == "FAILED" && i+3 < len(out) && out[i+1] == "SU" && strings.HasPrefix(out[i+2], "(to"):
			for j := i + 2; j < min(i+4, len(out)-1); j++ {
				if strings.HasSuffix(out[j], ")") && !maskTokens[out[j+1]] && !nameWord(out[j+1]) {
					out[j+1] = "<name>"
					break
				}
			}
		}
	}
}

// maskEmails replaces every e-mail address (local@domain.tld: [A-Za-z0-9._%+-]+ "@" [A-Za-z0-9.-]+ "." [A-Za-z]{2,24}) by <email>. It
// scans by hand around each "@", in time linear in the line: the regular expression with counted repeats ({1,64}@...{1,255}) cost 3 to
// 6 ms on a hostile 4 KB line, and even the unbounded form costs about 0.3 ms (10 times the rest of Mine). The length limits of an
// address are not enforced: masking too much is harmless, and a name left in the text would be a name in a signature.
func maskEmails(s string) string {
	var b strings.Builder
	last := 0 // what has been written to b
	for at := strings.IndexByte(s, '@'); at >= 0; at = indexFrom(s, '@', at+1) {
		start := at
		for start > last && emailLocalByte(s[start-1]) {
			start--
		}
		end := at + 1
		for end < len(s) && (isAlnum(s[end]) || s[end] == '.' || s[end] == '-') {
			end++
		}
		if start == at {
			continue
		}
		// the domain ends at the last "." of the run that is followed by 2 letters or more (at most 24 are taken), after at least one character
		stop := -1
		for p := end - 1; p > at+1; p-- {
			if s[p] != '.' {
				continue
			}
			k := 0
			for p+1+k < end && k < 24 && isAlpha(s[p+1+k]) {
				k++
			}
			if k >= 2 {
				stop = p + 1 + k
				break
			}
		}
		if stop < 0 {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString("<email>")
		last = stop
		at = stop - 1 // the next search starts after the match
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func emailLocalByte(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isAlnum(c byte) bool { return isAlpha(c) || isDigit(c) }

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// identityKey says whether a key (a word of letters and underscores) names somebody or something: it is one of identityKeys or ends
// with one of identitySuffixes, in any case.
func identityKey(k string) bool {
	k = strings.ToLower(k)
	if identityKeys[k] {
		return true
	}
	for _, suf := range identitySuffixes {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// maskIdentity replaces the value of every identity key by <v>: key=value, key = value, key:value, key: value, key := value,
// key="value", key=<value>, and the JSON form "key":"value". One pass, no regular expression (this runs on every line a device sends).
func maskIdentity(s string) string {
	if strings.IndexByte(s, '=') < 0 && strings.IndexByte(s, ':') < 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 1; i < len(s); i++ {
		if s[i] != '=' && s[i] != ':' {
			continue
		}
		sepEnd := i + 1
		if s[i] == ':' && sepEnd < len(s) && s[sepEnd] == '=' { // :=
			sepEnd++
		} else if s[i] == '=' && s[i-1] == ':' { // the = of := was handled with its colon
			continue
		}
		k := i
		for k > 0 && (s[k-1] == ' ' || s[k-1] == '\t') && i-k < 2 { // key = value
			k--
		}
		if k > 0 && s[k-1] == '"' { // "key":"value"
			k--
		}
		start := k
		for start > 0 && (s[start-1] >= 'a' && s[start-1] <= 'z' || s[start-1] >= 'A' && s[start-1] <= 'Z' || s[start-1] == '_') {
			start--
		}
		if k-start < 3 || k-start > 24 || start > 0 && isDigit(s[start-1]) {
			continue
		}
		if !identityKey(s[start:k]) {
			continue
		}
		v := sepEnd
		for v < len(s) && (s[v] == ' ' || s[v] == '\t') && v-sepEnd < 4 {
			v++
		}
		end := valueEnd(s, v)
		if end <= v {
			continue
		}
		b.WriteString(s[last:v])
		b.WriteString("<v>")
		last, i = end, end-1
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// maskBeforeParen masks the name that stands before "(address)" or "(uid=": "bob (10.5.50.3): login failed" of a hotspot, and
// "session opened for user root(uid=0) by bob(uid=1000)" of PAM.
func maskBeforeParen(s string) string {
	if strings.IndexByte(s, '(') < 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 1; i < len(s); i++ {
		if s[i] != '(' {
			continue
		}
		rest := s[i+1:]
		ok := strings.HasPrefix(rest, "uid=")
		if n := ipv4Prefix(rest); n > 0 && n < len(rest) && rest[n] == ')' {
			ok = true
		}
		if !ok {
			continue
		}
		end := i
		if s[end-1] == ' ' {
			end--
		}
		start := end
		for start > 0 && start > end-64 && nameRune(s, start-1) {
			start--
		}
		for start < end && !utf8.RuneStart(s[start]) {
			start++
		}
		if start == end || start > 0 && s[start-1] != ' ' && s[start-1] != '\t' && s[start-1] != '[' || nameWord(s[start:end]) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString("<name>")
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// nameRune says whether the byte at s[i] can be part of a name: a letter, digit or . _ @ - of any script (bytes of multi-byte characters count).
func nameRune(s string, i int) bool {
	c := s[i]
	return c >= 0x80 || isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c == '@' || c == '-'
}

// nameWord says whether a token is a word of the sentence and not a name: a keyword, a skip word or a sentence word.
func nameWord(w string) bool {
	l := strings.ToLower(w)
	return nameKeywords[l] || skipWords[l] || sentenceWords[l]
}

// maskBracketBeforeLogin masks the [name] of "[bob] FAIL LOGIN" and "[bob] OK LOGIN" (vsftpd).
func maskBracketBeforeLogin(s string) string {
	i := strings.Index(s, "] FAIL LOGIN")
	if j := strings.Index(s, "] OK LOGIN"); i < 0 || j >= 0 && j < i {
		i = j
	}
	if i < 0 {
		return s
	}
	open := strings.LastIndexByte(s[:i], '[')
	if open < 0 || i-open > 66 {
		return s
	}
	return s[:open+1] + "<name>" + s[i:]
}

// nameToken says whether w is, once the brackets, quotes and punctuation around it are taken off, a name: letters of any script, digits
// and . _ @ - (so a name may start with a digit or be written in Cyrillic), at most 64 bytes.
func nameToken(w string) bool {
	w = strings.TrimLeft(w, `[<"'(`)
	w = strings.TrimRight(w, `]>"':,;.)!?`)
	if w == "" || len(w) > 64 {
		return false
	}
	for _, r := range w {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_' && r != '@' && r != '-' {
			return false
		}
	}
	return !nameWord(w)
}

// valueEnd returns where the value that starts at v ends: after its closing quote or bracket, or at the first space or separator.
func valueEnd(s string, v int) int {
	if v >= len(s) {
		return v
	}
	closer := byte(0)
	switch s[v] {
	case '"':
		closer = '"'
	case '\'':
		closer = '\''
	case '<':
		closer = '>'
	}
	if closer != 0 {
		for j := v + 1; j < len(s) && j <= v+256; j++ {
			if s[j] == closer {
				return j + 1
			}
			if closer == '>' && s[j] == ' ' {
				break
			}
		}
		return v // not closed: not a value
	}
	j := v
	for j < len(s) && j-v < 256 && strings.IndexByte(" \t,;&}])\"'<>", s[j]) < 0 {
		j++
	}
	return j
}

// maskPamName replaces the name of "(name,address)", the form of PAM and Dovecot lines, by <name>.
func maskPamName(s string) string {
	i := strings.IndexByte(s, ',')
	if i < 0 || strings.IndexByte(s, '(') < 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for ; i >= 0 && i < len(s); i = indexFrom(s, ',', i+1) {
		start := i
		for start > 0 && start > i-64 && (isAtomByte(s[start-1]) && s[start-1] != ':' || s[start-1] == '@' || s[start-1] == '+') {
			start--
		}
		if start == 0 || s[start-1] != '(' || start == i {
			continue
		}
		if n := ipv4Prefix(s[i+1:]); n > 0 && i+1+n < len(s) && s[i+1+n] == ')' {
			b.WriteString(s[last:start])
			b.WriteString("<name>")
			last = i
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func indexFrom(s string, c byte, from int) int {
	if from >= len(s) {
		return -1
	}
	if i := strings.IndexByte(s[from:], c); i >= 0 {
		return from + i
	}
	return -1
}

// lowerWord is the word in lower case without the punctuation that ends it.
func lowerWord(w string) string {
	return strings.ToLower(strings.TrimRight(w, ":,;."))
}

// enumLike says whether v is a short plain word: letters, '_' and '-' only, at most 16 bytes (deny, accept, forward).
func enumLike(v string) bool {
	if v == "" || len(v) > 16 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < 'A' || c > 'Z' && c < 'a' || c > 'z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// maskQuotes replaces every "quoted string" (closed within 256 bytes) by <s>, or by the bare word when it is an enumeration, and
// every 'single quoted word' (no space in it, at most 64 bytes, opened at the start of a word) by <s>.
func maskQuotes(s string) string {
	if !strings.ContainsAny(s, `"'`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '"':
			end := -1
			for j := i + 1; j < len(s) && j <= i+256; j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '"' {
					end = j
					break
				}
			}
			if end < 0 { // not closed: the quote is just a character
				b.WriteByte(c)
				i++
				continue
			}
			if in := s[i+1 : end]; enumLike(in) || keepsQuote(s[:i]) {
				b.WriteString(in) // an enumeration, or the sentence of a msg: its words stay (the names in it were masked)
			} else {
				b.WriteString("<s>")
			}
			i = end + 1
		case c == '\'' && (i == 0 || strings.IndexByte(" ([=:,", s[i-1]) >= 0):
			end := -1
			for j := i + 1; j < len(s) && j <= i+65; j++ {
				if s[j] == ' ' {
					break
				}
				if s[j] == '\'' && (j+1 == len(s) || !isAtomByte(s[j+1])) {
					end = j
					break
				}
			}
			if end < 0 {
				b.WriteByte(c)
				i++
				continue
			}
			b.WriteString("<s>")
			i = end + 1
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// keepsQuote says whether the quote that follows s opens the value of msg, logdesc or message: a sentence the device wrote, whose words
// belong in the signature.
func keepsQuote(before string) bool {
	for _, k := range []string{"msg=", "logdesc=", "message="} {
		if len(before) >= len(k) && strings.EqualFold(before[len(before)-len(k):], k) {
			return true
		}
	}
	return false
}

// maskWord masks one word (no space in it).
func maskWord(w string) string {
	if len(w) > 1 && w[0] == '/' {
		return "<path>"
	}
	if strings.Contains(w, "://") {
		return "<url>"
	}
	if i := strings.IndexByte(w, '/'); i > 0 && i <= 65 && ipv4Prefix(w[i+1:]) > 0 && ipv4Prefix(w[:i]) != i && !shoutingKeyword(w[:i]) {
		return "<name>/" + maskPlain(w[i+1:]) // openvpn "bob/203.0.113.9:51234" (squid's HIER_DIRECT/ip is a keyword, not a name)
	}
	if i := strings.IndexByte(w, '='); i > 0 {
		key := w[:i]
		ok := true
		for k := 0; k < len(key); k++ {
			if !isAtomByte(key[k]) || key[k] == ':' {
				ok = false
			}
		}
		if ok {
			return maskPlain(key) + "=" + maskValue(w[i+1:])
		}
	}
	return maskPlain(w)
}

// shoutingKeyword says whether a word is a keyword of the device in capitals with an underscore (squid's HIER_DIRECT, TCP_DENIED), not a name.
func shoutingKeyword(w string) bool { return strings.Contains(w, "_") && w == strings.ToUpper(w) }

// maskValue masks what follows "=": a mask that is already there, a short plain word, an address, a number or a hex value stay, everything
// else is <v>. Punctuation that ends the value stays where it is.
func maskValue(v string) string {
	core := strings.TrimRight(v, ",;)]}")
	tail := v[len(core):]
	switch {
	case core == "", maskTokens[core], enumLike(core):
		return v
	}
	switch m := maskPlain(core); m {
	case "<ip>", "<n>", "<hex>", "<dom>":
		return m + tail
	}
	return "<v>" + tail
}

// maskPlain walks a word and masks its atoms; punctuation and non-ASCII text are kept as they are.
func maskPlain(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); {
		c := text[i]
		if isAtomByte(c) {
			j := i
			for j < len(text) && isAtomByte(text[j]) {
				j++
			}
			maskAtom(&b, text[i:j])
			i = j
			continue
		}
		r, n := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && n == 1 || !unicode.IsControl(r) {
			b.WriteString(text[i : i+n])
		}
		i += n
	}
	return b.String()
}

// domainLike says whether h is a host or domain name: labels of letters, digits, '-' and '_' separated by dots, the last one
// letters only; at least two dots, or one dot and a last label that is a common top-level domain (so "config.bak" and "wp-login.php"
// are words, "example.com" and "www.example.org" are names).
func domainLike(h string) bool {
	dots := strings.Count(h, ".")
	if dots == 0 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !isDigit(c) && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' && c != '_' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if c := last[i]; (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return dots >= 2 && len(last) >= 2 || tlds[strings.ToLower(last)]
}

// isAtomByte says whether c can be part of a word or a value: letters, digits and the joiners of addresses and identifiers.
func isAtomByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == ':' || c == '-' || c == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// maskAtom writes one atom with its variable parts masked.
func maskAtom(b *strings.Builder, a string) {
	for a != "" {
		if n := ipv4Prefix(a); n > 0 {
			b.WriteString("<ip>")
			a = a[n:]
			if len(a) > 1 && a[0] == ':' && isDigit(a[1]) { // the port belongs to the address
				k := 1
				for k < len(a) && isDigit(a[k]) {
					k++
				}
				a = a[k:]
			}
			continue
		}
		if hexLike(a) {
			b.WriteString("<hex>")
			return
		}
		if host := a[:strings.IndexByte(a+":", ':')]; domainLike(host) { // a name, with or without a port
			b.WriteString("<dom>")
			a = a[len(host):]
			continue
		}
		if machineName(a) {
			b.WriteString("<host>")
			return
		}
		if randomLike(a) {
			b.WriteString("<tok>")
			return
		}
		for i := 0; i < len(a); {
			if isDigit(a[i]) {
				for i < len(a) && isDigit(a[i]) {
					i++
				}
				b.WriteString("<n>")
				continue
			}
			b.WriteByte(a[i])
			i++
		}
		return
	}
}

// ipv4Prefix returns the length of a dotted quad at the start of a (four numbers of at most three digits, each at most 255,
// not followed by another ".digit"), or 0.
func ipv4Prefix(a string) int {
	i := 0
	for part := 0; part < 4; part++ {
		start, v := i, 0
		for i < len(a) && i-start < 3 && isDigit(a[i]) {
			v = v*10 + int(a[i]-'0')
			i++
		}
		if i == start || v > 255 {
			return 0
		}
		if part < 3 {
			if i >= len(a) || a[i] != '.' {
				return 0
			}
			i++
		}
	}
	if i < len(a) && (isDigit(a[i]) || a[i] == '.' && i+1 < len(a) && isDigit(a[i+1])) {
		return 0
	}
	return i
}

// hexLike says whether the atom is a hexadecimal value, a hash, a MAC or an IPv6 address: 0x followed by hex digits; or only hex
// digits with at least 8 of them and one digit; or hex digits joined by at least two ':' or '-' with at least 6 digits in all and
// one letter (so a time 12:30:45 and a date 2026-11-09 are numbers, not hex).
func hexLike(a string) bool {
	if len(a) > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X') {
		for i := 2; i < len(a); i++ {
			if !isHex(a[i]) {
				return false
			}
		}
		return true
	}
	hex, seps, digits, letters := 0, 0, 0, 0
	for i := 0; i < len(a); i++ {
		switch c := a[i]; {
		case isDigit(c):
			hex++
			digits++
		case isHex(c):
			hex++
			letters++
		case c == ':' || c == '-':
			seps++
		default:
			return false
		}
	}
	if seps == 0 {
		return hex >= 8 && digits > 0
	}
	return seps >= 2 && hex >= 6 && letters > 0
}

// clip returns at most n bytes of s, cut on a character boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return cut(s, n)
}

// cut returns at most n bytes of s without splitting a character.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// randomLike says whether an atom looks like an identifier or a random token and not like a word: 16 bytes or more with letters and
// digits mixed, or 20 bytes or more with an upper-case letter after the first character, or 24 bytes or more with a digit or an
// upper-case letter (session ids, base64, tokens, serial numbers).
func randomLike(a string) bool {
	if len(a) < 16 {
		return false
	}
	digit, letter, upper := false, false, false
	for i := 0; i < len(a); i++ {
		switch c := a[i]; {
		case isDigit(c):
			digit = true
		case c >= 'A' && c <= 'Z':
			letter = true
			upper = upper || i > 0
		case c >= 'a' && c <= 'z':
			letter = true
		}
	}
	return digit && letter || len(a) >= 20 && upper || len(a) >= 24 && (digit || upper)
}

// machineName says whether a is a name that Windows and phones give themselves: upper-case letters, a hyphen and 5 or more upper-case
// letters and digits with a digit among them (DESKTOP-4K8R2QP, LAPTOP-7XJ3L9A).
func machineName(a string) bool {
	i := strings.IndexByte(a, '-')
	if i < 2 || i > 10 || len(a)-i-1 < 5 || len(a)-i-1 > 15 {
		return false
	}
	for k := 0; k < i; k++ {
		if a[k] < 'A' || a[k] > 'Z' {
			return false
		}
	}
	digit := machineWords[a[:i]]
	for k := i + 1; k < len(a); k++ {
		switch c := a[k]; {
		case isDigit(c):
			digit = true
		case c < 'A' || c > 'Z':
			return false
		}
	}
	return digit
}
