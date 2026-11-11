package signature

import (
	"regexp"
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
	if strings.IndexByte(text, '@') >= 0 { // rare: a regular expression is fine
		text = emailRE.ReplaceAllString(text, "<email>")
	}
	text = maskIdentity(maskPamName(text))
	text = maskQuotes(text)
	var out []string
	size, maskNext := 0, false
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || unicode.IsControl(r) }) {
		if size >= MaxSignatureBytes {
			break
		}
		low := lowerWord(w)
		var m string
		switch {
		case maskNext && skipWords[low]: // "login of bob", "for invalid user x": the name comes later
			m = w
		case maskNext && sentenceWords[low]: // "SSL user failed to logged in": no name here
			m, maskNext = w, false
		case maskNext && plainName(w):
			m, maskNext = "<name>", false
		default:
			m, maskNext = maskWord(w), nameKeywords[low]
		}
		out = append(out, m)
		size += len(m) + 1
	}
	res := strings.TrimSpace(cut(strings.Join(out, " "), MaxSignatureBytes))
	if res == "" {
		return "(empty)"
	}
	return res
}

var (
	// emailRE finds an e-mail address.
	emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}`)
	// identityKeys are the keys whose value names somebody or something: whatever the shape of the value and of the separator, it is
	// never part of a signature, enumeration or not.
	identityKeys = set("user", "username", "usr", "acct", "account", "login", "logname", "uname", "name", "uid", "host", "hostname", "rhost", "src", "dst", "query", "domain", "url", "uri", "email", "mail")
	// nameKeywords are the words after which a name comes. skipWords can stand between the keyword and the name; sentenceWords end
	// the search ("account locked after 5 failures" has no name).
	nameKeywords  = set("user", "username", "login", "account", "acct", "khoản", "dùng", "for")
	skipWords     = set("of", "for", "as", "by", "invalid", "illegal", "user", "username", "account", "name", "the", "a", "an")
	sentenceWords = set("failed", "failure", "successful", "successfully", "success", "ok", "denied", "from", "via", "at", "on", "in", "to", "with", "is", "was", "has", "not", "error", "locked", "logged", "rejected", "accepted", "closed", "opened", "started", "stopped")
	tlds          = set("com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co", "uk", "de", "fr", "ru", "cn", "jp", "vn", "us", "ca", "au", "in", "br", "xyz", "top", "cc", "me", "tv", "app", "dev", "ai", "tk", "ml", "ga", "cf", "gq", "online", "site", "club", "shop", "cloud")
	maskTokens    = set("<v>", "<s>", "<ip>", "<n>", "<hex>", "<tok>", "<path>", "<dom>", "<url>", "<name>", "<email>")
)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// maskIdentity replaces the value of every identity key by <v>: key=value, key:value, key: value, key="value", key=<value>,
// 'key'='value' and the JSON form "key":"value". One pass, no regular expression (this runs on every line a device sends).
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
		k := i
		if s[k-1] == '"' { // "key":"value"
			k--
		}
		start := k
		for start > 0 && (s[start-1] >= 'a' && s[start-1] <= 'z' || s[start-1] >= 'A' && s[start-1] <= 'Z') {
			start--
		}
		if k-start < 3 || k-start > 8 || start > 0 && (isAtomByte(s[start-1]) && s[start-1] != ':' && s[start-1] != '.' && s[start-1] != '-') {
			continue
		}
		if !identityKeys[strings.ToLower(s[start:k])] {
			continue
		}
		v := i + 1
		if v < len(s) && s[v] == ' ' {
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

// plainName says whether w can be the name of an account: it starts with a letter and has only letters, digits and . _ - (at most 64).
func plainName(w string) bool {
	if w == "" || len(w) > 64 || (w[0] < 'A' || w[0] > 'Z' && w[0] < 'a' || w[0] > 'z') {
		return false
	}
	for i := 0; i < len(w); i++ {
		if !isAtomByte(w[i]) || w[i] == ':' {
			return false
		}
	}
	return true
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
			if in := s[i+1 : end]; enumLike(in) {
				b.WriteString(in)
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

// maskWord masks one word (no space in it).
func maskWord(w string) string {
	if len(w) > 1 && w[0] == '/' {
		return "<path>"
	}
	if strings.Contains(w, "://") {
		return "<url>"
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
