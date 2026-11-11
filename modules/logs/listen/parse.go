package listen

import (
	"strings"
	"time"
)

// Envelope is what the header of a syslog message says. Parsing never fails: a line that is not recognised comes back with
// Format "raw", PRI -1 and the whole line in Msg, so it is kept and counted instead of being dropped (INV-1).
type Envelope struct {
	Format   string // FormatRFC5424, FormatRFC3164 or FormatRaw
	PRI      int    // -1 when the line has no priority
	Facility int    // PRI / 8, -1 when PRI is -1
	Severity int    // PRI % 8, -1 when PRI is -1
	Time     time.Time
	Host     string
	App      string
	ProcID   string
	MsgID    string
	Msg      string
	CEF      *CEF // set when the message carries a CEF or LEEF header
}

// The values of Envelope.Format.
const (
	FormatRFC5424 = "rfc5424"
	FormatRFC3164 = "rfc3164"
	FormatRaw     = "raw"
)

// Field caps (RFC 5424 section 6): longer values are not a header, and a bound keeps the memory of a parsed line small.
const (
	maxHost   = 255
	maxApp    = 48
	maxProcID = 128
	maxMsgID  = 32
	maxCEFVal = 512
)

// Parse reads the envelope of one line and, when the message carries one, its CEF or LEEF header.
func Parse(line string) Envelope {
	e := ParseSyslog(line)
	scan := line
	if len(scan) > 512 {
		scan = scan[:512]
	}
	for _, p := range []string{"CEF:", "LEEF:"} {
		i := strings.Index(scan, p)
		if i < 0 || (i > 0 && scan[i-1] != ' ' && scan[i-1] != '>') {
			continue
		}
		if c, ok := ParseCEF(line[i:]); ok {
			e.CEF = c
			break
		}
	}
	return e
}

// Counted is the name a line is counted under: cef and leef when the message has such a header, else the envelope format.
func (e Envelope) Counted() string {
	if e.CEF != nil {
		return e.CEF.Kind
	}
	return e.Format
}

// ParseSyslog reads RFC 5424 and RFC 3164 (BSD) headers. It is total: every input gives an Envelope.
func ParseSyslog(line string) Envelope {
	raw := Envelope{Format: FormatRaw, PRI: -1, Facility: -1, Severity: -1, Msg: line}
	pri, rest, ok := parsePRI(line)
	if !ok {
		return raw
	}
	if e, ok := parse5424(rest); ok {
		e.setPRI(pri)
		return e
	}
	e := parse3164(rest)
	e.setPRI(pri)
	return e
}

func (e *Envelope) setPRI(p int) {
	e.PRI, e.Facility, e.Severity = p, p/8, p%8
}

// parsePRI reads "<n>" with 1 to 3 digits and a value of at most 191 (facility 23, severity 7).
func parsePRI(s string) (pri int, rest string, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, "", false
	}
	i, n := 1, 0
	for i < len(s) && i <= 3 && s[i] >= '0' && s[i] <= '9' {
		n = n*10 + int(s[i]-'0')
		i++
	}
	if i == 1 || i >= len(s) || s[i] != '>' || n > 191 {
		return 0, "", false
	}
	return n, s[i+1:], true
}

// token cuts the text up to the first space; ok is false when there is none or the token is empty or longer than max.
func token(s string, limit int) (tok, rest string, ok bool) {
	i := strings.IndexByte(s, ' ')
	if i <= 0 || i > limit {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// parse5424 reads VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG] strictly: anything
// out of line is not 5424 and the caller tries the older format.
func parse5424(s string) (Envelope, bool) {
	if len(s) < 2 || s[0] != '1' || s[1] != ' ' {
		return Envelope{}, false
	}
	s = s[2:]
	var ts, host, app, proc, msgid string
	var ok bool
	if ts, s, ok = token(s, 40); !ok {
		return Envelope{}, false
	}
	if host, s, ok = token(s, maxHost); !ok {
		return Envelope{}, false
	}
	if app, s, ok = token(s, maxApp); !ok {
		return Envelope{}, false
	}
	if proc, s, ok = token(s, maxProcID); !ok {
		return Envelope{}, false
	}
	// MSGID is followed by the structured data, which can be the end of the line.
	i := strings.IndexByte(s, ' ')
	if i <= 0 || i > maxMsgID {
		return Envelope{}, false
	}
	msgid, s = s[:i], s[i+1:]
	end, ok := skipSD(s)
	if !ok {
		return Envelope{}, false
	}
	msg := s[end:]
	if msg != "" {
		if msg[0] != ' ' {
			return Envelope{}, false
		}
		msg = strings.TrimPrefix(msg[1:], "\xef\xbb\xbf")
	}
	e := Envelope{Format: FormatRFC5424, Host: nilValue(host), App: nilValue(app), ProcID: nilValue(proc), MsgID: nilValue(msgid), Msg: msg}
	if ts != "-" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return Envelope{}, false
		}
		e.Time = t.UTC()
	}
	return e, true
}

// skipSD returns where the structured data ends: "-", or one or more [ID name="value" ...] elements in which a quote, a
// backslash and a closing bracket inside a value are escaped with a backslash.
func skipSD(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	if s[0] == '-' {
		return 1, true
	}
	i := 0
	for i < len(s) && s[i] == '[' {
		i++
		inQuote := false
		closed := false
		for i < len(s) && !closed {
			c := s[i]
			switch {
			case inQuote && c == '\\':
				i++ // the escaped character is skipped, whatever it is
			case c == '"':
				inQuote = !inQuote
			case c == ']' && !inQuote:
				closed = true
			}
			i++
		}
		if !closed || i > len(s) {
			return 0, false
		}
	}
	return i, i > 0
}

var months = [...]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// parse3164 reads the BSD header "Mmm dd hh:mm:ss HOST TAG[PID]: msg". Every part is optional in practice (many devices send no
// timestamp), so what does not match stays in Msg. The year is not in the line, so Time stays zero (the receive time is the time).
func parse3164(s string) Envelope {
	e := Envelope{Format: FormatRFC3164, Msg: s}
	if !hasBSDStamp(s) {
		return e
	}
	s = s[16:]
	if host, rest, ok := token(s, maxHost); ok {
		e.Host, s = host, rest
	}
	i := 0
	for i < len(s) && i < maxApp && isTagChar(s[i]) {
		i++
	}
	if i > 0 && i < len(s) && (s[i] == ':' || s[i] == '[') {
		e.App = s[:i]
		s = s[i:]
		if s[0] == '[' {
			if j := strings.IndexByte(s, ']'); j > 0 && j <= maxProcID+1 {
				e.ProcID = s[1:j]
				s = s[j+1:]
			}
		}
		s = strings.TrimPrefix(s, ":")
		s = strings.TrimPrefix(s, " ")
	}
	e.Msg = s
	return e
}

func isTagChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '/'
}

// hasBSDStamp says whether s starts with "Mmm dd hh:mm:ss " (the day is space padded to two characters).
func hasBSDStamp(s string) bool {
	if len(s) < 16 || s[3] != ' ' || s[6] != ' ' || s[9] != ':' || s[12] != ':' || s[15] != ' ' {
		return false
	}
	found := false
	for _, m := range months {
		if s[:3] == m {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	digit := func(i int) bool { return s[i] >= '0' && s[i] <= '9' }
	return (s[4] == ' ' || digit(4)) && digit(5) && digit(7) && digit(8) && digit(10) && digit(11) && digit(13) && digit(14)
}

// CEF is the header of an ArcSight CEF or IBM LEEF message. The extension (key=value pairs) is kept whole: reading it is for
// the signature profiles (L3), not for the listener.
type CEF struct {
	Kind       string // "cef" or "leef"
	Version    string
	Vendor     string
	Product    string
	DevVersion string
	SigID      string // CEF Signature ID; LEEF EventID
	Name       string // CEF name; empty for LEEF
	Severity   string // CEF severity; empty for LEEF
	Delimiter  string // LEEF 2.0 delimiter field; empty otherwise
	Ext        string
}

// ParseCEF reads "CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension" and the LEEF forms
// "LEEF:1.0|Vendor|Product|Version|EventID|Extension" and "LEEF:2.0|...|EventID|Delimiter|Extension" at the start of s. A pipe
// and a backslash inside a header field are escaped with a backslash. ok is false when the header is not complete.
func ParseCEF(s string) (*CEF, bool) {
	var c CEF
	var n int // header fields before the extension
	switch {
	case strings.HasPrefix(s, "CEF:"):
		c.Kind, s, n = "cef", s[4:], 7
	case strings.HasPrefix(s, "LEEF:"):
		c.Kind, s, n = "leef", s[5:], 5
	default:
		return nil, false
	}
	fields := make([]string, 0, 8)
	for len(fields) < n {
		f, rest, ok := cefField(s)
		if !ok {
			return nil, false
		}
		fields = append(fields, f)
		s = rest
	}
	if c.Kind == "leef" && fields[0] == "2.0" {
		f, rest, ok := cefField(s)
		if !ok {
			return nil, false
		}
		c.Delimiter, s = f, rest
	}
	c.Version, c.Vendor, c.Product, c.DevVersion, c.SigID = fields[0], fields[1], fields[2], fields[3], fields[4]
	if c.Kind == "cef" {
		c.Name, c.Severity = fields[5], fields[6]
	}
	c.Ext = s
	return &c, true
}

// cefField cuts one header field at the first unescaped pipe and unescapes it; ok is false when there is no pipe.
func cefField(s string) (field, rest string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '\\'):
			if b.Len() < maxCEFVal {
				b.WriteByte(s[i+1])
			}
			i++
		case c == '|':
			return b.String(), s[i+1:], true
		default:
			if b.Len() < maxCEFVal {
				b.WriteByte(c)
			}
		}
	}
	return "", "", false
}
