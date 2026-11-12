package logs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// What goes to a SIEM is a siemRecord, built from an event of another module (untrusted text: a finding title, a trap label, a device
// name can all come from the network) and written in one of three formats. Nothing of the record reaches the wire before siemText
// has cut it and removed every control character, and each format then escapes what its own grammar treats as special.

const (
	maxSiemField = 128 // one value; a datagram stays well under the MTU of a LAN
	maxSiemHost2 = 64  // the box's host name in a syslog header
)

// siemField is one value of a record. CEF names the standard CEF key it maps to ("" = a numbered custom string with a label).
type siemField struct {
	Key string // lower-case ASCII name, also the JSON key and the syslog SD-PARAM name
	CEF string
	Val string
}

// siemRecord is one event to forward: the name (finding.created), the severity (info, low, medium, high, critical), the time, and
// the fields in a fixed order.
type siemRecord struct {
	Name     string
	Severity string
	At       time.Time
	Fields   []siemField
}

func newSiemRecord(name, severity string, at time.Time, f ...siemField) siemRecord {
	out := siemRecord{Name: name, Severity: severity, At: at.UTC().Truncate(time.Millisecond)}
	for _, x := range f {
		if x.Val = siemText(x.Val, maxSiemField); x.Val != "" {
			out.Fields = append(out.Fields, x)
		}
	}
	return out
}

// siemText makes a value of untrusted text safe for every format: valid UTF-8, no control or format character (so no newline, no
// bidi override, no NUL), at most max bytes, and no space at the ends.
func siemText(s string, limit int) string {
	if len(s) > 4*limit {
		s = s[:4*limit]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0, r == 0xad, r == 0x061c, r == 0x180e,
			r >= 0x200b && r <= 0x200f, r >= 0x2028 && r <= 0x202e, r >= 0x2060 && r <= 0x206f, r == 0xfeff, r >= 0xfff9 && r <= 0xfffb:
			b.WriteByte(' ')
		default:
			if b.Len()+utf8.RuneLen(r) > limit {
				return strings.TrimSpace(b.String())
			}
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// syslogSeverity is the RFC 5424 severity of a record; the facility is local0 (16): PRI = 16*8 + severity (critical -> <130>).
func syslogSeverity(sev string) int {
	switch sev {
	case "critical":
		return 2
	case "high":
		return 3
	case "medium":
		return 4
	case "low":
		return 5
	}
	return 6
}

// cefSeverity maps to the 0..10 scale of CEF.
func cefSeverity(sev string) int {
	switch sev {
	case "critical":
		return 10
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	}
	return 1
}

const siemTimeFormat = "2006-01-02T15:04:05.000Z"

// sdEscape escapes a PARAM-VALUE of RFC 5424 section 6.3.3: the double quote, the backslash and the closing bracket.
func sdEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(v)
}

// asciiToken makes a header token of RFC 5424 (printable US-ASCII, no space, at most max), "-" when nothing is left.
func asciiToken(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0x20 && r < 0x7f && b.Len() < limit {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// formatSyslog is RFC 5424: <PRI>1 TIMESTAMP HOSTNAME vedette - MSGID [vedette@32473 k="v" ...] MSG. 32473 is the example enterprise
// number of RFC 5612 (Vedette has none); the structured data carries the fields, the message is the event name and the severity.
func formatSyslog(r siemRecord, host string) []byte {
	var sd strings.Builder
	sd.WriteString("[vedette@32473")
	for _, f := range r.Fields {
		sd.WriteString(" " + f.Key + `="` + sdEscape(f.Val) + `"`)
	}
	sd.WriteString("]")
	return []byte(fmt.Sprintf("<%d>1 %s %s vedette - %s %s %s severity=%s", 16*8+syslogSeverity(r.Severity), r.At.Format(siemTimeFormat), asciiToken(host, maxSiemHost2), asciiToken(r.Name, 32), sd.String(), r.Name, r.Severity))
}

// octetFrame is the framing of syslog over a stream (RFC 6587 octet counting, also what RFC 5425 prescribes for TLS).
func octetFrame(msg []byte) []byte {
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}

func cefHeader(v string) string { return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(v) }

func cefValue(v string) string { return strings.NewReplacer(`\`, `\\`, `=`, `\=`).Replace(v) }

// formatCEF is CEF:0|Vedette|Vedette|1.0|<event>|<title>|<severity 0-10>|<extension>. The extension has rt (receipt time, ms since
// the epoch), the standard keys the fields map to, and up to six custom strings with their labels.
func formatCEF(r siemRecord) []byte {
	var ext []string
	ext = append(ext, "rt="+strconv.FormatInt(r.At.UnixMilli(), 10))
	n := 0
	for _, f := range r.Fields {
		std := f.CEF
		// A flag (blocked, D-227): the CEF deviceAction says "blocked" when it is true and nothing when it is not (never "allowed": a
		// line that does not say the device stopped the connection is not known to have gone through).
		if std == "act" {
			if f.Val == "true" {
				ext = append(ext, "act=blocked")
			}
			continue
		}
		if std == "src" || std == "dst" { // these two keys hold an address; a name goes to a custom string
			if _, err := netip.ParseAddr(f.Val); err != nil {
				std = ""
			}
		}
		switch {
		case std != "":
			ext = append(ext, std+"="+cefValue(f.Val))
		case n < 6:
			n++
			ext = append(ext, fmt.Sprintf("cs%dLabel=%s cs%d=%s", n, f.Key, n, cefValue(f.Val)))
		}
	}
	return []byte(fmt.Sprintf("CEF:0|Vedette|Vedette|1.0|%s|%s|%d|%s", cefHeader(r.Name), cefHeader(siemTitle(r.Name)), cefSeverity(r.Severity), strings.Join(ext, " ")))
}

// siemTitle is the fixed English name of an event.
func siemTitle(name string) string {
	switch name {
	case "finding.created":
		return "Exploited vulnerability matches a device"
	case "finding.status_changed":
		return "Finding status changed"
	case "incident.created":
		return "Incident opened"
	case "honeypot.hit":
		return "Trap touched"
	case "ioc.hit":
		return "Connection to a known-bad address"
	}
	return "Vedette test record"
}

// formatJSON is one JSON object: event, time, severity, the box, then the fields (encoding/json sorts the keys, so the bytes are
// stable and the HMAC is computed over exactly what is sent).
func formatJSON(r siemRecord, host string) []byte {
	m := map[string]string{"event": r.Name, "time": r.At.Format(siemTimeFormat), "severity": r.Severity, "box": siemText(host, maxSiemHost2)}
	for _, f := range r.Fields {
		if _, taken := m[f.Key]; !taken {
			m[f.Key] = f.Val
		}
	}
	b, _ := json.Marshal(m) // a map of strings cannot fail
	return b
}

// Headers of a signed JSON webhook: the scheme of notify's webhook channel, so a customer verifies both the same way
// (hex(HMAC-SHA256(key, timestamp + "." + body)) after "sha256="; reject an old timestamp). Written out here because a module never
// imports another.
const (
	siemTimestampHeader = "X-Vedette-Timestamp"
	siemSignatureHeader = "X-Vedette-Signature"
)

func siemSign(key, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
