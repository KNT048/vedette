package honeypot

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/observe"
)

// MaxLine is the longest line of the OpenCanary log that is read (INV-12): a longer one is dropped and counted.
const MaxLine = 16 << 10

// Caps on what a record keeps. Every byte of the line comes from the network (SYS-6).
const (
	maxUser    = 64
	maxHost    = 64
	maxPath    = 200
	maxFile    = 200
	maxAgent   = 120
	maxVersion = 80
	maxCmd     = 40
)

// OpenCanary logtypes the module reads (opencanary/logger.py of the pinned 0.9.10; testdata/opencanary-0.9.10-lines.jsonl has a
// real line of each). Others (boot, ping, services that are off) are skipped.
const (
	ltFTPLogin     = 2000 // USERNAME, PASSWORD (never read)
	ltFTPAuthStart = 2001 // ftp.log_auth_attempt_initiated, not switched on
	ltSSHNew       = 4000
	ltSSHVersion   = 4001
	ltSSHLogin     = 4002
	ltSMBFile      = 5000
	ltPortSYN      = 5001
	ltPortNmapEnd  = 5005 // 5001..5005: the portscan module; it is off (D-90 (5), D-467), the mapping is ready for when it is on
	ltHTTPGet      = 3000 // 3000..3003 are the HTTPS trap's too: its port tells them apart
	ltHTTPLogin    = 3001
	ltHTTPOther    = 3002 // a method the fake page refuses (HEAD, PUT ...); needs http.log_unimplemented_method_requests
	ltHTTPRedirect = 3003 // GET / (the redirect to the login page); needs http.log_redirect_request
	ltTelnetLogin  = 6001 // USERNAME, PASSWORD
	ltTelnetNew    = 6002 // telnet.log_tcp_connection
	ltProxyLogin   = 7001 // USERNAME (Basic) or the raw NTLM token, PASSWORD
	ltMySQLLogin   = 8001 // USERNAME, PASSWORD (hex of the scrambled answer)
	ltMSSQLSQL     = 9001
	ltMSSQLWin     = 9002
	ltMySQLNew     = 9003 // mysql.log_connection_made
	ltTFTP         = 10001
	ltNTPMonlist   = 11001
	ltVNC          = 12001 // the challenge, the answer and a password guessed from a short list (never read)
	ltRDP          = 14001
	ltSIP          = 15001
	ltGit          = 16001
	ltRedis        = 17001 // CMD, ARGS (never read: AUTH carries the password), ERROR
	ltBannerNew    = 18001 // 18001..18005: the tcpbanner module (the SMTP greeting)
	ltBannerEnd    = 18005
	ltMongoDB      = 20001 // action, username, mechanism, auth_data (never read)
)

// Record is one OpenCanary line reduced to the fields the module uses, every text cut and cleaned.
type Record struct {
	LogType       int
	Src, Dst      netip.Addr // Dst is the zero Addr when the line has none (the SMB audit lines)
	SrcPort       int
	DstPort       int
	TS            time.Time // zero when the line has no usable time
	User          string
	Hostname      string
	Path          string
	Filename      string
	UserAgent     string
	RemoteVersion string
	Cmd           string // Redis: the command (never its arguments); MongoDB: the command
	Repo          string // Git: the repository asked for
	Opcode        string // TFTP: READ or WRITE
	Action        string // MongoDB: mongodb.connection, mongodb.auth_attempt ...
	Error         string // Redis: a protocol error
}

// text is a JSON value that is kept only when it is a string or a number: logdata values are free-form.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) > 0 && b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*t = text(s)
	case len(b) > 0 && (b[0] == '-' || b[0] >= '0' && b[0] <= '9') && len(b) <= 20:
		*t = text(b)
	}
	return nil
}

type rawLine struct {
	LogType int  `json:"logtype"`
	SrcHost text `json:"src_host"`
	DstHost text `json:"dst_host"`
	SrcPort text `json:"src_port"` // OpenCanary's SMB lines carry "-1" as a string; text takes a string or a number
	DstPort text `json:"dst_port"`
	UTCTime text `json:"utc_time"`
	Data    struct {
		User    text `json:"USERNAME"`
		Host    text `json:"HOSTNAME"`
		Path    text `json:"PATH"`
		File    text `json:"FILENAME"`
		Agent   text `json:"USERAGENT"`
		Version text `json:"REMOTEVERSION"`
		Client  text `json:"CLIENTVERSION"`
		// encoding/json matches names without regard to case: MongoDB's "username" is USERNAME
		Cmd     text `json:"CMD"`
		Command text `json:"command"`
		Repo    text `json:"REPO"`
		Opcode  text `json:"OPCODE"`
		Action  text `json:"action"`
		Error   text `json:"ERROR"`
	} `json:"logdata"`
}

// ErrLine is wrapped by ParseLine for a line the module cannot use.
var ErrLine = errors.New("honeypot: unusable log line")

// ParseLine decodes one JSON line. Only the fields in rawLine are read; unknown fields are ignored, nothing is
// evaluated or stored as it came, and a source that is not an IPv4 address makes the line unusable.
func ParseLine(line []byte) (Record, error) {
	if len(line) == 0 || len(line) > MaxLine {
		return Record{}, ErrLine
	}
	var r rawLine
	if err := json.Unmarshal(line, &r); err != nil {
		return Record{}, ErrLine
	}
	src, ok := ipv4Of(string(r.SrcHost))
	if !ok || r.LogType <= 0 {
		return Record{}, ErrLine
	}
	rec := Record{LogType: r.LogType, Src: src, SrcPort: clampPort(r.SrcPort), DstPort: clampPort(r.DstPort),
		User: clean(string(r.Data.User), maxUser), Hostname: clean(string(r.Data.Host), maxHost), Path: clean(string(r.Data.Path), maxPath),
		Filename: clean(string(r.Data.File), maxFile), UserAgent: clean(string(r.Data.Agent), maxAgent),
		RemoteVersion: clean(string(r.Data.Version), maxVersion), Cmd: clean(string(r.Data.Cmd), maxCmd), Repo: clean(string(r.Data.Repo), maxPath),
		Opcode: clean(string(r.Data.Opcode), maxCmd), Action: clean(string(r.Data.Action), maxCmd), Error: clean(string(r.Data.Error), maxPath)}
	if rec.Cmd == "" {
		rec.Cmd = clean(string(r.Data.Command), maxCmd)
	}
	if rec.RemoteVersion == "" {
		rec.RemoteVersion = clean(string(r.Data.Client), maxVersion)
	}
	if dst, ok := ipv4Of(string(r.DstHost)); ok {
		rec.Dst = dst
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, strings.TrimSpace(string(r.UTCTime)), time.UTC); err == nil {
			rec.TS = t
			break
		}
	}
	return rec, nil
}

// clampPort reads a port that may arrive as a number or a string; anything that is not 1-65535 (the "-1" of the SMB lines, text) is 0.
func clampPort(t text) int {
	s := strings.TrimSpace(string(t))
	if s == "" || strings.Trim(s, "0123456789") != "" { // plain decimal digits only: no sign, exponent or fraction
		return 0
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

// ipv4Of parses a dotted IPv4 address (no zone, no IPv6, no leading zeros).
func ipv4Of(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a, true
}

// clean makes attacker text safe to store and show: valid UTF-8, no control character (Cc, replaced by a space so words
// stay apart), none of the invisible or reordering ones (Cf: bidi marks, zero-width characters, the byte order mark, the
// soft hyphen, Unicode tag characters; Zl, Zp: line and paragraph separators; and every Default_Ignorable_Code_Point,
// which includes the variation selectors that carry attacker-chosen invisible bytes, L13; all dropped), at most n
// characters (INV-12). The set of invisible characters is observe.Ignorable, the table core/auth uses for names. It is
// data; nothing reads it as a command.
func clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= n {
			break
		}
		switch {
		case unicode.Is(unicode.Cc, r) || r == utf8.RuneError:
			r = ' '
		case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp), observe.Ignorable(r):
			continue
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}
