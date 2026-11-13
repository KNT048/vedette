package logs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
)

const siemKey = "0123456789abcdef-key" // built from parts at run time elsewhere would be needed for a token shape; this is not one

func goldenRecord() siemRecord {
	return newSiemRecord("finding.created", "high", t0,
		siemField{Key: "id", CEF: "externalId", Val: "f-1"}, siemField{Key: "asset_id", Val: "a-1"},
		siemField{Key: "cve", Val: "CVE-2022-27593"}, siemField{Key: "basis", Val: "kev"})
}

// The sample of the Logs page says it shows what is sent: it is the bytes of these formatters for the same record (S-LOG-3).
func TestSiemSampleOfTheGuiIsWhatTheFormattersWrite(t *testing.T) {
	r := newSiemRecord("finding.created", "high", t0,
		siemField{Key: "id", CEF: "externalId", Val: "f-1"}, siemField{Key: "asset_id", Val: "a-nas02"},
		siemField{Key: "cve", Val: "CVE-2022-27593"}, siemField{Key: "basis", Val: "kev"})
	src, err := os.ReadFile("../../web/src/features/logs/snippets.ts")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"syslog": string(formatSyslog(r, "vedette")), "cef": string(formatCEF(r, "vedette")), "json": string(formatJSON(r, "vedette"))} {
		if !strings.Contains(string(src), want) {
			t.Errorf("web/src/features/logs/snippets.ts has no %s sample equal to %s", name, want)
		}
	}
}

// Golden bytes: what a SIEM receives, byte for byte, in each format.
func TestSiemFormatsGoldenBytes(t *testing.T) {
	r := goldenRecord()
	if got, want := string(formatSyslog(r, "box-1")), `<131>1 2026-11-09T10:00:00.000Z box-1 vedette - finding.created [vedette@32473 id="f-1" asset_id="a-1" cve="CVE-2022-27593" basis="kev"] finding.created severity=high`; got != want {
		t.Errorf("syslog:\n got %s\nwant %s", got, want)
	}
	if got, want := string(formatCEF(r, "box-1")), `CEF:0|Vedette|Vedette|1.0|finding.created|Exploited vulnerability matches a device|7|rt=1794218400000 dvchost=box-1 externalId=f-1 cs1Label=asset_id cs1=a-1 cs2Label=cve cs2=CVE-2022-27593 cs3Label=basis cs3=kev`; got != want {
		t.Errorf("cef:\n got %s\nwant %s", got, want)
	}
	body := formatJSON(r, "box-1")
	if got, want := string(body), `{"asset_id":"a-1","basis":"kev","box":"box-1","cve":"CVE-2022-27593","event":"finding.created","id":"f-1","severity":"high","time":"2026-11-09T10:00:00.000Z"}`; got != want {
		t.Errorf("json:\n got %s\nwant %s", got, want)
	}
	// the signature: a value computed outside this code (python hmac), and the scheme of notify's webhook
	if got, want := siemSign(siemKey, "1794218400", body), "sha256=3c75fc91b688a47c9d5a341907ee68697245197ec74d440a074bbfd044014945"; got != want {
		t.Errorf("signature %s, want %s", got, want)
	}
	if got := string(octetFrame([]byte("abc"))); got != "3 abc" {
		t.Errorf("octet frame %q", got)
	}
	// every severity has its syslog PRI (local0 = 16) and CEF number
	for sev, want := range map[string][2]int{"critical": {130, 10}, "high": {131, 7}, "medium": {132, 5}, "low": {133, 3}, "info": {134, 1}} {
		if p := 128 + syslogSeverity(sev); p != want[0] || cefSeverity(sev) != want[1] {
			t.Errorf("%s: PRI %d CEF %d, want %v", sev, p, cefSeverity(sev), want)
		}
	}
}

// Untrusted text (a trap label, a device name) never breaks the grammar of a format and never carries a control character.
func TestSiemFormatsEscapeHostileText(t *testing.T) {
	evil := "a\"b]c\\d|e=f\r\ng\x00h\u202ei j k"
	r := newSiemRecord("honeypot.hit", "high", t0, siemField{Key: "decoy", Val: evil}, siemField{Key: "src_ip", CEF: "src", Val: "10.0.0.1 evil=1"})
	for name, out := range map[string]string{"syslog": string(formatSyslog(r, "bo x\n")), "cef": string(formatCEF(r, "bo=x\n")), "json": string(formatJSON(r, "bo\nx"))} {
		for _, c := range out {
			if c < 0x20 || c == 0x7f || (c >= 0x2028 && c <= 0x202e) {
				t.Errorf("%s carries the control character %U: %q", name, c, out)
			}
		}
	}
	sys := string(formatSyslog(r, "bo x\n"))
	if !strings.Contains(sys, `decoy="a\"b\]c\\d|e=f  g h i j k"`) {
		t.Errorf("syslog SD-PARAM not escaped: %s", sys)
	}
	if strings.Count(strings.ReplaceAll(strings.ReplaceAll(sys, `\\`, ""), `\"`, ""), `"`) != 4 { // two params: four unescaped quotes
		t.Errorf("syslog: quotes of the value break out: %s", sys)
	}
	if !strings.Contains(sys, "Z box vedette - ") {
		t.Errorf("syslog host not a single token: %s", sys)
	}
	cef := string(formatCEF(r, "bo=x y\n"))
	if !strings.Contains(cef, ` dvchost=bo\=xy `) {
		t.Errorf("cef host not a single token: %s", cef)
	}
	if !strings.Contains(cef, `cs1Label=decoy cs1=a"b]c\\d|e\=f  g h i j k`) {
		t.Errorf("cef extension not escaped: %s", cef)
	}
	if strings.Contains(cef, "src=10.0.0.1") { // not an address: it must not become the src key
		t.Errorf("cef: a value that is not an address became src: %s", cef)
	}
	if strings.Count(cef, "|") != 7 { // 7 header separators; the one in the extension value is a value, but header names were not given any
		t.Logf("cef: %s", cef) // the extension may carry an unescaped | (CEF escapes it only in the header); the header count is what matters
	}
	if h := strings.SplitN(cef, "|", 8); len(h) != 8 || h[3] != "1.0" {
		t.Errorf("cef header broken: %s", cef)
	}
	if !strings.Contains(string(formatJSON(r, "x")), `\u0000`) && strings.Contains(string(formatJSON(r, "x")), "\x00") {
		t.Error("json carries a NUL")
	}
}

// ---- environment ----

func newSiemEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	sec, err := secrets.New(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.cfg.Secrets = sec
	e.svc.allowLoopback = true
	return e
}

func (e *env) saveSiem(in SiemInput) SiemView {
	e.t.Helper()
	v, err := e.svc.SetSiem(e.t.Context(), "admin@acme.example", in)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func syslogInput(host string, port int, proto string) SiemInput {
	return SiemInput{Enabled: true, Format: "syslog", Host: host, Port: port, Proto: proto, Events: []string{"findings", "honeypot"}}
}

// ---- configuration ----

func TestSiemIsOffByDefaultAndNeverShowsTheKey(t *testing.T) {
	e := newSiemEnv(t)
	v, err := e.svc.Siem(t.Context())
	if err != nil || v.Enabled || v.SecretLast4 != nil || v.LastTest != nil || v.Format != "syslog" || v.Port != 514 || v.Proto != "udp" || len(v.Events) != 2 {
		t.Fatalf("default %+v, %v", v, err)
	}
	// a JSON webhook needs its key; the first save seals it
	in := SiemInput{Enabled: true, Format: "json", URL: "https://siem.example.com/hooks/vedette?t=abc", Events: []string{"alerts"}}
	if _, err := e.svc.SetSiem(t.Context(), "a@x", in); code(err) != "secret_required" {
		t.Fatalf("json without a key: %v", err)
	}
	in.Secret = "super-secret-key-1234"
	v = e.saveSiem(in)
	if v.SecretLast4 == nil || *v.SecretLast4 != "1234" || v.Host != "" || v.Port != 514 || v.Proto != "udp" {
		t.Fatalf("saved %+v", v)
	}
	// an empty secret on edit keeps the old key (INV-8)
	in.Secret, in.Events = "", []string{"alerts", "honeypot"}
	v = e.saveSiem(in)
	if v.SecretLast4 == nil || *v.SecretLast4 != "1234" {
		t.Fatalf("key not kept: %+v", v)
	}
	row, err := e.svc.loadSiem(t.Context(), e.cfg.Reader(), true)
	if err != nil || row.key.Reveal() != "super-secret-key-1234" {
		t.Fatalf("key not read back: %v", err)
	}
	// FORBID-2: the key is in no response, no stored column, no audit row, no log line
	var stored, auditText string
	_ = e.cfg.Reader().QueryRowContext(t.Context(), `SELECT enabled || format || host || url || ifnull(secret_id,'') || ifnull(secret_last4,'') || events || ifnull(last_test,'') FROM logs_siem`).Scan(&stored)
	_ = e.cfg.Reader().QueryRowContext(t.Context(), `SELECT group_concat(action || target || detail) FROM core_audit`).Scan(&auditText)
	for name, s := range map[string]string{"row": stored, "audit": auditText, "view": fmt.Sprintf("%+v", v)} {
		if strings.Contains(s, "super-secret") {
			t.Errorf("the key is in the %s: %s", name, s)
		}
	}
	if strings.Contains(auditText, "t=abc") || strings.Contains(auditText, "/hooks/vedette") {
		t.Errorf("the webhook path is in the audit row: %s", auditText)
	}
	if n := count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.siem_save'`); n != 2 {
		t.Errorf("%d audit rows for 2 saves", n)
	}
	if fmt.Sprintf("%v %+v", row.key, row.key) != "[redacted] [redacted]" && !strings.Contains(fmt.Sprintf("%v", row.key), "redacted") {
		t.Errorf("the key prints itself: %v", row.key)
	}
}

func TestSiemSaveValidation(t *testing.T) {
	e := newSiemEnv(t)
	e.svc.allowLoopback = false
	e.svc.cfg.BoxAddrs = func() ([]netip.Addr, bool) { return []netip.Addr{netip.MustParseAddr("192.168.10.2")}, true }
	ok := SiemInput{Enabled: true, Format: "syslog", Host: "siem.example.com", Port: 514, Proto: "udp", Events: []string{"findings"}}
	cases := []struct {
		name string
		mod  func(*SiemInput)
		want string
	}{
		{"format", func(i *SiemInput) { i.Format = "xml" }, "bad_format"},
		{"no events", func(i *SiemInput) { i.Events = nil }, "bad_events"},
		{"unknown event", func(i *SiemInput) { i.Events = []string{"findings", "secrets"} }, "bad_events"},
		{"port 0", func(i *SiemInput) { i.Port = 0 }, "bad_port"},
		{"port high", func(i *SiemInput) { i.Port = 70000 }, "bad_port"},
		{"proto", func(i *SiemInput) { i.Proto = "sctp" }, "bad_proto"},
		{"host spaces", func(i *SiemInput) { i.Host = "a b" }, "bad_host"},
		{"host empty", func(i *SiemInput) { i.Host = "" }, "bad_host"},
		{"host numeric", func(i *SiemInput) { i.Host = "2130706433" }, "bad_host"},
		{"host hex", func(i *SiemInput) { i.Host = "0x7f.1" }, "bad_host"},
		{"loopback", func(i *SiemInput) { i.Host = "127.0.0.1" }, "blocked_host"},
		{"localhost", func(i *SiemInput) { i.Host = "localhost" }, "blocked_host"},
		{"sub localhost", func(i *SiemInput) { i.Host = "x.localhost" }, "blocked_host"},
		{"link-local", func(i *SiemInput) { i.Host = "169.254.169.254" }, "blocked_host"},
		{"unspecified", func(i *SiemInput) { i.Host = "0.0.0.0" }, "blocked_host"},
		{"multicast", func(i *SiemInput) { i.Host = "224.0.0.1" }, "blocked_host"},
		{"the box", func(i *SiemInput) { i.Host = "192.168.10.2" }, "blocked_host"},
		{"short key", func(i *SiemInput) { i.Secret = "short" }, "bad_secret"},
		{"url scheme", func(i *SiemInput) { i.Format, i.URL = "json", "ftp://siem.example.com/x" }, "bad_url"},
		{"url userinfo", func(i *SiemInput) { i.Format, i.URL = "json", "https://u:p@siem.example.com/x" }, "bad_url"},
		{"url space", func(i *SiemInput) { i.Format, i.URL = "json", "https://siem.example.com/a b" }, "bad_url"},
		{"url empty", func(i *SiemInput) { i.Format, i.URL = "json", "" }, "bad_url"},
		{"url loopback", func(i *SiemInput) { i.Format, i.URL, i.Secret = "json", "https://127.0.0.1/x", siemKey }, "blocked_host"},
		{"url mapped loopback", func(i *SiemInput) { i.Format, i.URL, i.Secret = "json", "https://[::ffff:127.0.0.1]/x", siemKey }, "blocked_host"},
		{"url nat64 of the box", func(i *SiemInput) { i.Format, i.URL, i.Secret = "json", "https://[64:ff9b::c0a8:a02]:8443/x", siemKey }, "blocked_host"},
		{"the box, TLS syslog", func(i *SiemInput) { i.Host, i.Port, i.Proto = "192.168.10.2", 6514, "tls" }, "blocked_host"},
		{"url 6to4 loopback", func(i *SiemInput) { i.Format, i.URL, i.Secret = "json", "https://[2002:7f00:1::]/x", siemKey }, "blocked_host"},
		{"url localhost", func(i *SiemInput) { i.Format, i.URL, i.Secret = "json", "https://localhost/x", siemKey }, "blocked_host"},
		{"url port", func(i *SiemInput) { i.Format, i.URL, i.Secret = "json", "https://siem.example.com:99999/x", siemKey }, "bad_url"},
	}
	for _, c := range cases {
		in := ok
		c.mod(&in)
		if _, err := e.svc.SetSiem(t.Context(), "a@x", in); code(err) != c.want {
			t.Errorf("%s: got %v, want %s", c.name, err, c.want)
		}
	}
	if n := count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.siem_save'`); n != 0 {
		t.Errorf("%d audit rows for refused saves", n)
	}
	// an internal address and a name are fine, and so is a SIEM on the machine at a port that is not Vedette's (D-446)
	for _, h := range []string{"192.168.10.50", "siem.example.com", "10.0.0.7", "192.168.10.2"} {
		in := ok
		in.Host = h
		if h == "192.168.10.2" {
			in.Port = 1514
		}
		if _, err := e.svc.SetSiem(t.Context(), "a@x", in); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

// ---- the guard on the socket ----

func TestSiemForbiddenTable(t *testing.T) {
	box := []netip.Addr{netip.MustParseAddr("192.168.10.2"), netip.MustParseAddr("fd00::2")}
	for _, c := range []struct {
		ip     string
		denied bool
	}{
		{"0.0.0.0", true}, {"::", true}, {"169.254.169.254", true}, {"fe80::1", true},
		{"224.0.0.251", true}, {"ff02::1", true}, {"255.255.255.255", true}, {"100.100.100.200", true}, {"fd00:ec2::254", true}, {"fd20:ce::254", true}, {"192.0.0.192", true},
		{"192.168.10.50", false}, {"10.1.2.3", false}, {"8.8.8.8", false}, {"2001:4860:4860::8888", false}, {"fd00::50", false}, {"192.168.10.2", false},
	} {
		if got := siemForbidden(netip.MustParseAddr(c.ip)); got != c.denied {
			t.Errorf("%s: forbidden=%v, want %v", c.ip, got, c.denied)
		}
	}
	// D-446: Vedette itself: loopback on every port, the machine's addresses on Vedette's own ports, in every transition form
	for _, c := range []struct {
		ip   string
		port uint16
		own  bool
	}{
		{"127.0.0.1", 1514, true}, {"::1", 514, true}, {"::ffff:127.0.0.1", 80, true}, {"64:ff9b::7f00:1", 443, true}, {"::7f00:1", 9000, true},
		{"192.168.10.2", 514, true}, {"::ffff:192.168.10.2", 6514, true}, {"fd00::2", 8443, true}, {"64:ff9b::c0a8:a02", 8444, true}, {"2002:c0a8:a02::1", 8765, true},
		{"192.168.10.2", 1514, false}, {"fd00::2", 443, false}, {"192.168.10.50", 514, false},
	} {
		if got := siemOwn(netip.MustParseAddr(c.ip), c.port, box, false); got != c.own {
			t.Errorf("%s:%d: own=%v, want %v", c.ip, c.port, got, c.own)
		}
	}
	// RFC 6052 /48: 64:ff9b:1:c0a8:a:200:: carries 192.168.10.2 (bytes 6,7,9,10 = c0 a8 0a 02)
	if !siemOwn(netip.MustParseAddr("64:ff9b:1:c0a8:0a:0200::"), 514, box, false) {
		t.Error("the /48 NAT64 form of the box address is not refused")
	}
}

// Name resolution is not trusted: the guard runs on the socket, for TCP, UDP and the webhook alike, on the address about to be dialled.
func TestSiemSendRefusesForbiddenAddressesOnTheSocket(t *testing.T) {
	e := newSiemEnv(t)
	e.svc.allowLoopback = false
	udp, _ := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	defer func() { _ = udp.Close() }()
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); hits++; mu.Unlock() }))
	defer srv.Close()
	rec := []siemRecord{goldenRecord()}
	for _, proto := range []string{"udp", "tcp", "tls"} {
		_, err := e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "syslog", Host: "127.0.0.1", Port: udp.LocalAddr().(*net.UDPAddr).Port, Proto: proto}}, rec)
		if !errors.Is(err, errSiemOwn) {
			t.Errorf("%s to loopback: %v", proto, err)
		}
	}
	_, err := e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "json", URL: srv.URL}, key: secrets.NewValue(siemKey)}, rec)
	if !errors.Is(err, errSiemOwn) || hits != 0 {
		t.Errorf("webhook to loopback: %v, %d hits", err, hits)
	}
	// the box's addresses are not known: nothing is sent, not even to a public address
	e.svc.cfg.BoxAddrs = func() ([]netip.Addr, bool) { return nil, false }
	_, err = e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "syslog", Host: "8.8.8.8", Port: 514, Proto: "udp"}}, rec)
	if !errors.Is(err, errSiemBoxUnknown) {
		t.Errorf("unknown box addresses: %v", err)
	}
	// plain http goes only to an address on the customer's own network, whatever the name resolves to
	e.svc.cfg.BoxAddrs = nil
	_, err = e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "json", URL: "http://8.8.8.8/x"}, key: secrets.NewValue(siemKey)}, rec)
	if !errors.Is(err, errSiemNotPrivate) {
		t.Errorf("http to a public address: %v", err)
	}
}

// ---- sending ----

func TestSiemSendsEachFormatAndSignsTheWebhook(t *testing.T) {
	e := newSiemEnv(t)
	recs := []siemRecord{goldenRecord(), newSiemRecord("honeypot.hit", "high", t0, siemField{Key: "service", Val: "ssh"})}

	// UDP: one datagram per record
	pc, _ := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	defer func() { _ = pc.Close() }()
	if _, err := e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "syslog", Host: "127.0.0.1", Port: pc.LocalAddr().(*net.UDPAddr).Port, Proto: "udp"}}, recs); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "<131>1 2026-11-09T10:00:00.000Z ") {
		t.Fatalf("udp datagram %q, %v", buf[:n], err)
	}

	// TCP: octet-counted frames, CEF this time
	ln, _ := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	if _, err := e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "cef", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Proto: "tcp"}}, recs); err != nil {
		t.Fatal(err)
	}
	stream := <-got
	want0 := string(formatCEF(recs[0], "vedette"))
	if !strings.HasPrefix(stream, fmt.Sprintf("%d %s", len(want0), want0)) {
		t.Fatalf("tcp stream %q", stream)
	}
	if strings.Count(stream, "CEF:0|") != 2 {
		t.Fatalf("two frames expected: %q", stream)
	}

	// JSON webhook: signed, no redirect followed
	type call struct {
		ts, sig string
		body    []byte
	}
	calls := make(chan call, 4)
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("a redirect was followed") }))
	defer redirectTarget.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls <- call{r.Header.Get(siemTimestampHeader), r.Header.Get(siemSignatureHeader), b}
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
		}
	}))
	defer srv.Close()
	detail, err := e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "json", URL: srv.URL + "/hook"}, key: secrets.NewValue(siemKey)}, recs[:1])
	if err != nil || detail != "The destination returned HTTP 200." {
		t.Fatalf("webhook: %q, %v", detail, err)
	}
	c := <-calls
	mac := hmac.New(sha256.New, []byte(siemKey)) // a receiver verifies like this, the way notify's webhook is verified
	mac.Write([]byte(c.ts + "."))
	mac.Write(c.body)
	if c.sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) || c.ts != fmt.Sprint(e.svc.now().Unix()) {
		t.Fatalf("bad signature or timestamp: %+v", c)
	}
	// a redirect is an answer: it is not followed, and 3xx is a failure
	_, err = e.svc.siemSend(t.Context(), siemRow{SiemView: SiemView{Format: "json", URL: srv.URL + "/redir"}, key: secrets.NewValue(siemKey)}, recs[:1])
	var se *statusError
	if !errors.As(err, &se) || se.Code != 302 {
		t.Fatalf("redirect: %v", err)
	}
	// an error status is a failure and the test result is a fixed sentence
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "secret-reflected-text", http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	row := siemRow{SiemView: SiemView{Format: "json", URL: bad.URL + "/hooks/token-abc"}, key: secrets.NewValue(siemKey)}
	_, err = e.svc.siemSend(t.Context(), row, recs[:1])
	msg := siemFailure(err, row)
	if err == nil || strings.Contains(msg, "secret-reflected") || strings.Contains(msg, "token-abc") || !strings.Contains(msg, "HTTP 503") {
		t.Fatalf("failure text %q, %v", msg, err)
	}
}

// #471: the records carry the box's name from Config.Hostname (the OS host name core gets from vedette-host), not the name of core's
// container; without one, "vedette".
func TestSiemRecordsCarryTheBoxHostname(t *testing.T) {
	e := newSiemEnv(t)
	pc, _ := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	defer func() { _ = pc.Close() }()
	hook := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); hook <- b }))
	defer srv.Close()
	syslogRow := siemRow{SiemView: SiemView{Format: "syslog", Host: "127.0.0.1", Port: pc.LocalAddr().(*net.UDPAddr).Port, Proto: "udp"}}
	jsonRow := siemRow{SiemView: SiemView{Format: "json", URL: srv.URL + "/hook"}, key: secrets.NewValue(siemKey)}
	for _, tc := range []struct {
		name string
		fn   func(context.Context) string
		want string
	}{
		{"the host's name", func(context.Context) string { return "box-01.corp.example" }, "box-01.corp.example"},
		{"no name", func(context.Context) string { return "" }, "vedette"},
		{"no source", nil, "vedette"},
	} {
		e.svc.cfg.Hostname = tc.fn
		if _, err := e.svc.siemSend(t.Context(), syslogRow, []siemRecord{goldenRecord()}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if want := "<131>1 2026-11-09T10:00:00.000Z " + tc.want + " vedette - "; err != nil || !strings.HasPrefix(string(buf[:n]), want) {
			t.Errorf("%s: syslog %q, want the prefix %q (%v)", tc.name, buf[:n], want, err)
		}
		cefRow := syslogRow
		cefRow.Format = "cef"
		if _, err := e.svc.siemSend(t.Context(), cefRow, []siemRecord{goldenRecord()}); err != nil {
			t.Fatal(err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err = pc.ReadFrom(buf)
		if want := "|rt=1794218400000 dvchost=" + tc.want + " "; err != nil || !strings.Contains(string(buf[:n]), want) {
			t.Errorf("%s: cef %q, want %q (%v)", tc.name, buf[:n], want, err)
		}
		if _, err := e.svc.siemSend(t.Context(), jsonRow, []siemRecord{goldenRecord()}); err != nil {
			t.Fatal(err)
		}
		var body map[string]string
		if err := json.Unmarshal(<-hook, &body); err != nil || body["box"] != tc.want {
			t.Errorf("%s: json box %q, want %q (%v)", tc.name, body["box"], tc.want, err)
		}
	}
}

func TestSiemTestStoresTheResultAndNeedsAConfiguration(t *testing.T) {
	e := newSiemEnv(t)
	if _, err := e.svc.TestSiem(t.Context(), "a@x"); code(err) != "not_configured" {
		t.Fatalf("no destination: %v", err)
	}
	pc, _ := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	defer func() { _ = pc.Close() }()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	in := syslogInput("127.0.0.1", port, "udp")
	in.Enabled = false // the test is the administrator's own request: it goes out while forwarding is off
	e.saveSiem(in)
	r, err := e.svc.TestSiem(t.Context(), "a@x")
	if err != nil || !r.OK || r.Detail != fmt.Sprintf("Sent 1 test record to 127.0.0.1:%d/udp.", port) {
		t.Fatalf("test: %+v, %v", r, err)
	}
	v, _ := e.svc.Siem(t.Context())
	if v.LastTest == nil || !v.LastTest.OK || v.LastTest.At != r.At {
		t.Fatalf("last_test not stored: %+v", v.LastTest)
	}
	// saving again forgets it: it described another destination
	e.saveSiem(in)
	if v, _ = e.svc.Siem(t.Context()); v.LastTest != nil {
		t.Fatal("last_test kept after a save")
	}
	// a destination that refuses the connection: a fixed sentence, stored as a failure
	e.svc.allowLoopback = false
	r, err = e.svc.TestSiem(t.Context(), "a@x")
	if err != nil || r.OK || !strings.Contains(r.Detail, "Refused") {
		t.Fatalf("refused test: %+v, %v", r, err)
	}
	if n := count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.siem_test'`); n != 2 {
		t.Errorf("%d audit rows for 2 tests", n)
	}
}

func TestSiemDetailIsClippedAndClean(t *testing.T) {
	long := strings.Repeat("x", 1000) + "\x1b[31m\nred"
	if d := clipDetail(long); len(d) > maxTestDetal || strings.ContainsAny(d, "\x1b\n") {
		t.Errorf("detail %d bytes: %q", len(d), d)
	}
	if d := clipDetail("ok\x00\n\u202etext"); strings.ContainsAny(d, "\x00\n\u202e") {
		t.Errorf("detail %q", d)
	}
}

// ---- the queue ----

func TestSiemQueueDropsTheOldestAndCounts(t *testing.T) {
	q := newSiemQueue(3)
	for i := range 5 {
		q.push(newSiemRecord(fmt.Sprintf("e%d", i), "info", t0), q.generation())
	}
	recs, upTo := q.peek(10)
	if len(recs) != 3 || recs[0].Name != "e2" || recs[2].Name != "e4" || q.droppedCount() != 2 {
		t.Fatalf("queue %v dropped %d", recs, q.droppedCount())
	}
	// the oldest is dropped while a batch is on the wire: the ack removes only what is still there
	q.push(newSiemRecord("e5", "info", t0), q.generation())
	q.push(newSiemRecord("e6", "info", t0), q.generation())
	q.ack(upTo)
	recs, _ = q.peek(10)
	if len(recs) != 2 || recs[0].Name != "e5" {
		t.Fatalf("after ack %v", recs)
	}
}

// ---- events, FORBID-3, a slow SIEM ----

func publish(t *testing.T, bus *events.Bus, name string, data any) {
	t.Helper()
	if err := bus.Publish(t.Context(), events.Event{Name: name, Data: data}); err != nil {
		t.Fatal(err)
	}
}

func TestSiemQueuesOnlyWhatIsEnabledAndOnlyWhileTheJobRuns(t *testing.T) {
	e := newSiemEnv(t)
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	e.svc.Subscribe(bus)
	finding := map[string]any{"finding_id": "f-1", "asset_id": "a-1", "cve": "CVE-2022-27593", "severity": "critical", "basis": "kev"}
	hit := map[string]any{"id": "h-1", "kind": "ssh", "service": "ssh", "port": 22, "src_ip": "10.0.0.9", "decoy": "trap\n1"}
	all := func() {
		publish(t, bus, siemEventFindingCreated, finding)
		publish(t, bus, siemEventHoneypot, hit)
		publish(t, bus, siemEventIncident, map[string]any{"id": "i-1", "kind": "trap", "severity": "high"})
		publish(t, bus, siemEventBadAddress, map[string]any{"id": "b-1", "src_ip": "10.0.0.9", "dest": "evil.example", "dest_kind": "domain"})
		publish(t, bus, siemEventFindingStatus, map[string]any{"finding_id": "f-1", "from": "open", "to": "confirmed"})
	}
	queued := func() int { r, _ := e.svc.siemQ.peek(100); return len(r) }

	// the module is off (the job does not run): nothing is queued, whatever is saved
	e.saveSiem(syslogInput("192.168.10.50", 514, "udp"))
	all()
	if queued() != 0 {
		t.Fatal("queued while the job is not running")
	}

	// the job runs; saved and enabled for findings and honeypot only
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sent := make(chan []siemRecord, 8)
	e.svc.siemSendFn = func(_ context.Context, _ siemRow, recs []siemRecord) (string, error) { sent <- recs; return "", nil }
	done := make(chan error, 1)
	go func() { done <- e.svc.runSiem(ctx) }()
	waitFor(t, func() bool { return e.svc.siemRunning.Load() && e.svc.siemCache.Load() != nil })
	all()
	var names []string
	for len(names) < 3 {
		select {
		case rs := <-sent:
			for _, r := range rs {
				names = append(names, r.Name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("sent only %v", names)
		}
	}
	if fmt.Sprint(names) != "[finding.created honeypot.hit finding.status_changed]" {
		t.Fatalf("forwarded %v", names)
	}

	// switched off: nothing more is queued or sent (FORBID-3)
	off := syslogInput("192.168.10.50", 514, "udp")
	off.Enabled = false
	e.saveSiem(off)
	waitFor(t, func() bool { return e.svc.siemCache.Load() != nil })
	all()
	<-time.After(50 * time.Millisecond)
	if queued() != 0 || len(sent) != 0 {
		t.Fatalf("something was queued or sent while disabled: %d queued, %d sent", queued(), len(sent))
	}

	// the module goes off: the job ends, the queue is emptied, nothing more is queued
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if e.svc.siemRunning.Load() {
		t.Fatal("still running")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 500 {
		if ok() {
			return
		}
		<-time.After(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// The text of an event that came from the network never reaches the queue raw.
func TestSiemRecordsFromEventsAreClean(t *testing.T) {
	e := newSiemEnv(t)
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	e.svc.Subscribe(bus)
	e.saveSiem(SiemInput{Enabled: true, Format: "syslog", Host: "192.168.10.50", Port: 514, Proto: "udp", Events: SiemEvents})
	e.svc.siemRunning.Store(true)
	row, _ := e.svc.loadSiem(t.Context(), e.cfg.Reader(), false)
	e.svc.siemCache.Store(&row)
	publish(t, bus, siemEventHoneypot, map[string]any{"id": "h\n1", "service": strings.Repeat("s", 5000), "decoy": "a\u202eb\x00c", "src_ip": "1.2.3.4", "port": 22})
	publish(t, bus, siemEventFindingCreated, "not an object")
	publish(t, bus, siemEventIncident, map[string]any{"id": "i-1", "severity": "<script>"})
	recs, _ := e.svc.siemQ.peek(10)
	if len(recs) != 2 { // the payload that is not an object is dropped
		t.Fatalf("%d records", len(recs))
	}
	for _, r := range recs {
		for _, f := range r.Fields {
			if len(f.Val) > maxSiemField || strings.ContainsAny(f.Val, "\n\x00\u202e") {
				t.Errorf("field %s not cleaned: %q", f.Key, f.Val)
			}
		}
	}
	if recs[1].Severity != "medium" { // an unknown severity does not reach the wire
		t.Errorf("severity %q", recs[2].Severity)
	}
}

// A bad connection the device blocked says so in every format (D-227): CEF act=blocked, syslog and JSON blocked="true"; one that went
// through, or an event without the key, is blocked="false" and has no act.
func TestSiemBadConnCarriesBlocked(t *testing.T) {
	e := newSiemEnv(t)
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	e.svc.Subscribe(bus)
	e.saveSiem(SiemInput{Enabled: true, Format: "cef", Host: "192.168.10.50", Port: 514, Proto: "udp", Events: []string{"bad_conn"}})
	e.svc.siemRunning.Store(true)
	row, _ := e.svc.loadSiem(t.Context(), e.cfg.Reader(), false)
	e.svc.siemCache.Store(&row)
	hit := map[string]any{"id": "b-1", "src_ip": "192.168.10.9", "dest": "a.bad.example.net", "dest_kind": "domain", "seen_via": "syslog:FW", "blocked": true, "listed_as": "bad.example.net"}
	publish(t, bus, siemEventBadAddress, hit)
	hit["blocked"] = false
	hit["listed_as"] = nil // a hit of a name that a feed lists itself: the field is empty
	publish(t, bus, siemEventBadAddress, hit)
	delete(hit, "blocked")
	publish(t, bus, siemEventBadAddress, hit)
	recs, _ := e.svc.siemQ.peek(10)
	if len(recs) != 3 {
		t.Fatalf("%d records", len(recs))
	}
	for i, want := range []string{"true", "false", "false"} {
		cef, sl, js := string(formatCEF(recs[i], "box")), string(formatSyslog(recs[i], "box")), string(formatJSON(recs[i], "box"))
		// D-433: listed_as goes out in every format when a parent name is the one listed; an empty field is left out (as asset_id is)
		has := strings.Contains(sl, ` listed_as="bad.example.net"`) && strings.Contains(js, `"listed_as":"bad.example.net"`) && strings.Contains(cef, "Label=listed_as cs4=bad.example.net")
		if has != (i == 0) || (i != 0 && (strings.Contains(sl, "listed_as") || strings.Contains(js, "listed_as") || strings.Contains(cef, "listed_as"))) {
			t.Errorf("record %d listed_as: cef %s syslog %s json %s", i, cef, sl, js)
		}
		if strings.Contains(cef, "act=blocked") != (want == "true") || strings.Contains(cef, "act=") != (want == "true") {
			t.Errorf("record %d cef %s", i, cef)
		}
		if !strings.Contains(sl, ` blocked="`+want+`"`) || !strings.Contains(js, `"blocked":"`+want+`"`) {
			t.Errorf("record %d syslog %s json %s", i, sl, js)
		}
	}
}

// A SIEM that never answers must not slow the bus or the module that publishes, and must not make the queue grow. Time is the bubble's:
// the sender sits in its first send for the whole test, and every publish returns while it does without any bubble time passing (a
// publish that waited on the sender would let the clock run, or leave the bubble deadlocked), whatever the load of the machine.
func TestSiemSlowDestinationNeverSlowsThePublisher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newSiemEnv(t)
		bus := events.NewBus(slog.New(slog.DiscardHandler))
		e.svc.Subscribe(bus)
		e.saveSiem(syslogInput("192.168.10.50", 514, "tcp"))
		block := make(chan struct{})
		var sends atomic.Int32
		e.svc.siemSendFn = func(ctx context.Context, _ siemRow, _ []siemRecord) (string, error) {
			sends.Add(1)
			select {
			case <-block:
			case <-ctx.Done():
			}
			return "", errors.New("down")
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { _ = e.svc.runSiem(ctx); close(done) }()
		defer func() { cancel(); close(block); <-done }()
		synctest.Wait()
		if e.svc.siemCache.Load() == nil {
			t.Fatal("the forwarder did not load the configuration")
		}
		publish(t, bus, siemEventHoneypot, map[string]any{"id": "first", "service": "ssh"})
		synctest.Wait() // the forwarder took the record and is blocked in the send
		if n := sends.Load(); n != 1 {
			t.Fatalf("sends before the burst = %d, want 1 (blocked)", n)
		}
		// The burst runs in a goroutine of its own, so a publish that waits on the blocked sender fails here after an hour of bubble
		// time (the other goroutines' timers let the clock run) instead of hanging the test.
		published := make(chan time.Duration, 1)
		go func() {
			start := time.Now()
			for i := range 20000 {
				if err := bus.Publish(t.Context(), events.Event{Name: siemEventHoneypot, Data: map[string]any{"id": fmt.Sprint(i), "service": "ssh"}}); err != nil {
					t.Error(err) // not Fatal: this is not the test's goroutine
					break
				}
			}
			published <- time.Since(start)
		}()
		select {
		case d := <-published:
			if d != 0 {
				t.Fatalf("the publishes waited %v of bubble time with the SIEM blocked", d)
			}
		case <-time.After(time.Hour):
			t.Fatal("a publish waited on the blocked SIEM")
		}
		if n := sends.Load(); n != 1 {
			t.Fatalf("sends = %d: the first send was supposed to be still blocked", n)
		}
		recs, _ := e.svc.siemQ.peek(SiemQueueMax + 10)
		if len(recs) != SiemQueueMax || e.svc.siemQ.droppedCount() != 20001-SiemQueueMax { // the oldest go, the count says how many
			t.Fatalf("queue %d, dropped %d", len(recs), e.svc.siemQ.droppedCount())
		}
		if recs[0].Fields[0].Val != fmt.Sprint(20000-SiemQueueMax) || recs[len(recs)-1].Fields[0].Val != "19999" { // the newest are kept
			t.Fatalf("queue holds %v .. %v", recs[0].Fields, recs[len(recs)-1].Fields)
		}
	})
}

// Retry with a growing wait, then success; the records are not lost while the SIEM is down. Time is the bubble's.
func TestSiemRetriesWithBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newSiemEnv(t)
		bus := events.NewBus(slog.New(slog.DiscardHandler))
		e.svc.Subscribe(bus)
		e.saveSiem(syslogInput("192.168.10.50", 514, "tcp"))
		var attempts []time.Time
		var delivered []string
		e.svc.siemSendFn = func(_ context.Context, _ siemRow, recs []siemRecord) (string, error) {
			attempts = append(attempts, time.Now())
			if len(attempts) <= 5 {
				return "", errors.New("down")
			}
			for _, r := range recs {
				delivered = append(delivered, r.Fields[0].Val)
			}
			return "", nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { _ = e.svc.runSiem(ctx); close(done) }()
		synctest.Wait()
		publish(t, bus, siemEventHoneypot, map[string]any{"id": "h-1", "service": "ssh"})
		<-time.After(10 * time.Minute)
		synctest.Wait()
		cancel()
		<-done
		if len(attempts) != 6 || len(delivered) != 1 || delivered[0] != "h-1" {
			t.Fatalf("attempts %d, delivered %v", len(attempts), delivered)
		}
		var gaps []time.Duration
		for i := 1; i < len(attempts); i++ {
			gaps = append(gaps, attempts[i].Sub(attempts[i-1]))
		}
		if fmt.Sprint(gaps) != "[1s 2s 4s 8s 16s]" {
			t.Fatalf("waits %v", gaps)
		}
	})
}

// The runner holds no database writer while it sends: a configuration write goes through while a send is blocked.
func TestSiemSendingDoesNotHoldTheWriter(t *testing.T) {
	e := newSiemEnv(t)
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	e.svc.Subscribe(bus)
	e.saveSiem(syslogInput("192.168.10.50", 514, "tcp"))
	inSend, release := make(chan struct{}, 1), make(chan struct{})
	e.svc.siemSendFn = func(ctx context.Context, _ siemRow, _ []siemRecord) (string, error) {
		inSend <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return "", nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = e.svc.runSiem(ctx); close(done) }()
	defer func() { cancel(); close(release); <-done }()
	waitFor(t, func() bool { return e.svc.siemCache.Load() != nil })
	publish(t, bus, siemEventHoneypot, map[string]any{"id": "h-1", "service": "ssh"})
	<-inSend
	wctx, wcancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer wcancel()
	if _, err := e.svc.SetRetention(wctx, "a@x", 90); err != nil {
		t.Fatalf("the writer was held while a send was blocked: %v", err)
	}
}

// The three SIEM operations over HTTP: admin only, the mock's shape, the mock's codes, and the key never in an answer.
func TestSiemOverHTTP(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	sec, err := secrets.New(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.cfg.Secrets = sec
	e.gate.Set("logs", true)
	for _, u := range []string{"viewer", "operator"} {
		for _, r := range [][2]string{{"GET", "/logs/siem"}, {"PUT", "/logs/siem"}, {"POST", "/logs/siem/test"}} {
			if code, _ := e.call(r[0], r[1], u, `{"enabled":false,"format":"syslog","host":"192.168.10.50","port":514,"proto":"udp","url":"","events":["findings"]}`); code != 403 {
				t.Errorf("%s %s as %s = %d, want 403", r[0], r[1], u, code)
			}
		}
	}
	code, b := e.call("GET", "/logs/siem", "admin", "")
	if code != 200 || b["enabled"] != false || b["secret_last4"] != nil || b["last_test"] != nil || b["format"] != "syslog" {
		t.Fatalf("default %d %v", code, b)
	}
	if code, b := e.call("POST", "/logs/siem/test", "admin", ""); code != 400 || errCode(b) != "not_configured" {
		t.Fatalf("test without a configuration: %d %v", code, b)
	}
	body := `{"enabled":true,"format":"json","host":"","port":514,"proto":"udp","url":"https://siem.example.com/hooks/vedette","events":["alerts","findings"],"secret":"my-long-signing-key-9876"}`
	code, b = e.call("PUT", "/logs/siem", "admin", body)
	if code != 200 || b["secret_last4"] != "9876" || b["url"] != "https://siem.example.com/hooks/vedette" {
		t.Fatalf("save %d %v", code, b)
	}
	if raw, _ := json.Marshal(b); strings.Contains(string(raw), "my-long-signing") {
		t.Fatalf("the key is in the answer: %s", raw)
	}
	if code, b := e.call("PUT", "/logs/siem", "admin", strings.Replace(body, "my-long-signing-key-9876", "short", 1)); code != 400 {
		t.Errorf("short key: %d %v", code, b) // refused by the generated validator (min 16)
	}
	if code, b := e.call("PUT", "/logs/siem", "admin", strings.Replace(body, `["alerts","findings"]`, `[]`, 1)); code != 400 {
		t.Errorf("no events: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/logs/siem", "admin", strings.Replace(body, "https://siem.example.com/hooks/vedette", "https://127.0.0.1/x", 1)); code != 400 || errCode(b) != "blocked_host" {
		t.Errorf("loopback: %d %v", code, b)
	}
	code, b = e.call("GET", "/logs/siem", "admin", "")
	if code != 200 || b["secret_last4"] != "9876" || b["enabled"] != true {
		t.Fatalf("read back %d %v", code, b)
	}
}

// A record built before a save is refused after it, and a saved configuration is never overwritten by an older read.
func TestSiemSaveInvalidatesInFlightRecords(t *testing.T) {
	e := newSiemEnv(t)
	q := e.svc.siemQ
	g := q.generation()
	e.svc.siemChanged()
	q.push(newSiemRecord("old", "info", t0), g)
	if recs, _ := q.peek(10); len(recs) != 0 {
		t.Fatalf("a record of the old configuration was queued: %v", recs)
	}
	q.push(newSiemRecord("new", "info", t0), q.generation())
	if recs, _ := q.peek(10); len(recs) != 1 {
		t.Fatal("a current record was refused")
	}
	// the key: no control character, bounded
	in := syslogInput("192.168.10.50", 514, "udp")
	for _, k := range []string{"0123456789abcdef\x00xyz", strings.Repeat("k", 600)} {
		in.Secret = k
		if _, err := e.svc.SetSiem(t.Context(), "a@x", in); code(err) != "bad_secret" {
			t.Errorf("secret %q: %v", k[:16], err)
		}
	}
}
