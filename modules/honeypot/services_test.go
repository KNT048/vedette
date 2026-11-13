package honeypot_test

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/honeypot"
)

// realLines are lines the pinned OpenCanary (0.9.10, the honeypot image's rootfs) wrote when each new service was touched once
// on loopback (B3, D-467): only the addresses and the times were replaced (source 192.168.10.157, Trap IP 192.168.10.240, times
// from t0). The UDP services report the target 0.0.0.0, as OpenCanary does.
func realLines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "opencanary-0.9.10-lines.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// newServices are the services B3 adds.
var newServices = []honeypot.ServiceName{honeypot.HTTPS, honeypot.FTP, honeypot.Telnet, honeypot.MySQL, honeypot.MongoDB, honeypot.Redis,
	honeypot.VNC, honeypot.Git, honeypot.HTTPProxy, honeypot.TCPBanner, honeypot.TFTP, honeypot.NTP, honeypot.SIP}

// Every new service turns OpenCanary's own lines into a hit with its label, port and Trap IP, and no password (nor anything made
// of one: the MySQL scramble, the VNC answer, Redis's AUTH argument, MongoDB's auth_data) is stored anywhere: not in the hit, its
// lines, the hit detail or the export (security.md, the rule of the SSH and HTTP logins).
func TestEveryNewServiceMakesAHitWithoutThePassword(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addTrapIP("BUILD-SRV-02", "192.168.10.240", honeypot.Custom, newServices...)
	e.appendLog(realLines(t)...)
	e.poll()
	hits, err := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		label, excerpt string
		port, conns    int
	}
	wants := map[honeypot.ServiceName]want{
		honeypot.FTP:       {"FTP", `login attempt, account "bob"`, 21, 1},
		honeypot.Telnet:    {"Telnet", `new connection; login attempt, account "admin"`, 23, 2},
		honeypot.MySQL:     {"MySQL", `new connection; login attempt, account "root"`, 3306, 2},
		honeypot.MongoDB:   {"MongoDB", `new connection; command "query:admin.$cmd"; login attempt, account "mongoadmin"; connection closed`, 27017, 4},
		honeypot.Redis:     {"Redis", `command "AUTH"; command "CONFIG GET"`, 6379, 2},
		honeypot.VNC:       {"VNC", "login attempt (answered the VNC password challenge)", 5900, 1},
		honeypot.Git:       {"Git", `clone request for repository "secret.git"`, 9418, 1},
		honeypot.HTTPProxy: {"HTTP proxy", `proxy login attempt, account "bob"`, 8080, 1},
		honeypot.TCPBanner: {"SMTP", "new connection", 25, 1},
		honeypot.HTTPS:     {"HTTPS", "request GET /index.html, User-Agent: probe/1", 443, 1},
		honeypot.TFTP:      {"TFTP", `read request for file "passwords.txt"`, 69, 1},
		honeypot.NTP:       {"NTP", "monlist request", 123, 1},
		honeypot.SIP:       {"SIP", "SIP request", 5060, 1},
	}
	got := map[honeypot.ServiceName]honeypot.Hit{}
	for _, h := range hits {
		if h.Kind != honeypot.KindService || h.Service == nil {
			t.Fatalf("not a service hit: %+v", h)
		}
		got[*h.Service] = h
	}
	for svc, w := range wants {
		h, ok := got[svc]
		switch {
		case !ok:
			t.Errorf("%s: no hit", svc)
			continue
		case h.Label != w.label || h.Port == nil || *h.Port != w.port || h.TrapIP != "192.168.10.240" || h.TrapHostname != "BUILD-SRV-02" || h.SrcIP != "192.168.10.157":
			t.Errorf("%s: %+v", svc, h)
		case !strings.HasPrefix(h.Excerpt, w.excerpt):
			t.Errorf("%s: excerpt %q, want %q", svc, h.Excerpt, w.excerpt)
		}
		if n := e.count(`SELECT conn_count FROM hp_hits WHERE id = ?`, h.ID); n != w.conns {
			t.Errorf("%s: %d connections, want %d", svc, n, w.conns)
		}
	}
	if len(got) != len(wants) {
		t.Errorf("%d services hit, want %d", len(got), len(wants))
	}
	var all bytes.Buffer
	for _, h := range hits {
		d, err := e.svc.HitDetail(e.ctx(), h.ID)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(d)
		all.Write(b)
	}
	if err := e.svc.ExportHits(e.ctx(), time.Time{}, time.Time{}, &all); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2", "pw123", "0101010101", "s3cret", `"secret"`, "Password was not", "6e2c2c6e", "auth_data", "Server Challenge", "VNC Client"} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("%q is stored", secret)
		}
	}
}

// A bait account used on any login trap fires its token, the new ones too (POST-2): the token names the account, never the password.
func TestABaitAccountFiresOnTheNewLogins(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addTrapIP("BUILD-SRV-02", "192.168.10.240", honeypot.Custom, newServices...)
	tok, err := e.svc.AddToken(e.ctx(), "a", honeypot.TokenInput{Type: honeypot.TokenCredential, Name: "svc-backup-old", PlantAt: "wiki"})
	if err != nil {
		t.Fatal(err)
	}
	src := []string{"192.168.10.151", "192.168.10.152", "192.168.10.153", "192.168.10.154", "192.168.10.155"}
	e.appendLog(
		ln{LogType: 2000, Src: src[0], SrcPort: 1, DstPort: 21, At: t0, Data: map[string]any{"USERNAME": tok.Value, "PASSWORD": "pw-never"}}.json(),
		ln{LogType: 6001, Src: src[1], SrcPort: 1, DstPort: 23, At: t0, Data: map[string]any{"USERNAME": tok.Value, "PASSWORD": "pw-never"}}.json(),
		ln{LogType: 8001, Src: src[2], SrcPort: 1, DstPort: 3306, At: t0, Data: map[string]any{"USERNAME": tok.Value, "PASSWORD": "ab"}}.json(),
		ln{LogType: 7001, Src: src[3], SrcPort: 1, DstPort: 8080, At: t0, Data: map[string]any{"USERNAME": tok.Value, "PASSWORD": "pw-never"}}.json(),
		ln{LogType: 20001, Src: src[4], SrcPort: 1, DstPort: 27017, At: t0, Data: map[string]any{"action": "mongodb.auth_attempt", "username": tok.Value}}.json(),
		// a Redis AUTH carries only a password: it is no account, and it never fires a token
		ln{LogType: 17001, Src: src[4], SrcPort: 2, DstPort: 6379, At: t0, Data: map[string]any{"CMD": "AUTH", "ARGS": tok.Value}}.json(),
	)
	e.poll()
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE kind = 'token'`); n != 5 {
		t.Fatalf("%d token hits, want one per login service", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE events LIKE '%pw-never%' OR excerpt LIKE '%pw-never%'`); n != 0 {
		t.Fatal("a password is stored")
	}
}

// An NTLM token on the proxy trap can carry the answer to the challenge (password material): never stored, the line says NTLM.
func TestTheProxyNeverStoresAnNTLMToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addTrapIP("PROXY-01", "192.168.10.240", honeypot.Custom, honeypot.HTTPProxy)
	ntlm := "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAAAAAB"
	e.appendLog(ln{LogType: 7001, Src: "192.168.10.157", SrcPort: 1, DstPort: 8080, At: t0, Data: map[string]any{"USERNAME": ntlm, "PASSWORD": ""}}.json())
	e.poll()
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE excerpt = 'proxy login attempt (NTLM)' AND events NOT LIKE '%TlRMTVNT%'`); n != 1 {
		t.Fatalf("%d", n)
	}
}

// A UDP line has no target (0.0.0.0): the hit names the oldest Trap IP with the service and is not fed to the sweep, which would
// count one Trap IP for another; the line of a Trap IP without the service is still no hit (INV-18).
func TestAUDPLineNamesTheTrapIPWithTheService(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addTrapIP("FILESRV-OLD", "192.168.10.240", honeypot.Custom, honeypot.SMB)
	e.addTrapIP("PRN-FLOOR2", "192.168.10.241", honeypot.Printer, honeypot.HTTP, honeypot.TFTP)
	e.appendLog(
		ln{LogType: 16001, Src: "192.168.10.157", SrcPort: 5, Dst: "0.0.0.0", DstPort: 9418, At: t0, Data: map[string]any{"REPO": "x"}}.json(), // no Trap IP has Git
		ln{LogType: 10001, Src: "192.168.10.157", SrcPort: 5, Dst: "0.0.0.0", DstPort: 69, At: t0, Data: map[string]any{"FILENAME": "boot.cfg", "OPCODE": "WRITE"}}.json(),
		ln{LogType: 5000, Src: "192.168.10.157", Dst: "192.168.10.240", At: t0.Add(5 * time.Second), Data: map[string]any{"FILENAME": "/"}}.json(),
	)
	e.poll()
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	var tftp *honeypot.Hit
	for i, h := range hits {
		if h.Kind == honeypot.KindScan {
			t.Fatalf("a UDP line and one Trap IP's line made a sweep: %+v", h)
		}
		if h.Service != nil && *h.Service == honeypot.TFTP {
			tftp = &hits[i]
		}
	}
	if len(hits) != 2 || tftp == nil || tftp.TrapIP != "192.168.10.241" || tftp.TrapHostname != "PRN-FLOOR2" || tftp.Excerpt != `write request for file "boot.cfg". UDP has no handshake, so the source address may be forged.` || !tftp.NoHandshake {
		t.Fatalf("%+v", hits)
	}
}

// Each Trap IP's host allow-list carries its services' own protocol and port: TFTP, NTP and SIP are UDP (host-api 6.6).
func TestTheHostGetsUDPPortsForTheUDPServices(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addTrapIP("VOIP-01", "192.168.10.241", honeypot.Custom, honeypot.SIP, honeypot.TFTP, honeypot.HTTPS, honeypot.NTP)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	got := e.host.specs[addr("192.168.10.241")].Ports
	e.host.mu.Unlock()
	want := []honeypot.Port{{Proto: "tcp", Port: 443}, {Proto: "udp", Port: 69}, {Proto: "udp", Port: 123}, {Proto: "udp", Port: 5060}}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
}

// The HTTPS trap's certificate (D-467): core makes it self-signed for the first Trap IP with HTTPS (its name, its vendor), writes
// it and its key to config/ for the container, keeps the same pair across a restart of core, and makes a new one when another Trap
// IP decides the name. The key is a core_secret row: hp_config holds only its id, so neither the export nor the logs can carry it.
func TestTheHTTPSTrapHasItsOwnCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "config", honeypot.CertFile)); !os.IsNotExist(err) {
		t.Fatalf("a certificate without an HTTPS trap: %v", err)
	}
	vendor := "synology"
	nas, err := e.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "NAS-ARCHIVE", IP: "192.168.10.241", Preset: honeypot.NAS, Vendor: &vendor, Services: []honeypot.ServiceName{honeypot.HTTP, honeypot.HTTPS, honeypot.SMB}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	cert, key := e.readCert()
	if cert.Subject.CommonName != "nas-archive" || !slices.Equal(cert.Subject.Organization, []string{"Synology"}) || cert.Issuer.String() != cert.Subject.String() ||
		!slices.Equal(cert.DNSNames, []string{"nas-archive"}) || !cert.NotAfter.After(t0.AddDate(4, 0, 0)) {
		t.Fatalf("%v issued by %v, %v, until %v", cert.Subject, cert.Issuer, cert.DNSNames, cert.NotAfter)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("not self-signed: %v", err)
	}
	conf, _ := os.ReadFile(e.confPath())
	for _, kv := range []string{`"https.enabled": true`, `"https.certificate": "/etc/opencanaryd/https.pem"`, `"https.key": "/etc/opencanaryd/https.pem"`, `"https.skin": "nasLogin"`, `"http.log_redirect_request": true`} {
		if !strings.Contains(string(conf), kv) {
			t.Errorf("opencanary.conf has no %s", kv)
		}
	}
	var value string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT value FROM hp_config WHERE key = 'https'`).Scan(&value); err != nil || strings.Contains(value, "PRIVATE") || !strings.Contains(value, "secret_id") {
		t.Fatalf("hp_config https = %q, %v", value, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_secret WHERE purpose = 'hp_https.key'`); n != 1 {
		t.Fatalf("%d sealed keys", n)
	}

	// a restart of core: the same pair, written again (core never reads config/ back)
	again := e.restart()
	if err := again.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	cert2, key2 := e.readCert()
	if !cert2.Equal(cert) || !bytes.Equal(key, key2) {
		t.Fatal("a restart made a new certificate")
	}

	// another Trap IP decides the name (the NAS goes): a new certificate with its name, the old key's row gone
	if err := again.svc.DeleteTrapIP(e.ctx(), "a", nas.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := again.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "WEB-OLD", IP: "192.168.10.242", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.HTTPS}}); err != nil {
		t.Fatal(err)
	}
	if err := again.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	cert3, key3 := e.readCert()
	if cert3.Subject.CommonName != "web-old" || len(cert3.Subject.Organization) != 0 || bytes.Equal(key3, key) {
		t.Fatalf("%v", cert3.Subject)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_secret WHERE purpose = 'hp_https.key'`); n != 1 {
		t.Fatalf("%d sealed keys", n)
	}
	names, _ := os.ReadDir(filepath.Join(e.dir, "config"))
	for _, f := range names {
		if strings.HasPrefix(f.Name(), "https.") && f.Name() != honeypot.CertFile {
			t.Errorf("a second key or certificate file: %s", f.Name())
		}
	}

	// review L1: no Trap IP has HTTPS any more: its key leaves the shared folder; the module off: the same
	if _, err := again.svc.EditTrapIP(e.ctx(), "a", tipID(t, again, "WEB-OLD"), honeypot.TrapIPInput{Name: "WEB-OLD", IP: "192.168.10.242", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.SSH}}); err != nil {
		t.Fatal(err)
	}
	if err := again.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "config", honeypot.CertFile)); !os.IsNotExist(err) {
		t.Fatalf("the key stays without an HTTPS trap: %v", err)
	}
	if _, err := again.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "WEB-NEW", IP: "192.168.10.243", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.HTTPS}}); err != nil {
		t.Fatal(err)
	}
	if err := again.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.readCert()
	if err := again.svc.Disable(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "config", honeypot.CertFile)); !os.IsNotExist(err) {
		t.Fatalf("the key stays with the module off: %v", err)
	}
}

func tipID(t *testing.T, e *env, name string) string {
	t.Helper()
	r, err := e.svc.TrapIPs(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Items {
		if d.Name == name {
			return d.ID
		}
	}
	t.Fatalf("no Trap IP %s", name)
	return ""
}

// restart is a new Service on the same database and folders: what core is after a restart.
func (e *env) restart() *env {
	e.t.Helper()
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	c := *e
	c.svc = svc
	return &c
}

// readCert reads the HTTPS trap's one file: the key, then the certificate it names, and nothing else (review L2: one rename replaces
// the pair, so the container never reads a new key with an old certificate).
func (e *env) readCert() (*x509.Certificate, []byte) {
	e.t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.dir, "config", honeypot.CertFile))
	if err != nil {
		e.t.Fatal(err)
	}
	k, rest := pem.Decode(raw)
	if k == nil || k.Type != "PRIVATE KEY" {
		e.t.Fatal("the file does not start with the key")
	}
	b, rest := pem.Decode(rest)
	if b == nil || b.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		e.t.Fatal("the key is not followed by the certificate alone")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		e.t.Fatal(err)
	}
	pub, err := x509.ParsePKCS8PrivateKey(k.Bytes)
	if err != nil {
		e.t.Fatal(err)
	}
	if !c.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(pub.(crypto.Signer).Public()) {
		e.t.Fatal("the certificate does not name the key")
	}
	return c, k.Bytes
}

// The banners follow the Trap IP that decides each service (the first with it): a NAS's FTP greets as a Synology, a Windows file
// server's mail greeting is Microsoft's; none of them is the box's own.
func TestBannersFollowTheTrapIPThatDecides(t *testing.T) {
	t.Parallel()
	looks := map[honeypot.ServiceName]honeypot.Look{
		honeypot.FTP: {Name: "NAS-ARCHIVE", Preset: honeypot.NAS}, honeypot.TCPBanner: {Name: "FILESRV-OLD", Preset: honeypot.FileServer},
		honeypot.MySQL: {Name: "SQL-OLD-01", Preset: honeypot.Database},
	}
	b, err := honeypot.RenderConfig(honeypot.ConfigInput{Enabled: []honeypot.ServiceName{honeypot.FTP, honeypot.TCPBanner, honeypot.MySQL}, LogPath: "/v/x.jsonl", Looks: looks})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c["ftp.banner"] != "NAS-ARCHIVE FTP server ready." || c["tcpbanner_1.initbanner"] != "220 FILESRV-OLD Microsoft ESMTP MAIL Service ready\r\n" ||
		c["mysql.banner"] != "5.7.44-log" || c["mysql.log_connection_made"] != true || c["telnet.log_tcp_connection"] != false {
		t.Fatalf("%v %q %v", c["ftp.banner"], c["tcpbanner_1.initbanner"], c["mysql.banner"])
	}
	for k, v := range c {
		if s, ok := v.(string); ok && strings.Contains(s, "$") {
			t.Errorf("%s has a $ (OpenCanary expands it): %q", k, s)
		}
	}
}

// M5-188: a second SMB visit within the hit window is a line of the hit and a connection more, although Samba's line has no source
// port and the same text; the same log line read twice (a batch that failed and is read again) still changes nothing.
func TestASecondSMBVisitIsALineOfTheHit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	visit := func(at time.Time) string {
		return ln{LogType: 5000, Src: "192.168.10.157", Dst: "192.168.10.240", At: at, Data: map[string]any{"FILENAME": "/"}}.json()
	}
	e.appendLog(visit(t0), visit(t0.Add(2*time.Minute)))
	e.poll()
	e.appendLog(visit(t0.Add(2 * time.Minute))) // the same line again
	e.poll()
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	if n := e.count(`SELECT conn_count FROM hp_hits WHERE id = ?`, hits[0].ID); n != 2 {
		t.Fatalf("%d connections, want 2", n)
	}
	d, err := e.svc.HitDetail(e.ctx(), hits[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var visits []string
	for _, ev := range d.Events {
		if ev.Text == "SMB trap: share opened" {
			visits = append(visits, ev.TS)
		}
	}
	if len(visits) != 2 || visits[0] == visits[1] {
		t.Fatalf("the visits in the hit's lines: %v (%+v)", visits, d.Events)
	}
}

// M5-189, INV-9: exactly one line of a hit is marked, the hit's own first line; the connections folded into it are not, and a row
// stored before the rule (every line marked) is shown by the rule.
func TestOnlyTheHitsOwnLineIsMarked(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.appendLog(sshNew("192.168.10.157", 5000, t0).json(), sshLogin("192.168.10.157", 5000, t0.Add(time.Second), "root").json(),
		sshNew("192.168.10.157", 5001, t0.Add(time.Minute)).json())
	e.poll()
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	check := func(what string) {
		t.Helper()
		d, err := e.svc.HitDetail(e.ctx(), hits[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		var marked []string
		for _, ev := range d.Events {
			if ev.Mark {
				marked = append(marked, ev.Text)
			}
		}
		if len(d.Events) < 3 || len(marked) != 1 || marked[0] != "SSH trap: 192.168.10.157 connected to 192.168.10.240:22" {
			t.Fatalf("%s: marked %v of %+v", what, marked, d.Events)
		}
	}
	check("stored now")
	if n := e.count(`SELECT COUNT(*) FROM hp_hits, json_each(hp_hits.events) j WHERE json_extract(j.value, '$.mark') = 1`); n != 1 {
		t.Fatalf("%d stored lines marked", n)
	}
	if err := e.db.Write(e.ctx(), func(tx *sqlTx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE hp_hits SET events = (SELECT json_group_array(json_set(j.value, '$.mark', json('true'))) FROM json_each(hp_hits.events) j)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	check("stored before the rule")
}

// Review H1: a UDP trap (TFTP, NTP, SIP) completes no handshake, so one datagram with a forged source makes its line. Its hit never
// confirms the source (SourceConnected, D-509), never takes "may be forged" off a scan of that source, says itself that the source
// may be forged, and its event is marked unconfirmed (response holds it from pre-approved rules). A real TCP connection still confirms.
func TestAForgedUDPDatagramNeverConfirmsItsSource(t *testing.T) {
	t.Parallel()
	var list []honeypot.Touch
	e := newEnv(t, func(e *env) { e.cfg.Host = touchHost{fakeHost: e.host, list: &list} })
	e.now = t0.Add(time.Minute)
	e.addTrapIP("PRN-FLOOR2", "192.168.10.241", honeypot.Printer, honeypot.HTTP, honeypot.TFTP, honeypot.NTP, honeypot.SIP)
	e.addTrapIP("FILESRV-OLD", "192.168.10.240", honeypot.Custom, honeypot.SSH)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	innocent := "192.168.10.50"
	// a scan of attempts only from the innocent address: "may be forged"
	list = []honeypot.Touch{{Src: addr(innocent), Dst: addr("192.168.10.240"), At: t0}, {Src: addr(innocent), Dst: addr("192.168.10.241"), At: t0.Add(time.Second)}}
	if err := e.svc.PollTouches(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.appendLog(
		ln{LogType: 10001, Src: innocent, SrcPort: 5, Dst: "0.0.0.0", DstPort: 69, At: t0.Add(time.Minute), Data: map[string]any{"FILENAME": "x", "OPCODE": "READ"}}.json(),
		ln{LogType: 11001, Src: innocent, SrcPort: 5, Dst: "0.0.0.0", DstPort: 123, At: t0.Add(time.Minute), Data: map[string]any{"NTP CMD": "monlist"}}.json(),
		ln{LogType: 15001, Src: innocent, SrcPort: 5, Dst: "0.0.0.0", DstPort: 5060, At: t0.Add(time.Minute)}.json(),
	)
	e.poll()
	if ok, err := e.svc.SourceConnected(e.ctx(), innocent, t0, time.Hour); err != nil || ok {
		t.Fatalf("UDP lines confirm the source: %v %v", ok, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE kind = 'scan' AND excerpt LIKE '%may be forged%'`); n != 1 {
		t.Fatalf("a UDP line took the forged note off the scan: %d", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE kind = 'service' AND handshake = 0 AND excerpt LIKE '%UDP has no handshake%'`); n != 3 {
		t.Fatalf("%d UDP hits say the source may be forged", n)
	}
	var unconfirmed int
	for _, ev := range e.pub.all() {
		if d, ok := ev.Data.(honeypot.HitEventData); ok && d.Kind == honeypot.KindService {
			if !d.Unconfirmed {
				t.Fatalf("a UDP hit event is not marked unconfirmed: %+v", d)
			}
			unconfirmed++
		}
	}
	if unconfirmed != 3 {
		t.Fatalf("%d hit events", unconfirmed)
	}
	// a real connection does confirm, and takes the note off
	e.appendLog(sshNew(innocent, 5000, t0.Add(2*time.Minute)).json())
	e.poll()
	if ok, _ := e.svc.SourceConnected(e.ctx(), innocent, t0, time.Hour); !ok {
		t.Fatal("an SSH connection does not confirm the source")
	}
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	for _, h := range hits {
		if h.Service != nil && *h.Service == honeypot.SSH && h.NoHandshake {
			t.Fatalf("an SSH hit is marked without handshake: %+v", h)
		}
	}
}

// Review M1: forged UDP datagrams with rotating sources make at most maxUDPHitsPerHour (20) new hits an hour, from their own budget:
// the hits of real connections keep theirs, so an SSH login after the flood is still a hit.
func TestForgedUDPHasItsOwnHitBudget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addTrapIP("PRN-FLOOR2", "192.168.10.241", honeypot.Printer, honeypot.TFTP, honeypot.SSH)
	var lines []string
	for i := range 30 {
		lines = append(lines, ln{LogType: 10001, Src: fmt.Sprintf("10.9.%d.%d", i/200, 1+i%200), SrcPort: 5, Dst: "0.0.0.0", DstPort: 69, At: t0, Data: map[string]any{"FILENAME": "x"}}.json())
	}
	e.appendLog(lines...)
	e.poll()
	e.appendLog(lines[:5]...) // the same sources again: no new hit, nothing taken
	login := sshLogin("192.168.10.157", 5000, t0.Add(time.Minute), "root")
	login.Dst = "192.168.10.241"
	e.appendLog(login.json())
	e.poll()
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE handshake = 0`); n != 20 {
		t.Fatalf("%d UDP hits, want the hourly budget of 20", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE service = 'ssh'`); n != 1 {
		t.Fatalf("the SSH login after the flood: %d hits", n)
	}
	if st := e.svc.Stats(); st.Suppressed != 10 {
		t.Fatalf("%d suppressed, want 10", st.Suppressed)
	}
	// the next hour has a new budget
	e.now = t0.Add(time.Hour)
	e.appendLog(ln{LogType: 10001, Src: "10.9.9.9", SrcPort: 5, Dst: "0.0.0.0", DstPort: 69, At: e.now, Data: map[string]any{"FILENAME": "x"}}.json())
	e.poll()
	if n := e.count(`SELECT COUNT(*) FROM hp_hits WHERE handshake = 0`); n != 21 {
		t.Fatalf("%d UDP hits in the next hour", n)
	}
}

// Review L4: migration 0004 rebuilds hp_hits and hp_config with every row and column as they were; the rows stored before get
// handshake 1 (every hit before B3 was a TCP one); afterwards a hit may name a new service, hp_config may hold "https", and the CHECKs
// still refuse what is not one.
func TestMigration0004KeepsEveryHitAndSetting(t *testing.T) {
	t.Parallel()
	db := migratedBeforeV(t, "0004")
	ctx := t.Context()
	exec := func(q string, args ...any) error {
		return db.Write(ctx, func(tx *sqlTx) error { _, err := tx.ExecContext(ctx, q, args...); return err })
	}
	const cols = `id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, token_id, events, conn_key, conn_count`
	key := strings.Repeat("a", 64)
	for _, q := range []string{
		`INSERT INTO hp_hits (` + cols + `) VALUES ('hit-1', '2026-11-09T10:00:00.000Z', 'service', 'smb', 'SMB', 445, '192.168.10.157', 0, 'share opened', '192.168.10.240', 'FILESRV-OLD', NULL, '[{"ts":"2026-11-09T10:00:00.000Z","source":"honeypot","text":"x","mark":true}]', '` + key + `', 3)`,
		`INSERT INTO hp_hits (` + cols + `) VALUES ('hit-2', '2026-11-09T10:01:00.000Z', 'token', NULL, 'File token Payroll', NULL, '192.168.10.158', 0, 'File opened', 'Payroll.xlsx', 'File token Payroll', 'tok-1', '[]', NULL, 1)`,
		`INSERT INTO hp_hits (` + cols + `) VALUES ('hit-3', '2026-11-09T10:02:00.000Z', 'scan', NULL, 'Scan across the Trap IPs', NULL, '192.168.10.159', 1, '[test] sweep', '192.168.10.240, 192.168.10.241', 'Decoy sweep', NULL, '[]', NULL, 1)`,
		`INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('applied', '["192.168.10.240"]', '2026-11-09T10:00:00.000Z', 'system'), ('tail', '{"offset":42}', '2026-11-09T10:00:00.000Z', 'system')`,
	} {
		if err := exec(q); err != nil {
			t.Fatal(err)
		}
	}
	dump := func(q string) string {
		t.Helper()
		rows, err := db.Reader().QueryContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		names, _ := rows.Columns()
		var out []string
		for rows.Next() {
			vals := make([]any, len(names))
			ptrs := make([]any, len(names))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprint(vals...))
		}
		return strings.Join(out, "\n")
	}
	hitsBefore := dump(`SELECT ` + cols + `, source_ip FROM hp_hits ORDER BY id`)
	confBefore := dump(`SELECT key, value, updated_at, updated_by FROM hp_config ORDER BY key`)
	if err := store.Migrate(ctx, db, "honeypot", honeypot.Migrations); err != nil {
		t.Fatal(err)
	}
	if got := dump(`SELECT ` + cols + `, source_ip FROM hp_hits ORDER BY id`); got != hitsBefore {
		t.Fatalf("hp_hits changed:\n%s\nwant\n%s", got, hitsBefore)
	}
	if got := dump(`SELECT key, value, updated_at, updated_by FROM hp_config ORDER BY key`); got != confBefore {
		t.Fatalf("hp_config changed:\n%s\nwant\n%s", got, confBefore)
	}
	if got := dump(`SELECT COUNT(*) FROM hp_hits WHERE handshake = 1`); got != "3" {
		t.Fatalf("%s rows with handshake 1", got)
	}
	if err := exec(`INSERT INTO hp_hits (id, ts, kind, service, label, port, src_ip, excerpt, trap_ip, trap_hostname, handshake) VALUES ('hit-4', '2026-11-09T10:03:00.000Z', 'service', 'tftp', 'TFTP', 69, '192.168.10.160', 'x', '192.168.10.240', 'X', 0)`); err != nil {
		t.Fatalf("a new service: %v", err)
	}
	if err := exec(`INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('https', '{"secret_id":"sec-1"}', '2026-11-09T10:00:00.000Z', 'system')`); err != nil {
		t.Fatalf("the https key: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO hp_hits (id, ts, kind, service, label, src_ip, excerpt, trap_ip, trap_hostname) VALUES ('hit-5', '2026-11-09T10:03:00.000Z', 'service', 'snmp', 'SNMP', '192.168.10.160', 'x', 'x', 'X')`,
		`INSERT INTO hp_hits (id, ts, kind, service, label, src_ip, excerpt, trap_ip, trap_hostname, handshake) VALUES ('hit-6', '2026-11-09T10:03:00.000Z', 'service', 'ssh', 'SSH', '192.168.10.160', 'x', 'x', 'X', 2)`,
		`INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('config', '{}', '2026-11-09T10:00:00.000Z', 'system')`,
	} {
		if err := exec(q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	if got := dump(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'hp_hits' AND sql IS NOT NULL ORDER BY name`); got != "hp_hits_src_ix\nhp_hits_token_ix\nhp_hits_ts_ix" {
		t.Fatalf("indexes: %s", got)
	}
}
