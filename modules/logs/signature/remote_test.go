package signature

import (
	"net/netip"
	"strings"
	"testing"
)

func addrOf(t *testing.T, s string) netip.Addr {
	t.Helper()
	if s == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestParseAddr(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:22", "1.2.3.4"},
		{`"1.2.3.4"`, "1.2.3.4"},
		{"<1.2.3.4>", "1.2.3.4"},
		{"1.2.3.4,", "1.2.3.4"},
		{"1.2.3.4:", "1.2.3.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::", "2001:db8::"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"::ffff:10.1.1.1", "10.1.1.1"},          // IPv4-mapped is the IPv4 address
		{"[::ffff:10.1.1.1]:80", "10.1.1.1"},     //
		{"fe80::1%eth0", "fe80::1"},              // the zone is dropped
		{"2001:db8::7%12", "2001:db8::7"},        //
		{"unknown[203.0.113.9]:", "203.0.113.9"}, // postfix
		{"mail.example.com[203.0.113.9]", "203.0.113.9"},
		{"https(198.51.100.4)", "198.51.100.4"}, // FortiGate ui=
		{"[AF_INET]203.0.113.5:51820", "203.0.113.5"},
		{"[AF_INET6]2001:db8::5", "2001:db8::5"},
		{"  8.8.8.8  ", "8.8.8.8"},
		{"", ""},
		{"-", ""},
		{"garbage", ""},
		{"999.1.1.1", ""},
		{"1.2.3", ""},
		{"1.2.3.4.5", ""},
		{"010.1.1.1", ""}, // leading zero: not an address
		{"1.2.3.4:99999x", ""},
		{"[1.2.3.4", ""},
		{"[::1", ""},
		{"1234", ""},
		{"sshd[1234]:", ""}, // a process id in brackets is not an address
		{"0x7f000001", ""},
		{strings.Repeat("1", 200), ""},
	} {
		got, ok := ParseAddr(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("%q gave %v", c.in, got)
			}
			continue
		}
		if !ok || got != addrOf(t, c.want) {
			t.Errorf("%q gave %v %v, want %s", c.in, got, ok, c.want)
		}
		if got.Zone() != "" || got.Is4In6() {
			t.Errorf("%q: %v has a zone or is mapped", c.in, got)
		}
	}
}

func TestCountable(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		a    string
		want bool
	}{
		{"203.0.113.5", true}, {"2001:db8::1", true},
		{"192.168.10.77", true}, {"10.0.0.5", true}, {"172.16.5.5", true}, {"fd00::5", true}, // a LAN brute-forcer is real
		{"0.0.0.0", false}, {"::", false}, {"127.0.0.1", false}, {"127.1.2.3", false}, {"::1", false},
		{"224.0.0.5", false}, {"239.255.255.250", false}, {"ff02::1", false},
		{"169.254.10.10", false}, {"fe80::1", false}, {"255.255.255.255", false},
	} {
		if got := Countable(addrOf(t, c.a)); got != c.want {
			t.Errorf("Countable(%s) = %v", c.a, got)
		}
	}
	if Countable(netip.Addr{}) {
		t.Error("the zero address is countable")
	}
}

// Each line is one layout of a daemon the miner already reads; the remote peer is the client, never the sender of the log.
func TestGenericRemote(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for _, c := range []struct{ line, want string }{
		{"sshd[812]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2", "203.0.113.9"},
		{"sshd[812]: Failed password for root from 2001:db8::9 port 51234 ssh2", "2001:db8::9"},
		{"sshd[812]: Invalid user oracle from 203.0.113.9 port 4444", "203.0.113.9"},
		{"sshd[812]: Connection closed by 203.0.113.9 port 22 [preauth]", "203.0.113.9"},
		{"sshd[812]: Connection closed by authenticating user root 203.0.113.9 port 22 [preauth]", "203.0.113.9"}, // R2: a bare address word is a candidate
		{"sshd[812]: Accepted publickey for bob from 10.1.2.3 port 5000 ssh2", "10.1.2.3"},
		{"sshd[812]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root", "203.0.113.9"},
		{"sshd[812]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=  user=root", ""},
		{"sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls", ""},
		{"su[99]: FAILED SU (to root) bob on pts/1", ""},
		{"dovecot: imap-login: Disconnected (auth failed, 3 attempts in 10 secs): user=<bob>, method=PLAIN, rip=203.0.113.20, lip=10.0.0.2, TLS", "203.0.113.20"},
		{"postfix/smtpd[77]: NOQUEUE: reject: RCPT from unknown[203.0.113.30]: 554 5.7.1 Relay access denied; from=<a@b.example> to=<c@d.example>", "203.0.113.30"},
		{"postfix/smtpd[77]: warning: unknown[203.0.113.31]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "203.0.113.31"},
		{"postfix/smtpd[77]: connect from mail.example.com[2001:db8::31]", "2001:db8::31"},
		{"postfix/smtpd[77]: disconnect from unknown[203.0.113.32] ehlo=1 auth=0/1 commands=1/2", "203.0.113.32"},
		{"postfix/smtpd[77]: lost connection after CONNECT from localhost[127.0.0.1]", ""},
		{"postfix/submission/smtpd[7]: client=unknown[203.0.113.33], sasl_username=bob", "203.0.113.33"},
		{"openvpn[1]: bob/203.0.113.40:51820 TLS Error: TLS handshake failed", "203.0.113.40"},
		{"openvpn[1]: 203.0.113.41:51820 TLS Error: TLS key negotiation failed", "203.0.113.41"}, // R2: a bare address word is a candidate
		{"openvpn[1]: TLS: Initial packet from [AF_INET]203.0.113.42:51820, sid=abc", "203.0.113.42"},
		{"kernel: IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=4444 DPT=22", "203.0.113.50"},
		{"app: login failed user=bob ip=203.0.113.60 reason=bad-password", "203.0.113.60"},
		{`app: login failed client_ip="203.0.113.61"`, "203.0.113.61"},
		{"app: login failed from 127.0.0.1", ""},
		{"app: login failed from 0.0.0.0", ""},
		{"app: login failed from ::1", ""},
		{"app: login failed from 224.0.0.251", ""},
		{"app: login failed from 169.254.3.3", ""},
		{"app: login failed from fe80::1%eth0", ""},
		{"app: login failed from 255.255.255.255", ""},
		{"app: login failed from 127.0.0.1 then from 203.0.113.70", "203.0.113.70"}, // the first countable one
		{"app: login failed from ::ffff:203.0.113.71", "203.0.113.71"},
		{"app: login failed from [2001:db8::71]:4433", "2001:db8::71"},
		{"app: login failed from not-an-address", ""},
		{"app: from", ""},
		{"app: 192.168.1.5 is mentioned with no layout", "192.168.1.5"}, // R2: the only address of the line
		{"app: gw=203.0.113.99 dst=1.1.1.1", ""},                        // dst and gw are not the peer
		// H1 (D-210): text that an attacker writes (a user name, a URL) must not name another address. Two different candidates in one line:
		// no address at all (the line still counts everywhere else); the same address twice is one.
		{"sshd[1]: Invalid user src=8.8.8.8 from 203.0.113.5 port 22", ""},
		{"sshd[1]: Invalid user x from 8.8.8.8 from 203.0.113.5 port 22", ""},
		{"sshd[1]: Failed password for invalid user rhost=8.8.8.8 from 203.0.113.5 port 22 ssh2", ""},
		{"sshd[1]: Failed password for invalid user a/8.8.8.8:1 from 203.0.113.5 port 22 ssh2", ""},
		{"sshd[1]: Failed password for invalid user a[8.8.8.8] from 203.0.113.5 port 22 ssh2", ""},
		{"sshd[1]: Failed password for invalid user ip=10.0.0.1 from 203.0.113.5 port 22 ssh2", ""},
		{"sshd[1]: Failed password for invalid user rip=8.8.8.8 from 203.0.113.5 port 22 ssh2", ""},
		{"sshd[1]: Connection closed by invalid user by 8.8.8.8 203.0.113.5 port 22 [preauth]", ""}, // "by" counts only before "addr port"
		{"sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2 rhost=203.0.113.5", "203.0.113.5"},
		{"nginx: 203.0.113.5 - - \"GET /login?client=8.8.8.8 HTTP/1.1\" 401", "203.0.113.5"}, // R2: the request is a quoted span; the client is the first word
		// R2 H1: nginx and apache have no profile; the text of the request, the referer and the agent is the client's.
		{"nginx: 203.0.113.5 - - [10/Nov/2026:10:00:00 +0000] \"POST http://h/8.8.8.8 HTTP/1.1\" 401 12", "203.0.113.5"},
		{"nginx: 203.0.113.5 - - [10/Nov/2026:10:00:00 +0000] \"POST /a[8.8.8.8] HTTP/1.1\" 401 12", "203.0.113.5"},
		{"nginx: 203.0.113.5 - - [10/Nov/2026:10:00:00 +0000] \"POST / HTTP/1.1\" 401 12 \"from 8.8.8.8\" \"src=8.8.8.8\"", "203.0.113.5"},
		{"nginx: 203.0.113.5 - - [10/Nov/2026:10:00:00 +0000] \"POST / HTTP/1.1\" 401 12 \"-\" \"curl\"", "203.0.113.5"},
		{"nginx: - - - [10/Nov/2026:10:00:00 +0000] \"POST /a[8.8.8.8] HTTP/1.1\" 401 12 \"src=8.8.8.8\"", ""}, // no client address: the quoted text is not read
		{"nginx: 203.0.113.5 - 8.8.8.8 [10/Nov/2026:10:00:00 +0000] \"POST / HTTP/1.1\" 401 12", ""},           // an unquoted second address: ambiguous
		{"sshd[1]: Invalid user x src=8.8.8.8 \" from 203.0.113.5 port 22 ssh2", ""},                           // an odd quote could hide the real address: none
		{"app: GET /a/8.8.8.8:80 from 203.0.113.5", "203.0.113.5"},
		{"app: GET http://x/8.8.8.8 from 203.0.113.5", ""},
		{"dovecot: imap-login: Disconnected (auth failed): user=<a rip=8.8.8.8>, method=PLAIN, rip=203.0.113.20, lip=10.0.0.2", ""},
		{"dovecot: imap-login: Disconnected (auth failed): user=<a/8.8.8.8:1>, method=PLAIN, rip=203.0.113.20, lip=10.0.0.2", ""},
		{"postfix/smtpd[7]: NOQUEUE: reject: RCPT from unknown[203.0.113.30]: 554 5.7.1 <x[8.8.8.8]>: Relay access denied", ""},
		{"openvpn[1]: x[8.8.8.8]/203.0.113.40:51820 TLS Error", ""},
		{"openvpn[1]: by/203.0.113.40:51820 from 8.8.8.8", ""},
		{"app: login failed from 192.168.10.2 from 203.0.113.70", ""}, // the evasion: the peer adds the box's address, and the line has no address
	} {
		r := set.Of("syslog", "<38>Nov  9 10:00:00 host "+c.line)
		if r.Profile != GenericProfile {
			t.Errorf("%q is read by %s", c.line, r.Profile)
		}
		if got := r.Remote; got != addrOf(t, c.want) {
			t.Errorf("%q\n got %v, want %q", c.line, got, c.want)
		}
	}
}

// The shipped profiles name the remote peer from their own fields and patterns, and the sender of the log is never it.
func TestShippedProfilesRemote(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for _, c := range []struct{ kind, line, want string }{
		// FortiGate: traffic has srcip; VPN events have remip; admin login has ui="https(addr)"; remip wins over srcip.
		{"fortigate", `logid="0000000013" type="traffic" srcip=203.0.113.1 dstip=10.0.0.1 action="deny"`, "203.0.113.1"},
		{"fortigate", `logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" user="bob" remip=203.0.113.2 srcip=10.9.9.9`, "203.0.113.2"},
		{"fortigate", `logid="0101039426" type="event" action="tunnel-up" remip=127.0.0.1 srcip=203.0.113.3`, "203.0.113.3"}, // loopback remip is skipped
		{"fortigate", `logid="0100032002" type="event" user="admin" ui="https(198.51.100.4)" action="login" status="failed"`, "198.51.100.4"},
		{"fortigate", `logid="0100032002" type="event" user="admin" ui="ssh(2001:db8::4)" action="login" status="failed"`, "2001:db8::4"},
		{"fortigate", `logid="0100032002" type="event" action="login" msg="Administrator admin login failed from https(198.51.100.5) because of invalid password"`, ""}, // msg is free text: no profile field, no generic reader
		// H1: a user name written into the line cannot be the address; a key written twice with two values is no address; msg is text.
		{"fortigate", `logid="0100032002" type="event" subtype="system" user="ui=https(8.8.8.8)" ui="https(203.0.113.4)" action="login" status="failed"`, "203.0.113.4"},
		{"fortigate", `logid="0100032002" type="event" subtype="system" user="x" action="login" status="failed" msg="Administrator x from 8.8.8.8 login failed"`, ""},
		{"fortigate", `logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" user="a\" remip=8.8.8.8 x=\"" remip=203.0.113.7`, "203.0.113.7"},
		{"fortigate", `logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" user="a" remip=8.8.8.8 x="" remip=203.0.113.7`, ""},
		{"fortigate", `logid="0100032002" type="event" subtype="system" user="a" srcip=8.8.8.8 x="" ui="https(203.0.113.4)" srcip=203.0.113.4 action="login"`, "203.0.113.4"},
		{"fortigate", `logid="0000000013" type="traffic" srcip=8.8.8.8 dstip=10.0.0.1 srcip=203.0.113.4 action="deny"`, ""},
		{"fortigate", `logid="0000000013" type="traffic" srcip=203.0.113.4 dstip=10.0.0.1 srcip=203.0.113.4 action="deny"`, "203.0.113.4"},
		{"fortigate", `logid="0100032002" type="event" action="login" ui="console" msg="Administrator admin login failed"`, ""},
		{"fortigate", `logid="0000000013" type="traffic" srcip=0.0.0.0 dstip=10.0.0.1 action="deny"`, ""},
		{"fortigate", `logid="0000000013" type="traffic" srcip="not an address" dstip=10.0.0.1 action="deny"`, ""},
		{"fortigate", `logid="0000000013" type="traffic" dstip=10.0.0.1 action="deny"`, ""}, // dstip is not the peer
		// Windows: 4625 Source Network Address, 4771 and 4768 Client Address, JSON and XML IpAddress; "-" is none.
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on.\tSource Network Address:\t203.0.113.50\tSource Port:\t52311", "203.0.113.50"},
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Source Network Address: -  Source Port: -", ""},
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Source Network Address: ::1  Source Port: 0", ""},
		{"windows", "<14>Nov  9 10:00:00 DC1 Security-Auditing: 4771: Kerberos pre-authentication failed. Client Address: ::ffff:198.51.100.9 Client Port: 49152", "198.51.100.9"},
		{"windows", "<14>Nov  9 10:00:00 DC1 Security-Auditing: 4768: A Kerberos authentication ticket (TGT) was requested. Client Address: 2001:db8::99", "2001:db8::99"},
		{"windows", `{"EventID":4625,"Channel":"Security","IpAddress":"2001:db8::5","IpPort":"0"}`, "2001:db8::5"},
		{"windows", `<Event><EventData><Data Name="IpAddress">203.0.113.51</Data></EventData><System><EventID>4625</EventID></System></Event>`, "203.0.113.51"},
		// H1: the labels are exact and anchored; a user or workstation name that carries a label makes a second candidate.
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on.\tAccount Name:\tIpAddress=8.8.8.8\tSource Network Address:\t203.0.113.50\tSource Port:\t1", "203.0.113.50"},
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Account Name: x Workstation Name: Client\tAddress:8.8.8.8 Source Network Address: 203.0.113.50 Source Port: 1", "203.0.113.50"},
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on.\tAccount Name:\tx Source Network Address:\t8.8.8.8\tSource Network Address:\t203.0.113.50", ""},
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Account Name: src=8.8.8.8 Source Network Address: - Source Port: -", ""},
		{"windows", `{"EventID":4625,"TargetUserName":"IpAddress:8.8.8.8","WorkstationName":"W","IpAddress":"203.0.113.50","IpPort":"1"}`, "203.0.113.50"},
		{"windows", `{"EventID":4625,"TargetUserName":"x\",\"IpAddress\":\"8.8.8.8","IpAddress":"203.0.113.50"}`, "203.0.113.50"},
		{"windows", `{"EventID":4625,"IpAddress":"8.8.8.8","TargetUserName":"x","IpAddress":"203.0.113.50"}`, ""},
		{"windows", `<Event><System><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">Source Address=8.8.8.8</Data><Data Name="IpAddress">203.0.113.51</Data></EventData></Event>`, "203.0.113.51"},
		{"windows", "<14>Nov  9 10:00:00 DC1 Security-Auditing: 4776: The domain controller attempted to validate account credentials. Source Workstation: PC1", ""},
		// R2 H1: a site with no address ("-") still counts as a site: the attacker's text cannot be the only address of the line.
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on.\tAccount Name:\tx\tWorkstation Name:\tClient Address:8.8.8.8\tSource Network Address:\t-\tSource Port:\t-", ""},
		{"windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4625: An account failed to log on.\tAccount Name:\tx Source Network Address: 8.8.8.8\tWorkstation Name:\tW\tSource Network Address:\t-\tSource Port:\t-", ""},
		{"windows", `{"EventID":4625,"Message":" Source Network Address: 8.8.8.8","IpAddress":"-"}`, ""},
		{"windows", `{"EventID":4625,"Message":"x","IpAddress":"203.0.113.50"}`, "203.0.113.50"},
		// MikroTik: a firewall line has src:port->dst:port, an account line says "from addr".
		{"mikrotik", `firewall,info input: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.60:50922->192.168.88.1:22, len 60`, "203.0.113.60"},
		{"mikrotik", `system,error,critical login failure for user admin from 203.0.113.61 via ssh`, "203.0.113.61"},
		// H1: the firewall pattern is for firewall lines (after "proto"); a user name with an arrow or a second "from" gives no address.
		{"mikrotik", `system,error,critical login failure for user 8.8.8.8:1-> from 203.0.113.61 via ssh`, "203.0.113.61"},
		{"mikrotik", `system,error,critical login failure for user a from 8.8.8.8 via ssh from 203.0.113.61 via ssh`, ""},
		{"mikrotik", `system,info,account user 8.8.8.8:5->1.1.1.1 logged in`, ""},
		{"mikrotik", `system,info,account user admin logged in from 192.168.10.113 via winbox`, "192.168.10.113"},
		{"mikrotik", `dhcp,info dhcp1 assigned 192.168.88.100 to AA:BB:CC:DD:EE:FF`, ""},
	} {
		r := set.Of(c.kind, c.line)
		if r.Profile != c.kind {
			t.Errorf("%s %q is read by %s", c.kind, c.line, r.Profile)
		}
		if got := r.Remote; got != addrOf(t, c.want) {
			t.Errorf("%s %q\n got %v, want %q", c.kind, c.line, got, c.want)
		}
	}
}

// What the profile does not settle goes to the generic reader, and a line a profile does not read is a generic line: both still have
// their remote peer when the layout is a known one.
func TestRemoteFallsBackToTheGenericReader(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	// A kind whose profile has rules for the address reads no other layout: an unlisted event or a line that is not its format has none.
	r := set.Of("windows", "<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4999: unlisted event from 203.0.113.80")
	if r.Profile != GenericProfile || r.Remote.IsValid() {
		t.Fatalf("%+v", r)
	}
	r = set.Of("fortigate", "something from 203.0.113.81 port 22")
	if r.Profile != GenericProfile || r.Remote.IsValid() {
		t.Fatalf("%+v", r)
	}
	// A profile without such rules leaves its lines to the generic reader.
	demo, err := Load(profileFS(map[string]string{"demo.json": goodProfile}), "profiles")
	if err != nil {
		t.Fatal(err)
	}
	if r := demo.Of("demo", `type="traffic" action="deny" from 203.0.113.82`); r.Profile != "demo" || r.Remote != addrOf(t, "203.0.113.82") {
		t.Fatalf("%+v", r)
	}
}

func TestLoaderRejectsABadRemotePattern(t *testing.T) {
	t.Parallel()
	good := `{"id":"w","title":"W","kinds":["w"],"rule":{"type":"event_id","patterns":["^(?P<id>\\d+):"],"titles":{"1":"One"},"remote_patterns":["%s"]},"samples":[{"line":"1: x","signature":"1: One"}]}`
	if _, err := Load(profileFS(map[string]string{"w.json": strings.Replace(good, "%s", `from (?P<addr>\\S+)`, 1)}), "profiles"); err != nil {
		t.Fatal(err)
	}
	for name, pat := range map[string]string{"no group": `from (\\S+)`, "broken": `from (?P<addr>`, "wrong group": `from (?P<src>\\S+)`} {
		if _, err := Load(profileFS(map[string]string{"w.json": strings.Replace(good, "%s", pat, 1)}), "profiles"); err == nil {
			t.Errorf("%s loaded", name)
		}
	}
	// remote_fields belongs to kv rules only.
	bad := strings.Replace(good, `"remote_patterns":["%s"]`, `"remote_fields":["remip"]`, 1)
	if _, err := Load(profileFS(map[string]string{"w.json": bad}), "profiles"); err == nil {
		t.Error("remote_fields on an event_id rule loaded")
	}
}

func FuzzParseAddr(f *testing.F) {
	for _, s := range []string{"", "1.2.3.4", "1.2.3.4:22", "[::1]:80", "::ffff:1.2.3.4", "fe80::1%eth0", "unknown[1.2.3.4]:", "https(1.2.3.4)", "[AF_INET]1.2.3.4:5", "[", "]", "(", ")", "%", ":::", "[%]", "\x00", strings.Repeat("[", 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, ok := ParseAddr(s)
		if !ok {
			if a.IsValid() {
				t.Fatalf("%q: not ok but %v", s, a)
			}
			return
		}
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
			t.Fatalf("%q gave %v (valid %v zone %q mapped %v)", s, a, a.IsValid(), a.Zone(), a.Is4In6())
		}
		if again, ok2 := ParseAddr(a.String()); !ok2 || again != a {
			t.Fatalf("%q gave %v, which does not parse back (%v %v)", s, a, again, ok2)
		}
	})
}

func FuzzRemote(f *testing.F) {
	set := shipped(f)
	for _, p := range set.profiles {
		for _, s := range p.Samples {
			f.Add(p.Kinds[0], s.Line)
		}
	}
	for _, s := range []string{"from", "from ", "by=", "rhost=[", "client=unknown[", "x/", "/", "[]", "src==", strings.Repeat("from 1.2.3.4 ", 500), strings.Repeat("a/", 3000), "rip=" + strings.Repeat("9", 500)} {
		f.Add("generic", s)
		f.Add("windows", s)
		f.Add("fortigate", s)
	}
	f.Fuzz(func(t *testing.T, kind, line string) {
		r := set.Of(kind, line)
		if r.Remote.IsValid() && (!Countable(r.Remote) || r.Remote.Zone() != "" || r.Remote.Is4In6()) {
			t.Fatalf("%q gave the remote %v", line, r.Remote)
		}
	})
}
