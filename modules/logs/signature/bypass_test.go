package signature

import (
	"fmt"
	"testing"
)

var users = []string{"admin", "root", "oracle", "postgres", "test", "guest", "ubuntu", "user", "ftp", "mysql", "pi", "support", "nagios", "git", "deploy", "jenkins", "hadoop", "tomcat", "www", "backup"}

// name, host and domain make 1,000 different values of the kind an attacker or a scan produces.
func name(i int) string {
	return fmt.Sprintf("%s%c%c", users[i%len(users)], rune('a'+i/20%26), rune('a'+i/520%26))
}

func host(i int) string {
	return fmt.Sprintf("%s-%s.corp.example.com", users[i%len(users)], users[(i/20)%len(users)])
}

func domain(i int) string {
	tl := []string{"com", "net", "org", "vn", "io"}
	return fmt.Sprintf("www.%s%s.%s", users[i%len(users)], users[(i/20)%len(users)], tl[(i/400)%len(tl)])
}

// distinct counts the signatures of 1,000 lines of one shape.
func distinct(set *Set, kind string, f func(i int) string) (n int, example string) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r := set.Of(kind, "<38>Nov  9 10:00:00 h "+f(i))
		if !seen[r.Signature] {
			example = r.Signature
		}
		seen[r.Signature] = true
	}
	return len(seen), example
}

// H-2: a value that names somebody or something (an account, a host, a domain, a URL) is never part of a signature, whatever the
// shape of the line around it: key=value, key:value, "key":"value", a quoted value, a word after "login of" or "tài khoản".
// Each shape gives at most 3 signatures for 1,000 different values.
func TestContract_INV1_IdentityShapesAreFewSignatures(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	shapes := map[string]func(i int) string{
		"ssh invalid user": func(i int) string { return fmt.Sprintf("sshd[1]: Invalid user %s from 1.2.3.4 port 22", name(i)) },
		"pam user=": func(i int) string {
			return fmt.Sprintf("sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=%s", name(i))
		},
		"dovecot user=<x>": func(i int) string {
			return fmt.Sprintf("dovecot: auth: pam(%s,1.2.3.4): pam_authenticate() failed: user=<%s>, method=PLAIN, rip=1.2.3.4", name(i), name(i))
		},
		`audit acct="x"`: func(i int) string {
			return fmt.Sprintf(`audit: USER_AUTH pid=1 uid=0 msg='op=PAM:authentication acct="%s" exe="/usr/sbin/sshd" hostname=1.2.3.4 addr=1.2.3.4 terminal=ssh res=failed'`, name(i))
		},
		"login of":         func(i int) string { return fmt.Sprintf("login of %s failed from 1.2.3.4", name(i)) },
		"account X locked": func(i int) string { return fmt.Sprintf("account %s locked after 5 failures", name(i)) },
		"single quotes":    func(i int) string { return fmt.Sprintf("Login failed: '%s' (Password: NO) from 1.2.3.4", name(i)) },
		"vietnamese": func(i int) string {
			return fmt.Sprintf("Đăng nhập thất bại: tài khoản %s từ 1.2.3.4", name(i))
		},
		"vietnamese people": func(i int) string { return fmt.Sprintf("Từ chối người dùng %s từ 1.2.3.4", name(i)) },
		"key:value":         func(i int) string { return fmt.Sprintf("auth failed user:%s src:1.2.3.4", name(i)) },
		"json":              func(i int) string { return fmt.Sprintf(`{"event":"login_failed","user":"%s","ip":"1.2.3.4"}`, name(i)) },
		"hostname":          func(i int) string { return fmt.Sprintf("connect from %s[1.2.3.4]", host(i)) },
		"dns query":         func(i int) string { return fmt.Sprintf("dnsmasq[123]: query[A] %s from 192.168.1.5", domain(i)) },
		"url":               func(i int) string { return fmt.Sprintf("GET http://%s/index.html 200", domain(i)) },
		"url-encoded path":  func(i int) string { return fmt.Sprintf("GET /a%%20%s HTTP/1.1", name(i)) },
		"email":             func(i int) string { return fmt.Sprintf("mail from=<%s@example.com> rejected", name(i)) },
	}
	for label, f := range shapes {
		if n, ex := distinct(set, "linux-rsyslog", f); n > 3 {
			t.Errorf("%-18s %4d signatures for 1,000 values, e.g. %q", label, n, ex)
		}
	}
}

// H-1: a line that a profile reads with a key that is not in the vocabulary of its data is not a bounded signature (the quota of the
// bounded ones is for what shipped data can name): it is read by the miner, or by the profile with Bounded false when the id is well
// formed.
func TestContract_INV1_ProfileNeedsAKeyFromItsVocabulary(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for label, c := range map[string]struct {
		kind    string
		profile string
		f       func(i int) string
	}{
		"fortigate random logid": {"fortigate", "fortigate", func(i int) string {
			return fmt.Sprintf(`logid="%010d" type="traffic" subtype="forward" action="deny"`, 9000000000+i)
		}},
		"fortigate id, no action":    {"fortigate", "fortigate", func(i int) string { return fmt.Sprintf(`logid="9%09d" type="event"`, i) }},
		"fortigate id, not a number": {"fortigate", GenericProfile, func(i int) string { return fmt.Sprintf(`logid="x%s" type="event"`, name(i)) }},
		"windows random event id":    {"windows", GenericProfile, func(i int) string { return fmt.Sprintf("EventID: %d junk", 10000+i) }},
		"windows Security-Auditing":  {"windows", GenericProfile, func(i int) string { return fmt.Sprintf("SRV Microsoft-Windows-Security-Auditing: %d: junk", 10000+i) }},
		"mikrotik random topics":     {"mikrotik", GenericProfile, func(i int) string { return fmt.Sprintf("t%s,info hello", name(i)) }},
	} {
		for i := 0; i < 1000; i++ {
			r := set.Of(c.kind, "<38>Nov  9 10:00:00 h "+c.f(i))
			if r.Profile != c.profile || r.Bounded {
				t.Errorf("%s: line %d: %+v, want the profile %q and not bounded", label, i, r, c.profile)
				break
			}
		}
	}
	// and a known id with free text and any action is still one signature of the profile
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r := set.Of("fortigate", fmt.Sprintf(`logid="0100032002" type="event" action="%s" user="%s" msg="Administrator %s login failed"`, name(i), name(i), name(i)))
		if r.Profile != "fortigate" || !r.Bounded {
			t.Fatalf("%+v", r)
		}
		seen[r.Signature] = true
	}
	if len(seen) > 1 {
		t.Fatalf("%d signatures for one log id: %v", len(seen), seen)
	}
}

// M-2: a Snare line (tab-delimited, the event id is the sixth field) is read by the Windows profile.
func TestWindowsSnareTabFormat(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	line := "<14>Nov  9 10:00:00 SRV MSWinEventLog\t1\tSecurity\t123\tMon Nov 09 10:00:00 2026\t4625\tMicrosoft-Windows-Security-Auditing\tCORP\\bob\tN/A\tFailure Audit\tSRV\tLogon\t\tAn account failed to log on."
	if r := set.Of("windows", line); r.Profile != "windows" || r.Signature != "4625: Failed logon" {
		t.Fatalf("%+v", r)
	}
}

// The word after "user" is a name unless it is a word that belongs to the sentence: "SSL user failed to logged in" keeps "failed".
func TestMineKeepsTheSentenceAfterAKeyword(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"SSL user failed to logged in":                  "SSL user failed to logged in",
		"Administrator admin login failed from 1.2.3.4": "Administrator admin login failed from <ip>",
		"login of bob failed":                           "login of <name> failed",
	} {
		if got := Mine(in); got != want {
			t.Errorf("Mine(%q) = %q, want %q", in, got, want)
		}
	}
}

func rnd7(i int) string {
	const a = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
	x := uint64(i)*2654435761 + 12345 //nolint:gosec // i is a small counter
	b := make([]byte, 7)
	for k := range b {
		b[k] = a[x%uint64(len(a))]
		x /= uint64(len(a))
		x = x*6364136223846793005 + 1
	}
	return string(b)
}

// realWorld are lines of the services and devices that the review listed, with 1,000 different account or host names each. The miner
// cannot know every format, so this is best effort (D-206); each of these gives at most 3 signatures.
var realWorld = []struct {
	kind, label string
	f           func(i int) string
}{
	{"nginx", `nginx user "X": password mismatch`, func(i int) string {
		return fmt.Sprintf(`2026/11/09 10:00:00 [error] 1#1: *%d user "%s": password mismatch, client: 1.2.3.4, server: example.com, request: "GET / HTTP/1.1", host: "example.com"`, i, name(i))
	}},
	{"nginx", `nginx user "X" was not found`, func(i int) string {
		return fmt.Sprintf(`2026/11/09 10:00:00 [error] 1#1: *%d user "%s" was not found in "/etc/nginx/.htpasswd", client: 1.2.3.4`, i, name(i))
	}},
	{"linux-rsyslog", "vsftpd [X] FAIL LOGIN", func(i int) string { return fmt.Sprintf(`vsftpd[1]: [%s] FAIL LOGIN: Client "1.2.3.4"`, name(i)) }},
	{"linux-rsyslog", "proftpd USER X: no such user", func(i int) string {
		return fmt.Sprintf("proftpd[1]: srv (1.2.3.4[1.2.3.4]) - USER %s: no such user found from 1.2.3.4 [1.2.3.4] to 10.0.0.1:21", name(i))
	}},
	{"linux-rsyslog", "pure-ftpd for user [X]", func(i int) string {
		return fmt.Sprintf("pure-ftpd: (?@1.2.3.4) [WARNING] Authentication failed for user [%s]", name(i))
	}},
	{"linux-rsyslog", "exim set_id=X", func(i int) string {
		return fmt.Sprintf("exim[1]: dovecot_login authenticator failed for (User) [1.2.3.4]:56789: 535 Incorrect authentication data (set_id=%s)", name(i))
	}},
	{"linux-rsyslog", "postfix sasl_username=X", func(i int) string {
		return fmt.Sprintf("postfix/smtpd[1]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure, sasl_username=%s", name(i))
	}},
	{"linux-rsyslog", "samba Authentication for user [X]", func(i int) string {
		return fmt.Sprintf("smbd[1]: check_ntlm_password:  Authentication for user [%s] -> [%s] FAILED with error NT_STATUS_NO_SUCH_USER", name(i), name(i))
	}},
	{"cisco-asa", "ASA 113015 user = X", func(i int) string {
		return fmt.Sprintf("%%ASA-6-113015: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.1 : user = %s : user IP = 1.2.3.4", name(i))
	}},
	{"cisco-asa", `ASA 605004 for user "X"`, func(i int) string {
		return fmt.Sprintf(`%%ASA-6-605004: Login denied from 1.2.3.4/22 to outside:10.0.0.1/ssh for user "%s"`, name(i))
	}},
	{"cisco-asa", "ASA 716039 User <X>", func(i int) string {
		return fmt.Sprintf("%%ASA-6-716039: Group <DfltGrpPolicy> User <%s> IP <1.2.3.4> Authentication: rejected, Session Type: WebVPN.", name(i))
	}},
	{"synology", "Synology User [X] from [ip]", func(i int) string {
		return fmt.Sprintf("WinFileService Event: User [%s] from [1.2.3.4] failed to log in via [DSM] due to authorization failure.", name(i))
	}},
	{"sophos", `Sophos user_name="X" message="User X failed"`, func(i int) string {
		return fmt.Sprintf(`device="SFW" date=2026-11-09 time=10:00:00 log_type="Event" log_component="Firewall Authentication" status="Failed" user_name="%s" src_ip=1.2.3.4 message="User %s failed to login to Firewall through Local authentication mechanism from 1.2.3.4"`, name(i), name(i))
	}},
	{"syslog-ng", "CEF suser/duser/shost", func(i int) string {
		return fmt.Sprintf("CEF:0|Vendor|Product|1.0|100|Login failed|5|src=1.2.3.4 suser=%s duser=%s shost=%s", name(i), name(i), "pc-"+name(i))
	}},
	{"windows", "WIN JSON unknown id TargetUserName", func(i int) string {
		return fmt.Sprintf(`{"EventID":4798,"TargetUserName":"%s","SubjectUserName":"%s","CallerProcessName":"C:\\Windows\\explorer.exe"}`, name(i), name(i))
	}},
	{"windows", "WIN unknown id, Account Name:<tab><tab>X", func(i int) string {
		return fmt.Sprintf("Microsoft-Windows-Security-Auditing: 4798: A user's local group membership was enumerated. Account Name:\t\t%s", name(i))
	}},
	{"windows", "WIN 5156 application path", func(i int) string {
		return fmt.Sprintf("Microsoft-Windows-Security-Auditing: 5156: The Windows Filtering Platform has permitted a connection. Application Name: \\device\\harddiskvolume3\\users\\%s\\appdata\\x.exe Direction: Inbound Source Address: 1.2.3.4", name(i))
	}},
	{"mikrotik", "MT hotspot X (ip): login failed", func(i int) string {
		return fmt.Sprintf("hotspot,info,debug %s (10.5.50.%d): login failed: invalid username or password", name(i), i%250)
	}},
	{"mikrotik", "MT dhcp DESKTOP-XXXXXXX", func(i int) string {
		return fmt.Sprintf("dhcp,info defconf assigned 192.168.88.%d for 4C:5E:0C:12:34:%02X DESKTOP-%s", i%250, i%256, rnd7(i))
	}},
	{"linux-rsyslog", "sshd invalid user with a digit first", func(i int) string { return fmt.Sprintf("sshd[1]: Invalid user %d%s from 1.2.3.4 port 22", i, name(i)) }},
	{"linux-rsyslog", "sshd invalid user, random 7 characters", func(i int) string { return fmt.Sprintf("sshd[1]: Invalid user %s from 1.2.3.4 port 22", rnd7(i)) }},
	{"linux-rsyslog", "Cyrillic name after a keyword", func(i int) string {
		return fmt.Sprintf("Invalid user пользователь%s from 1.2.3.4", string(rune('а'+i%32))+string(rune('а'+i/32%32)))
	}},
	{"linux-rsyslog", "Russian: пользователя X", func(i int) string {
		return fmt.Sprintf("Неудачный вход пользователя %s%s с 1.2.3.4", string(rune('а'+i%32)), string(rune('а'+i/32%32)))
	}},
	{"linux-rsyslog", "pam session opened for user X(uid=N)", func(i int) string {
		return fmt.Sprintf("CRON[1]: pam_unix(cron:session): session opened for user %s(uid=%d) by %s(uid=0)", name(i), 1000+i, name(i+1))
	}},
	{"linux-rsyslog", "user = X (spaces around =)", func(i int) string { return fmt.Sprintf("auth failed: user = %s", name(i)) }},
	{"linux-rsyslog", `user = "X"`, func(i int) string { return fmt.Sprintf(`auth failed: user = "%s"`, name(i)) }},
	{"linux-rsyslog", "user := X", func(i int) string { return fmt.Sprintf("auth failed user := %s", name(i)) }},
	{"linux-rsyslog", "username:  X (two spaces)", func(i int) string { return fmt.Sprintf("auth failed username:  %s", name(i)) }},
	{"linux-rsyslog", "client_user=X (prefixed key)", func(i int) string { return fmt.Sprintf("auth failed client_user=%s", name(i)) }},
	{"linux-rsyslog", "userName=X", func(i int) string { return fmt.Sprintf("auth failed userName=%s", name(i)) }},
	{"linux-rsyslog", "user-name=X / user_name=X", func(i int) string { return fmt.Sprintf("auth failed user_name=%s", name(i)) }},
	{"linux-rsyslog", "src=/dst= host names", func(i int) string { return fmt.Sprintf("conn src=%s dst=%s proto=tcp", host(i), "srv-"+name(i)) }},
}

func TestContract_INV1_RealWorldFormatsAreFewSignatures(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for _, g := range realWorld {
		if n, ex := distinct(set, g.kind, g.f); n > 3 {
			t.Errorf("%-44s %4d signatures for 1,000 values, e.g. %q", g.label, n, ex)
		}
	}
}

// M-1: a log id that is well formed (ten digits) and not in the list is still read by the profile, in the miner's quota
// (Bounded false): the signature keeps the id and the action, and nothing else (no country, no application).
func TestFortiUnknownLogidKeepsTheIdAndTheAction(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for _, c := range []struct{ line, want string }{
		{`logid="0100032102" type="event" subtype="system" logdesc="Admin password changed" action="Edit" msg="User admin changed the password of admin"`, "logid=0100032102 action=Edit"},
		{`logid="0000000015" type="traffic" subtype="forward" srcip=192.168.1.5 dstip=8.8.8.8 action="start" dstcountry="Germany" app="HTTPS"`, "logid=0000000015 action=start"},
		{`logid="0000000015" type="traffic" dstcountry="Germany" app="SSH"`, "logid=0000000015"},
	} {
		r := set.Of("fortigate", c.line)
		if r.Profile != "fortigate" || r.Bounded || r.Signature != c.want {
			t.Errorf("%q\n got %+v want %q unbounded", c.line, r, c.want)
		}
	}
	// the ones the review asked for are in the list
	for _, id := range []string{"0000000020", "0101039947", "0101037138"} {
		if r := set.Of("fortigate", `logid="`+id+`" type="x" action="tunnel-up"`); !r.Bounded {
			t.Errorf("%s is not in the vocabulary: %+v", id, r)
		}
	}
	if r := set.Of("fortigate", `logid="0000000011" type="x"`); r.Bounded {
		t.Errorf("0000000011 has no source and must not be in the list")
	}
	// not even ten digits: the miner
	if r := set.Of("fortigate", `logid="xyz" type="traffic"`); r.Profile != GenericProfile {
		t.Errorf("%+v", r)
	}
}

// M-2: on a device the miner reads as key=value text, the sentence of a quoted msg, logdesc or message stays in the signature; only the
// names in it are masked.
func TestMineKeepsTheQuotedMessage(t *testing.T) {
	t.Parallel()
	//nolint:gosec // "message=…" is text to mask, not a credential
	for in, want := range map[string]string{
		`status="Failed" message="User bob failed to login to Firewall from 1.2.3.4"`: "status=Failed message=User <name> failed to login to Firewall from <ip>",
		`logdesc="Admin password changed" msg="Firmware upgraded"`:                    "logdesc=Admin password changed msg=Firmware upgraded",
	} {
		if got := Mine(in); got != want {
			t.Errorf("Mine(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}
