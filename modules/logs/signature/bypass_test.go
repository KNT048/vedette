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

// H-1: a line that a profile reads with a key that is not in the vocabulary of its data is not a profile signature (the quota of
// the profiles is for what shipped data can name), it is read by the miner.
func TestContract_INV1_ProfileNeedsAKeyFromItsVocabulary(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for label, c := range map[string]struct {
		kind string
		f    func(i int) string
	}{
		"fortigate random logid": {"fortigate", func(i int) string {
			return fmt.Sprintf(`logid="%010d" type="traffic" subtype="forward" action="deny"`, 9000000000+i)
		}},
		"windows random event id":    {"windows", func(i int) string { return fmt.Sprintf("EventID: %d junk", 10000+i) }},
		"windows Security-Auditing":  {"windows", func(i int) string { return fmt.Sprintf("SRV Microsoft-Windows-Security-Auditing: %d: junk", 10000+i) }},
		"mikrotik random topics":     {"mikrotik", func(i int) string { return fmt.Sprintf("t%s,info hello", name(i)) }},
		"fortigate known id, no msg": {"fortigate", func(i int) string { return fmt.Sprintf(`logid="9%09d" type="event"`, i) }},
	} {
		for i := 0; i < 1000; i++ {
			if r := set.Of(c.kind, "<38>Nov  9 10:00:00 h "+c.f(i)); r.Profile != GenericProfile {
				t.Errorf("%s: line %d is read by the profile %q: %q", label, i, r.Profile, r.Signature)
				break
			}
		}
	}
	// and a known id with free text and any action is still one signature of the profile
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r := set.Of("fortigate", fmt.Sprintf(`logid="0100032002" type="event" action="%s" user="%s" msg="Administrator %s login failed"`, name(i), name(i), name(i)))
		if r.Profile != "fortigate" {
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
