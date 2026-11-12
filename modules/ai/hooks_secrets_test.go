package ai

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// fake builds a secret-looking value at run time, so no secret-shaped literal sits in the source (and none is real).
func fake(parts ...string) string { return strings.Join(parts, "") }

// Device secrets are masked and the keyword stays (INV-12, D-220).
func TestDeviceSecretsAreMaskedAndTheKeywordStays(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	h7 := strings.ToUpper(hex.EncodeToString([]byte("fakeSecret7")))
	md5 := fake("$1", "$", "abCd", "$", "Zx9Qw3Er5Ty7Ui1Op2As4D")
	sha := fake("$5", "$", "saltsalt", "$", "Qw3Er5Ty7Ui1Op2As4Df6Gh8Jk0Lz")
	t8 := fake("$8", "$", "mErr9fAkE0", "$", "abcDEF123ghiJKL456mnoPQR789stuVWX012yz")
	t9 := fake("$9", "$", "x3Fk9Lq2Zp7W", "$", "abcDEF123ghiJKL456mnoPQR789stuVWX012yz")
	bc := fake("$2", "y", "$", "10", "$", "N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	ar := fake("$argon", "2id", "$v=19$m=65536,t=3,p=4$", "c29tZXNhbHQ", "$", "RdescudvJCsgt3ub+b+dWRWJTmaaJObG")
	enc := base64.StdEncoding.EncodeToString([]byte("fake-fortigate-secret-0123456789"))
	pw := "Zq" + "7Lm" + "p4Xv"
	cases := []struct{ name, in, keep string }{
		{"type 7 password", "username admin password 7 " + h7, "username admin password 7 "},
		{"line password 7", " password 7 " + h7 + "\n login", " password 7 "},
		{"enable secret 5", "enable secret 5 " + md5, "enable secret 5 "},
		{"secret 8", "username a privilege 15 secret 8 " + t8, "secret 8 "},
		{"secret 9", "enable secret 9 " + t9, "enable secret 9 "},
		{"type 0 clear", "username bob secret 0 " + pw, "secret 0 "},
		{"radius key 7", "radius-server key 7 " + h7, "radius-server key 7 "},
		{"ospf md5", "ip ospf message-digest-key 1 md5 7 " + h7, "md5 7 "},
		{"key-string", "  key-string 7 " + h7, "key-string 7 "},
		{"bare sha crypt", "root:" + sha + ":19000:0:99999:7:::", "root:"},
		{"bcrypt", "hash=" + bc, "hash="},
		{"argon2", "pw " + ar, "pw "},
		{"snmp-server", "snmp-server community " + pw + " RO 10", "snmp-server community "},
		{"snmp quoted", "snmp-server community \"" + pw + " x\" RW", "snmp-server community "},
		{"rocommunity", "rocommunity " + pw + " default", "rocommunity "},
		{"community=", "/snmp set community=" + pw + " enabled=yes", "community="},
		{"mikrotik name", "/snmp community add addresses=::/0 name=" + pw, "addresses=::/0 name="},
		{"forti community", "    set community " + pw, "set community "},
		{"pre-shared-key", "pre-shared-key remote 10.0.0.1 key 6 " + h7, "pre-shared-key"},
		{"mikrotik wpa", "wpa-pre-shared-key=" + pw + " wpa2-pre-shared-key=" + pw, "wpa-pre-shared-key="},
		{"wpa-psk", "wpa-psk ascii " + pw, "wpa-psk "},
		{"psksecret enc", "set psksecret ENC " + enc, "set psksecret ENC "},
		{"psksecret clear", "set psksecret " + pw, "set psksecret "},
		{"isakmp key", "crypto isakmp key " + pw + " address 10.1.1.1", "crypto isakmp key "},
		{"forti password enc", "set password ENC " + enc, "set password ENC "},
		{"mikrotik password=", "/user add name=admin password=" + pw + " group=full", "/user add name=admin password="},
		{"mikrotik snmpv3", "authentication-password=" + pw + " encryption-password=" + pw, "authentication-password="},
		{"full width", "ｐａｓｓｗｏｒｄ ７ " + h7, "ｐａｓｓｗｏｒｄ ７ "}, // normalised before matching, masked in the original
	}
	for _, c := range cases {
		res := run(t, r, BeforeAI, c.in)
		if res.Outcome != OutcomeMasked {
			t.Errorf("%s: outcome %v for %q", c.name, res.Outcome, c.in)
			continue
		}
		for _, secret := range []string{h7, md5, sha, t8, t9, bc, ar, enc, pw, "Zx9Qw3"} {
			if strings.Contains(res.Text, secret) {
				t.Errorf("%s: %q survives in %q", c.name, secret, res.Text)
			}
		}
		if !strings.Contains(res.Text, c.keep) || !strings.Contains(res.Text, "[masked]") {
			t.Errorf("%s: want %q kept and a mask, got %q", c.name, c.keep, res.Text)
		}
	}
}

func TestPrivateKeyBlocksAreMaskedWhole(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	body := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("not a real key ", 12)))
	for _, kind := range []string{"RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		whole := "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----"
		res := run(t, r, BeforeAI, "before\n"+whole+"\nafter")
		if res.Outcome != OutcomeMasked || strings.Contains(res.Text, body[:20]) || res.Text != "before\n[masked]\nafter" {
			t.Errorf("%s: %+v", kind, res)
		}
		cut := run(t, r, BeforeAI, "before\n-----BEGIN "+kind+"-----\n"+body[:40]) // the text was cut: to the end
		if strings.Contains(cut.Text, body[:20]) || !strings.HasPrefix(cut.Text, "before\n") {
			t.Errorf("%s cut: %+v", kind, cut)
		}
	}
	// a public key or a certificate is not a secret
	pub := "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----"
	if res := run(t, r, BeforeAI, pub); res.Outcome != OutcomePass {
		t.Errorf("certificate masked: %+v", res)
	}
}

// Ordinary text about devices is left alone.
func TestDeviceSecretPatternsLeaveOrdinaryTextAlone(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, in := range []string{
		"Device: NAS-01, IP 192.168.1.20, kind nas\nFinding: CVE-2024-3400\n",
		"The password policy needs 12 characters.",
		"Join the community meeting at noon; the secret santa is Friday.",
		"interface Gi0/1\n description uplink\n switchport mode trunk",
		"Price is $5 or $6 a month, $1$ is not a hash",
		"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"ENC Technologies and ENC\nshort",
	} {
		if res := run(t, r, BeforeAI, in); res.Outcome != OutcomePass || res.Text != in {
			t.Errorf("%q -> %+v", in, res)
		}
	}
}

// The secret finders are RE2 and take time in proportion to the text (D-205): hostile input of the biggest size takes about as
// long as plain text of that size.
func TestDeviceSecretFindersAreLinear(t *testing.T) {
	const top = hostileSize - 16
	timeOf := func(in string) time.Duration {
		start := time.Now()
		if _, err := runner(t, nil).Run(bg, BeforeAI, in); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	plain := strings.Repeat("The firewall log shows a blocked probe. ", top/40)
	base := min(timeOf(plain), timeOf(plain))
	for name, in := range map[string]string{
		"unclosed quotes":   strings.Repeat(`snmp-server community "`, top/24),
		"community no name": strings.Repeat("community x ", top/12),
		"community lines":   strings.Repeat("community "+strings.Repeat("a", 70)+"\n", top/81),
		"keywords only":     strings.Repeat("password 7 ", top/11),
		"begin no end":      strings.Repeat("-----BEGIN PRIVATE KEY-----\n", top/28),
		"begin end pairs":   strings.Repeat("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n", top/56),
		"dollars":           strings.Repeat("$1$", top/3),
		"psk modifiers":     strings.Repeat("psk enc hex 7 ", top/14),
		"enc":               strings.Repeat("ENC ", top/4),
		"one long value":    "password=" + strings.Repeat("a", top-9),
	} {
		d := timeOf(in)
		t.Logf("%-18s %8d bytes %v (plain text %v)", name, len(in), d, base)
		if d > 8*base+500*time.Millisecond {
			t.Errorf("%s: %v for %d bytes, plain text of the same size takes %v", name, d, len(in), base)
		}
	}
}

func FuzzDeviceSecrets(f *testing.F) {
	for _, s := range []string{"", "password 7 0822455D0A16", "enable secret 5 $1$ab$cdefghijkl", "snmp-server community x RO", "set psksecret ENC QUJDREVGR0hJSktMTU5PUA==",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "community[x] name=", "\xff$2y$10$\x00", "ｐａｓｓｗｏｒｄ ７ x"} {
		f.Add(s)
	}
	r, err := NewHookRunner(nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		spans := findDeviceSecrets(text)
		for _, sp := range spans {
			if sp.start < 0 || sp.end <= sp.start || sp.end > len(text) {
				t.Fatalf("span %+v out of range for %q", sp, text)
			}
		}
		res, err := r.Run(bg, BeforeAI, text) // never panics, never fails on text under the cap
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome == OutcomePass && res.Text != text {
			t.Fatalf("pass changed the text: %q -> %q", text, res.Text)
		}
	})
}
