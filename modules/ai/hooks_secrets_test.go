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
		// review round 1: a number after the keyword is not a type unless the value has the shape of one (hex for 7, $ for 5/8/9)
		// or the line is a configuration line; a BGP community is not an SNMP one; psk in prose has no = or : after it
		"Change your password 3 times before you give up.",
		"The secret 5 steps to security",
		"we have key 2 doors",
		"Rotate the key 7 days after a leak.",
		"the psk is weak",
		"Use pre-shared-key authentication on the tunnel.",
		"Community: OpenWrt forums say this",
		"route-map X permit 10\n set community 65000:100 additive",
		"route-map Y permit 20\n set community no-export",
		"route-map Z permit 30\n set community 4200000000:1:2",
		"The password is encrypted at rest.",
		"auth md5 is weak, use sha",
		// D-428: the new patterns need their marker
		"ntp server 10.0.0.1 key 1 prefer\nntp peer 10.0.0.2 key 2 source Lo0",
		"line vty 0 4\n exec-timeout 5 0\n login local\nline aux 0\n no exec",
		"the line vty has no password set",
		"password_policy:\n  min_length: 12\npassword: ${DB_PASSWORD}\npassword: null",
		"snmp-server host 10.1.1.1 version 3 auth ops\nsnmp-server host inside 10.1.1.1 version 3",
		"config system snmp community\n    edit 1\n        set status enable\n    next\nend\nconfig system global\n    set name FW-HQ\nend",
		"Private-Lines: 2\nPrivate-MAC: 00ff",
		"bypass: true\ncompass_dir: /x\nsnmp-server host 10.1.1.1 version 3 auth ops",
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
		// review round 1: patterns that read to the end of a line, escaped quotes, configuration lines
		"snmp host no comm":  "snmp-server host " + strings.Repeat("x ", top/2-10),
		"snmp user no auth":  "snmp-server user " + strings.Repeat("auth md5 x ", top/11-2),
		"server host no key": "tacacs-server host " + strings.Repeat("host x ", top/7-3),
		"username lines":     strings.Repeat("username a privilege 15 password\n", top/33),
		"cfg no type":        strings.Repeat("username a password secret key ", top/31),
		"escaped quotes":     strings.Repeat(`password="\\\"`, top/14),
		"json keys":          strings.Repeat(`"password":`, top/11),
		"community braces":   strings.Repeat("community x y {", top/15),
		"set community bgp":  strings.Repeat("set community 65000:100\n", top/24),
		"key=value prefixes": "x" + strings.Repeat("a_", top/2-2) + "password",
		"every pattern runs": "password secret key md5 community psk shared private enc $ -key -server snmp-server encrypted pbkdf2 enable " +
			"username neighbor ospf isakmp key-string private key\n" + strings.Repeat("The firewall log shows a blocked probe. ", top/40-4),
		"asa no suffix": strings.Repeat("password 8Ry2Yj ", top/16),
		// D-428: block walks and the line-anchored patterns
		"vty headers":    strings.Repeat("line vty 0 4\n x\n", top/17),
		"vty indented":   "line vty 0 4\n" + strings.Repeat(" exec-timeout 5 0\n", top/18-2),
		"yaml keys":      strings.Repeat("password:\n", top/10),
		"putty lines":    "Private-Lines: 9\n" + strings.Repeat("AAAAAAAAAAAAAAAA\n", top/17-2),
		"snmp host many": strings.Repeat("snmp-server host x vrf y traps\n", top/31),
		"forti headers":  strings.Repeat("config system snmp community\n  edit 1\n", top/38),
		"forti staircase": func() string {
			var b strings.Builder
			for i := 0; b.Len() < top-2000; i++ {
				b.WriteString(strings.Repeat(" ", i))
				b.WriteString("config system snmp community\n")
			}
			return b.String()
		}(),
	} {
		d := timeOf(in)
		t.Logf("%-18s %8d bytes %v (plain text %v)", name, len(in), d, base)
		if d > 8*base+500*time.Millisecond {
			t.Errorf("%s: %v for %d bytes, plain text of the same size takes %v", name, d, len(in), base)
		}
	}
}

func FuzzDeviceSecrets(f *testing.F) {
	for _, s := range []string{"", "password 7 " + fake("0822", "455D0A16"), "enable secret 5 " + fake("$1", "$ab$", "cdefghijkl"), "snmp-server community x RO",
		"set psksecret ENC " + base64.StdEncoding.EncodeToString([]byte("fake-fuzz-seed-16")), "ntp authentication-key 1 md5 " + fake("104D", "000A0618") + " 7",
		"snmp-server user u g v3 auth sha x priv aes 128 y", `{"password":"x\"y"}`, "set community 65000:100",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "community[x] name=", "\xff$2y$10$\x00", "ｐａｓｓｗｏｒｄ ７ x"} {
		f.Add(s)
	}
	r, err := NewHookRunner(nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		spans := findDeviceSecrets(text)
		for i, sp := range spans {
			if sp.start < 0 || sp.end <= sp.start || sp.end > len(text) {
				t.Fatalf("span %+v out of range for %q", sp, text)
			}
			if i > 0 && sp.start <= spans[i-1].end {
				t.Fatalf("spans %+v and %+v overlap or touch for %q", spans[i-1], sp, text)
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

// More vendor shapes (review round 1): an algorithm word before the value (NTP), crypt prefixes of yescrypt, Apache, Solaris and
// the ASA, ASA hashes named by a word after them, WireGuard and hostapd keys, SNMP communities and server keys written after a host,
// SNMPv3 user keys, JSON fields, escaped quotes and the cleartext forms of a few Cisco commands. Every value must go and every
// keyword must stay.
func TestDeviceSecretsInMoreVendorShapesAreMasked(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	d := "$"
	h7 := strings.ToUpper(hex.EncodeToString([]byte("ntpKey7")))
	plainPW := fake("Zq", "7Lm", "p4Xv")
	two := fake("Wr", "9Kd", "2Hs")
	ye := fake(d, "y", d, "j9T", d, "abcdefSALT", d, "HASHhashHASHhash")
	gy := fake(d, "gy", d, "j9T", d, "abcdefSALT", d, "HASHhashHASHhash")
	sc7 := fake(d, "7", d, "CU..../....", "abcdefSALT", d, "HASHhashHASHhash")
	apr := fake(d, "apr1", d, "abcdSALT", d, "HASHhashHASHhash")
	smd := fake(d, "md5", ",rounds=5000", d, "abcSALT", d, "HASHhashHASH")
	sh1 := fake(d, "sha1", d, "40000", d, "abcSALT", d, "HASHhashHASH")
	s256 := fake(d, "sha256", d, "5000", d, "abcSALT", d, "HASHhashHASH")
	s512 := fake(d, "sha512", d, "5000", d, "abcSALT", d, "HASHhashHASH")
	asa := fake("8Ry2Yj", "Iyt7RRXU24")
	asaLetters := fake("abcdefgh", "ijklmnop")
	asaDot := fake("2KFQnb", "NIdI.2KYOU")
	wg := base64.StdEncoding.EncodeToString([]byte("not-a-real-wireguard-key-32byte"))
	psk64 := strings.Repeat(hex.EncodeToString([]byte("fake")), 8)
	cases := []struct {
		name, in, keep string
		secrets        []string
	}{
		{"pre_shared_key", "pre_shared_key=" + plainPW, "pre_shared_key=", []string{plainPW}},
		{"private_key", "private_key=" + plainPW, "private_key=", []string{plainPW}},
		{"json private_key", `{"private_key":"` + plainPW + `"}`, `{"private_key":`, []string{plainPW}},
		{"json pre_shared_key", `{"pre_shared_key":"` + plainPW + `"}`, `{"pre_shared_key":`, []string{plainPW}},
		{"json camelCase password", `{"adminPassword":"` + plainPW + `"}`, `{"adminPassword":`, []string{plainPW}},
		{"json camelCase secret", `{"clientSecret":"` + plainPW + `"}`, `{"clientSecret":`, []string{plainPW}},
		{"json camelCase community", `{"snmpCommunity":"` + plainPW + `"}`, `{"snmpCommunity":`, []string{plainPW}},
		{"camelCase key=value", "adminPassword=" + plainPW, "adminPassword=", []string{plainPW}},
		{"long s folded by (?i)", "pa\u017fsword=" + plainPW, "=", []string{plainPW}},
		{"ntp type 7 after md5", "ntp authentication-key 1 md5 " + h7 + " 7", "ntp authentication-key 1 md5 ", []string{h7}},
		{"ntp cleartext", "ntp authentication-key 42 md5 " + plainPW, "ntp authentication-key 42 md5 ", []string{plainPW}},
		{"ntp hmac-sha", "ntp authentication-key 2 hmac-sha256 " + plainPW, "hmac-sha256 ", []string{plainPW}},
		{"yescrypt", "root:" + ye + ":19000:0:99999:7:::", "root:", []string{ye}},
		{"gost yescrypt", "root:" + gy + ":19000", "root:", []string{gy}},
		{"scrypt $7$", "u:" + sc7, "u:", []string{sc7}},
		{"apache apr1", "admin:" + apr, "admin:", []string{apr}},
		{"solaris md5", "u:" + smd + ":::", "u:", []string{smd}},
		{"netbsd sha1", "u:" + sh1, "u:", []string{sh1}},
		{"sha256 crypt word", "hash " + s256, "hash ", []string{s256}},
		{"asa pbkdf2", "username admin password " + s512 + " pbkdf2 privilege 15", "username admin password ", []string{s512}},
		{"asa enable encrypted", "enable password " + asa + " encrypted", "enable password ", []string{asa}},
		{"asa passwd encrypted", "passwd " + asaDot + " encrypted", "passwd ", []string{asaDot}},
		{"asa all letters", "username bob password " + asaLetters + " encrypted privilege 15", "username bob password ", []string{asaLetters}},
		{"asa nt-encrypted", "username bob password " + asa + " nt-encrypted", "username bob password ", []string{asa}},
		{"wireguard", "[Interface]\nPrivateKey = " + wg + "\n[Peer]\nPresharedKey = " + wg, "PrivateKey = ", []string{wg}},
		{"mikrotik wireguard", "/interface wireguard add listen-port=13231 name=wg1 private-key=\"" + wg + "\"", "private-key=", []string{wg}},
		{"hostapd passphrase", "ssid=lab\nwpa_passphrase=" + plainPW, "wpa_passphrase=", []string{plainPW}},
		{"hostapd psk", "wpa_psk=" + psk64, "wpa_psk=", []string{psk64}},
		{"juniper snmp block", "snmp {\n    community " + plainPW + " {\n        authorization read-only;\n    }\n}", "community ", []string{plainPW}},
		{"asa snmp host", "snmp-server host inside 10.1.1.1 community " + plainPW + " version 2c", "community ", []string{plainPW}},
		{"tacacs host key", "tacacs-server host 1.1.1.1 key " + plainPW, "tacacs-server host 1.1.1.1 key ", []string{plainPW}},
		{"radius host key", "radius-server host 1.1.1.1 auth-port 1812 key 0 " + plainPW, "key 0 ", []string{plainPW}},
		{"snmpv3 hex", "snmp-server user admin network-admin auth md5 0x" + psk64 + " priv 0x" + strings.ToUpper(psk64) + " localizedkey", "auth md5 ", []string{psk64, strings.ToUpper(psk64)}},
		{"snmpv3 aes", "snmp-server user u g v3 auth sha " + plainPW + " priv aes 128 " + two, "priv aes 128 ", []string{plainPW, two}},
		{"json password", `{"name":"admin","password":"` + plainPW + `","wifi_passphrase":"` + two + `"}`, `"password":`, []string{plainPW, two}},
		{"json community", `{"community": "` + plainPW + `"}`, `"community": `, []string{plainPW}},
		{"escaped quote", `set password "ab\"` + plainPW + `"`, "set password ", []string{plainPW}},
		{"enable cleartext", "enable password " + plainPW, "enable password ", []string{plainPW}},
		{"username cleartext", "username admin privilege 15 password " + plainPW, "username admin privilege 15 password ", []string{plainPW}},
		{"bgp neighbor", "router bgp 65000\n neighbor 10.0.0.1 password " + plainPW, " neighbor 10.0.0.1 password ", []string{plainPW}},
		{"ospf auth key", "interface Gi0/1\n ip ospf authentication-key " + plainPW, " ip ospf authentication-key ", []string{plainPW}},
		{"ios keyring psk", "crypto keyring K\n pre-shared-key address 10.0.0.1 key " + plainPW, "pre-shared-key address 10.0.0.1 key ", []string{plainPW}},
		{"asa tunnel-group psk", "tunnel-group 1.2.3.4 ipsec-attributes\n ikev1 pre-shared-key " + plainPW, "ikev1 pre-shared-key ", []string{plainPW}},
		{"psk colon", "PSK: " + plainPW, "PSK: ", []string{plainPW}},
		{"username type 6", "username bob password 6 " + plainPW, "username bob password 6 ", []string{plainPW}},
		// D-428: secrets that sit where the vendor's syntax puts them
		{"line vty cleartext", "line con 0\n login\nline vty 0 4\n exec-timeout 5 0\n password " + plainPW + "\n login\n", " password ", []string{plainPW}},
		{"line vty crlf", "line vty 0 4\r\n password " + plainPW + "\r\n login\r\n", " password ", []string{plainPW}},
		{"two vty blocks", "line vty 0 4\n password " + plainPW + "\nline vty 5 15\n password " + two + "\n", " password ", []string{plainPW, two}},
		{"yaml password", "db:\n  host: x\n  password: " + plainPW + "\n", "password: ", []string{plainPW}},
		{"yaml list item quoted", "users:\n  - db_password: \"" + plainPW + "\"\n", "db_password: ", []string{plainPW}},
		{"yaml snmp community", "snmp_community: " + plainPW, "snmp_community: ", []string{plainPW}},
		{"yaml secret", "client-secret: " + plainPW, "client-secret: ", []string{plainPW}},
		{"putty key body", "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: k\nPublic-Lines: 1\nAAAAB3NzaC1yc2EAAAA\nPrivate-Lines: 2\n" + wg + "\n" + two + "xyz==\nPrivate-MAC: 00ff\n", "Private-MAC: 00ff", []string{wg, two}},
		{"snmp host version", "snmp-server host 10.1.1.1 version 2c " + plainPW + " udp-port 162", "version 2c ", []string{plainPW}},
		{"snmp host vrf traps", "snmp-server host 10.1.1.1 vrf MGMT traps version 1 " + plainPW, "version 1 ", []string{plainPW}},
		{"snmp host traps", "snmp-server host 10.1.1.1 traps " + plainPW + " config", "traps ", []string{plainPW}},
		{"snmp host bare", "snmp-server host 10.1.1.1 " + plainPW, "snmp-server host 10.1.1.1 ", []string{plainPW}},
		// review r1: a community of digits or hex after the version, a bare community after a host name, vrf or IPv6 address
		{"snmp host hex community", "snmp-server host 10.1.1.1 version 2c deadbeef01", "version 2c ", []string{"deadbeef01"}},
		{"snmp host cafe", "snmp-server host 10.1.1.1 traps version 1 cafe", "version 1 ", []string{"cafe"}},
		{"snmp host digits", "snmp-server host 10.1.1.1 version 2c 1234567", "version 2c ", []string{"1234567"}},
		{"snmp host vrf bare", "snmp-server host 10.1.1.1 vrf MGMT " + plainPW, "vrf MGMT ", []string{plainPW}},
		{"snmp host name bare", "snmp-server host nms.example.com " + plainPW, "snmp-server host nms.example.com ", []string{plainPW}},
		{"snmp host ipv6 bare", "snmp-server host 2001:db8::1 " + plainPW, "snmp-server host 2001:db8::1 ", []string{plainPW}},
		{"vty every password", "line vty 0 4\n password " + plainPW + "\n login\n password " + two + "\n", " password ", []string{plainPW, two}},
		{"vty indented header and blank line", "  line vty 0 4\n\n    exec-timeout 5 0\n\n    password " + plainPW + "\n  login\n", "password ", []string{plainPW}},
		{"putty indented", "  Private-Lines: 2\n  " + wg + "  \n  " + two + "xyz  \n  Private-MAC: 00ff\n", "Private-MAC: 00ff", []string{wg, two}},
		{"yaml anchor", "password: &pw " + plainPW, "password: &pw ", []string{plainPW}},
		{"yaml block scalar", "db:\n  password: |\n    " + plainPW + "\n    " + two + "\n  host: x\n", "host: x", []string{plainPW, two}},
		{"yaml block scalar list", "- password: >-\n    " + plainPW + "\n  name: x\n", "name: x", []string{plainPW}},
		{"yaml _pass", "api_pass: " + plainPW, "api_pass: ", []string{plainPW}},
		{"yaml bare community", "community: " + plainPW, "community: ", []string{plainPW}},
		{"capital Password", "Password: " + plainPW, "Password: ", []string{plainPW}},
		{"forti blank line in block", "config system snmp community\n    edit 1\n\n        set name \"" + plainPW + "\"\n    next\nend\n", "set name ", []string{plainPW}},
		{"forti snmp name", "config system snmp community\n    edit 1\n        set name \"" + plainPW + "\"\n        set status enable\n    next\n    edit 2\n        set name " + two + "\n    next\nend\n", "set name ", []string{plainPW, two}},
	}
	for _, c := range cases {
		res := run(t, r, BeforeAI, c.in)
		if res.Outcome != OutcomeMasked {
			t.Errorf("%s: outcome %v for %q", c.name, res.Outcome, c.in)
			continue
		}
		for _, secret := range c.secrets {
			if strings.Contains(res.Text, secret) {
				t.Errorf("%s: %q survives in %q", c.name, secret, res.Text)
			}
		}
		if !strings.Contains(res.Text, c.keep) || !strings.Contains(res.Text, "[masked]") {
			t.Errorf("%s: want %q kept and a mask, got %q", c.name, c.keep, res.Text)
		}
	}
}
