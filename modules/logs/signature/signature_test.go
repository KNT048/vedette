package signature

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"unicode"
	"unicode/utf8"
)

func profileFS(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m["profiles/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

const goodProfile = `{
  "id": "demo", "title": "Demo", "kinds": ["demo"],
  "rule": {"type": "kv", "fields": ["type", "action", "msg"], "mined": ["msg"], "src_field": "srcip", "dst_field": "dstip"},
  "samples": [{"line": "type=traffic action=deny srcip=10.0.0.5 dstip=8.8.8.8", "signature": "type=traffic action=deny", "src": "10.0.0.5", "dest": "8.8.8.8", "remote": "10.0.0.5"}]
}`

func TestMineMasksIPsNumbersAndHex(t *testing.T) {
	t.Parallel()
	//nolint:gosec // "token=…" and "session…=…" are text to mask, not credentials
	cases := map[string]string{
		"user admin logged in from 192.168.10.113 via winbox":                     "user <name> logged in from <ip> via winbox",
		"Failed password for root from 10.1.2.3:51022 ssh2":                       "Failed password for <name> from <ip> ssh<n>",
		"session 4711 closed after 93 seconds":                                    "session <n> closed after <n> seconds",
		"hash 9f86d081884c7d659a2feaa0c55ad015 seen":                              "hash <hex> seen",
		"mac aa:bb:cc:dd:ee:ff moved":                                             "mac <hex> moved",
		"id 0x7ffe1234 ok":                                                        "id <hex> ok",
		"conn from fe80::1ff:fe23:4567:890a refused":                              "conn from <hex> refused",
		"in:ether1 out:ether2, proto TCP (SYN), 192.168.10.113:50922->8.8.8.8:53": "in:ether<n> out:ether<n>, proto TCP (SYN), <ip>-><ip>",
		"Invalid user oracle from 45.9.148.20 port 50123":                         "Invalid user <name> from <ip> port <n>",
		"Invalid user postgres from 45.9.148.21 port 50124":                       "Invalid user <name> from <ip> port <n>",
		"Failed password for invalid user admin2 from 1.2.3.4":                    "Failed password for invalid user <name> from <ip>",
		"token=dXNlcjpwYXNzd29yZA== accepted":                                     "token=<v> accepted",
		"session JSESSIONID=AbCdEfGhIjKlMnOpQrSt opened":                          "session JSESSIONID=<v> opened",
		"GET /wp-login.php?x=abc HTTP/1.1":                                        "GET <path> HTTP/<n>.<n>",
		"GET /admin/config.bak HTTP/1.1":                                          "GET <path> HTTP/<n>.<n>",
		`msg="Administrator admin login failed" action="deny" srcip=1.2.3.4 n=42`: "msg=Administrator admin login failed action=deny srcip=<ip> n=<n>",
		"id sess_Ab12Cd34Ef56Gh78Ij done":                                         "id <tok> done",
		"open ConfigurationManagerFactory now":                                    "open <tok> now",
		"":                                                                        "(empty)",
		"   ":                                                                     "(empty)",
	}
	for in, want := range cases {
		if got := Mine(in); got != want {
			t.Errorf("Mine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMineIsBounded(t *testing.T) {
	t.Parallel()
	got := Mine(strings.Repeat("word ", 5000))
	if len(got) > MaxSignatureBytes {
		t.Fatalf("%d bytes", len(got))
	}
	if got := Mine(strings.Repeat("é", 5000)); !utf8.ValidString(got) || len(got) > MaxSignatureBytes {
		t.Fatalf("not a bounded valid string: %d bytes", len(got))
	}
}

func TestLoaderRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"top level": strings.Replace(goodProfile, `"title"`, `"colour": "red", "title"`, 1),
		"in rule":   strings.Replace(goodProfile, `"mined"`, `"extra": 1, "mined"`, 1),
		"in sample": strings.Replace(goodProfile, `"dest"`, `"note": "x", "dest"`, 1),
	} {
		if _, err := Load(profileFS(map[string]string{"demo.json": body}), "profiles"); err == nil {
			t.Errorf("%s: an unknown field was accepted", name)
		}
	}
	if _, err := Load(profileFS(map[string]string{"demo.json": goodProfile}), "profiles"); err != nil {
		t.Fatalf("the good profile: %v", err)
	}
}

func TestLoaderRejectsBadProfiles(t *testing.T) {
	t.Parallel()
	big := strings.Replace(goodProfile, `"title": "Demo"`, `"title": "`+strings.Repeat("x", MaxProfileBytes)+`"`, 1)
	many := map[string]string{}
	for i := range MaxProfiles + 1 {
		many[string(rune('a'+i%26))+string(rune('a'+i/26))+".json"] = strings.NewReplacer(`"id": "demo"`, `"id": "d`+string(rune('a'+i%26))+string(rune('a'+i/26))+`"`, `"kinds": ["demo"]`, `"kinds": ["k`+string(rune('a'+i%26))+string(rune('a'+i/26))+`"]`).Replace(goodProfile)
	}
	cases := map[string]map[string]string{
		"oversized":            {"demo.json": big},
		"too many files":       many,
		"not json":             {"demo.json": "{"},
		"trailing data":        {"demo.json": goodProfile + goodProfile},
		"no kinds":             {"demo.json": strings.Replace(goodProfile, `["demo"]`, `[]`, 1)},
		"bad id":               {"demo.json": strings.Replace(goodProfile, `"id": "demo"`, `"id": "Demo!"`, 1)},
		"unknown rule type":    {"demo.json": strings.Replace(goodProfile, `"kv"`, `"magic"`, 1)},
		"sample mismatch":      {"demo.json": strings.Replace(goodProfile, `"signature": "type=traffic action=deny"`, `"signature": "something else"`, 1)},
		"no samples":           {"demo.json": strings.Replace(goodProfile, `"samples": [{"line": "type=traffic action=deny srcip=10.0.0.5 dstip=8.8.8.8", "signature": "type=traffic action=deny", "src": "10.0.0.5", "dest": "8.8.8.8", "remote": "10.0.0.5"}]`, `"samples": []`, 1)},
		"same kind twice":      {"a.json": goodProfile, "b.json": strings.Replace(goodProfile, `"id": "demo"`, `"id": "demo2"`, 1)},
		"same id twice":        {"a.json": goodProfile, "b.json": strings.Replace(goodProfile, `["demo"]`, `["other"]`, 1)},
		"kv with a pattern":    {"demo.json": strings.Replace(goodProfile, `"mined"`, `"patterns": ["(?P<id>1)"], "mined"`, 1)},
		"regex that is broken": {"demo.json": `{"id":"w","title":"W","kinds":["w"],"rule":{"type":"event_id","patterns":["(?P<id>"],"unknown":"x"},"samples":[{"line":"1: a","signature":"1: x"}]}`},
		"regex without id":     {"demo.json": `{"id":"w","title":"W","kinds":["w"],"rule":{"type":"event_id","patterns":["^(\\d+):"],"unknown":"x"},"samples":[{"line":"1: a","signature":"1: x"}]}`},
		"regex too long":       {"demo.json": `{"id":"w","title":"W","kinds":["w"],"rule":{"type":"event_id","patterns":["^(?P<id>\\d+):` + strings.Repeat("a", MaxPatternBytes) + `"],"unknown":"x"},"samples":[{"line":"1: a","signature":"1: x"}]}`},
		"too many fields":      {"demo.json": strings.Replace(goodProfile, `["type", "action", "msg"]`, `["a","b","c","d","e","f","g","h","i","j","k","l","m"]`, 1)},
	}
	for name, files := range cases {
		if _, err := Load(profileFS(files), "profiles"); err == nil {
			t.Errorf("%s: loaded without an error", name)
		}
	}
}

func TestLoaderOnAnEmptyDirectoryFails(t *testing.T) {
	t.Parallel()
	if _, err := Load(fstest.MapFS{"profiles/.keep": &fstest.MapFile{}}, "profiles"); err == nil {
		t.Fatal("no profile at all must be an error: a box that lost its profiles must not start as if it had them")
	}
}

func TestKVProfile(t *testing.T) {
	t.Parallel()
	set, err := Load(profileFS(map[string]string{"demo.json": goodProfile}), "profiles")
	if err != nil {
		t.Fatal(err)
	}
	if !set.HasProfile("demo") || set.HasProfile("other") {
		t.Fatal("HasProfile")
	}
	r := set.Of("demo", `<189>Nov  9 10:00:00 date=2026-11-09 type="traffic" action="deny" srcip=10.0.0.5 dstip=1.2.3.4 dstport=443`)
	if r.Signature != "type=traffic action=deny" || r.Dest != "1.2.3.4" || r.Src != "10.0.0.5" || r.Profile != "demo" {
		t.Fatalf("%+v", r)
	}
	// A kind without a profile, and a line the profile does not recognise, both go to the generic miner.
	if r := set.Of("nginx", "GET /a/b 200 1234"); r.Profile != GenericProfile || r.Signature != "GET <path> <n> <n>" || r.Dest != "" {
		t.Fatalf("%+v", r)
	}
	if r := set.Of("demo", "no key value pairs here 42"); r.Profile != GenericProfile {
		t.Fatalf("%+v", r)
	}
	// A destination that is not a plain address or name is dropped, not stored.
	if r := set.Of("demo", `type=traffic dstip="a b; drop table"`); r.Dest != "" {
		t.Fatalf("dest %q", r.Dest)
	}
}

func TestShippedProfiles(t *testing.T) {
	t.Parallel()
	set := shipped(t)
	for _, kind := range []string{"fortigate", "mikrotik", "windows"} {
		if !set.HasProfile(kind) {
			t.Errorf("no profile for %s", kind)
		}
	}
	cases := []struct{ kind, line, sig, dest string }{
		{"fortigate", `<189>date=2026-11-09 time=10:00:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" level="warning" srcip=45.9.148.20 dstip=192.168.10.1 dstport=3389 action="deny" policyid=3`,
			"logid=0000000013 action=deny", "192.168.10.1"},
		{"fortigate", `type="event" subtype="system" logid="0100032001" level="alert" msg="Administrator admin login failed from https(10.0.0.9) because of invalid password"`,
			"logid=0100032001", ""},
		{"mikrotik", `<134>Nov  9 10:00:00 RT system,info,account user admin logged in from 192.168.10.113 via winbox`,
			"system,info,account: user <name> logged in from <ip> via winbox", ""},
		{"mikrotik", `firewall,info forward: in:ether1 out:ether2, proto TCP (SYN), 192.168.10.113:50922->8.8.8.8:53, len 60`,
			"firewall,info: forward: in:ether<n> out:ether<n>, proto TCP (SYN), <ip>-><ip>, len <n>", "8.8.8.8"},
		{"windows", `<14>Nov  9 10:00:00 SRV-AD Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Logon Type: 3`,
			"4625: Failed logon", ""},
		{"windows", `EventID: 4720 Subject Account Name: admin.it`, "4720: A user account was created", ""},
		{"windows", `{"EventID":4688,"Channel":"Security"}`, "4688: A new process was created", ""},
		{"windows", `<14>Nov  9 10:00:00 SRV Microsoft-Windows-Security-Auditing: 4999: something unlisted`, "", ""}, // not in the table: the miner reads it
	}
	for _, c := range cases {
		r := set.Of(c.kind, c.line)
		if c.sig == "" {
			if r.Profile != GenericProfile || r.Bounded {
				t.Errorf("%s %q is read by %+v", c.kind, c.line, r)
			}
			continue
		}
		if r.Signature != c.sig || r.Dest != c.dest || r.Profile != c.kind {
			t.Errorf("%s %q\n got  %+v\n want sig %q dest %q", c.kind, c.line, r, c.sig, c.dest)
		}
	}
}

// Every shipped profile and the miner are total, bounded and clean on any input (INV-1): the log lines are untrusted.
func FuzzSignature(f *testing.F) {
	set := shipped(f)
	for _, p := range set.profiles {
		for _, s := range p.Samples {
			f.Add(p.Kinds[0], s.Line)
		}
	}
	for _, s := range []string{"", "\x00", "\xff\xfe", strings.Repeat("a", 10000), "<999>x", "type=", `type="`, `type="\`, "EventID:", "EventID: 99999999999999999999", strings.Repeat("1.2.3.4 ", 500), "0x", "::", "a:b:c:d:e:f:1:2"} {
		f.Add("generic", s)
		f.Add("windows", s)
		f.Add("fortigate", s)
		f.Add("mikrotik", s)
	}
	f.Fuzz(func(t *testing.T, kind, line string) {
		r := set.Of(kind, line)
		for _, v := range []string{r.Signature, r.Dest, r.Src} {
			if !utf8.ValidString(v) {
				t.Fatalf("invalid UTF-8 %q from %q", v, line)
			}
			for _, c := range v {
				if unicode.IsControl(c) {
					t.Fatalf("control character %U in %q from %q", c, v, line)
				}
			}
		}
		if r.Signature == "" || len(r.Signature) > MaxSignatureBytes {
			t.Fatalf("signature of %d bytes from %q", len(r.Signature), line)
		}
		if len(r.Dest) > MaxDestBytes || len(r.Src) > MaxDestBytes {
			t.Fatalf("address too long: %q %q", r.Src, r.Dest)
		}
		if again := set.Of(kind, line); !reflect.DeepEqual(again, r) {
			t.Fatalf("not deterministic: %+v then %+v", r, again)
		}
	})
}
