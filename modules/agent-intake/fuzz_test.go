package agentintake

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-faster/jx"

	"github.com/knt048/vedette/core/api/oas"
)

// One fuzz target per parser (INV-7, the pattern of modules/honeypot/fuzz_test.go): the bytes go through the same ogen decoder the
// server uses, then through the parser. Each asserts no panic and that what is accepted is exactly the allow-listed, bounded, clean shape.
// The seeds are shaped like the osquery 5.x requests of its remote-API documentation; real captures come with the real-client slice.

// The invisible characters of the seeds, made from code points so that the source holds none (a bidi control in a source file is a
// Trojan Source warning).
var (
	rlo  = string(rune(0x202e))
	zwsp = string(rune(0x200b))
)

func clean(t *testing.T, what, s string, limit int) {
	t.Helper()
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit {
		t.Fatalf("%s: %q is not valid UTF-8 or over %d runes", what, s, limit)
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) || (c >= 0x202A && c <= 0x202E) || c == 0x200B || c == 0xFEFF {
			t.Fatalf("%s: %q has the character %U", what, s, c)
		}
	}
}

func FuzzParseEnroll(f *testing.F) {
	for _, s := range []string{
		`{"enroll_secret":"vdt_osquery_abcdefghijkmnpqrstuvwxyz234567ab","host_identifier":"srv-1","host_details":{"os_version":{"name":"Ubuntu","platform":"ubuntu","version":"24.04"},"osquery_info":{"version":"5.12.1","pid":"1"},"system_info":{"hostname":"srv-1","cpu_brand":"x"},"platform_info":{"vendor":"QEMU"}}}`,
		`{"enroll_secret":"vdt_osquery_abcdefghijkmnpqrstuvwxyz234567ab","host_identifier":"h","host_details":{"system_info":{"hostname":5},"os_version":[],"osquery_info":null}}`,
		`{"host_identifier":"h"}`, `{"enroll_secret":"x","host_identifier":"h` + rlo + `"}`, `{"enroll_secret":"vdt_osquery_abcdefghijkmnpqrstuvwxyz234567ab","host_identifier":"\u0000"}`,
		`{"enroll_secret":"vdt_osquery_abcdefghijkmnpqrstuvwxyz234567ab","host_identifier":"h","host_details":{"system_info":{"hostname":"a` + zwsp + `b"}}}`,
		`[]`, `{`, ``, `null`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var req oas.InventoryPostIntakeOsqueryEnrollReq
		if err := req.Decode(jx.DecodeBytes(b)); err != nil {
			return
		}
		in, ok := parseEnroll(&req)
		if !ok {
			return
		}
		if !enrollSecretRE.MatchString(in.secret) || in.hostIdentifier == "" {
			t.Fatalf("accepted %+v", in)
		}
		clean(t, "host_identifier", in.hostIdentifier, maxHostID)
		clean(t, "hostname", in.hostname, maxHostID)
		clean(t, "platform", in.platform, 32)
		clean(t, "version", in.osqueryVersion, 32)
	})
}

func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		`{"node_key":"` + strings.Repeat("a", 43) + `"}`, `{"node_key":"` + strings.Repeat("A-_", 14) + `a"}`, `{"node_key":""}`, `{"node_key":5}`, `{}`, `{"node_key":"x","extra":{"a":[1,2,3]}}`, `[]`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var req oas.InventoryPostIntakeOsqueryConfigReq
		if err := req.Decode(jx.DecodeBytes(b)); err != nil {
			return
		}
		if k, ok := parseConfig(&req); ok && (!nodeKeyRE.MatchString(k) || len(k) != 43) {
			t.Fatalf("accepted key %q", k)
		}
	})
}

func FuzzParseStatus(f *testing.F) {
	for _, s := range []string{"Bearer vdt_osquery_abcdefghijkmnpqrstuvwxyz234567ab", "", "Bearer ", "bearer x", "Basic abc", "Bearer vdt_osquery_" + strings.Repeat("a", 33), "Bearer \x00", "Bearer vdt_osquery_abcdefghijkmnpqrstuvwxyz234567ab\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		if s, ok := parseStatus(h); ok && (!enrollSecretRE.MatchString(s) || h != "Bearer "+s) {
			t.Fatalf("accepted %q from %q", s, h)
		}
	})
}

func FuzzParseLog(f *testing.F) {
	key := strings.Repeat("k", 43)
	for _, s := range []string{
		`{"node_key":"` + key + `","log_type":"result","data":[{"name":"deb_packages","hostIdentifier":"srv","calendarTime":"Wed Nov 11 08:00:00 2026 UTC","unixTime":1,"epoch":0,"counter":0,"numerics":false,"decorations":{"a":"b"},"action":"snapshot","snapshot":[{"name":"openssh-server","version":"1:9.6p1-3ubuntu13.5","arch":"amd64","source":"openssh"}]}]}`,
		`{"node_key":"` + key + `","log_type":"result","data":[{"name":"interfaces","action":"snapshot","snapshot":[{"mac":"52:54:00:aa:bb:01","address":"192.0.2.10"},{"mac":"zz","address":"::1"}]}]}`,
		`{"node_key":"` + key + `","log_type":"result","data":[{"name":"os_version","action":"snapshot","snapshot":[{"name":"Ubuntu","version":"24.04","major":"24","minor":"4","patch":"0","build":"","platform":"ubuntu","arch":"x86_64"}]},{"name":"system_info","action":"snapshot","snapshot":[{"hostname":"srv","hardware_vendor":"QEMU","hardware_model":"Standard PC"}]}]}`,
		`{"node_key":"` + key + `","log_type":"status","data":[{"filename":"x.cpp","line":"1","message":"m","severity":"0","version":"5.12.1"}]}`,
		`{"node_key":"` + key + `","log_type":"result","data":[{"name":"programs","action":"snapshot","snapshot":[{"name":5,"version":"1"},{"name":"7-Zip 23.01","version":"23.01","publisher":"Igor Pavlov"},{"name":"a` + rlo + `b"}]}]}`,
		`{"node_key":"` + key + `","log_type":"result","data":[{"name":"deb_packages","action":"added","columns":{"name":"x"}},{"name":5},[],null,{"snapshot":[]}]}`,
		`{"node_key":"x","log_type":"result","data":[]}`, `{"log_type":"result"}`, `[]`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var req oas.InventoryPostIntakeOsqueryLogReq
		if err := req.Decode(jx.DecodeBytes(b)); err != nil {
			return
		}
		in, ok := parseLog(&req)
		if !ok {
			return
		}
		if !nodeKeyRE.MatchString(in.nodeKey) {
			t.Fatalf("accepted key %q", in.nodeKey)
		}
		if !in.result && len(in.snaps) != 0 {
			t.Fatal("a status log fed results")
		}
		for name, rows := range in.snaps {
			cols, known := columns[name]
			if !known {
				t.Fatalf("query %q is not in the allow-list", name)
			}
			limit := maxRows
			if name == "interfaces" {
				limit = maxIfaceRows
			}
			if len(rows) > limit {
				t.Fatalf("%s: %d rows over %d", name, len(rows), limit)
			}
			for _, r := range rows {
				for c, v := range r {
					if !contains(cols, c) {
						t.Fatalf("%s: column %q is not allow-listed", name, c)
					}
					clean(t, name+"."+c, v, maxValue)
				}
			}
		}
		for _, i := range parseInterfaces(in.snaps["interfaces"]) {
			if !i.ip.Is4() || i.ip.IsLoopback() || i.ip.IsUnspecified() || i.ip.IsLinkLocalUnicast() || i.ip.IsMulticast() {
				t.Fatalf("interface address %v", i.ip)
			}
			if m, ok := normMAC(i.mac); !ok || m != i.mac {
				t.Fatalf("interface mac %q", i.mac)
			}
		}
		items, _ := mapPackages(in.snaps, maxRows)
		if len(items) > maxRows {
			t.Fatalf("%d software items", len(items))
		}
		for _, it := range items {
			clean(t, "display", it.Display, maxName)
			clean(t, "vendor", it.Vendor, maxName)
			clean(t, "product", it.Product, maxName)
			clean(t, "version", it.Version, maxVersion)
			if len(it.Vendor)+len(it.Product)+1 > maxKeyBytes {
				t.Fatalf("key of %q|%q is over %d bytes", it.Vendor, it.Product, maxKeyBytes)
			}
		}
	})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func FuzzDebUpstream(f *testing.F) {
	for _, s := range []string{"1:9.6p1-3ubuntu13.5", "", "1:", ":", "-", "a-b-c", "99999999999999999999:x-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		out := debUpstream(v)
		if len(out) > len(v) {
			t.Fatalf("%q grew to %q", v, out)
		}
	})
}
