package logs

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// What a device sends is untrusted (INV-1, SYS-6): whatever the bytes, the stored text is valid UTF-8, has no control,
// format or separator character but tab (the check below uses the unicode tables itself, not isControl), and is never
// longer than the limit. Characters are given by code point (ch, in service_test.go) so the invisible ones can be seen.
func FuzzSanitizeLine(f *testing.F) {
	seeds := []string{
		"", "plain", "nul\x00byte", "\xff\xfe", "\x1b[31m", strings.Repeat("e"+ch(0x301), 3000), strings.Repeat("a", 5000), "tab\tok",
		"trailing   ", "\xed\xa0\x80", "a\x7fb",
	}
	for _, c := range []rune{0x2028, 0x2029, 0x200b, 0x200d, 0xfeff, 0x202e, 0x2066, 0x061c, 0x85, 0x80, 0xad} {
		seeds = append(seeds, "a"+ch(c)+"b")
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeLine(in)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 out of %q: %q", in, out)
		}
		if len(out) > MaxLineBytes {
			t.Fatalf("%d bytes", len(out))
		}
		for _, r := range out {
			if r != '\t' && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
				t.Fatalf("control, format or separator character %U in %q", r, out)
			}
		}
		if again := sanitizeLine(out); again != out {
			t.Fatalf("not idempotent: %q then %q", out, again)
		}
	})
}

// A source input is judged without panicking, and what is accepted has a safe name, a dotted-quad address and a port in range.
func FuzzNormalizeSource(f *testing.F) {
	f.Add("fortigate", "FW-HQ", "192.168.10.1", "udp", 514)
	f.Add("", "", "", "", 0)
	f.Add("sophos", "  x  ", "::ffff:1.2.3.4", "tcp", 70000)
	f.Add("fortigate", "a\x00b", "1.2.3.4\n", "udp", -1)
	f.Fuzz(func(t *testing.T, kindID, name, ip, proto string, port int) {
		out, err := Input{Kind: kindID, Name: name, SenderIP: ip, Proto: proto, Port: port}.normalize()
		if err != nil {
			return
		}
		if !nameRE.MatchString(out.Name) || out.Port < 1 || out.Port > 65535 || strings.ContainsAny(out.SenderIP, ":\n \x00") || out.SenderIP != ip {
			t.Fatalf("accepted %+v from %q %q %q %q %d", out, kindID, name, ip, proto, port)
		}
		if _, ok := kinds[out.Kind]; !ok {
			t.Fatalf("accepted an unknown kind %q", out.Kind)
		}
	})
}
