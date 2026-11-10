package logs

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// What a device sends is untrusted (INV-1, SYS-6): whatever the bytes, the stored text is valid UTF-8, has no control
// character but tab, and is never longer than the limit.
func FuzzSanitizeLine(f *testing.F) {
	for _, s := range []string{"", "plain", "nul\x00byte", "\xff\xfe", "\x1b[31m", strings.Repeat("é", 3000), strings.Repeat("a", 5000), "tab\tok", " ", "trailing   ", "\xed\xa0\x80"} {
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
			if isControl(r) {
				t.Fatalf("control character %U in %q", r, out)
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
