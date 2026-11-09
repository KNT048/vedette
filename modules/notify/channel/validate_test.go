package channel

import (
	"strings"
	"testing"
)

func TestValidEmail(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"it@acme.example":               true,
		"first.last+tag@sub.acme.io":    true,
		"o'brien@acme.example":          true,
		"a@b.co":                        true,
		"":                              false,
		"no-at.example":                 false,
		"@acme.example":                 false,
		"a@acme":                        false,
		"a@1.2.3.4":                     false,
		"a b@acme.example":              false,
		"a@acme.example\r\nBcc: x@y.zz": false,
		"a\n@acme.example":              false,
		"<a@acme.example>":              false,
		"Name <a@acme.example>":         false,
		"\"a b\"@acme.example":          false,
		".a@acme.example":               false,
		"a..b@acme.example":             false,
		"a.@acme.example":               false,
		"a@-acme.example":               false,
		strings.Repeat("a", 65) + "@acme.example": false,
	} {
		if got := validEmail(in); got != want {
			t.Errorf("validEmail(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidHost(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"smtp.acme.example": true, "192.168.10.5": true, "8.8.8.8": true, "mail.lan": true,
		"localhost": false, "": false, "::1": false, "256.1.1.1": false, "01.2.3.4": false,
		"smtp.acme.example:587": false, "a b.example": false, "smtp.acme.example/": false,
		"smtp.acme.example\r\n": false, "-x.example": false,
	} {
		if got := validHost(in); got != want {
			t.Errorf("validHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestInternalHost(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "172.31.255.255": true, "172.32.0.1": false, "172.15.0.1": false,
		"192.168.1.1": true, "192.169.1.1": false, "127.0.0.1": true, "127.9.9.9": true, "11.0.0.1": false,
		"localhost": true, "LOCALHOST.": true, "printer.local": true, "nas.lan": true, "wiki.internal": true, "app.localhost": true,
		"example.com": false, "locallan.com": false, "evil-localhost": false, "::1": false, "": false,
		"10.0.0.1.evil.com": false, "8.8.8.8": false,
	} {
		if got := internalHost(in); got != want {
			t.Errorf("internalHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func FuzzValidEmail(f *testing.F) {
	for _, s := range []string{"a@b.co", "a\r\nb@c.dd", "\"x\"@y.zz", "a@b.c", "é@acme.example", "a@b.co\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !validEmail(s) {
			return
		}
		// Whatever is accepted must be safe inside a header line and an SMTP command.
		if len(s) > 254 || strings.ContainsAny(s, "\r\n\x00 <>,;\"") || strings.Count(s, "@") != 1 {
			t.Fatalf("accepted unsafe address %q", s)
		}
	})
}

func FuzzValidHost(f *testing.F) {
	for _, s := range []string{"smtp.acme.example", "1.2.3.4", "a..b", "x\r\n", "ＡＢＣ.example", strings.Repeat("a.", 200) + "com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validHost(s) && (len(s) > 253 || strings.ContainsAny(s, "\r\n\x00 /:@")) {
			t.Fatalf("accepted unsafe host %q", s)
		}
		_ = internalHost(s)
	})
}
