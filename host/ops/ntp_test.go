package ops

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestValidNTPServer(t *testing.T) {
	t.Parallel()
	good := []string{"pool.ntp.org", "0.ubuntu.pool.ntp.org", "ntp_1.example", "time-a.example.net", "203.0.113.7", "192.168.1.1", "a", "x1", "1x", "10.0.0.1.example"}
	for _, s := range good {
		if !validNTPServer(s) {
			t.Errorf("%q refused", s)
		}
	}
	bad := []string{
		"", " ", "a b", "a\nb", "a\rb", "a\x00", "-a", ".a", "a;b", "a$b", "a`b", "a/b", "a:123", "[::1]", "::1", "fe80::1%eth0", "2001:db8::1",
		"0.0.0.0", "127.0.0.1", "169.254.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "1.2.3.999", "01.2.3.4", "1.2.3", "1234", "1.2.3.4/32",
		strings.Repeat("a", 65), "é", "a b", "iburst\nserver x",
	}
	for _, s := range bad {
		if validNTPServer(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestCheckNTPList(t *testing.T) {
	t.Parallel()
	for _, l := range [][]string{nil, {}, {"a.example"}, {"a.example", "1.2.3.4", "b.example", "c.example"}} {
		if err := checkNTPList(l); err != nil {
			t.Errorf("%v: %v", l, err)
		}
	}
	for _, l := range [][]string{{"a.example", "b.example", "c.example", "d.example", "e.example"}, {"a.example", "A.example"}, {"a.example", "bad name"}, {""}} {
		if err := checkNTPList(l); err == nil {
			t.Errorf("%v accepted", l)
		}
	}
}

func TestSourcesRenderAndParseRoundTrip(t *testing.T) {
	t.Parallel()
	for _, l := range [][]string{nil, {"a.example"}, {"203.0.113.7", "b.example", "c_d.example", "ntp.example.org"}} {
		b := renderSources(l)
		if !bytes.HasPrefix(b, []byte(ntpHeader)) || !bytes.HasSuffix(b, []byte(" iburst\n")) || bytes.Count(b, []byte("\n")) != 1+max(len(l), 1) {
			t.Errorf("%v rendered as %q", l, b)
		}
		got, ok := parseSources(b)
		if !ok || !slices.Equal(got, l) {
			t.Errorf("%v parsed back as %v %v", l, got, ok)
		}
	}
	// Anything but the exact bytes of a render is not the host's file.
	for _, s := range []string{
		"", "pool pool.ntp.org iburst\n", ntpHeader, ntpHeader + "pool pool.ntp.org iburst", ntpHeader + "pool other.example iburst\n",
		ntpHeader + "server a.example iburst\nserver evil.example minpoll 0 iburst\n", ntpHeader + "server a.example iburst\n# x\n",
		ntpHeader + "server a.example iburst\r\n", ntpHeader + "server a b iburst\n", ntpHeader + "server a.example iburst\n\n",
		ntpHeader + "pool pool.ntp.org iburst\nserver a.example iburst\n", ntpHeader + "server a.example iburst\nserver a.example iburst\n",
		strings.Repeat("server a.example iburst\n", 5),
	} {
		if _, ok := parseSources([]byte(s)); ok {
			t.Errorf("%q was read as the host's file", s)
		}
	}
}

func FuzzParseSources(f *testing.F) {
	f.Add(string(renderSources(nil)))
	f.Add(string(renderSources([]string{"a.example", "1.2.3.4"})))
	f.Add(ntpHeader + "server a.example iburst\nserver b iburst\n")
	f.Fuzz(func(t *testing.T, s string) {
		l, ok := parseSources([]byte(s))
		if !ok {
			return
		}
		if len(l) > 4 || checkNTPList(l) != nil || !bytes.Equal(renderSources(l), []byte(s)) {
			t.Fatalf("%q parsed as %v", s, l)
		}
	})
}

func FuzzValidNTPServer(f *testing.F) {
	for _, s := range []string{"a.example", "1.2.3.4", "a\nb", "::1", "x y", "0.0.0.0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validNTPServer(s) && strings.ContainsAny(s, " \t\r\n\x00#;,\"'`$\\/:%[]") {
			t.Fatalf("%q accepted", s)
		}
	})
}

func TestSourcesListed(t *testing.T) {
	t.Parallel()
	out := []byte("^,*,203.0.113.7,2,6,377,12,0.1,0.2,0.3\n=,+,Ntp.Example.Org,2,6,377,12,0.1,0.2,0.3\n#,-,gps,0,4,377,1,0,0,0\n^,?,\n\ngarbage\n")
	for _, c := range []struct {
		servers []string
		want    bool
	}{
		{nil, true}, {[]string{"203.0.113.7"}, true}, {[]string{"ntp.example.org"}, true}, {[]string{"203.0.113.7", "ntp.example.org"}, true},
		{[]string{"other.example"}, false}, {[]string{"203.0.113.7", "other.example"}, false}, {[]string{"gps"}, false}, // '#' is a reference clock, not an NTP server
	} {
		if got := sourcesListed(out, c.servers); got != c.want {
			t.Errorf("%v: %v", c.servers, got)
		}
	}
	for _, empty := range []string{"", "\n", "garbage\n", "#,*,gps,0,4,377,1,0,0,0\n"} {
		if sourcesListed([]byte(empty), nil) {
			t.Errorf("%q counted as a source", empty)
		}
	}
}

func TestValidateChronycArgv(t *testing.T) {
	t.Parallel()
	for _, a := range [][]string{{"reload", "sources"}, chronycSources} {
		if err := validateChronyc(a); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	for _, a := range [][]string{
		nil, {}, {"reload"}, {"reload", "sources", "x"}, {"reload", "Sources"}, {"add", "server", "x.example"}, {"makestep"}, {"sources"},
		{"-N", "sources"}, {"-N", "sources", "-" + "c"}, {"-" + "c", "-N", "sources"}, {"-a", "reload", "sources"}, {"-h", "x", "sources"}, {"-N", "-" + "c", "sources", "-v"},
		{"waitsync"}, {"selectdata"}, {"sourcestats"}, {"password", "x"}, {"cmdaccheck", "x"}, {"reload sources"}, {"reload", "sources\n"},
	} {
		if err := validateChronyc(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}
