package feeds

import (
	"errors"
	"testing"
)

func one(src string) []Sighting { return []Sighting{{Source: src}} }

func wl(t *testing.T, entries ...string) Whitelist {
	t.Helper()
	w, err := NewWhitelist(entries)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestContract_INV12_Verdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		kind  string
		value string
		s     []Sighting
		allow Whitelist
		want  Verdict
	}{
		{"one source alerts", "ip", "45.148.10.95", one("custom-a"), Whitelist{}, VerdictAlert},
		{"two independent sources block", "ip", "45.148.10.95", []Sighting{{Source: "custom-a"}, {Source: "custom-b"}}, Whitelist{}, VerdictBlock},
		{"same source twice is not independent", "ip", "45.148.10.95", []Sighting{{Source: "custom-a"}, {Source: "custom-a"}}, Whitelist{}, VerdictAlert},
		{"one block-class source blocks", "ip", "45.148.10.95", []Sighting{{Source: "abusech-feodo", BlockClass: true}}, Whitelist{}, VerdictBlock},
		{"empty source names do not count", "ip", "45.148.10.95", []Sighting{{Source: ""}, {Source: "custom-a"}}, Whitelist{}, VerdictAlert},
		{"no sightings", "ip", "45.148.10.95", nil, Whitelist{}, VerdictNone},
		{"domain alert", "domain", "Evil.Example.com.", one("custom-a"), Whitelist{}, VerdictAlert},
		{"domain block", "domain", "evil.example.com", []Sighting{{Source: "a"}, {Source: "b"}}, Whitelist{}, VerdictBlock},
		{"whitelisted domain", "domain", "login.microsoft.com", []Sighting{{Source: "a"}, {Source: "b"}}, wl(t, "microsoft.com"), VerdictNone},
		{"whitelist exact", "domain", "microsoft.com", one("a"), wl(t, "Microsoft.com."), VerdictNone},
		{"whitelist is by label, not suffix text", "domain", "evilmicrosoft.com", one("a"), wl(t, "microsoft.com"), VerdictAlert},
		{"whitelist never excuses an IP", "ip", "45.148.10.95", []Sighting{{Source: "a"}, {Source: "b"}}, wl(t, "microsoft.com"), VerdictBlock},
		{"invalid ip", "ip", "999.1.1.1", []Sighting{{Source: "a"}, {Source: "b"}}, Whitelist{}, VerdictNone},
		{"invalid domain", "domain", "not a domain", one("a"), Whitelist{}, VerdictNone},
		{"unknown kind", "email", "a@b.example", one("a"), Whitelist{}, VerdictNone},
	}
	for _, c := range cases {
		if got := Judge(c.kind, c.value, c.s, c.allow); got != c.want {
			t.Errorf("%s: Judge = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestContract_INV12_NeverWidensAnIPToASlash24(t *testing.T) {
	t.Parallel()
	a, _ := IOCKey("ip", "45.148.10.5")
	b, _ := IOCKey("ip", "45.148.10.6")
	c, _ := IOCKey("ip", "45.148.10.0")
	if a == b || a == c || b == c || a != "45.148.10.5" {
		t.Fatalf("keys must be the exact address: %q %q %q", a, b, c)
	}
	// A listing of .5 says nothing about its neighbours: judging a neighbour with no sighting gives no verdict.
	if Judge("ip", "45.148.10.5", one("custom-a"), Whitelist{}) != VerdictAlert || Judge("ip", "45.148.10.6", nil, Whitelist{}) != VerdictNone {
		t.Error("verdicts leaked across addresses")
	}
	if k, ok := IOCKey("ip", "45.148.10.0/24"); ok || k != "" {
		t.Errorf("a CIDR is not an IP IOC: %q %v", k, ok)
	}
	if k, _ := IOCKey("ip", "::ffff:45.148.10.5"); k != "45.148.10.5" {
		t.Errorf("mapped address key = %q", k)
	}
	if k, _ := IOCKey("ip", "2606:4700:0:0::0001"); k != "2606:4700::1" {
		t.Errorf("v6 key = %q", k)
	}
}

func TestRegress_VerdictIndependence(t *testing.T) {
	t.Parallel()
	ip := "45.148.10.95"
	// ids are compared normalised
	for _, s := range [][]Sighting{{{Source: "custom-a"}, {Source: "CUSTOM-A"}}, {{Source: "custom-a"}, {Source: " custom-a "}}} {
		if v := Judge("ip", ip, s, Whitelist{}); v != VerdictAlert {
			t.Errorf("one source written two ways = %q", v)
		}
	}
	// ids of built-ins: an aggregate alone never blocks, with an upstream it is not a second source
	ipsum, _ := BuiltinByID("ipsum")
	et, _ := BuiltinByID("et-open")
	feodo, _ := BuiltinByID("abusech-feodo")
	hagezi, _ := BuiltinByID("hagezi-tif")
	tor, _ := BuiltinByID("tor-exit")
	if !ipsum.Aggregate || !hagezi.Aggregate || !tor.Informational || et.Aggregate || len(ipsum.Upstreams) == 0 {
		t.Fatalf("registry flags: ipsum=%+v", ipsum)
	}
	cases := []struct {
		name string
		s    []Sighting
		want Verdict
	}{
		{"aggregate alone", []Sighting{SightingOf(ipsum)}, VerdictAlert},
		{"aggregate written in capitals", []Sighting{{Source: "IPSUM"}, {Source: "ipsum"}}, VerdictAlert},
		{"aggregate with its upstream", []Sighting{SightingOf(ipsum), SightingOf(et)}, VerdictAlert},
		{"aggregate with an independent source", []Sighting{SightingOf(ipsum), {Source: "custom-a"}}, VerdictBlock},
		{"two aggregates count once", []Sighting{SightingOf(ipsum), SightingOf(hagezi)}, VerdictAlert},
		{"upstream that is block-class still blocks", []Sighting{SightingOf(ipsum), SightingOf(feodo)}, VerdictBlock},
		{"caller flags cannot downgrade a built-in", []Sighting{{Source: "ipsum"}, {Source: "hagezi-tif"}}, VerdictAlert},
		{"informational alone alerts", []Sighting{SightingOf(tor)}, VerdictAlert},
		{"informational never counts toward block", []Sighting{SightingOf(tor), {Source: "custom-a"}}, VerdictAlert},
		{"informational with aggregate", []Sighting{SightingOf(tor), SightingOf(ipsum)}, VerdictAlert},
		{"informational plus two independent", []Sighting{SightingOf(tor), {Source: "custom-a"}, {Source: "custom-b"}}, VerdictBlock},
		{"custom aggregate with upstream", []Sighting{{Source: "mix", Aggregate: true, Upstreams: []string{"Custom-A"}}, {Source: "custom-a"}}, VerdictAlert},
		{"custom informational", []Sighting{{Source: "x", Informational: true}, {Source: "custom-a"}}, VerdictAlert},
	}
	for _, c := range cases {
		if got := Judge("ip", ip, c.s, Whitelist{}); got != c.want {
			t.Errorf("%s: Judge = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRegress_WhitelistEntries(t *testing.T) {
	t.Parallel()
	two := []Sighting{{Source: "a"}, {Source: "b"}}
	for _, entry := range []string{"google.com", "*.google.com", ".google.com", " Google.COM. ", "*.Google.com."} {
		w := wl(t, entry)
		for _, d := range []string{"google.com", "mail.google.com", "a.b.google.com"} {
			if got := Judge("domain", d, two, w); got != VerdictNone {
				t.Errorf("entry %q does not cover %s: %q", entry, d, got)
			}
		}
		if got := Judge("domain", "notgoogle.com", two, w); got != VerdictBlock {
			t.Errorf("entry %q covers notgoogle.com: %q", entry, got)
		}
	}
	for _, bad := range []string{"", "  ", "*", "*.", "com", "*.com", "co.uk", "github.io", "not a domain", "localhost", "a.local", "x\u202e.com", "https://google.com", "google.com/path", "1.2.3.4"} {
		if _, err := NewWhitelist([]string{"google.com", bad}); !errors.Is(err, ErrInvalidWhitelist) {
			t.Errorf("entry %q accepted: %v", bad, err)
		}
	}
	if w, err := NewWhitelist(nil); err != nil || Judge("domain", "evil.example.com", two, w) != VerdictBlock {
		t.Errorf("empty whitelist: %v", err)
	}
}
