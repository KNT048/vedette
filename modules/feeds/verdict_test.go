package feeds

import "testing"

func one(src string) []Sighting { return []Sighting{{Source: src}} }

func TestContract_INV12_Verdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		kind  string
		value string
		s     []Sighting
		allow []string
		want  Verdict
	}{
		{"one source alerts", "ip", "203.0.113.5", one("ipsum"), nil, VerdictAlert},
		{"two independent sources block", "ip", "203.0.113.5", []Sighting{{Source: "ipsum"}, {Source: "et-open"}}, nil, VerdictBlock},
		{"same source twice is not independent", "ip", "203.0.113.5", []Sighting{{Source: "ipsum"}, {Source: "ipsum"}}, nil, VerdictAlert},
		{"one block-class source blocks", "ip", "203.0.113.5", []Sighting{{Source: "abusech-feodo", BlockClass: true}}, nil, VerdictBlock},
		{"empty source names do not count", "ip", "203.0.113.5", []Sighting{{Source: ""}, {Source: "ipsum"}}, nil, VerdictAlert},
		{"no sightings", "ip", "203.0.113.5", nil, nil, VerdictNone},
		{"domain alert", "domain", "Evil.Example.com.", one("hagezi-tif"), nil, VerdictAlert},
		{"domain block", "domain", "evil.example.com", []Sighting{{Source: "a"}, {Source: "b"}}, nil, VerdictBlock},
		{"whitelisted domain", "domain", "login.microsoft.com", []Sighting{{Source: "a"}, {Source: "b"}}, []string{"microsoft.com"}, VerdictNone},
		{"whitelist exact", "domain", "microsoft.com", one("a"), []string{"Microsoft.com."}, VerdictNone},
		{"whitelist is by label, not suffix text", "domain", "evilmicrosoft.com", one("a"), []string{"microsoft.com"}, VerdictAlert},
		{"whitelist never excuses an IP", "ip", "203.0.113.5", []Sighting{{Source: "a"}, {Source: "b"}}, []string{"203.0.113.5", "microsoft.com"}, VerdictBlock},
		{"invalid ip", "ip", "999.1.1.1", []Sighting{{Source: "a"}, {Source: "b"}}, nil, VerdictNone},
		{"invalid domain", "domain", "not a domain", one("a"), nil, VerdictNone},
		{"unknown kind", "email", "a@b.example", one("a"), nil, VerdictNone},
	}
	for _, c := range cases {
		if got := Judge(c.kind, c.value, c.s, c.allow); got != c.want {
			t.Errorf("%s: Judge = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestContract_INV12_NeverWidensAnIPToASlash24(t *testing.T) {
	t.Parallel()
	a, _ := IOCKey("ip", "203.0.113.5")
	b, _ := IOCKey("ip", "203.0.113.6")
	c, _ := IOCKey("ip", "203.0.113.0")
	if a == b || a == c || b == c || a != "203.0.113.5" {
		t.Fatalf("keys must be the exact address: %q %q %q", a, b, c)
	}
	// A listing of .5 says nothing about its neighbours: judging a neighbour with no sighting gives no verdict.
	if Judge("ip", "203.0.113.5", one("ipsum"), nil) != VerdictAlert || Judge("ip", "203.0.113.6", nil, nil) != VerdictNone {
		t.Error("verdicts leaked across addresses")
	}
	if k, ok := IOCKey("ip", "203.0.113.0/24"); ok || k != "" {
		t.Errorf("a CIDR is not an IP IOC: %q %v", k, ok)
	}
	if k, _ := IOCKey("ip", "::ffff:203.0.113.5"); k != "203.0.113.5" {
		t.Errorf("mapped address key = %q", k)
	}
	if k, _ := IOCKey("ip", "2001:0DB8::0001"); k != "2001:db8::1" {
		t.Errorf("v6 key = %q", k)
	}
}
