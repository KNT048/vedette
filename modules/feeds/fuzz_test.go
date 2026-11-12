package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// checkInvariants is what must hold for any input that ParseFeed accepts.
func checkInvariants(t *testing.T, kind Kind, r Result) {
	t.Helper()
	if r.Accepted != len(r.Records) || r.Accepted+r.Rejected > MaxRows || len(r.Rejects) > MaxRejects {
		t.Fatalf("accounting broken: %+v records=%d", r.Stats, len(r.Records))
	}
	if r.Rejected < len(r.Rejects) {
		t.Fatalf("more listed rejects than rejected rows: %+v", r.Stats)
	}
	sum := 0
	for _, x := range r.Reasons {
		sum += x.Count
	}
	if sum != r.Rejected {
		t.Fatalf("reasons sum %d != rejected %d", sum, r.Rejected)
	}
	for _, rec := range r.Records {
		for _, id := range FieldIDs(kind) {
			if _, ok := rec[id]; !ok {
				t.Fatalf("record without field %s: %v", id, rec)
			}
		}
		for k, v := range rec {
			if s, ok := v.(string); ok && (!utf8.ValidString(s) || hasControl(s) || (k != "description" && hasControlStrict(s))) {
				t.Fatalf("field %s holds unsafe text %q", k, s)
			}
		}
		if kind == KindVulnerabilities {
			if c, _ := rec["cve"].(string); !cveRE.MatchString(c) {
				t.Fatalf("bad cve accepted: %q", c)
			}
			if l, ok := rec["link"].(string); ok && !validLink(l) {
				t.Fatalf("bad link accepted: %q", l)
			}
			if d, ok := rec["description"].(string); ok && jsLen(d) > 500 {
				t.Fatalf("description not clipped")
			}
		} else {
			ind, _ := rec["indicator"].(string)
			switch rec["kind"] {
			case "ip":
				if a, err := netip.ParseAddr(ind); err != nil || a.String() != ind || isSpecialAddr(a) {
					t.Fatalf("bad ip accepted: %q", ind)
				}
			case "domain":
				if !validDomain(ind) || localName(ind) || ind != strings.ToLower(ind) {
					t.Fatalf("bad domain accepted: %q", ind)
				}
			case "url":
				if u, err := url.Parse(ind); !validIndicatorURL(ind) || err != nil || !hostRejection(u.Hostname()).none() {
					t.Fatalf("bad url accepted: %q", ind)
				}
			case "hash":
				if !hashRE.MatchString(ind) || emptyFileHashes[ind] || ind != strings.ToLower(ind) {
					t.Fatalf("bad hash accepted: %q", ind)
				}
			default:
				t.Fatalf("unknown kind %v", rec["kind"])
			}
			if c, ok := rec["confidence"].(float64); ok && (c < 0 || c > 1) {
				t.Fatalf("confidence out of range: %v", c)
			}
		}
	}
	if _, err := json.Marshal(r.Preview()); err != nil {
		t.Fatalf("result does not marshal: %v", err)
	}
}

func fuzzFormat(f *testing.F, kind Kind, format Format, extraSeeds ...string) {
	f.Helper()
	f.Add(sample(f, kind, format), "", "")
	for _, s := range extraSeeds {
		f.Add([]byte(s), "", "")
	}
	f.Add([]byte(""), "$.a", "(x)")
	f.Add([]byte("{}"), "$..a", "([")
	f.Fuzz(func(t *testing.T, data []byte, src, regex string) {
		p := DefaultParser(kind, format)
		if src != "" || regex != "" {
			// Customer-supplied mapping: any source and any regex must give a clean error or a safe result.
			id := FieldIDs(kind)[0]
			fmap := p.Fields[id]
			if src != "" {
				fmap.Source = src
			}
			fmap.Regex = regex
			p.Fields[id] = fmap
		}
		r, err := ParseFeed(context.Background(), data, kind, p)
		if err != nil {
			if !errors.Is(err, ErrBadConfig) && !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		checkInvariants(t, kind, r)
	})
}

func FuzzParseJSON(f *testing.F) {
	fuzzFormat(f, KindIOC, FormatJSON, `[`, `{"data":[{"ioc":"1.2.3.4","type":"ip","score":1e999}]}`, `{"data":[[[[[[]]]]]]}`)
}

func FuzzParseJSONVulns(f *testing.F) {
	fuzzFormat(f, KindVulnerabilities, FormatJSON, `{"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"x","notes":"http://a"}]}`)
}

func FuzzParseCSV(f *testing.F) {
	fuzzFormat(f, KindIOC, FormatCSV, "dst_ip\n\"1.2.3.4", "dst_ip\r\n\"\"\"\"\r\n#c\r\n1.2.3.4,\r", "\xef\xbb\xbfdst_ip\n1.1.1.1")
}

func FuzzParseRSS(f *testing.F) {
	fuzzFormat(f, KindIOC, FormatRSS,
		`<?xml version="1.0" encoding="ISO-8859-1"?><rss><item><title>a.example.com</title></item></rss>`,
		`<!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><rss><item><title>&b;</title></item></rss>`,
		`<feed><entry><title><![CDATA[1.2.3.4]]></title></entry></feed>`)
}

func FuzzParseSTIX(f *testing.F) {
	fuzzFormat(f, KindIOC, FormatSTIX, `{"objects":[{"type":"indicator","pattern":"[url:value = 'http://x.example/a\\'b']","confidence":null}]}`, `{"objects":null}`)
}

func FuzzParseLines(f *testing.F) {
	fuzzFormat(f, KindIOC, FormatLines, "1.2.3.4\t5\r\n#c\n\n  2001:db8::1  \n", "\x00\xff", "a b c")
}

func FuzzParseKEV(f *testing.F) {
	f.Add(fixture(f, "kev.json"))
	f.Add([]byte(`{"vulnerabilities":[{"cveID":1}]}`))
	f.Add([]byte(`{"vulnerabilities":[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseKEV(data)
		if err != nil {
			if !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if c.Accepted != len(c.Vulns) || c.Accepted+c.Rejected > MaxRows {
			t.Fatalf("accounting: %+v", c.Stats)
		}
		seen := map[string]bool{}
		for _, v := range c.Vulns {
			if !cveRE.MatchString(v.CVE) || seen[v.CVE] || v.Vendor == "" || v.Product == "" || !strictDateRE.MatchString(v.DateAdded) || v.Links == nil {
				t.Fatalf("bad entry accepted: %+v", v)
			}
			seen[v.CVE] = true
			for _, l := range v.Links {
				if !validIndicatorURL(l) {
					t.Fatalf("bad link %q", l)
				}
			}
			for _, s := range []string{v.Vendor, v.Product, v.Name, v.Description, v.RequiredAction} {
				if !utf8.ValidString(s) || hasControl(s) {
					t.Fatalf("unsafe text %q", s)
				}
			}
		}
		if _, err := json.Marshal(c.Vulns); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseNucleiCVEs(f *testing.F) {
	f.Add(fixture(f, "nuclei-cves.jsonl"))
	f.Add([]byte(`[{"ID":"CVE-2026-1234"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseNucleiCVEs(data)
		if err != nil {
			if !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if r.Accepted != len(r.CVEs) {
			t.Fatalf("accounting: %+v", r.Stats)
		}
		for _, c := range r.CVEs {
			if !cveRE.MatchString(c) {
				t.Fatalf("bad CVE %q", c)
			}
		}
	})
}

func FuzzParseEPSS(f *testing.F) {
	f.Add(fixture(f, "epss.json"))
	f.Add([]byte(`{"total":9,"data":[{"cve":"CVE-2026-1234","epss":"1e-5","percentile":0.5,"date":"2026-01-01"}]}`))
	f.Add([]byte(`{"data":[{"cve":1,"epss":[],"percentile":{}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := ParseEPSS(data)
		if err != nil {
			if !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if d.Accepted != len(d.Scores) || len(d.Rejects) > MaxRejects || len(d.Reasons) > maxReasons+1 {
			t.Fatalf("accounting: %+v", d.Stats)
		}
		for _, s := range d.Scores {
			if !cveRE.MatchString(s.CVE) || s.Score < 0 || s.Score > 1 || s.Percentile < 0 || s.Percentile > 1 || (s.Date != "" && !strictDateRE.MatchString(s.Date)) {
				t.Fatalf("bad score accepted: %+v", s)
			}
		}
		for _, x := range d.Rejects {
			if !printable(x.Reason) {
				t.Fatalf("unsafe reject text %q", x.Reason)
			}
		}
	})
}

func FuzzEPSSBatchURLs(f *testing.F) {
	f.Add("CVE-2026-1234", "2026-01-01")
	f.Add("CVE-2026-1&x=1", "2026-1-1")
	f.Fuzz(func(t *testing.T, id, date string) {
		urls, err := EPSSBatchURLs("https://api.first.org/data/v1/epss", []string{id}, date)
		if err != nil {
			return
		}
		for _, raw := range urls {
			u, perr := url.Parse(raw)
			if perr != nil || u.Host != "api.first.org" || u.Path != "/data/v1/epss" || len(u.Query()) > 2 || !cveRE.MatchString(u.Query().Get("cve")) {
				t.Fatalf("bad batch URL %q", raw)
			}
		}
	})
}

// domainOracle is the regular expression validDomain replaced; the loop must answer exactly as it did.
var domainOracle = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,63}|[xX][nN]--[a-zA-Z0-9-]{0,58}[a-zA-Z0-9])$`)

func domainAsBefore(v string) bool { return len(v) <= 253 && domainOracle.MatchString(v) }

var domainSeeds = []string{"", ".", "a", "com", "a.b", "a.bc", "a.b1", "a.com.", ".a.com", "a..com", "-a.com", "a-.com", "a-b.com", "1.com", "1.2.3.4",
	"xn--bcher-kva.example", "a_b.com", "A.COM", "é.com", "a.cé", "a.c\xff", "a\x00.com", strings.Repeat("a", 63) + ".com", strings.Repeat("a", 64) + ".com",
	"a." + strings.Repeat("c", 63), "a." + strings.Repeat("c", 64), "a.xn--p1ai", "a.XN--P1AI", "a.xn--", "a.xn--p1ai-", "a.xn--p-1", "a.xn--1",
	"a.xn--" + strings.Repeat("c", 59), "a.xn--" + strings.Repeat("c", 60), "a.xn-p1ai", "a.xn--p_1", strings.Repeat("a.", 125) + "com", strings.Repeat("a.", 126) + "com", "a.c-m", "a.-cm"}

func TestValidDomainIsTheRegexp(t *testing.T) {
	t.Parallel()
	for _, s := range domainSeeds {
		if got, want := validDomain(s), domainAsBefore(s); got != want {
			t.Errorf("validDomain(%q) = %v, the regexp says %v", s, got, want)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // a seeded generator for a test
	const alphabet = "aZxn09-._é"
	for range 5000 {
		b := make([]byte, rng.IntN(80))
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		if s := string(b); validDomain(s) != domainAsBefore(s) {
			t.Fatalf("validDomain(%q) = %v, the regexp says %v", s, validDomain(s), domainAsBefore(s))
		}
	}
}

func FuzzValidDomainIsTheRegexp(f *testing.F) {
	for _, s := range domainSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := validDomain(s), domainAsBefore(s); got != want {
			t.Fatalf("validDomain(%q) = %v, the regexp says %v", s, got, want)
		}
	})
}
