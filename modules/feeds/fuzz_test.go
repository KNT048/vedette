package feeds

import (
	"encoding/json"
	"errors"
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
			if s, ok := v.(string); ok && (!utf8.ValidString(s) || hasControl(s)) {
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
				if c, ok := canonicalIP(ind); !ok || c != ind {
					t.Fatalf("bad ip accepted: %q", ind)
				}
			case "domain":
				if !validDomain(ind) {
					t.Fatalf("bad domain accepted: %q", ind)
				}
			case "url":
				if !validIndicatorURL(ind) {
					t.Fatalf("bad url accepted: %q", ind)
				}
			case "hash":
				if !hashRE.MatchString(ind) {
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
		r, err := ParseFeed(data, kind, p)
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
