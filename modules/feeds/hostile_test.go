package feeds

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Pathological inputs must end quickly with an error or a bounded result.
func TestHostileInputsAreBounded(t *testing.T) {
	t.Parallel()
	big := MaxBodyBytes
	inputs := map[Format]map[string]string{
		FormatLines: {
			"one huge line":     strings.Repeat("a", big),
			"only newlines":     strings.Repeat("\n", big),
			"only comments":     strings.Repeat("#\n", big/2),
			"many tiny tokens":  strings.Repeat("a\n", big/2),
			"whitespace blob":   strings.Repeat(" \t", big/2),
			"invalid utf8 blob": strings.Repeat("\xff", big),
		},
		FormatCSV: {
			"quote spans the file":  "dst_ip\n\"" + strings.Repeat("x,\n", big/3),
			"only delimiters":       strings.Repeat(",", big),
			"only quotes":           strings.Repeat("\"", big),
			"doubled quotes":        "dst_ip\n\"" + strings.Repeat("\"\"", big/2-3) + "\"",
			"lots of empty records": "dst_ip\n" + strings.Repeat("\r\n", big/2-8),
			"wide row":              "dst_ip\n" + strings.Repeat("a,", big/2-8),
		},
		FormatJSON: {
			"deep arrays":     strings.Repeat("[", big/2) + strings.Repeat("]", big/2),
			"deep objects":    strings.Repeat(`{"a":`, big/6),
			"wide array":      "[" + strings.Repeat("1,", big/2-2) + "1]",
			"many keys":       "{" + strings.Repeat(`"k":1,`, big/6-2) + `"z":1}`,
			"huge string":     `["` + strings.Repeat("a", big-10) + `"]`,
			"long number run": "[" + strings.Repeat("9", big-10) + "]",
		},
		FormatRSS: {
			"deep elements":      strings.Repeat("<a>", big/6),
			"many elements":      "<r>" + strings.Repeat("<item/>", big/7-2) + "</r>",
			"billion laughs":     `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><rss><item><title>&lol3;</title></item></rss>`,
			"nested items":       strings.Repeat("<item>", 100) + "x" + strings.Repeat("</item>", 100),
			"huge text in item":  "<rss><item><title>" + strings.Repeat("a", big-40) + "</title></item></rss>",
			"unterminated":       "<rss><item><title>" + strings.Repeat("a", 1000),
			"bad encoding label": `<?xml version="1.0" encoding="x-unknown"?><rss/>`,
		},
		FormatSTIX: {
			"many indicators": `{"objects":[` + strings.Repeat(`{"type":"indicator","pattern":"[ipv4-addr:value = '1.2.3.4']"},`, big/70) + `{}]}`,
			"huge pattern":    `{"objects":[{"type":"indicator","pattern":"` + strings.Repeat("[a:b = 'x'] OR ", big/16) + `"}]}`,
			"many comparisons": `{"objects":[{"type":"indicator","pattern":"` +
				strings.Repeat("[ipv4-addr:value = '1.2.3.4'] OR ", 55) + `"}]}`,
			"backslash run": `{"objects":[{"type":"indicator","pattern":"[ipv4-addr:value = '` + strings.Repeat(`\\\\`, 400) + `"}]}`,
		},
	}
	for format, cases := range inputs {
		for name, in := range cases {
			t.Run(string(format)+"/"+name, func(t *testing.T) {
				t.Parallel()
				if len(in) > MaxBodyBytes {
					in = in[:MaxBodyBytes]
				}
				start := time.Now()
				r, err := ParseFeed(context.Background(), []byte(in), KindIOC, DefaultParser(KindIOC, format))
				// The bound catches a blow-up (minutes), not speed: CI runs this with -race on 2 CPUs next to the whole
				// suite, where many_indicators takes ~15 s against ~2.4 s alone (issue #89).
				if d := time.Since(start); d > 60*time.Second {
					t.Fatalf("took %v", d)
				}
				if err != nil {
					if !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrBadConfig) {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				checkInvariants(t, KindIOC, r)
			})
		}
	}
}

func TestXMLEntitiesAndEncodings(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatRSS)
	laughs := `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><rss><item><title>&b;</title></item></rss>`
	if _, err := ParseFeed(context.Background(), []byte(laughs), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("entity declarations must be refused: %v", err)
	}
	if _, err := ParseFeed(context.Background(), []byte(`<rss><item><title>&nbsp;x</title></item></rss>`), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("undefined entity must be an error: %v", err)
	}
	if _, err := ParseFeed(context.Background(), []byte(`<?xml version="1.0" encoding="x-unknown"?><rss/>`), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("unsupported encoding: %v", err)
	}
	if _, err := ParseFeed(context.Background(), []byte(strings.Repeat("<a>", maxXMLDepth+5)), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("deep xml: %v", err)
	}
	if _, err := ParseFeed(context.Background(), []byte(`<a/><b/>`), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("two roots: %v", err)
	}
	// ISO-8859-1 is decoded; predefined and numeric entities and CDATA work.
	latin := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><rss><item><title>caf\xe9.example.com</title></item><item><title>&#x31;.2.3.4</title></item><item><title><![CDATA[5.6.7.8]]></title></item><item><title>a&amp;b.example.com</title></item></rss>"
	r, err := ParseFeed(context.Background(), []byte(latin), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Accepted != 2 || r.Records[0]["indicator"] != "1.2.3.4" || r.Records[1]["indicator"] != "5.6.7.8" || r.Rejected != 2 {
		t.Errorf("%+v %v", r.Stats, r.Records)
	}
}

func TestRSSFieldLookup(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindVulnerabilities, FormatRSS)
	p.Fields["cve"] = fm("id")
	p.Fields["vendor"] = fm("author")
	p.Fields["product"] = fm("category")
	p.Fields["description"] = fm("Description")
	p.Fields["link"] = fm("link")
	p.Fields["date"] = fm("updated")
	xmlText := `<feed xmlns="http://www.w3.org/2005/Atom" xmlns:x="urn:x"><entry>
	<id>CVE-2026-5555</id><x:author>Vendor <b>Inc</b></x:author><category term="Router"/>
	<summary>Short <![CDATA[text]]></summary><link href="https://a.example/x"/><updated>2026-11-03T01:02:03Z</updated></entry></feed>`
	r, err := ParseFeed(context.Background(), []byte(xmlText), KindVulnerabilities, p)
	if err != nil || r.Accepted != 1 {
		t.Fatalf("%v %+v", err, r.Stats)
	}
	rec := r.Records[0]
	if rec["cve"] != "CVE-2026-5555" || rec["vendor"] != "Vendor Inc" || rec["product"] != "Router" || rec["description"] != "Short text" || rec["link"] != "https://a.example/x" || rec["date"] != "2026-11-03" {
		t.Errorf("record = %v", rec)
	}
	// parsers.ts compares the tag name exactly for the term attribute: "Category" reads the text instead.
	p.Fields["product"] = fm("Category")
	r, _ = ParseFeed(context.Background(), []byte(`<rss><item><guid>CVE-2026-5555</guid><category term="T">text</category></item></rss>`), KindVulnerabilities, withField(p, "cve", fm("guid"), "link", fm("")))
	if r.Accepted != 1 || r.Records[0]["product"] != "text" {
		t.Errorf("category quirk: %v", r.Records)
	}
}

func withField(p Parser, kv ...any) Parser {
	m := map[string]FieldMap{}
	for k, v := range p.Fields {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1].(FieldMap)
	}
	p.Fields = m
	return p
}

func TestCSVQuirks(t *testing.T) {
	t.Parallel()
	got := csvCells("a;b\r\n\r\n#skip;me\r\n\"x;y\";z\n\"multi\nline\";q\nlast;row", ';')
	want := [][]string{{"a", "b"}, {"x;y", "z"}, {"multi\nline", "q"}, {"last", "row"}}
	if len(got) != len(want) {
		t.Fatalf("rows = %q", got)
	}
	for i := range want {
		if strings.Join(got[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("row %d = %q want %q", i, got[i], want[i])
		}
	}
	// Header names are case-insensitive; numeric sources fall back to 1-based columns; short rows give null.
	p := DefaultParser(KindIOC, FormatCSV)
	p.Fields["indicator"] = fm(" DST_IP ")
	p.Fields["first_seen"] = fm("9")
	r, _ := ParseFeed(context.Background(), []byte("dst_ip,x\n1.2.3.4\n5.6.7.8,y\n"), KindIOC, p)
	if r.Accepted != 2 || r.Records[0]["first_seen"] != nil {
		t.Errorf("%+v %v", r.Stats, r.Records)
	}
}

// csvCells is parseCSV reduced to the cells, for tests that do not care about flags.
func csvCells(text string, delim rune) [][]string {
	var out [][]string
	for _, r := range parseCSV(text, delim) {
		out = append(out, r.cells)
	}
	return out
}
