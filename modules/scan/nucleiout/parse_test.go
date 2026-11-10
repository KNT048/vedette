package nucleiout

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

var (
	templates = []string{"CVE-2022-27593", "CVE-2024-3400"}
	hosts     = []string{"192.168.10.21"}
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The recorded-shape fixture: one match with request and response, one non-match, one error line (-ms).
func TestParse_Fixture(t *testing.T) {
	t.Parallel()
	res, err := Parse(fixture(t, "matched.jsonl"), templates, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("%d results: %+v", len(res), res)
	}
	m := res[0]
	if m.Template != "CVE-2022-27593" || !m.Matched || m.Host != "192.168.10.21" || m.Error != "" ||
		!strings.HasPrefix(m.Request, "GET /photo/p/api/video.php") || !strings.HasPrefix(m.Response, "HTTP/1.1 200 OK") {
		t.Fatalf("match: %+v", m)
	}
	if n := res[1]; n.Matched || n.Template != "CVE-2024-3400" || n.Error != "" {
		t.Fatalf("non-match: %+v", n)
	}
	if e := res[2]; e.Matched || e.Error == "" || e.Request != "" {
		t.Fatalf("error line: %+v", e)
	}
	if res[2].Error != "context deadline exceeded (Client.Timeout exceeded while awaiting headers)" {
		t.Fatalf("error text: %q", res[2].Error)
	}
}

func TestParse_EmptyOutputIsNoResult(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "\n", "\n\n  \n"} {
		res, err := Parse([]byte(in), templates, hosts)
		if err != nil || len(res) != 0 {
			t.Fatalf("%q: %v %v", in, res, err)
		}
	}
}

const ok = `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:5000","matched-at":"http://192.168.10.21:5000/photo/","matcher-status":false}`

// Fail closed: one bad line throws the whole run away (INV-10, SYS-6). A compromised or confused worker cannot slip a
// result in beside good ones.
func TestParse_RefusesTheWholeOutput(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"not JSON":                ok + "\n{",
		"array":                   ok + "\n[]",
		"string":                  ok + "\n\"x\"",
		"repeated key":            `{"template-id":"CVE-2022-27593","template-id":"CVE-2024-3400","host":"192.168.10.21","matcher-status":true}`,
		"key differing by case":   `{"template-id":"CVE-2022-27593","Template-ID":"CVE-2024-3400","host":"192.168.10.21","matcher-status":true}`,
		"no matcher-status":       `{"template-id":"CVE-2022-27593","host":"192.168.10.21"}`,
		"matcher-status a string": `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":"true"}`,
		"template not in the job": `{"template-id":"CVE-2021-44228","host":"192.168.10.21","matcher-status":true}`,
		"no template":             `{"host":"192.168.10.21","matcher-status":true}`,
		"host not in the job":     `{"template-id":"CVE-2022-27593","host":"http://192.168.10.99:5000","matcher-status":true}`,
		"host prefix trick":       `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21.evil.example:80","matcher-status":true}`,
		"user-info trick":         `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21@10.0.0.9:80","matcher-status":true}`,
		"no host":                 `{"template-id":"CVE-2022-27593","matcher-status":true}`,
		"match with an error":     `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":true,"error":"timeout"}`,
		"deep nesting":            `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":true,"meta":` + strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40) + `}`,
		"trailing data":           ok + ` {}`,
		"request not a string":    `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":true,"request":{}}`,
	}
	for name, in := range cases {
		if res, err := Parse([]byte(in), templates, hosts); err == nil {
			t.Errorf("%s: accepted %+v", name, res)
		}
	}
}

func TestParse_Limits(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte(ok+"\n"), MaxOutput/len(ok)+1)
	if _, err := Parse(big, templates, hosts); err == nil {
		t.Fatal("more than MaxOutput accepted")
	}
	lines := bytes.Repeat([]byte(ok+"\n"), MaxLines+1)
	if len(lines) > MaxOutput {
		t.Fatal("test needs a smaller line")
	}
	if _, err := Parse(lines, templates, hosts); err == nil {
		t.Fatal("more than MaxLines accepted")
	}
	if _, err := Parse(bytes.Repeat([]byte(ok+"\n"), MaxLines), templates, hosts); err != nil {
		t.Fatalf("MaxLines lines refused: %v", err)
	}
}

// INV-10: evidence is untrusted text: capped, valid UTF-8, no control or bidi characters; newlines and tabs stay.
func TestParse_EvidenceIsCleanedAndCapped(t *testing.T) {
	t.Parallel()
	resp := "HTTP/1.1 200 OK\r\nX: \x1b[31mred\x07‮evil\r\n\r\n" + strings.Repeat("é", MaxResponse) + "\xff"
	line := `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":true,"request":"GET / HTTP/1.1\r\n\tHost: x\u0000","response":` + quote(resp) + `}`
	res, err := Parse([]byte(line), templates, hosts)
	if err != nil {
		t.Fatal(err)
	}
	r := res[0]
	if r.Request != "GET / HTTP/1.1\n\tHost: x" {
		t.Fatalf("request: %q", r.Request)
	}
	if !strings.HasPrefix(r.Response, "HTTP/1.1 200 OK\nX: [31mredevil\n\n") {
		t.Fatalf("response head: %q", r.Response[:40])
	}
	if len(r.Response) > MaxResponse+len(cutMark) || !strings.HasSuffix(r.Response, cutMark) || !utf8.ValidString(r.Response) {
		t.Fatalf("response not capped on a rune boundary: %d bytes", len(r.Response))
	}
	long := `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":false,"error":` + quote(strings.Repeat("e", 1000)) + `}`
	if res, err := Parse([]byte(long), templates, hosts); err != nil || len(res[0].Error) > MaxError+len(cutMark) {
		t.Fatalf("error not capped: %v %d", err, len(res[0].Error))
	}
}

func TestHostOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"192.168.10.21":                       "192.168.10.21",
		"192.168.10.21:22":                    "192.168.10.21",
		"http://192.168.10.21:5000":           "192.168.10.21",
		"https://scan.acme.example:443/x?y=1": "scan.acme.example",
		"https://scan.acme.example":           "scan.acme.example",
		"http://u@10.0.0.9:80":                "",
		"http://[::1]:80":                     "",
		"":                                    "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range []byte(s) {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteByte(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte("0123456789abcdef"[r>>4])
			b.WriteByte("0123456789abcdef"[r&15])
		default:
			b.WriteByte(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Parse never panics, and what it returns always respects the caps and the job.
func FuzzParse(f *testing.F) {
	f.Add(string(fixtureBytes()))
	f.Add(ok)
	f.Add(`{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":true,"response":"‮\u0000x"}`)
	f.Add("{\"a\":" + strings.Repeat("[", 50))
	f.Fuzz(func(t *testing.T, in string) {
		res, err := Parse([]byte(in), templates, hosts)
		if err != nil {
			return
		}
		for _, r := range res {
			if r.Host != hosts[0] || (r.Template != templates[0] && r.Template != templates[1]) {
				t.Fatalf("result outside the job: %+v", r)
			}
			for _, s := range []string{r.Request, r.Response, r.Error} {
				if !utf8.ValidString(s) || strings.ContainsFunc(s, unsafeRune) {
					t.Fatalf("unclean evidence: %q", s)
				}
			}
			if len(r.Request) > MaxRequest+len(cutMark) || len(r.Response) > MaxResponse+len(cutMark) || len(r.Error) > MaxError+len(cutMark) {
				t.Fatalf("evidence over the cap: %+v", r)
			}
			if r.Matched && r.Error != "" {
				t.Fatalf("a match with an error: %+v", r)
			}
		}
	})
}

func fixtureBytes() []byte {
	b, _ := os.ReadFile("testdata/matched.jsonl")
	return b
}
