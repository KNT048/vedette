package nucleiout

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

var (
	templates = []string{"CVE-2022-27593", "CVE-2024-3400"}
	targets   = []string{"192.168.10.21:5000", "192.168.10.21:443", "192.168.10.21:22"}
)

func fixture(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/matched.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The fixture: one match with request and response, one non-match, one error line (-ms).
func TestParse_Fixture(t *testing.T) {
	t.Parallel()
	res, err := Parse(fixture(t), templates, targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("%d results: %+v", len(res), res)
	}
	m := res[0]
	if m.Template != "CVE-2022-27593" || !m.Matched || m.Target != "192.168.10.21:5000" || m.Error != "" ||
		!strings.HasPrefix(m.Request, "GET /photo/p/api/video.php") || !strings.HasPrefix(m.Response, "HTTP/1.1 200 OK") {
		t.Fatalf("match: %+v", m)
	}
	if n := res[1]; n.Matched || n.Template != "CVE-2024-3400" || n.Error != "" {
		t.Fatalf("non-match: %+v", n)
	}
	if e := res[2]; e.Matched || e.Error != "context deadline exceeded (Client.Timeout exceeded while awaiting headers)" || e.Request != "" || e.Target != "192.168.10.21:443" {
		t.Fatalf("error line: %+v", e)
	}
}

func TestParse_EmptyOutputIsNoResult(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "\n", "\n\n  \n"} {
		res, err := Parse([]byte(in), templates, targets)
		if err != nil || len(res) != 0 {
			t.Fatalf("%q: %v %v", in, res, err)
		}
	}
}

const ok = `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:5000","matched-at":"http://192.168.10.21:5000/photo/","matcher-status":false}`

// Fail closed: one bad line throws the whole run away (INV-10, SYS-6).
func TestParse_RefusesTheWholeOutput(t *testing.T) {
	t.Parallel()
	const h = `"host":"http://192.168.10.21:5000"`
	cases := map[string]string{ //nolint:gosec // G101: not credentials; the user-info form is an attack the parser must refuse
		"not JSON":                ok + "\n{",
		"array":                   ok + "\n[]",
		"string":                  ok + "\n\"x\"",
		"repeated key":            `{"template-id":"CVE-2022-27593","template-id":"CVE-2024-3400",` + h + `,"matcher-status":true}`,
		"key differing by case":   `{"template-id":"CVE-2022-27593","Template-ID":"CVE-2024-3400",` + h + `,"matcher-status":true}`,
		"no matcher-status":       `{"template-id":"CVE-2022-27593",` + h + `}`,
		"matcher-status a string": `{"template-id":"CVE-2022-27593",` + h + `,"matcher-status":"true"}`,
		"template not in the job": `{"template-id":"CVE-2021-44228",` + h + `,"matcher-status":true}`,
		"no template":             `{` + h + `,"matcher-status":true}`,
		"host not in the job":     `{"template-id":"CVE-2022-27593","host":"http://192.168.10.99:5000","matcher-status":true}`,
		"port not in the job":     `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:8080","matcher-status":true}`,
		"no port, no scheme":      `{"template-id":"CVE-2022-27593","host":"192.168.10.21","matcher-status":true}`,
		"host prefix trick":       `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21.evil.example:5000","matcher-status":true}`,
		"user-info trick":         `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:5000@10.0.0.9:80","matcher-status":true}`,
		"no host":                 `{"template-id":"CVE-2022-27593","matcher-status":true}`,
		"match with an error":     `{"template-id":"CVE-2022-27593",` + h + `,"matcher-status":true,"error":"timeout"}`,
		"deep nesting":            `{"template-id":"CVE-2022-27593",` + h + `,"matcher-status":true,"meta":` + strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40) + `}`,
		"trailing data":           ok + ` {}`,
		"request not a string":    `{"template-id":"CVE-2022-27593",` + h + `,"matcher-status":true,"request":{}}`,
	}
	for name, in := range cases {
		if res, err := Parse([]byte(in), templates, targets); err == nil {
			t.Errorf("%s: accepted %+v", name, res)
		}
	}
	// a scheme without a port means its default port
	if res, err := Parse([]byte(`{"template-id":"CVE-2022-27593","host":"https://192.168.10.21","matcher-status":false}`), templates, targets); err != nil || res[0].Target != "192.168.10.21:443" {
		t.Fatalf("https default port: %+v %v", res, err)
	}
}

func TestParse_Limits(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte(ok+"\n"), nucleiargv.MaxOutput/len(ok)+1)
	if _, err := Parse(big, templates, targets); err == nil {
		t.Fatal("more than MaxOutput accepted")
	}
	if _, err := Parse(bytes.Repeat([]byte(ok+"\n"), MaxLines+1), templates, targets); err == nil {
		t.Fatal("more than MaxLines accepted")
	}
	if _, err := Parse(bytes.Repeat([]byte(ok+"\n"), MaxLines), templates, targets); err != nil {
		t.Fatalf("MaxLines lines refused: %v", err)
	}
}

// invisible is written apart from Clean: characters evidence must never hold. Newline and tab are the only controls
// kept. Built from code points so that no such character is ever in this source file.
func invisible(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20, r >= 0x7f && r <= 0x9f: // C0, DEL, C1
		return true
	case r == 0xad, r == 0x61c, r == 0x180e, r == 0xfeff, r == 0xfffd: // soft hyphen, Arabic letter mark, Mongolian vowel separator, BOM, replacement
		return true
	case r >= 0x200b && r <= 0x200f, r >= 0x2028 && r <= 0x202e, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x206f: // zero-width, line/paragraph separators, bidi, invisible operators
		return true
	case r >= 0xfff9 && r <= 0xfffb, r >= 0xe0000 && r <= 0xe007f: // interlinear annotation, tag characters
		return true
	}
	return false
}

// L1: the categories Cc, Cf, Zl and Zp go, newlines and tabs stay, text is capped on a rune boundary.
func TestClean_DropsInvisibleAndControlCharacters(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("a\tb\nc")
	for _, r := range []rune{0x00, 0x07, 0x1b, 0x7f, 0x85, 0xad, 0x61c, 0x180e, 0x200b, 0x200d, 0x200e, 0x2028, 0x2029, 0x202a, 0x202e, 0x2060, 0x2066, 0x2069, 0xfeff, 0xfffd, 0xe0001, 0xe0041, 0xe007f} {
		b.WriteRune(r)
	}
	b.WriteString("d\r\ne")
	if got := Clean(b.String(), 100); got != "a\tb\ncd\ne" {
		t.Fatalf("Clean = %q", got)
	}
	long := strings.Repeat("é", 10)
	if got := Clean(long, 5); got != "éé"+cutMark || !utf8.ValidString(got) {
		t.Fatalf("cap: %q", got)
	}
	for r := rune(0); r < 0x110000; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		if invisible(r) && Clean(string(r), 10) != "" {
			t.Fatalf("U+%04X kept", r)
		}
	}
}

// INV-10: evidence from a whole line is cleaned and capped.
func TestParse_EvidenceIsCleanedAndCapped(t *testing.T) {
	t.Parallel()
	rlo := string(rune(0x202e))
	resp := "HTTP/1.1 200 OK\r\nX: \x1b[31mred\x07" + rlo + "evil\r\n\r\n" + strings.Repeat("é", MaxResponse) + "\xff"
	line := `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:5000","matcher-status":true,"request":"GET / HTTP/1.1\r\n\tHost: x\u0000","response":` + quote(resp) + `}`
	res, err := Parse([]byte(line), templates, targets)
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
	long := `{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:5000","matcher-status":false,"error":` + quote(strings.Repeat("e", 1000)) + `}`
	if res, err := Parse([]byte(long), templates, targets); err != nil || len(res[0].Error) > MaxError+len(cutMark) {
		t.Fatalf("error not capped: %v %d", err, len(res[0].Error))
	}
}

// L2: the target of a line is host:port, with the scheme's default port when there is none.
func TestHostOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"192.168.10.21:22":                    "192.168.10.21:22",
		"http://192.168.10.21:5000":           "192.168.10.21:5000",
		"https://192.168.10.21:443/x?y=1":     "192.168.10.21:443",
		"https://192.168.10.21":               "192.168.10.21:443",
		"http://192.168.10.21/a":              "192.168.10.21:80",
		"192.168.10.21":                       "",
		"ftp://192.168.10.21":                 "",
		"http://u@10.0.0.9:80":                "",
		"http://[::1]:80":                     "",
		"http://10.0.0.9:0x50":                "",
		"http://10.0.0.9:":                    "",
		"":                                    "",
		"https://scan.acme.example:8443/path": "scan.acme.example:8443",
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

// Parse never panics, and what it returns is always inside the job and clean by the independent rule above.
func FuzzParse(f *testing.F) {
	f.Add(string(fixture(f)))
	f.Add(ok)
	f.Add("{\"template-id\":\"CVE-2022-27593\",\"host\":\"http://192.168.10.21:5000\",\"matcher-status\":true,\"response\":\"\xe2\x80\xae\xe2\x80\x8b x\"}")
	f.Add("{\"a\":" + strings.Repeat("[", 50))
	f.Fuzz(func(t *testing.T, in string) {
		res, err := Parse([]byte(in), templates, targets)
		if err != nil {
			return
		}
		for _, r := range res {
			if (r.Target != targets[0] && r.Target != targets[1] && r.Target != targets[2]) || (r.Template != templates[0] && r.Template != templates[1]) {
				t.Fatalf("result outside the job: %+v", r)
			}
			for _, s := range []string{r.Request, r.Response, r.Error} {
				if !utf8.ValidString(s) || strings.ContainsFunc(s, invisible) {
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
