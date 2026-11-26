package nucleiout

import (
	"bytes"
	"os"
	"slices"
	"strconv"
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

// The fixture is a real recording (lab VM ubuntu2404, 2026-11-12): the pinned nuclei v3.11.1 with the argv of
// nucleiargv.Build (-rl 5 -mhe 3), three pack templates and four targets served inside the VM: 192.168.10.21:5000 answers
// like a vulnerable QNAP Photo Station, 192.168.10.21:21 like a vulnerable ProFTPd, 192.168.10.22:80 drops every packet
// (timeouts), 192.168.11.30:80 has no host behind it (no route to host). nuclei 3.11.1 writes "host" as the bare address
// with "port" apart.
var (
	labTemplates = []string{"CVE-2015-3306", "CVE-2001-0537", "CVE-2022-27593"}
	labTargets   = []string{"192.168.10.21:5000", "192.168.10.22:80", "192.168.11.30:80", "192.168.10.21:21"}
)

func TestParse_Fixture(t *testing.T) {
	t.Parallel()
	res, err := Parse(fixture(t), labTemplates, labTargets)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		tpl, target string
		matched     bool
		err         string
	}
	wants := []want{
		{"CVE-2015-3306", "192.168.10.21:21", true, ""},
		{"CVE-2015-3306", "192.168.10.21:5000", false, "EOF"},
		{"CVE-2015-3306", "192.168.10.22:80", false, "context cancelled before establishing connection"},
		{"CVE-2015-3306", "192.168.11.30:80", false, "port closed or filtered"},
		{"CVE-2001-0537", "192.168.10.21:21", false, "tls: first record does not look like a TLS handshake"},
		{"CVE-2001-0537", "192.168.10.21:5000", false, ""},
		{"CVE-2001-0537", "192.168.10.22:80", false, "got err while executing http://192.168.10.22:80/level/16/exec/show/config/CR"},
		{"CVE-2001-0537", "192.168.11.30:80", false, "port closed or filtered"},
		{"CVE-2022-27593", "192.168.10.21:21", false, "tls: first record does not look like a TLS handshake"},
		{"CVE-2022-27593", "192.168.10.21:5000", true, ""},
		{"CVE-2022-27593", "192.168.11.30:80", false, "host was skipped as it was found unresponsive"}, // "host" is the input URL here, no "port"
		{"CVE-2022-27593", "192.168.10.22:80", false, "net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)"},
	}
	if len(res) != len(wants) {
		t.Fatalf("%d results: %+v", len(res), res)
	}
	for i, w := range wants {
		if r := res[i]; r.Template != w.tpl || r.Target != w.target || r.Matched != w.matched || r.Error != w.err {
			t.Errorf("line %d: %+v, want %+v", i+1, r, w)
		}
	}
	if m := res[9]; !strings.HasPrefix(m.Request, "GET /photo/combine.php?type=javascript") || !strings.HasPrefix(m.Response, "HTTP/1.0 200 OK") ||
		!strings.Contains(m.Response, "module.exports") {
		t.Fatalf("http match evidence: %+v", m)
	}
	if m := res[0]; !strings.Contains(m.Response, "Copy successful") {
		t.Fatalf("tcp match evidence: %+v", m)
	}
	// a line for a target the job did not name is skipped and counted; one for a template it did not name still throws
	// the whole run away
	if got, skip, err := Read(fixture(t), labTemplates, labTargets[:3]); err != nil || skip.Lines != 3 || len(got) != len(res)-3 ||
		slices.ContainsFunc(got, func(r Result) bool { return r.Target == labTargets[3] }) {
		t.Fatalf("a target outside the job: %d results, %+v, %v", len(got), skip, err)
	}
	if _, err := Parse(fixture(t), labTemplates[1:], labTargets); err == nil {
		t.Fatal("a template outside the job was accepted")
	}
}

// nuclei 3.11.1's bare host with its port, and the older shapes; "port" beside a host that has one must agree with it.
func TestParse_HostAndPort(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`"host":"192.168.10.21","port":"5000"`:                "192.168.10.21:5000",
		`"host":"http://192.168.10.21:5000","port":"5000"`:    "192.168.10.21:5000",
		`"host":"192.168.10.21:5000","port":"5000"`:           "192.168.10.21:5000",
		`"host":"https://192.168.10.21","port":"443"`:         "192.168.10.21:443",
		`"host":"http://192.168.10.21:5000"`:                  "192.168.10.21:5000",
		`"host":"192.168.10.21","port":"443","url":"x"`:       "192.168.10.21:443",
		`"host":"192.168.10.21","port":"22","scheme":"https"`: "192.168.10.21:22",
		`"host":"192.168.10.21:5000","port":"443"`:            "",
		`"host":"http://192.168.10.21:5000","port":"443"`:     "",
		`"host":"192.168.10.21","port":"05000"`:               "",
		`"host":"192.168.10.21","port":""`:                    "",
		`"host":"192.168.10.21","port":"0"`:                   "",
		`"host":"192.168.10.21/x","port":"5000"`:              "",
		`"host":"a@192.168.10.21","port":"5000"`:              "",
		`"host":"","port":"5000"`:                             "",
		`"host":"192.168.10.21.evil.example","port":"5000"`:   "",
		`"host":"192.168.10.21","port":"5000/anything"`:       "", // a port that is not only digits
		`"host":"http","port":"//192.168.10.21:5000"`:         "", // the two fields making up a URL together
		`"host":"192.168.10.21","port":"5000?x"`:              "",
		`"host":"192.168.010.21","port":"5000"`:               "",
		`"host":"192.168.10.21","port":"+5000"`:               "",
		`"host":"192.168.10.21","port":"65536"`:               "",
	} {
		line := `{"template-id":"CVE-2022-27593",` + in + `,"matcher-status":false}`
		res, err := Parse([]byte(line), templates, targets)
		switch {
		case want == "" && err == nil && len(res) > 0:
			t.Errorf("%s accepted: %+v", in, res)
		case want != "" && (err != nil || res[0].Target != want):
			t.Errorf("%s: %+v %v, want %s", in, res, err, want)
		}
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
	cases := map[string]string{
		"not JSON":                ok + "\n{",
		"array":                   ok + "\n[]",
		"string":                  ok + "\n\"x\"",
		"repeated key":            `{"template-id":"CVE-2022-27593","template-id":"CVE-2024-3400",` + h + `,"matcher-status":true}`,
		"key differing by case":   `{"template-id":"CVE-2022-27593","Template-ID":"CVE-2024-3400",` + h + `,"matcher-status":true}`,
		"matcher-status a string": `{"template-id":"CVE-2022-27593",` + h + `,"matcher-status":"true"}`,
		"template not in the job": `{"template-id":"CVE-2021-44228",` + h + `,"matcher-status":true}`,
		"no template":             `{` + h + `,"matcher-status":true}`,
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

// A line about an address the job did not name (another host, another port, a name) is skipped and counted, never a
// result; the run is kept. The first one's template, host and port go to the log and the probe row.
func TestRead_SkipsALineForAnotherTarget(t *testing.T) {
	t.Parallel()
	lines := []string{
		ok,
		`{"template-id":"CVE-2022-27593","host":"192.168.10.99","port":"5000","matcher-status":true}`,                // another host
		`{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:8080","matcher-status":true}`,                  // another port
		`{"template-id":"CVE-2024-3400","host":"http://192.168.10.21.evil.example:5000","matcher-status":false}`,     // a name
		`{"template-id":"CVE-2024-3400","host":"https://192.168.10.21","port":"443","matcher-status":true}`,          // the job's 443 in URL form
		`{"template-id":"CVE-2024-3400","host":"192.168.10.21:22","port":"22","matcher-status":false,"error":"EOF"}`, // host:port in host
		`{"template-id":"CVE-2024-3400","host":"http://192.168.10.99:11080/landing","matcher-status":true}`,          // a redirect elsewhere
	}
	res, skip, err := Read([]byte(strings.Join(lines, "\n")), templates, targets)
	if err != nil || len(res) != 3 || skip.Lines != 4 {
		t.Fatalf("res %+v skip %+v err %v", res, skip, err)
	}
	if skip.Template != "CVE-2022-27593" || skip.Host != "192.168.10.99" || skip.Port != "5000" {
		t.Fatalf("first skipped: %+v", skip)
	}
	if res[1].Target != "192.168.10.21:443" || !res[1].Matched || res[2].Target != "192.168.10.21:22" {
		t.Fatalf("the job's targets in another spelling: %+v", res)
	}
	if n := skip.Note(); n != " [not counted: 4 nuclei line(s) that could not be a result of this check (another address, an unreadable target, no match status, or a match with an error), 3 said matched; first: CVE-2022-27593 on 192.168.10.99:5000]" {
		t.Fatalf("note %q", n)
	}
	if !slices.Equal(skip.Templates, []string{"CVE-2022-27593", "CVE-2024-3400"}) {
		t.Fatalf("skipped templates %q", skip.Templates)
	}
	if (Skipped{}).Note() != "" {
		t.Fatal("a note with nothing skipped")
	}
	// review r2 L5: templates past the cap are counted, not named
	var many21 []string
	tpls := []string{}
	for i := range MaxSkippedTemplates + 2 {
		id := "T-" + strconv.Itoa(i)
		tpls = append(tpls, id)
		many21 = append(many21, `{"template-id":"`+id+`","host":"fw.lan","port":"443","matcher-status":false}`)
	}
	if _, sk, err := Read([]byte(strings.Join(many21, "\n")), tpls, targets); err != nil || len(sk.Templates) != MaxSkippedTemplates || sk.MoreTemplates != 2 || len(sk.MatchedTemplates) != 0 {
		t.Fatalf("over the cap: %+v %v", sk, err)
	}
	// skipped lines still count toward the line limit
	many := bytes.Repeat([]byte(lines[1]+"\n"), MaxLines+1)
	if _, _, err := Read(many, templates, targets); err == nil {
		t.Fatal("more than MaxLines skipped lines were read")
	}
}

// Review r1 M6: a line of one of the job's templates whose target cannot be read (a bare name, IPv6, a name with "_", host:port
// with no port, user info), with no matcher-status, or a match with an error, is skipped and counted like a foreign one: the run is
// kept. The host of such a line is never stored raw. Only broken JSON, a template outside the job and output over the cap reject.
func TestRead_SkipsLinesThatCannotBeAResult(t *testing.T) {
	t.Parallel()
	lines := []string{
		ok,
		`{"template-id":"CVE-2022-27593","host":"fw.lan","port":"443","matcher-status":false}`,
		`{"template-id":"CVE-2022-27593","host":"[::1]","port":"443","matcher-status":false}`,
		`{"template-id":"CVE-2022-27593","host":"https://[::1]:443","matcher-status":false}`,
		`{"template-id":"CVE-2022-27593","host":"my_host.lan:443","matcher-status":false}`,
		`{"template-id":"CVE-2022-27593","host":"192.168.10.21","port":"","matcher-status":true}`,
		`{"template-id":"CVE-2022-27593","host":"http://192.168.10.21:5000@10.0.0.9:80","matcher-status":true}`,
		`{"template-id":"CVE-2024-3400","host":"http://192.168.10.21:5000"}`,
		`{"template-id":"CVE-2024-3400","host":"http://192.168.10.21:5000","matcher-status":true,"error":"timeout"}`,
	}
	res, skip, err := Read([]byte(strings.Join(lines, "\n")), templates, targets)
	if err != nil || len(res) != 1 || skip.Lines != 8 || skip.Matched != 3 || skip.Host != "(unreadable)" || skip.Port != "" || skip.Template != "CVE-2022-27593" {
		t.Fatalf("res %+v skip %+v err %v", res, skip, err)
	}
	// review r2 M3: the templates of skipped lines that said matched are named, so they never read "no match reported"
	if !slices.Equal(skip.MatchedTemplates, []string{"CVE-2022-27593", "CVE-2024-3400"}) {
		t.Fatalf("matched templates %q", skip.MatchedTemplates)
	}
	for name, in := range map[string]string{
		"broken JSON":          ok + "\n{",
		"a template not asked": `{"template-id":"CVE-2021-44228","host":"fw.lan","port":"443","matcher-status":false}`,
		"a status of a string": `{"template-id":"CVE-2022-27593","host":"fw.lan","port":"443","matcher-status":"false"}`,
	} {
		if _, _, err := Read([]byte(in), templates, targets); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the note goes after the request and is cut, never the request
	req := strings.Repeat("r", 290)
	if got := AppendNote(req, skip.Note(), 300); !strings.HasPrefix(got, req) || len([]rune(got)) != 300 {
		t.Fatalf("AppendNote = %q", got)
	}
	if got := AppendNote(strings.Repeat("r", 301), skip.Note(), 300); got != strings.Repeat("r", 301) {
		t.Fatal("AppendNote cut the request")
	}
}

// Every line shape the pinned nuclei v3.11.1 printed in the lab (kf-scan item 4, 2026-11-14: the release binary,
// in a podman container with no network against servers on 127.0.0.1, rewritten to
// 192.168.10.21; the argv of a full job, -or -ot): tcp, ssl and http templates on an https port, a plain TCP port and 443; a page
// that redirects to another port and to another host (-dr: not followed, the line is about the job's target); a template with
// two named matchers (two lines); an http template whose path names another port (nuclei refuses the URL, the line is about the
// job's target). Every line maps to a target of the job; none is skipped.
func TestRead_EveryShapeOfThePinnedNuclei(t *testing.T) {
	t.Parallel()
	tpls := []string{"lab-banner", "lab-ssl", "lab-hostredirect", "lab-miss", "lab-tech", "lab-redirect", "lab-otherport"}
	tgts := []string{"192.168.10.21:10443", "192.168.10.21:10022", "192.168.10.21:443"}
	for _, f := range []string{"testdata/shapes.jsonl", "testdata/otherport.jsonl"} {
		out := mustRead(t, f)
		res, skip, err := Read(out, tpls, tgts)
		if err != nil || skip.Lines != 0 || len(res) != bytes.Count(out, []byte("\n")) {
			t.Fatalf("%s: %d results, %+v, %v", f, len(res), skip, err)
		}
		for _, r := range res {
			if r.Template == "lab-redirect" && r.Matched {
				t.Fatalf("%s: a redirect was followed: %+v", f, r)
			}
		}
	}
	res, _, _ := Read(mustRead(t, "testdata/shapes.jsonl"), tpls, tgts)
	names := 0
	for _, r := range res {
		if r.Template == "lab-tech" && r.Matched && (r.MatcherName == "labadmin" || r.MatcherName == "hello") {
			names++
		}
	}
	if names != 4 {
		t.Fatalf("matcher names of the two-matcher template: %d", names)
	}
	// the job without 443: its lines are skipped, the others kept
	res, skip, err := Read(mustRead(t, "testdata/shapes.jsonl"), tpls, tgts[:2])
	if err != nil || skip.Lines != 7 || skip.Port != "443" || skip.Template != "lab-ssl" || len(res) != 13 {
		t.Fatalf("without 443: %d %+v %v", len(res), skip, err)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // G304: a fixed name under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
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

// The categories Cc, Cf, Zl and Zp go, newlines and tabs stay, text is capped on a rune boundary.
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

// The target of a line is host:port, with the scheme's default port when there is none.
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

// nuclei 3.11.1 merges templates that send the same request into one cluster. When it gives up a host it found unresponsive, it
// prints one skip line per cluster under the cluster's own id ("cluster-" and a SHA-256), not under the templates of the job. Such
// a line is not a result of any template: it is skipped and counted, and the run is kept (a deep run of 200 http/technologies
// templates on a host that stopped answering was thrown away whole, "a template the job did not ask for"). A cluster id with a
// match, or one that is not exactly that shape, still throws the run away.
func TestRead_ClusterSkipLineOfAnUnresponsiveHost(t *testing.T) {
	t.Parallel()
	const cluster = `"template-id":"cluster-49941d3cbc6e510ee8b2606610b8f809ecebf7d0c5a21bb373704f46592eb5eb","info":{"author":null,"tags":null,"severity":""},"type":"","host":"https://192.0.2.10:9443","timestamp":"2026-11-26T03:49:38.507968195Z"`
	own := `{"template-id":"gitlab-detect","host":"192.0.2.10","port":"9443","matcher-status":false,"error":"port closed or filtered"}`
	skip := `{` + cluster + `,"matcher-status":false,"error":"host was skipped as it was found unresponsive"}`
	out := []byte(own + "\n" + skip + "\n" + skip + "\n")
	res, sk, err := Read(out, []string{"gitlab-detect", "grafana-detect"}, []string{"192.0.2.10:9443"})
	if err != nil {
		t.Fatalf("the run was thrown away: %v", err)
	}
	if len(res) != 1 || res[0].Template != "gitlab-detect" || sk.Lines != 2 || sk.Matched != 0 || slices.Contains(sk.Templates, "") {
		t.Fatalf("results %+v, skipped %+v", res, sk)
	}
	for name, line := range map[string]string{
		"a cluster line with a match":        `{` + cluster + `,"matcher-status":true}`,
		"a cluster id that is not a SHA-256": strings.Replace(skip, "cluster-49941d3c", "cluster-49941d3X", 1),
		"a cluster line without an error":    `{` + cluster + `,"matcher-status":false}`,
	} {
		if _, _, err := Read([]byte(line+"\n"), []string{"gitlab-detect"}, []string{"192.0.2.10:9443"}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
