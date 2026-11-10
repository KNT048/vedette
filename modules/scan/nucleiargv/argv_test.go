package nucleiargv

import (
	"slices"
	"strings"
	"testing"
)

func job() Job {
	return Job{
		Templates:     []string{"CVE-2022-27593", "CVE-2024-3400"},
		Targets:       []Target{{Host: "192.168.10.21", Port: 5000, Scheme: "http"}, {Host: "192.168.10.21", Port: 443, Scheme: "https"}, {Host: "192.168.10.21", Port: 22}},
		Rate:          5,
		MaxHostErrors: 3,
	}
}

func TestBuild_Shape(t *testing.T) {
	t.Parallel()
	args, err := Build(job())
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(fixedFlags),
		"-rl", "5", "-mhe", "3", "-id", "CVE-2022-27593,CVE-2024-3400",
		"-u", "http://192.168.10.21:5000", "-u", "https://192.168.10.21:443", "-u", "192.168.10.21:22")
	if !slices.Equal(args, want) {
		t.Fatalf("argv:\n%q\nwant:\n%q", args, want)
	}
	if err := Validate(args); err != nil {
		t.Fatalf("Validate refuses what Build made: %v", err)
	}
}

// The fixed part is what keeps nuclei safe and quiet (D-125 (4)): one template file tree, no update check, no
// interactsh (out-of-band hosts outside the scope), no headless, code or file templates, no dos/intrusive/fuzz tags.
func TestBuild_FixedFlagsAreTheSafeOnes(t *testing.T) {
	t.Parallel()
	joined := strings.Join(fixedFlags, " ")
	for _, want := range []string{"-t " + TemplatesDir, "-duc", "-ni", "-jsonl", "-ms", "-etags dos,intrusive,fuzz", "-ept headless,code,file", "-c 1", "-bs 1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("fixed flags lack %q: %s", want, joined)
		}
	}
	for _, never := range []string{"-ut", "-update", "-iserver", "-interactsh-url", "-cloud-upload", "-dashboard", "-code", "-headless", "-dast", "-fuzz", "-itags", "-include-tags", "-tl", "-H", "-var", "-proxy"} {
		for _, a := range fixedFlags {
			if a == never {
				t.Errorf("fixed flags contain %q", never)
			}
		}
	}
}

func TestBuild_Refuses(t *testing.T) {
	t.Parallel()
	mut := func(f func(*Job)) Job { j := job(); f(&j); return j }
	many := func(n int, f func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	cases := map[string]Job{
		"no template":       mut(func(j *Job) { j.Templates = nil }),
		"33 templates":      mut(func(j *Job) { j.Templates = many(33, func(i int) string { return "t" + strings.Repeat("x", i) }) }),
		"template comma":    mut(func(j *Job) { j.Templates = []string{"a,b"} }),
		"template flag":     mut(func(j *Job) { j.Templates = []string{"-code"} }),
		"template path":     mut(func(j *Job) { j.Templates = []string{"../x"} }),
		"template space":    mut(func(j *Job) { j.Templates = []string{"a b"} }),
		"template repeated": mut(func(j *Job) { j.Templates = []string{"a", "a"} }),
		"no target":         mut(func(j *Job) { j.Targets = nil }),
		"17 targets": mut(func(j *Job) {
			j.Targets = nil
			for p := 1; p <= 17; p++ {
				j.Targets = append(j.Targets, Target{Host: "10.0.0.1", Port: p})
			}
		}),
		"rate 0":            mut(func(j *Job) { j.Rate = 0 }),
		"rate 21":           mut(func(j *Job) { j.Rate = 21 }),
		"host errors 1":     mut(func(j *Job) { j.MaxHostErrors = 1 }),
		"host errors 21":    mut(func(j *Job) { j.MaxHostErrors = 21 }),
		"loopback":          mut(func(j *Job) { j.Targets = []Target{{Host: "127.0.0.1", Port: 80, Scheme: "http"}} }),
		"unspecified":       mut(func(j *Job) { j.Targets = []Target{{Host: "0.0.0.0", Port: 80, Scheme: "http"}} }),
		"link-local":        mut(func(j *Job) { j.Targets = []Target{{Host: "169.254.169.254", Port: 80, Scheme: "http"}} }),
		"multicast":         mut(func(j *Job) { j.Targets = []Target{{Host: "224.0.0.1", Port: 80, Scheme: "http"}} }),
		"broadcast":         mut(func(j *Job) { j.Targets = []Target{{Host: "255.255.255.255", Port: 80, Scheme: "http"}} }),
		"IPv6":              mut(func(j *Job) { j.Targets = []Target{{Host: "fe80::1", Port: 80, Scheme: "http"}} }),
		"mapped IPv6":       mut(func(j *Job) { j.Targets = []Target{{Host: "::ffff:192.168.1.1", Port: 80, Scheme: "http"}} }),
		"leading zero":      mut(func(j *Job) { j.Targets = []Target{{Host: "192.168.010.1", Port: 80, Scheme: "http"}} }),
		"upper-case domain": mut(func(j *Job) { j.Targets = []Target{{Host: "Acme.example", Port: 443, Scheme: "https"}} }),
		"domain with path":  mut(func(j *Job) { j.Targets = []Target{{Host: "acme.example/x", Port: 443, Scheme: "https"}} }),
		"domain with at":    mut(func(j *Job) { j.Targets = []Target{{Host: "user@acme.example", Port: 443, Scheme: "https"}} }),
		"single-label host": mut(func(j *Job) { j.Targets = []Target{{Host: "localhost", Port: 80, Scheme: "http"}} }),
		"port 0":            mut(func(j *Job) { j.Targets = []Target{{Host: "10.0.0.1", Port: 0}} }),
		"port 65536":        mut(func(j *Job) { j.Targets = []Target{{Host: "10.0.0.1", Port: 65536}} }),
		"scheme ftp":        mut(func(j *Job) { j.Targets = []Target{{Host: "10.0.0.1", Port: 21, Scheme: "ftp"}} }),
		"same target twice": mut(func(j *Job) {
			j.Targets = []Target{{Host: "10.0.0.1", Port: 80, Scheme: "http"}, {Host: "10.0.0.1", Port: 80, Scheme: "http"}}
		}),
		"flag-shaped host": mut(func(j *Job) { j.Targets = []Target{{Host: "-iserver", Port: 80, Scheme: "http"}} }),
		"empty host":       mut(func(j *Job) { j.Targets = []Target{{Port: 80, Scheme: "http"}} }),
		"256-char domain":  mut(func(j *Job) { j.Targets = []Target{{Host: strings.Repeat("a.", 127) + "ab", Port: 80, Scheme: "http"}} }),
		"label of 64 chars": mut(func(j *Job) {
			j.Targets = []Target{{Host: strings.Repeat("a", 64) + ".example", Port: 80, Scheme: "http"}}
		}),
		"label ending in -":  mut(func(j *Job) { j.Targets = []Target{{Host: "acme-.example", Port: 80, Scheme: "http"}} }),
		"numeric last label": mut(func(j *Job) { j.Targets = []Target{{Host: "acme.123", Port: 80, Scheme: "http"}} }),
	}
	for name, j := range cases {
		if args, err := Build(j); err == nil {
			t.Errorf("%s: built %q", name, args)
		}
	}
	if _, err := Build(mut(func(j *Job) {
		j.Targets = []Target{{Host: "scan.acme.example", Port: 8443, Scheme: "https"}, {Host: "203.0.113.7", Port: 80, Scheme: "http"}}
	})); err != nil {
		t.Errorf("a domain and a public IPv4 (D-125 (1), external targets later): %v", err)
	}
}

func TestValidate_RefusesAnythingElse(t *testing.T) {
	t.Parallel()
	good, err := Build(job())
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func([]string) []string) []string { return f(slices.Clone(good)) }
	n := len(fixedFlags)
	cases := map[string][]string{
		"empty":                    nil,
		"fixed flag dropped":       edit(func(a []string) []string { return slices.Delete(a, 2, 3) }),
		"extra flag at the end":    edit(func(a []string) []string { return append(a, "-code") }),
		"extra flag in the middle": edit(func(a []string) []string { return slices.Insert(a, n, "-headless") }),
		"other templates dir":      edit(func(a []string) []string { a[1] = "/tmp/t"; return a }),
		"rate as word":             edit(func(a []string) []string { a[n+1] = "five"; return a }),
		"rate with sign":           edit(func(a []string) []string { a[n+1] = "+5"; return a }),
		"rate leading zero":        edit(func(a []string) []string { a[n+1] = "05"; return a }),
		"rate 50":                  edit(func(a []string) []string { a[n+1] = "50"; return a }),
		"host errors 99":           edit(func(a []string) []string { a[n+3] = "99"; return a }),
		"no -id":                   edit(func(a []string) []string { a[n+4] = "-tags"; return a }),
		"id list with flag":        edit(func(a []string) []string { a[n+5] = "CVE-2022-27593,-code"; return a }),
		"id list empty item":       edit(func(a []string) []string { a[n+5] = "CVE-2022-27593,"; return a }),
		"no target":                edit(func(a []string) []string { return a[:n+6] }),
		"-u without value":         edit(func(a []string) []string { return a[:len(a)-1] }),
		"-l instead of -u":         edit(func(a []string) []string { a[n+6] = "-l"; return a }),
		"target with path":         edit(func(a []string) []string { a[n+7] = "http://192.168.10.21:5000/admin"; return a }),
		"target without port":      edit(func(a []string) []string { a[n+7] = "http://192.168.10.21"; return a }),
		"target with user":         edit(func(a []string) []string { a[n+7] = "http://x@192.168.10.21:5000"; return a }),
		"target loopback":          edit(func(a []string) []string { a[n+7] = "http://127.0.0.1:5000"; return a }),
		"target port zero-padded":  edit(func(a []string) []string { a[n+7] = "http://192.168.10.21:05000"; return a }),
		"target repeated":          edit(func(a []string) []string { return append(a, "-u", "192.168.10.21:22") }),
	}
	for name, args := range cases {
		if err := Validate(args); err == nil {
			t.Errorf("%s: accepted %q", name, args)
		}
	}
}

func TestTarget_Input(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		t    Target
		want string
	}{
		{Target{Host: "10.0.0.1", Port: 80, Scheme: "http"}, "http://10.0.0.1:80"},
		{Target{Host: "acme.example", Port: 443, Scheme: "https"}, "https://acme.example:443"},
		{Target{Host: "10.0.0.1", Port: 22}, "10.0.0.1:22"},
	} {
		if got := c.t.Input(); got != c.want {
			t.Errorf("%+v: %s", c.t, got)
		}
		back, ok := parseInput(c.want)
		if !ok || back != c.t {
			t.Errorf("parseInput(%s) = %+v %v", c.want, back, ok)
		}
	}
}

// Validate must never panic and must only accept what Build could have made from a job it accepts.
func FuzzValidate(f *testing.F) {
	good, _ := Build(job())
	f.Add(strings.Join(good, "\x00"))
	f.Add(strings.Join(append(slices.Clone(fixedFlags), "-rl", "1", "-mhe", "2", "-id", "a", "-u", "10.0.0.1:1"), "\x00"))
	f.Add("-t\x00/x\x00-u\x00http://[::1]:80")
	f.Fuzz(func(t *testing.T, s string) {
		args := strings.Split(s, "\x00")
		if err := Validate(args); err != nil {
			return
		}
		j, err := parse(args)
		if err != nil {
			t.Fatalf("Validate accepted what parse refuses: %q: %v", args, err)
		}
		again, err := Build(j)
		if err != nil || !slices.Equal(again, args) {
			t.Fatalf("accepted argv is not what Build makes:\n%q\n%q %v", args, again, err)
		}
	})
}
