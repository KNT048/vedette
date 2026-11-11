package nucleiargv

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func job() Job {
	return Job{
		Templates:     []string{"http/cves/2022/CVE-2022-27593.yaml", "http/cves/2024/CVE-2024-3400.yaml"},
		Targets:       []Target{{Host: "192.168.10.21", Port: 5000, Scheme: "http"}, {Host: "192.168.10.21", Port: 443, Scheme: "https"}, {Host: "192.168.10.21", Port: 22}},
		Rate:          5,
		MaxHostErrors: 3,
	}
}

// M2: each selected template is named by its file, from the verified index; nuclei loads nothing else.
func TestBuild_Shape(t *testing.T) {
	t.Parallel()
	args, err := Build(job())
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(fixedFlags),
		"-rl", "5", "-mhe", "3",
		"-t", TemplatesDir+"/http/cves/2022/CVE-2022-27593.yaml", "-t", TemplatesDir+"/http/cves/2024/CVE-2024-3400.yaml",
		"-u", "http://192.168.10.21:5000", "-u", "https://192.168.10.21:443", "-u", "192.168.10.21:22")
	if !slices.Equal(args, want) {
		t.Fatalf("argv:\n%q\nwant:\n%q", args, want)
	}
	if err := Validate(args); err != nil {
		t.Fatalf("Validate refuses what Build made: %v", err)
	}
}

// M1: the fixed part allows protocols (http, tcp, ssl) instead of denying some, follows no redirect and probes nothing.
func TestBuild_FixedFlagsAreTheSafeOnes(t *testing.T) {
	t.Parallel()
	joined := " " + strings.Join(fixedFlags, " ") + " "
	for _, want := range []string{" -duc ", " -ni ", " -jsonl ", " -ms ", " -etags dos,intrusive,fuzz ", " -pt http,tcp,ssl ", " -dr ", " -nh ", " -c 1 ", " -bs 1 "} {
		if !strings.Contains(joined, want) {
			t.Errorf("fixed flags lack %q: %s", want, joined)
		}
	}
	for _, never := range []string{"-ept", "-id", "-t", "-tags", "-w", "-workflows", "-l", "-list", "-config", "-ut", "-update", "-iserver",
		"-interactsh-url", "-cloud-upload", "-dashboard", "-code", "-headless", "-dast", "-fuzz", "-itags", "-include-tags", "-tl", "-H", "-var", "-proxy"} {
		if slices.Contains(fixedFlags, never) {
			t.Errorf("fixed flags contain %q", never)
		}
	}
}

func TestBuild_Refuses(t *testing.T) {
	t.Parallel()
	mut := func(f func(*Job)) Job { j := job(); f(&j); return j }
	tpl := func(p string) Job { return mut(func(j *Job) { j.Templates = []string{p} }) }
	host := func(h string) Job {
		return mut(func(j *Job) { j.Targets = []Target{{Host: h, Port: 80, Scheme: "http"}} })
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "http/t" + strconv.Itoa(i) + ".yaml"
	}
	cases := map[string]Job{
		"no template":         mut(func(j *Job) { j.Templates = nil }),
		"33 templates":        mut(func(j *Job) { j.Templates = many }),
		"template up a dir":   tpl("http/../../x.yaml"),
		"template absolute":   tpl("/etc/x.yaml"),
		"template not yaml":   tpl("http/x.sh"),
		"template space":      tpl("http/a b.yaml"),
		"template flag-like":  tpl("-code.yaml"),
		"template comma":      tpl("http/a,b.yaml"),
		"template repeated":   mut(func(j *Job) { j.Templates = []string{"http/a.yaml", "http/a.yaml"} }),
		"no target":           mut(func(j *Job) { j.Targets = nil }),
		"rate 0":              mut(func(j *Job) { j.Rate = 0 }),
		"rate 21":             mut(func(j *Job) { j.Rate = 21 }),
		"host errors 1":       mut(func(j *Job) { j.MaxHostErrors = 1 }),
		"host errors 21":      mut(func(j *Job) { j.MaxHostErrors = 21 }),
		"public IP":           host("8.8.8.8"),
		"documentation IP":    host("203.0.113.7"),
		"CGNAT":               host("100.64.0.1"),
		"benchmark range":     host("198.18.0.1"),
		"reserved 240/4":      host("240.0.0.1"),
		"loopback":            host("127.0.0.1"),
		"unspecified":         host("0.0.0.0"),
		"link-local metadata": host("169.254.169.254"),
		"multicast":           host("224.0.0.1"),
		"broadcast":           host("255.255.255.255"),
		"private .255":        host("192.168.10.255"),
		"private .0":          host("10.1.2.0"),
		"IPv6":                host("fe80::1"),
		"mapped IPv6":         host("::ffff:192.168.1.1"),
		"leading zero":        host("192.168.010.1"),
		"domain":              host("scan.acme.example"),
		"nip.io loopback":     host("127.0.0.1.nip.io"),
		"single label":        host("localhost"),
		"empty host":          host(""),
		"flag-shaped host":    host("-iserver"),
		"port 0":              mut(func(j *Job) { j.Targets = []Target{{Host: "10.0.0.1", Port: 0}} }),
		"port 65536":          mut(func(j *Job) { j.Targets = []Target{{Host: "10.0.0.1", Port: 65536}} }),
		"scheme ftp":          mut(func(j *Job) { j.Targets = []Target{{Host: "10.0.0.1", Port: 21, Scheme: "ftp"}} }),
		"same target twice": mut(func(j *Job) {
			j.Targets = []Target{{Host: "10.0.0.1", Port: 80, Scheme: "http"}, {Host: "10.0.0.1", Port: 80, Scheme: "http"}}
		}),
		"17 targets": mut(func(j *Job) {
			j.Targets = nil
			for p := 1; p <= 17; p++ {
				j.Targets = append(j.Targets, Target{Host: "10.0.0.1", Port: p})
			}
		}),
	}
	for name, j := range cases {
		if args, err := Build(j); err == nil {
			t.Errorf("%s: built %q", name, args)
		}
	}
	for _, h := range []string{"10.0.0.1", "172.16.5.4", "172.31.255.254", "192.168.10.21"} {
		if _, err := Build(host(h)); err != nil {
			t.Errorf("private %s refused: %v", h, err)
		}
	}
}

func TestValidate_RefusesAnythingElse(t *testing.T) {
	t.Parallel()
	good, err := Build(job())
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func([]string) []string) []string { return f(slices.Clone(good)) }
	n := len(fixedFlags) // then -rl n -mhe n, two -t pairs (n+4..n+7), three -u pairs (n+8..)
	cases := map[string][]string{
		"empty":                    nil,
		"fixed flag dropped":       edit(func(a []string) []string { return slices.Delete(a, 2, 3) }),
		"extra flag at the end":    edit(func(a []string) []string { return append(a, "-code") }),
		"extra flag in the middle": edit(func(a []string) []string { return slices.Insert(a, n, "-headless") }),
		"-id added":                edit(func(a []string) []string { return slices.Insert(a, n+4, "-id", "x") }),
		"whole dir as -t":          edit(func(a []string) []string { a[n+5] = TemplatesDir; return a }),
		"-t outside the dir":       edit(func(a []string) []string { a[n+5] = "/tmp/x.yaml"; return a }),
		"-t up a dir":              edit(func(a []string) []string { a[n+5] = TemplatesDir + "/../x.yaml"; return a }),
		"no -t":                    edit(func(a []string) []string { return append(a[:n+4], a[n+8:]...) }),
		"rate as word":             edit(func(a []string) []string { a[n+1] = "five"; return a }),
		"rate leading zero":        edit(func(a []string) []string { a[n+1] = "05"; return a }),
		"rate 50":                  edit(func(a []string) []string { a[n+1] = "50"; return a }),
		"host errors 99":           edit(func(a []string) []string { a[n+3] = "99"; return a }),
		"no target":                edit(func(a []string) []string { return a[:n+8] }),
		"-u without value":         edit(func(a []string) []string { return a[:len(a)-1] }),
		"-l instead of -u":         edit(func(a []string) []string { a[n+8] = "-l"; return a }),
		"target with path":         edit(func(a []string) []string { a[n+9] = "http://192.168.10.21:5000/admin"; return a }),
		"target without port":      edit(func(a []string) []string { a[n+9] = "http://192.168.10.21"; return a }),
		"target with user":         edit(func(a []string) []string { a[n+9] = "http://x@192.168.10.21:5000"; return a }),
		"target loopback":          edit(func(a []string) []string { a[n+9] = "http://127.0.0.1:5000"; return a }),
		"target public":            edit(func(a []string) []string { a[n+9] = "http://8.8.8.8:5000"; return a }),
		"target domain":            edit(func(a []string) []string { a[n+9] = "http://scan.acme.example:5000"; return a }),
		"target port zero-padded":  edit(func(a []string) []string { a[n+9] = "http://192.168.10.21:05000"; return a }),
		"target repeated":          edit(func(a []string) []string { return append(a, "-u", "192.168.10.21:22") }),
		"-t after -u":              edit(func(a []string) []string { return append(a, "-t", TemplatesDir+"/http/x.yaml") }),
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
		{Target{Host: "192.168.1.9", Port: 443, Scheme: "https"}, "https://192.168.1.9:443"},
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

// The fixed part as the review approved it, written out here on purpose: a change in argv.go must change this too.
var approvedFixed = []string{"-jsonl", "-silent", "-nc", "-duc", "-ni", "-ms", "-dr", "-nh", "-etags", "dos,intrusive,fuzz", "-pt", "http,tcp,ssl", "-elog", "/dev/stderr", "-c", "1", "-bs", "1", "-timeout", "10", "-retries", "1"}

// rfc1918Literal is written apart from validHost: a dotted IPv4 literal in 10/8, 172.16/12 or 192.168/16, last octet 1..254.
func rfc1918Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	var o [4]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != p {
			return false
		}
		o[i] = n
	}
	private := o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 192 && o[1] == 168)
	return private && o[3] >= 1 && o[3] <= 254
}

func independentTarget(s string) bool {
	hp := strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	host, port, ok := strings.Cut(hp, ":")
	if !ok || strings.ContainsAny(port, ":/@?#") {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p >= 1 && p <= 65535 && strconv.Itoa(p) == port && rfc1918Literal(host)
}

// L5: whatever Validate accepts has these properties, checked without its code: the approved fixed part, then -rl
// 1..20, -mhe 2..20, then only -t pairs under TemplatesDir, then only -u pairs of private literal targets.
func FuzzValidate(f *testing.F) {
	good, _ := Build(job())
	f.Add(strings.Join(good, "\x00"))
	f.Add(strings.Join(append(slices.Clone(approvedFixed), "-rl", "1", "-mhe", "2", "-t", TemplatesDir+"/a.yaml", "-u", "10.0.0.1:1"), "\x00"))
	f.Add("-t\x00/x\x00-u\x00http://[::1]:80")
	f.Fuzz(func(t *testing.T, s string) {
		args := strings.Split(s, "\x00")
		if Validate(args) != nil {
			return
		}
		n := len(approvedFixed)
		if len(args) < n+8 || !slices.Equal(args[:n], approvedFixed) || args[n] != "-rl" || args[n+2] != "-mhe" {
			t.Fatalf("accepted a line without the approved fixed part: %q", args)
		}
		if r, err := strconv.Atoi(args[n+1]); err != nil || r < 1 || r > 20 {
			t.Fatalf("rate: %q", args)
		}
		if m, err := strconv.Atoi(args[n+3]); err != nil || m < 2 || m > 20 {
			t.Fatalf("max host errors: %q", args)
		}
		rest, seenU, tpls := args[n+4:], false, 0
		for i := 0; i+1 < len(rest); i += 2 {
			switch flag, v := rest[i], rest[i+1]; {
			case flag == "-t" && !seenU:
				tpls++
				if !strings.HasPrefix(v, TemplatesDir+"/") || !strings.HasSuffix(v, ".yaml") || strings.Contains(v, "..") {
					t.Fatalf("template %q", v)
				}
			case flag == "-u":
				seenU = true
				if !independentTarget(v) {
					t.Fatalf("target %q", v)
				}
				if _, err := netip.ParseAddr(strings.Split(strings.TrimPrefix(strings.TrimPrefix(v, "http://"), "https://"), ":")[0]); err != nil {
					t.Fatalf("target host %q", v)
				}
			default:
				t.Fatalf("flag %q in position %d of %q", flag, n+4+i, args)
			}
		}
		if len(rest)%2 != 0 || tpls == 0 || !seenU {
			t.Fatalf("shape: %q", args)
		}
	})
}
