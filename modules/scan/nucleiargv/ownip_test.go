package nucleiargv

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// D-520: the own_ip scope of exposure's safe checks (D-561) takes exactly one public IPv4 literal, at OwnIPRate, with the classes of
// D-559 K-6 excluded on top of the forbidden tags; the LAN scope still takes private addresses only.
// The own_ip fixed part as D-520 approved it, written out on purpose: a change in argv.go must change this too.
var approvedOwnIPFixed = []string{"-jsonl", "-silent", "-nc", "-duc", "-ni", "-ms", "-dr", "-nh", "-etags", "dos,intrusive,fuzz,default-login,brute-force,sqli,xss,injection,file-upload",
	"-pt", "http,tcp,ssl", "-elog", "/dev/stderr", "-c", "1", "-bs", "1", "-timeout", "10", "-retries", "1"}

func ownIPJob() Job {
	return Job{Templates: []string{"http/cves/2021/CVE-2021-41773.yaml"}, Targets: []Target{{Host: "203.0.114.7", Port: 18443, Scheme: "http"}},
		Rate: OwnIPRate, MaxHostErrors: 3, Scope: ScopeOwnIP}
}

func TestOwnIP_PublicTargetOnlyInItsScope(t *testing.T) {
	t.Parallel()
	args, err := Build(ownIPJob())
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(approvedOwnIPFixed), "-rl", "5", "-mhe", "3", "-t", TemplatesDir+"/http/cves/2021/CVE-2021-41773.yaml", "-u", "http://203.0.114.7:18443")
	if !slices.Equal(args, want) {
		t.Fatalf("argv:\n%q\nwant:\n%q", args, want)
	}
	if err := Validate(args); err != nil {
		t.Fatalf("Validate refuses what Build made: %v", err)
	}
	lan := ownIPJob()
	lan.Scope = ""
	if _, err := Build(lan); err == nil {
		t.Error("a public target was accepted in the LAN scope")
	}
	// The same line with the LAN flags is not a valid line: the scope is read from the flags, never from the target.
	if err := Validate(append(slices.Clone(approvedFixed), args[len(approvedFixed):]...)); err == nil {
		t.Error("Validate accepted a public target behind the LAN flags")
	}
}

func TestOwnIP_Refuses(t *testing.T) {
	t.Parallel()
	mut := func(f func(*Job)) Job { j := ownIPJob(); f(&j); return j }
	host := func(h string) Job { return mut(func(j *Job) { j.Targets[0].Host = h }) }
	many := make([]string, MaxTemplates+1)
	for i := range many {
		many[i] = "http/cves/t" + strconv.Itoa(i) + ".yaml"
	}
	for name, j := range map[string]Job{
		"private":        host("192.168.10.21"),
		"shared":         host("100.64.0.9"),
		"loopback":       host("127.0.0.1"),
		"documentation":  host("203.0.113.5"),
		"multicast":      host("224.0.0.1"),
		"a name":         host("example.com"),
		"ipv6":           host("2001:4860:4860::8888"),
		"not canonical":  host("203.0.114.007"),
		"two targets":    mut(func(j *Job) { j.Targets = append(j.Targets, Target{Host: "203.0.114.7", Port: 80, Scheme: "http"}) }),
		"rate 6":         mut(func(j *Job) { j.Rate = 6 }),
		"rate 1":         mut(func(j *Job) { j.Rate = 1 }),
		"33 templates":   mut(func(j *Job) { j.Templates = many }),
		"no template":    mut(func(j *Job) { j.Templates = nil }),
		"unknown scope":  mut(func(j *Job) { j.Scope = "internet" }),
		"template up":    mut(func(j *Job) { j.Templates = []string{"http/../x.yaml"} }),
		"scheme ftp":     mut(func(j *Job) { j.Targets[0].Scheme = "ftp" }),
		"port 0":         mut(func(j *Job) { j.Targets[0].Port = 0 }),
		"host errors 21": mut(func(j *Job) { j.MaxHostErrors = 21 }),
	} {
		if args, err := Build(j); err == nil {
			t.Errorf("%s: built %q", name, args)
		}
	}
}

// The own_ip flags differ from the LAN ones only by the excluded tags, and keep every safe flag (-duc -ni -dr -nh, http/tcp/ssl, one
// template and one target at a time).
func TestOwnIP_FlagsKeepTheSafeOnes(t *testing.T) {
	t.Parallel()
	if len(ownIPFlags) != len(fixedFlags) {
		t.Fatalf("own_ip flags %q", ownIPFlags)
	}
	for i := range fixedFlags {
		if ownIPFlags[i] != fixedFlags[i] && fixedFlags[i-1] != "-etags" {
			t.Errorf("own_ip flag %d is %q, LAN %q", i, ownIPFlags[i], fixedFlags[i])
		}
	}
	tags := strings.Split(ownIPFlags[slices.Index(ownIPFlags, "-etags")+1], ",")
	for _, want := range []string{"dos", "intrusive", "fuzz", "default-login", "brute-force", "sqli", "xss", "injection", "file-upload"} {
		if !slices.Contains(tags, want) {
			t.Errorf("own_ip -etags lacks %s", want)
		}
	}
}
