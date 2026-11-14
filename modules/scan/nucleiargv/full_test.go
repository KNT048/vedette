package nucleiargv

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// D-527: the full shape of an own_ip job (testing terms accepted), written out on purpose: a change in argv.go must change this too.
var approvedFullFixed = []string{"-jsonl", "-silent", "-nc", "-duc", "-ni", "-ms", "-dr", "-nh", "-etags", "dos,intrusive,fuzz,brute-force,default-login,authenticated",
	"-pt", "http,tcp,ssl", "-elog", "/dev/stderr", "-c", "10", "-bs", "1", "-timeout", "10", "-retries", "1", "-or", "-ot"}

func fullJob() Job {
	return Job{Templates: []string{"http/exposures/configs/git-config.yaml", "http/technologies/tech-detect.yaml"}, Targets: []Target{{Host: "203.0.114.7", Port: 443, Scheme: "https"}},
		Rate: FullRate, MaxHostErrors: 3, Scope: ScopeOwnIP, Depth: DepthFull}
}

func TestFull_ShapeRoundTrips(t *testing.T) {
	t.Parallel()
	for _, disruptive := range []bool{false, true} {
		j := fullJob()
		j.Disruptive = disruptive
		args, err := Build(j)
		if err != nil {
			t.Fatal(err)
		}
		fixed := slices.Clone(approvedFullFixed)
		if disruptive {
			fixed[slices.Index(fixed, "-etags")+1] = "intrusive,fuzz"
		}
		want := append(fixed, "-rl", "20", "-mhe", "3", "-t", TemplatesDir+"/http/exposures/configs/git-config.yaml", "-t", TemplatesDir+"/http/technologies/tech-detect.yaml", "-u", "https://203.0.114.7:443")
		if !slices.Equal(args, want) {
			t.Fatalf("disruptive %t argv:\n%q\nwant:\n%q", disruptive, args, want)
		}
		if err := Validate(args); err != nil {
			t.Fatalf("Validate refuses what Build made: %v", err)
		}
		back, err := parse(args)
		if err != nil || back.Depth != DepthFull || back.Disruptive != disruptive || back.Scope != ScopeOwnIP || back.Rate != FullRate {
			t.Fatalf("parse: %+v %v", back, err)
		}
	}
	// the full line behind the own_ip flags (5 requests a second, 32 templates, the K-6 tags) is not a valid line
	args, _ := Build(fullJob())
	if err := Validate(append(slices.Clone(approvedOwnIPFixed), args[len(approvedFullFixed):]...)); err == nil {
		t.Error("Validate accepted a full job behind the own_ip flags")
	}
}

func TestFull_Refuses(t *testing.T) {
	t.Parallel()
	mut := func(f func(*Job)) Job { j := fullJob(); f(&j); return j }
	many := make([]string, MaxFullTemplates+1)
	for i := range many {
		many[i] = "http/cves/t" + strconv.Itoa(i) + ".yaml"
	}
	for name, j := range map[string]Job{
		"a LAN target":         mut(func(j *Job) { j.Targets[0].Host = "192.168.10.21" }),
		"the LAN scope":        mut(func(j *Job) { j.Scope = "" }),
		"two targets":          mut(func(j *Job) { j.Targets = append(j.Targets, Target{Host: "203.0.114.8", Port: 80, Scheme: "http"}) }),
		"the own_ip rate":      mut(func(j *Job) { j.Rate = OwnIPRate }),
		"another rate":         mut(func(j *Job) { j.Rate = 19 }),
		"201 templates":        mut(func(j *Job) { j.Templates = many }),
		"another depth":        mut(func(j *Job) { j.Depth = "deep" }),
		"dos without depth":    mut(func(j *Job) { j.Depth, j.Rate, j.Disruptive = "", OwnIPRate, true }),
		"disruptive LAN":       {Templates: []string{"http/a.yaml"}, Targets: []Target{{Host: "10.0.0.1", Port: 80, Scheme: "http"}}, Rate: 5, MaxHostErrors: 3, Disruptive: true},
		"full LAN":             {Templates: []string{"http/a.yaml"}, Targets: []Target{{Host: "10.0.0.1", Port: 80, Scheme: "http"}}, Rate: FullRate, MaxHostErrors: 3, Depth: DepthFull},
		"a name as the target": mut(func(j *Job) { j.Targets[0].Host = "example.com" }),
	} {
		if args, err := Build(j); err == nil {
			t.Errorf("%s: built %q", name, args)
		}
	}
	// a non-disruptive full line with dos let through is no valid line
	args, _ := Build(fullJob())
	i := slices.Index(args, "-etags")
	args[i+1] = "intrusive,fuzz"
	if err := Validate(args); err != nil {
		t.Fatalf("the disruptive flags are a valid shape: %v", err)
	}
	args[i+1] = strings.Join(ForbiddenTags(), ",")
	if err := Validate(args); err == nil {
		t.Error("Validate accepted a full line that lets the brute-force and default-login templates through without the tick")
	}
}

// LAN jobs are unchanged: dos stays excluded, and no LAN line has the full flags.
func TestFull_LANUnchanged(t *testing.T) {
	t.Parallel()
	if !slices.Contains(strings.Split(fixedFlags[slices.Index(fixedFlags, "-etags")+1], ","), "dos") || fixedFlags[slices.Index(fixedFlags, "-c")+1] != "1" {
		t.Fatalf("LAN flags changed: %q", fixedFlags)
	}
	for _, d := range []bool{false, true} {
		if slices.Contains(FullForbiddenTags(d), "intrusive") != true || slices.Contains(FullForbiddenTags(d), "fuzz") != true {
			t.Errorf("disruptive %t: intrusive and fuzz must stay excluded", d)
		}
		if slices.Contains(FullForbiddenTags(d), "dos") == d {
			t.Errorf("disruptive %t: dos excluded %t", d, slices.Contains(FullForbiddenTags(d), "dos"))
		}
	}
}
