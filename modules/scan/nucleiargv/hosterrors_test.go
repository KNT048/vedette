package nucleiargv

import (
	"slices"
	"testing"
)

// -mhe follows the templates a shape keeps in flight: a port is given up only after two whole waves of them got no answer with no
// answer in between, never fewer than 3 (the scan module's default).
func TestHostErrors_TwoWavesOfTheTemplatesInFlight(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		depth string
		rate  int
		want  int
	}{
		{"deep", DepthFull, FullRate, 20},
		{"deep, gentle", DepthFull, GentleFullRate, 4},
		{"own IP", "", OwnIPRate, 3},
		{"LAN", "", MaxRate, 3},
	} {
		if got := HostErrors(c.depth, c.rate); got != c.want {
			t.Errorf("%s: -mhe %d, want %d", c.name, got, c.want)
		}
	}
}

// A deep job carries its -mhe on the line, and the line passes Validate as it stands: the bound every released worker checks is
// still 2..20, so an older worker runs the job with the new value and a newer worker still runs an older core's jobs.
func TestHostErrors_ADeepLineEveryWorkerAccepts(t *testing.T) {
	t.Parallel()
	if MinHostErrors != 2 || MaxHostErrors != 20 {
		t.Fatalf("the grammar's bound moved to %d..%d: workers already released refuse a job outside 2..20", MinHostErrors, MaxHostErrors)
	}
	for _, rate := range []int{FullRate, GentleFullRate} {
		for _, disruptive := range []bool{false, true} {
			j := fullJob()
			j.Rate, j.Disruptive, j.MaxHostErrors = rate, disruptive, HostErrors(DepthFull, rate)
			args, err := Build(j)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.Index(args, "-mhe")
			if i < 0 || args[i+1] != map[int]string{FullRate: "20", GentleFullRate: "4"}[rate] {
				t.Fatalf("rate %d: argv %q", rate, args)
			}
			if err := Validate(args); err != nil {
				t.Fatalf("rate %d disruptive %t: Validate refuses the deep line: %v", rate, disruptive, err)
			}
		}
	}
	for _, mhe := range []int{1, 21, 30} { // nothing outside the bound: -nmhe (no limit) or upstream's 30 never reach nuclei
		j := fullJob()
		j.MaxHostErrors = mhe
		if _, err := Build(j); err == nil {
			t.Errorf("Build accepted -mhe %d", mhe)
		}
	}
}
