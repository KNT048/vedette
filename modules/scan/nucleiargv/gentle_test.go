package nucleiargv

import (
	"slices"
	"strconv"
	"testing"
)

// The gentle speed of a deep scan: a full job also runs at GentleFullRate, with GentleFullConcurrency templates in flight. The job's
// own rate says which; the rest of the line is the full one. A worker that does not know the gentle shape refuses the rate (the
// full shape takes FullRate only): fail closed.
func TestFull_GentleIsASecondShape(t *testing.T) {
	t.Parallel()
	if GentleFullRate >= FullRate || GentleFullConcurrency >= FullConcurrency || GentleFullRate < 1 || GentleFullConcurrency < 1 {
		t.Fatalf("gentle %d/%d is not slower than %d/%d", GentleFullRate, GentleFullConcurrency, FullRate, FullConcurrency)
	}
	for _, disruptive := range []bool{false, true} {
		j := fullJob()
		j.Rate, j.Disruptive = GentleFullRate, disruptive
		args, err := Build(j)
		if err != nil {
			t.Fatal(err)
		}
		if i := slices.Index(args, "-c"); args[i+1] != strconv.Itoa(GentleFullConcurrency) {
			t.Fatalf("gentle -c %q", args[i+1])
		}
		if i := slices.Index(args, "-rl"); args[i+1] != strconv.Itoa(GentleFullRate) {
			t.Fatalf("gentle -rl %q", args[i+1])
		}
		normal, _ := Build(fullJob())
		if i := slices.Index(args, "-etags"); !disruptive && args[i+1] != normal[i+1] {
			t.Fatalf("gentle changed the excluded tags: %q", args[i+1])
		}
		if err := Validate(args); err != nil {
			t.Fatalf("Validate refuses a gentle line: %v", err)
		}
		back, err := parse(args)
		if err != nil || back.Rate != GentleFullRate || back.Disruptive != disruptive || back.Depth != DepthFull {
			t.Fatalf("parse: %+v %v", back, err)
		}
	}
	// the full line of before is unchanged
	normal, _ := Build(fullJob())
	if !slices.Equal(normal[:len(approvedFullFixed)], approvedFullFixed) || normal[slices.Index(normal, "-rl")+1] != "20" {
		t.Fatalf("the full line changed: %q", normal)
	}
	// only the two pairs: the gentle rate with the normal concurrency, or the reverse, is no line
	g := fullJob()
	g.Rate = GentleFullRate
	gentle, _ := Build(g)
	mixed := slices.Clone(gentle)
	mixed[slices.Index(mixed, "-c")+1] = strconv.Itoa(FullConcurrency)
	if err := Validate(mixed); err == nil {
		t.Error("Validate accepted the gentle rate with the normal concurrency")
	}
	mixed = slices.Clone(normal)
	mixed[slices.Index(mixed, "-c")+1] = strconv.Itoa(GentleFullConcurrency)
	if err := Validate(mixed); err == nil {
		t.Error("Validate accepted the normal rate with the gentle concurrency")
	}
	for _, rate := range []int{GentleFullRate + 1, FullRate - 1, OwnIPRate + 1} {
		j := fullJob()
		j.Rate = rate
		if rate == GentleFullRate || rate == FullRate {
			continue
		}
		if _, err := Build(j); err == nil {
			t.Errorf("a full job at %d requests a second was built", rate)
		}
	}
}

// The time a full job's templates take scales with its rate: the bounds of the template step stretch by TimeScale.
func TestFull_TimeScale(t *testing.T) {
	t.Parallel()
	if TimeScale(FullRate) != 1 || TimeScale(GentleFullRate) != FullRate/GentleFullRate || TimeScale(GentleFullRate) < 2 {
		t.Fatalf("TimeScale %d, %d", TimeScale(FullRate), TimeScale(GentleFullRate))
	}
	if TimeScale(7) != 0 {
		t.Error("TimeScale of a rate that is no full rate is not 0")
	}
}
