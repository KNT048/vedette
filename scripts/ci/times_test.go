package main

import (
	"strings"
	"testing"
)

// The weights of the shards are the measured seconds of testtime.tsv; a package missing from the table weighs its test bytes at
// the table's own rate, so a new package is never free (D-365).
func TestWeighUsesTheTableAndPricesNewPackages(t *testing.T) {
	t.Parallel()
	times, err := testTimes("# c\n100\tmodules/a\n10\t.\n")
	if err != nil {
		t.Fatal(err)
	}
	a, root, b := modulePath+"/modules/a", modulePath, modulePath+"/modules/b"
	got := weigh([]string{a, root, b}, map[string]int64{a: 1000, root: 100, b: 500}, times)
	if got[0].weight != 100_000 || got[1].weight != 10_000 || got[2].weight != 50_000 {
		t.Fatalf("weights = %+v, want 100 s, 10 s and 500 bytes at 110 s / 1100 bytes = 50 s", got)
	}
	if _, err := testTimes("x\tmodules/a\n"); err == nil {
		t.Fatal("a bad line was accepted")
	}
}

// printTimes turns go test's lines in a CI log (with the runner's prefixes) into table rows, and the embedded table parses.
func TestPrintTimesReadsACILog(t *testing.T) {
	t.Parallel()
	log := "go-test (2)\tgo test -race, shard 2 of 3\t2026-11-11T22:59:32.1Z ok  \t" + modulePath + "/modules/response\t599.267s\n" +
		"go-test (1)\tx\t2026-11-11T22:52:13Z ok  \t" + modulePath + "\t1.2s\n" +
		"go-test (1)\tx\t2026-11-11T22:52:13Z ?   \t" + modulePath + "/x\t[no test files]\n" +
		"go-test (3)\tx\t2026-11-11T22:52:13Z FAIL\t" + modulePath + "/modules/agent-intake\t48.760s\n"
	var out strings.Builder
	if err := printTimes(strings.NewReader(log), &out); err != nil {
		t.Fatal(err)
	}
	if want := "1\t.\n49\tmodules/agent-intake\n599\tmodules/response\n"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
	if _, err := testTimes(testTimeTSV); err != nil {
		t.Fatal(err)
	}
}
