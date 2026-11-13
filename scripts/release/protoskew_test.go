package main

import (
	"context"
	"os"
	"os/exec" //nolint:depguard // the test looks up git; SYS-1 is about the product
	"path/filepath"
	"strings"
	"testing"
)

// putProto writes core/sensorlink/limits.go with ProtoVersion n into repo, as the real file spells it.
func putProto(t *testing.T, repo, n string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Join(repo, "core/sensorlink"), 0o750))
	must(t, os.WriteFile(filepath.Join(repo, sensorProtoFile), []byte("package sensorlink\n\nconst (\n\tProtoVersion = \""+n+"\" // comment\n\tProtoPrevious = \"0\"\n)\n"), 0o600))
}

// The real file is read the way the gate reads it.
func TestSensorProtoOfThisTree(t *testing.T) {
	b, err := os.ReadFile("../../" + sensorProtoFile)
	must(t, err)
	if m := sensorProtoRE.FindSubmatch(b); m == nil {
		t.Fatalf("%s: the gate cannot read ProtoVersion", sensorProtoFile)
	}
}

func TestCheckSensorProto(t *testing.T) {
	hist := []releaseProto{{"1.0.0", 3}, {"1.1.0", 3}, {"1.2.0", 4}, {"1.3.0", 4}}
	for name, c := range map[string]struct {
		cur     int
		min     string
		earlier []releaseProto
		want    string // "" = passes
	}{
		"no bump":                {4, "", hist, ""},
		"one bump, all at n-1":   {5, "", hist[2:], ""},
		"one bump, old releases": {5, "", hist, "set min_upgrade_from to 1.2.0 or later"},
		"min too low":            {5, "1.1.0", hist, "release 1.1.0 speaks 3"},
		"min at the first n-1":   {5, "1.2.0", hist, ""},
		"min above":              {5, "1.3.0", hist, ""},
		"first release":          {9, "", nil, ""},
		"two bumps at once":      {6, "1.3.0", hist, "no box could update to it"},
	} {
		err := checkSensorProto("2.0.0", c.min, c.cur, c.earlier)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
}

// The protocols come from git at each release tag; test tags and later tags are not releases a box updates from.
func TestEarlierProtosFromGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	for _, r := range [][2]string{{"1.0.0", "3"}, {"1.1.0-test.4", "2"}, {"1.1.0", "4"}, {"3.0.0", "9"}} {
		putProto(t, repo, r[1])
		gitT(t, repo, "add", "-A")
		gitT(t, repo, "commit", "-q", "-m", r[0])
		gitT(t, repo, "tag", "v"+r[0])
	}
	got, err := earlierProtos(context.Background(), repo, "2.0.0")
	must(t, err)
	if len(got) != 2 || got[0] != (releaseProto{"1.0.0", 3}) || got[1] != (releaseProto{"1.1.0", 4}) {
		t.Errorf("earlier releases: %v", got)
	}
	if p, err := sensorProtoAt(context.Background(), repo, "HEAD"); err != nil || p != 9 {
		t.Errorf("HEAD: %d %v", p, err)
	}
}
