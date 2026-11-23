//nolint:gosec // test code: every path is in a directory the test made
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// freshInstall is the advisory a release that starts a new schema epoch publishes for the boxes of the earlier epoch.
func freshInstall(v string) []release.Advisory {
	return []release.Advisory{{
		ID: "VED-2026-001", Severity: "medium", Affects: "< " + v, FixedIn: v,
		Title: "Vedette " + v + " needs a fresh install: back up what you need, uninstall, then install " + v + " with install.sh",
		URL:   "https://github.com/KNT048/vedette/releases/tag/v" + v,
	}}
}

func TestParseAdvisory(t *testing.T) {
	good := freshInstall("0.1.1")[0]
	raw, err := json.Marshal(good)
	must(t, err)
	a, err := ParseAdvisory(raw)
	if err != nil || a != good {
		t.Fatalf("%+v %v", a, err)
	}
	mut := func(f func(*release.Advisory)) release.Advisory { b := good; f(&b); return b }
	bad := map[string]struct {
		a    release.Advisory
		want string
	}{
		"severity info (every box would refuse the index)": {mut(func(a *release.Advisory) { a.Severity = "info" }), "severity"},
		"no id":                    {mut(func(a *release.Advisory) { a.ID = "" }), "id"},
		"id longer than 64":        {mut(func(a *release.Advisory) { a.ID = strings.Repeat("A", 65) }), "id"},
		"no title":                 {mut(func(a *release.Advisory) { a.Title = "" }), "title"},
		"title of two lines":       {mut(func(a *release.Advisory) { a.Title = "a\nb" }), "refuse the whole index"},
		"title longer than 256":    {mut(func(a *release.Advisory) { a.Title = strings.Repeat("a", 257) }), "refuse the whole index"},
		"no fixed_in":              {mut(func(a *release.Advisory) { a.FixedIn = "" }), "fixed_in is required"},
		"fixed_in with a v":        {mut(func(a *release.Advisory) { a.FixedIn = "v0.1.1" }), "refuse the whole index"},
		"url http":                 {mut(func(a *release.Advisory) { a.URL = "http://github.com/x" }), "not https"},
		"url with a fragment":      {mut(func(a *release.Advisory) { a.URL = "https://github.com/x#y" }), "refuse the whole index"},
		"url with a user":          {mut(func(a *release.Advisory) { a.URL = "https://u@github.com/x" }), "refuse the whole index"},
		"no affects":               {mut(func(a *release.Advisory) { a.Affects = "" }), "empty"},
		"affects without operator": {mut(func(a *release.Advisory) { a.Affects = "0.1.1" }), "does not start with"},
		"affects not SemVer":       {mut(func(a *release.Advisory) { a.Affects = "< 0.1" }), "not a SemVer"},
		"fixed_in inside affects":  {mut(func(a *release.Advisory) { a.Affects = "<= 0.1.1" }), "inside affects"},
	}
	for name, c := range bad {
		raw, err := json.Marshal(c.a)
		must(t, err)
		if _, err := ParseAdvisory(raw); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error %q, got %v", name, c.want, err)
		}
	}
	if _, err := ParseAdvisory([]byte(`{"id":"X","severity":"low","title":"t","affects":"< 1.0.0","fixed_in":"1.0.0","url":"https://x.test/","text":"more"}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
	// a range of several comparators
	if _, err := ParseAdvisory([]byte(`{"id":"X","severity":"low","title":"t","affects":">= 0.1.0-beta.1, < 0.1.1","fixed_in":"0.1.1","url":"https://x.test/"}`)); err != nil {
		t.Error(err)
	}
}

// A new advisory goes into the index, carries over to the next one, and is not added twice.
func TestBuildIndexAdvisories(t *testing.T) {
	man := []byte(`{"version":"0.1.0-beta.1"}`)
	f1, err := BuildIndex(nil, IndexParams{Now: t1, Rollout: -1, Channel: "beta", ManifestVersion: "0.1.0-beta.1", ManifestRaw: man})
	must(t, err)
	var x1 release.Index
	must(t, json.Unmarshal(f1[0].Data, &x1))

	man2 := []byte(`{"version":"0.1.1","min_upgrade_from":"0.1.1"}`)
	p := IndexParams{Now: t1, Rollout: -1, Channel: "beta", ManifestVersion: "0.1.1", ManifestRaw: man2}
	if _, err := BuildIndex(&x1, p); err == nil || !strings.Contains(err.Error(), "box on 0.1.0-beta.1") {
		t.Fatalf("a release that strands the boxes on 0.1.0-beta.1 without telling them: %v", err)
	}
	p.Advisories = freshInstall("0.1.1")
	f2, err := BuildIndex(&x1, p)
	must(t, err)
	var x2 release.Index
	must(t, json.Unmarshal(f2[0].Data, &x2))
	if len(x2.Advisories) != 1 || x2.Advisories[0] != freshInstall("0.1.1")[0] {
		t.Fatalf("%+v", x2.Advisories)
	}
	// the weekly refresh and the next release carry it over unchanged, and need no new one
	f3, err := BuildIndex(&x2, IndexParams{Now: t1.Add(7 * 24 * time.Hour), Rollout: -1})
	must(t, err)
	var x3 release.Index
	must(t, json.Unmarshal(f3[0].Data, &x3))
	if len(x3.Advisories) != 1 || x3.Advisories[0] != x2.Advisories[0] {
		t.Fatalf("not carried over: %+v", x3.Advisories)
	}
	f4, err := BuildIndex(&x3, IndexParams{Now: t1, Rollout: -1, Channel: "beta", ManifestVersion: "0.1.2", ManifestRaw: []byte(`{"version":"0.1.2"}`)})
	must(t, err)
	var x4 release.Index
	must(t, json.Unmarshal(f4[0].Data, &x4))
	if len(x4.Advisories) != 1 {
		t.Fatalf("%+v", x4.Advisories)
	}
	// the same id again, an invalid one, and one past what a box accepts are refused
	if _, err := BuildIndex(&x3, IndexParams{Now: t1, Rollout: -1, Advisories: freshInstall("0.1.1")}); err == nil || !strings.Contains(err.Error(), "already in the index") {
		t.Errorf("a duplicate id: %v", err)
	}
	invalid := freshInstall("0.1.2")
	invalid[0].ID, invalid[0].Severity = "VED-2026-002", "info"
	if _, err := BuildIndex(&x3, IndexParams{Now: t1, Rollout: -1, Advisories: invalid}); err == nil || !strings.Contains(err.Error(), "severity") {
		t.Errorf("an invalid advisory: %v", err)
	}
	many := make([]release.Advisory, maxIndexAdvisories)
	for i := range many {
		many[i] = freshInstall("0.1.2")[0]
		many[i].ID = fmt.Sprintf("VED-2027-%03d", i)
	}
	if _, err := BuildIndex(&x3, IndexParams{Now: t1, Rollout: -1, Advisories: many}); err == nil || !strings.Contains(err.Error(), "more than 256") {
		t.Errorf("257 advisories: %v", err)
	}
}

// boxStatus is how the Updates page of a released box shows an advisory of a verified index: modules/core advisoriesOf, the same
// code since v0.1.0-beta.1 (an unknown severity or a fixed_in that is not SemVer leaves it out; "affected" when the running
// version is below fixed_in). "" = not listed.
func boxStatus(a release.Advisory, running string) string {
	switch a.Severity {
	case "critical", "high", "medium", "low":
	default:
		return ""
	}
	c, err := release.CompareVersions(running, a.FixedIn)
	switch {
	case err != nil:
		return ""
	case c < 0:
		return "affected"
	}
	return "fixed"
}

// The whole release pipeline for the first release of a new schema epoch: the signed index passes the box's verifier, and a box
// on 0.1.0-beta.1 lists the advisory as affected while one on 0.1.1 or later lists it as fixed.
func TestNewEpochAdvisoryShowsOnOldBoxes(t *testing.T) {
	r := newRig(t)
	epoch1 := Tree{"modules/a/migrations/sqlite/0001_old.sql": up("CREATE TABLE old (id INT);")}
	prev, err := r.build(buildOpts{version: "0.1.0-beta.1", cur: epoch1})
	must(t, err)
	dir, err := r.build(buildOpts{version: "0.1.1", minUpgrade: "0.1.1", advisories: freshInstall("0.1.1"), prevDir: prev,
		cur: epochTree("2", addOnlyTree), earlier: []ReleaseTree{{Version: "0.1.0-beta.1", Tree: epoch1}}})
	must(t, err)
	if _, err := VerifyDir(dir, prev, r.trust); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, indexFile))
	must(t, err)
	sig, err := os.ReadFile(filepath.Join(dir, indexFile+".minisig"))
	must(t, err)
	idx, err := release.VerifyIndex(raw, sig, r.trust, nil)
	if err != nil {
		t.Fatalf("the box's verifier refuses the index: %v", err)
	}
	if len(idx.Advisories) != 1 {
		t.Fatalf("%+v", idx.Advisories)
	}
	a := idx.Advisories[0]
	for running, want := range map[string]string{"0.1.0-beta.1": "affected", "0.1.1": "fixed", "0.1.2": "fixed"} {
		if got := boxStatus(a, running); got != want {
			t.Errorf("a box on %s shows the advisory as %q, want %q", running, got, want)
		}
	}
}

// Through the command line: -advisory adds the advisory of a file to a refresh, and refuses an invalid one before writing anything.
func TestIndexCommandAdvisory(t *testing.T) {
	r := newRig(t)
	keys := t.TempDir()
	writeKeys(t, r, keys)
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	run1 := func(args ...string) (int, string) {
		var o, e bytes.Buffer
		c := run(args, nil, &o, &e)
		return c, o.String() + e.String()
	}
	files := t.TempDir()
	good := filepath.Join(files, "advisory.json")
	b, err := json.Marshal(freshInstall("0.1.1")[0])
	must(t, err)
	must(t, os.WriteFile(good, b, 0o600))
	badFile := filepath.Join(files, "bad.json")
	must(t, os.WriteFile(badFile, []byte(strings.Replace(string(b), `"medium"`, `"info"`, 1)), 0o600))

	out := t.TempDir()
	if c, msg := run1("index", "-out", out, "-prev-index", pub, "-keys-dir", keys, "-advisory", badFile); c == 0 || !strings.Contains(msg, "severity") {
		t.Errorf("an invalid advisory: %d %s", c, msg)
	}
	if _, err := os.Stat(filepath.Join(out, indexFile)); err == nil {
		t.Error("an index was written for an invalid advisory")
	}
	if c, msg := run1("index", "-out", out, "-prev-index", pub, "-keys-dir", keys, "-advisory", good); c != 0 {
		t.Fatalf("%d %s", c, msg)
	}
	raw, err := os.ReadFile(filepath.Join(out, indexFile))
	must(t, err)
	var x release.Index
	must(t, json.Unmarshal(raw, &x))
	if len(x.Advisories) != 1 || x.Advisories[0] != freshInstall("0.1.1")[0] {
		t.Fatalf("%+v", x.Advisories)
	}
}
