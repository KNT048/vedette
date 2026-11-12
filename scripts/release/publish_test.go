package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// signedRelease builds a signed, verified release directory with the container assets, install.sh and its signature, and returns
// it with its summary and description.
func signedRelease(t *testing.T) (string, *Summary, *Inputs) {
	t.Helper()
	r := newRig(t)
	var in Inputs
	assets := writeAssets(t)
	dir, err := r.build(buildOpts{version: "0.2.0", channel: "stable", cur: addOnlyTree, services: []string{"core", "sensor", "scan"}, installModes: bothModes,
		beforeSign: func(dir string, x Inputs) {
			assets(dir, x)
			in = x
			must(t, os.WriteFile(filepath.Join(dir, installer), []byte("#!/bin/sh\nVEDETTE_VERSION=\"0.2.0\"\n"), 0o600))
			must(t, os.WriteFile(filepath.Join(dir, installerSig), []byte("sig\n"), 0o600))
		}})
	must(t, err)
	s, err := VerifyDir(dir, "", r.trust)
	must(t, err)
	return dir, s, &in
}

// ghFake is GitHub releases in memory: view, create, upload, edit.
type ghFake struct {
	rel     map[string]*ghRelease
	noTag   bool
	corrupt string // an uploaded asset of this name gets another digest
}

func (g *ghFake) fn(argv []string) ([]byte, error) {
	a := strings.Join(argv, " ")
	if strings.HasPrefix(a, "git -C repo rev-parse --verify --quiet refs/tags/") {
		if g.noTag {
			return nil, errors.New("exit status 1")
		}
		return []byte("abc\n"), nil
	}
	if len(argv) < 4 || argv[0] != "gh" || argv[1] != "release" {
		return nil, errors.New("unexpected " + a)
	}
	tag := argv[3]
	r := g.rel[tag]
	switch argv[2] {
	case "view":
		if r == nil {
			return nil, errors.New("gh release view: exit status 1: release not found")
		}
		return json.Marshal(r)
	case "create":
		if !slices.Contains(argv, "--verify-tag") || !slices.Contains(argv, "--draft") {
			return nil, errors.New("create without --verify-tag --draft")
		}
		g.rel[tag] = &ghRelease{IsDraft: true}
		return nil, nil
	case "upload":
		if r == nil {
			return nil, errors.New("release not found")
		}
		for _, f := range argv[7:] { // gh release upload <tag> --repo R --clobber <files>

			sum, size, err := hashFile(f)
			if err != nil {
				return nil, err
			}
			d := "sha256:" + sum
			if filepath.Base(f) == g.corrupt {
				d = digestOf("other")
			}
			r.Assets = slices.DeleteFunc(r.Assets, func(x ghAsset) bool { return x.Name == filepath.Base(f) })
			r.Assets = append(r.Assets, ghAsset{Name: filepath.Base(f), Size: size, Digest: &d, State: "uploaded"})
		}
		return nil, nil
	case "edit":
		if slices.Contains(argv, "--draft=false") {
			r.IsDraft = false
		}
		return nil, nil
	}
	return nil, errors.New("unexpected " + a)
}

func TestPublishPrintsTheOrder(t *testing.T) {
	dir, s, in := signedRelease(t)
	p, err := planPublish(dir, s, in)
	must(t, err)
	want := []string{"release-manifest.json", "release-manifest.json.minisig", "install.sh", "install.sh.minisig",
		"compose.yaml", "compose.yaml.minisig", "compose.sensors.yaml", "compose.sensors.yaml.minisig", "compose.syslog.yaml",
		"compose.syslog.yaml.minisig", "vedette.env", "vedette.env.minisig", "vedette-host_0.2.0_amd64.deb", "vedette-host_0.2.0_arm64.deb"}
	if got := baseNames(p.Assets); !slices.Equal(got, want) {
		t.Errorf("assets %v", got)
	}
	if got := baseNames(p.Index); !slices.Equal(got, []string{"index.json", "index.json.minisig"}) {
		t.Errorf("index %v", got)
	}
	g := &ghFake{rel: map[string]*ghRelease{}}
	fr := &fakeRun{fn: g.fn}
	var out bytes.Buffer
	must(t, Publish(context.Background(), fr.run, "repo", p, false, &out))
	var cmds []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(l, "#") {
			cmds = append(cmds, l)
		}
	}
	if len(cmds) != 4 || !strings.HasPrefix(cmds[0], "gh release create v0.2.0 --repo KNT048/vedette --verify-tag --draft") ||
		!strings.HasPrefix(cmds[1], "gh release upload v0.2.0 --repo KNT048/vedette --clobber") || cmds[2] != "gh release edit v0.2.0 --repo KNT048/vedette --draft=false" ||
		!strings.HasPrefix(cmds[3], "gh release upload index --repo KNT048/vedette --clobber") || strings.Contains(cmds[0], "--prerelease") {
		t.Errorf("printed:\n%s", out.String())
	}
	if len(fr.calls) != 1 || fr.calls[0][0] != "git" {
		t.Errorf("printing runs nothing but the tag lookup: %v", fr.joined())
	}
}

func TestPublishRun(t *testing.T) {
	dir, s, in := signedRelease(t)
	p, err := planPublish(dir, s, in)
	must(t, err)
	index := func() *ghRelease { return &ghRelease{Assets: []ghAsset{{Name: "README", Size: 1, State: "uploaded"}}} }
	isIndexUpload := func(c string) bool { return strings.HasPrefix(c, "gh release upload index") }

	t.Run("fresh: draft, upload, check, publish, then the index last", func(t *testing.T) {
		g := &ghFake{rel: map[string]*ghRelease{indexTag: index()}}
		fr := &fakeRun{fn: g.fn}
		must(t, Publish(context.Background(), fr.run, "repo", p, true, &bytes.Buffer{}))
		calls := fr.joined()
		ix := slices.IndexFunc(calls, isIndexUpload)
		ed := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "gh release edit v0.2.0") })
		if ix < 0 || ed < 0 || ix < ed || ix != len(calls)-2 { // the index upload, then its read-back
			t.Errorf("order: %v", calls)
		}
		if g.rel["v0.2.0"].IsDraft || len(g.rel["v0.2.0"].Assets) != len(p.Assets) || len(g.rel[indexTag].Assets) != 3 {
			t.Errorf("%+v %+v", g.rel["v0.2.0"], g.rel[indexTag])
		}
		// run again: the published version is compared, never uploaded to again; the index goes up again
		fr2 := &fakeRun{fn: g.fn}
		must(t, Publish(context.Background(), fr2.run, "repo", p, true, &bytes.Buffer{}))
		if slices.ContainsFunc(fr2.joined(), func(c string) bool { return strings.Contains(c, " v0.2.0 ") && !strings.Contains(c, "view") }) {
			t.Errorf("a published release was changed: %v", fr2.joined())
		}
	})
	t.Run("a draft left by a failed run is filled again", func(t *testing.T) {
		g := &ghFake{rel: map[string]*ghRelease{indexTag: index(), "v0.2.0": {IsDraft: true}}}
		fr := &fakeRun{fn: g.fn}
		must(t, Publish(context.Background(), fr.run, "repo", p, true, &bytes.Buffer{}))
		if slices.ContainsFunc(fr.joined(), func(c string) bool { return strings.HasPrefix(c, "gh release create") }) || g.rel["v0.2.0"].IsDraft {
			t.Errorf("%v", fr.joined())
		}
	})
	refusals := map[string]struct {
		g        *ghFake
		want     string
		noIndex  bool
		noCreate bool
	}{
		"no tag":                {g: &ghFake{noTag: true}, want: "no tag v0.2.0", noCreate: true},
		"no index release":      {g: &ghFake{rel: map[string]*ghRelease{}}, want: `no published release "index"`},
		"upload corrupted":      {g: &ghFake{corrupt: "vedette.env"}, want: "still a draft"},
		"published and changed": {g: &ghFake{rel: map[string]*ghRelease{"v0.2.0": {Assets: []ghAsset{{Name: "release-manifest.json", Size: 1, State: "uploaded"}}}}}, want: "never changed", noCreate: true},
	}
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			if c.g.rel == nil {
				c.g.rel = map[string]*ghRelease{indexTag: index()}
			} else if name != "no index release" {
				c.g.rel[indexTag] = index()
			}
			fr := &fakeRun{fn: c.g.fn}
			err := Publish(context.Background(), fr.run, "repo", p, true, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if slices.ContainsFunc(fr.joined(), isIndexUpload) {
				t.Errorf("the index went up: %v", fr.joined())
			}
			if c.noCreate && slices.ContainsFunc(fr.joined(), func(c string) bool {
				return strings.HasPrefix(c, "gh release create") || strings.HasPrefix(c, "gh release upload")
			}) {
				t.Errorf("%v", fr.joined())
			}
		})
	}
}

func TestPlanPublishRefusals(t *testing.T) {
	cases := map[string]struct {
		mut  func(dir string, in *Inputs)
		want string
	}{
		"no install.sh":          {func(d string, _ *Inputs) { must(t, os.Remove(filepath.Join(d, installer))) }, "release-bake-install"},
		"no install.sh.minisig":  {func(d string, _ *Inputs) { must(t, os.Remove(filepath.Join(d, installerSig))) }, "release-bake-install"},
		"package rebuilt":        {func(_ string, in *Inputs) { must(t, os.WriteFile(in.Host.Files[1], []byte("other"), 0o600)) }, "not the package the signed manifest names"},
		"package not described":  {func(_ string, in *Inputs) { in.Host.Files = in.Host.Files[:1] }, "names no vedette-host_0.2.0_arm64.deb"},
		"description of another": {func(_ string, in *Inputs) { in.Version = "0.2.1" }, "release.in.json is for"},
		"a container file gone":  {func(d string, _ *Inputs) { must(t, os.Remove(filepath.Join(d, "compose.yaml.minisig"))) }, "compose.yaml.minisig is missing"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir, s, in := signedRelease(t)
			c.mut(dir, in)
			if _, err := planPublish(dir, s, in); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestPublishRefreshIsTheIndexOnly(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"index.json", "index.json.minisig"} {
		must(t, os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600))
	}
	p, err := planPublish(dir, &Summary{IndexOnly: true}, nil)
	must(t, err)
	if p.Version != "" || len(p.Assets) != 0 || len(p.Index) != 2 {
		t.Fatalf("%+v", p)
	}
	g := &ghFake{rel: map[string]*ghRelease{indexTag: {}}}
	fr := &fakeRun{fn: g.fn}
	must(t, Publish(context.Background(), fr.run, "repo", p, true, &bytes.Buffer{}))
	if calls := fr.joined(); len(calls) != 3 || !strings.HasPrefix(calls[1], "gh release upload index") {
		t.Errorf("%v", calls)
	}
}
