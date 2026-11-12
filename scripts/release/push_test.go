//nolint:gosec // test code: every path is in a directory the test made
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeRun records every argv and answers with fn.
type fakeRun struct {
	calls [][]string
	fn    func(argv []string) ([]byte, error)
}

func (f *fakeRun) run(_ context.Context, argv ...string) ([]byte, error) {
	f.calls = append(f.calls, argv)
	return f.fn(argv)
}

func (f *fakeRun) joined() []string {
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = strings.Join(c, " ")
	}
	return out
}

// listJSON is a manifest list as `podman manifest inspect` prints it.
func listJSON(plats map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[`)
	keys := make([]string, 0, len(plats))
	for k := range plats {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	slices.Reverse(keys) // podman lists arm64 first; the result must not depend on it
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		goos, arch, _ := strings.Cut(k, "/")
		if a, v, ok := strings.Cut(arch, "/"); ok {
			fmt.Fprintf(&b, `{"digest":%q,"platform":{"architecture":%q,"os":%q,"variant":%q}}`, plats[k], a, goos, v)
			continue
		}
		fmt.Fprintf(&b, `{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":567,"digest":%q,"platform":{"architecture":%q,"os":%q}}`, plats[k], arch, goos)
	}
	b.WriteString("]}")
	return []byte(b.String())
}

func both(prefix string) map[string]string {
	return map[string]string{"linux/amd64": digestOf(prefix + "amd64"), "linux/arm64": digestOf(prefix + "arm64")}
}

// registryFake is a registry and a podman store in memory, plus git; tweak changes one answer.
type registryFake struct {
	head, tag, status string
	tweak             func(argv []string) ([]byte, error, bool)
}

func (r *registryFake) fn(argv []string) ([]byte, error) {
	if r.tweak != nil {
		if out, err, ok := r.tweak(argv); ok {
			return out, err
		}
	}
	a := strings.Join(argv, " ")
	last := argv[len(argv)-1]
	switch {
	case strings.HasPrefix(a, "git -C repo status"):
		return []byte(r.status), nil
	case strings.HasPrefix(a, "git -C repo rev-parse --verify HEAD"):
		return []byte(r.head + "\n"), nil
	case strings.HasPrefix(a, "git -C repo rev-parse --verify --quiet refs/tags/"):
		if r.tag == "" {
			return nil, errors.New("exit status 1")
		}
		return []byte(r.tag + "\n"), nil
	case strings.HasPrefix(a, "podman manifest exists localhost/"):
		return nil, nil
	case strings.HasPrefix(a, "podman manifest inspect localhost/"):
		return listJSON(both("local " + last)), nil
	case strings.HasPrefix(a, "podman manifest push"):
		i := slices.Index(argv, "--digestfile")
		repo, _, _ := strings.Cut(strings.TrimPrefix(last, "docker://"), ":0.2.0")
		return nil, os.WriteFile(argv[i+1], []byte(digestOf(repo)), 0o600)
	case strings.HasPrefix(a, "podman manifest inspect"):
		repo, d, ok := strings.Cut(last, "@")
		if !ok {
			repo, _, _ = strings.Cut(last, ":0.2.0")
		}
		if ok && d != digestOf(repo) {
			return nil, errors.New("Manifest does not match provided manifest digest")
		}
		return listJSON(both("remote " + repo)), nil
	}
	return nil, fmt.Errorf("unexpected command %q", a)
}

var allPlatforms = []string{"linux/amd64", "linux/arm64"}

func TestPushWritesImagesJSON(t *testing.T) {
	for _, reg := range []string{"127.0.0.1:5099", "ghcr.io/knt048"} {
		t.Run(reg, func(t *testing.T) {
			rf := &registryFake{head: "abc", tag: "abc"}
			fr := &fakeRun{fn: rf.fn}
			var out bytes.Buffer
			doc, err := Push(context.Background(), fr.run, pushOpts{Version: "0.2.0", Registry: reg, Platforms: allPlatforms, Repo: "repo", Out: t.TempDir()}, &out)
			if err != nil {
				t.Fatal(err, fr.joined())
			}
			b, err := marshal(doc)
			must(t, err)
			// exactly the schema part C reads, in the order of make images, platforms sorted
			var want strings.Builder
			want.WriteString("{\n  \"version\": \"0.2.0\",\n  \"images\": [\n")
			for i, svc := range []string{"core", "sensor", "scan", "honeypot"} {
				repo := reg + "/vedette-" + svc
				fmt.Fprintf(&want, "    {\n      \"service\": %q,\n      \"repo\": %q,\n      \"index_digest\": %q,\n      \"platforms\": [\n"+
					"        {\n          \"platform\": \"linux/amd64\",\n          \"digest\": %q\n        },\n"+
					"        {\n          \"platform\": \"linux/arm64\",\n          \"digest\": %q\n        }\n      ]\n    }",
					svc, repo, digestOf(repo), digestOf("remote "+repo+"amd64"), digestOf("remote "+repo+"arm64"))
				if i < 3 {
					want.WriteString(",")
				}
				want.WriteString("\n")
			}
			want.WriteString("  ]\n}\n")
			if string(b) != want.String() {
				t.Errorf("images.json:\n%s\nwant:\n%s", b, want.String())
			}
			calls := fr.joined()
			loop := reg == "127.0.0.1:5099"
			for _, c := range calls {
				if strings.HasPrefix(c, "podman manifest push") || strings.HasPrefix(c, "podman manifest inspect "+reg) || strings.HasPrefix(c, "podman manifest inspect --") {
					if strings.Contains(c, "--tls-verify=false") != loop {
						t.Errorf("TLS verification off only for a loopback registry: %s", c)
					}
				}
			}
			if slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "git ") }) == loop {
				t.Errorf("git checks run for the real registry only: %v", calls)
			}
			push := fr.calls[slices.IndexFunc(fr.calls, func(c []string) bool { return len(c) > 2 && c[2] == "push" })]
			wantArgv := []string{"podman", "manifest", "push", "--all", "--quiet", "--digestfile", "?", "localhost/vedette-core:0.2.0", "docker://" + reg + "/vedette-core:0.2.0"}
			if loop {
				wantArgv = slices.Insert(wantArgv, 5, "--tls-verify=false")
			}
			got := slices.Clone(push)
			if i := slices.Index(got, "--digestfile"); i > 0 {
				got[i+1] = "?"
			}
			if !slices.Equal(got, wantArgv) {
				t.Errorf("push argv %q, want %q", got, wantArgv)
			}
			if !slices.ContainsFunc(calls, func(c string) bool {
				return strings.Contains(c, "localhost/vedette-scan-base:0.2.0 docker://"+reg+"/vedette-scan:0.2.0")
			}) {
				t.Errorf("scan-base is published as vedette-scan: %v", calls)
			}
		})
	}
}

func TestPushRefusals(t *testing.T) {
	only := func(prefix string, out []byte, err error) func([]string) ([]byte, error, bool) {
		return func(argv []string) ([]byte, error, bool) {
			if strings.HasPrefix(strings.Join(argv, " "), prefix) {
				return out, err, true
			}
			return nil, nil, false
		}
	}
	cases := map[string]struct {
		version, reg string
		plats        []string
		rf           registryFake
		want         string
	}{
		"another registry":                 {reg: "docker.io/knt048", want: "pushed to ghcr.io/knt048 only"},
		"malformed registry":               {reg: "ghcr.io/KNT048", want: "malformed"},
		"v prefix":                         {version: "v0.2.0", want: "not SemVer"},
		"test version, real":               {version: "0.2.0-test.1", want: "-test."},
		"dirty tree":                       {rf: registryFake{head: "a", tag: "a", status: " M go.mod\n"}, want: "uncommitted"},
		"no tag":                           {rf: registryFake{head: "a"}, want: "no tag v0.2.0"},
		"head is not the tag":              {rf: registryFake{head: "a", tag: "b"}, want: "is not v0.2.0"},
		"platform not a release":           {plats: []string{"linux/amd64", "linux/386"}, want: "linux/386"},
		"local list lacks arm64":           {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest inspect localhost/vedette-sensor", listJSON(map[string]string{"linux/amd64": digestOf("x")}), nil)}, want: "platforms [linux/amd64]"},
		"no local list":                    {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest exists localhost/vedette-core", nil, errors.New("exit status 1"))}, want: "no local manifest list"},
		"a single image, no list":          {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest inspect localhost/vedette-core", []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`), nil)}, want: "not a manifest list"},
		"push fails":                       {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest push", nil, errors.New("denied"))}, want: "denied"},
		"no digest written":                {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest push", nil, nil)}, want: "wrote no digest"},
		"registry returns other bytes":     {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest inspect ghcr.io/knt048/vedette-core@", nil, errors.New("Manifest does not match provided manifest digest"))}, want: "read back"},
		"pushed list has another platform": {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest inspect ghcr.io/knt048/vedette-scan@", listJSON(map[string]string{"linux/amd64": digestOf("1"), "linux/arm64": digestOf("2"), "linux/arm64/v8": digestOf("3")}), nil)}, want: "platforms"},
		"tag names another list":           {rf: registryFake{head: "a", tag: "a", tweak: only("podman manifest inspect ghcr.io/knt048/vedette-honeypot:0.2.0", listJSON(both("other")), nil)}, want: "does not name the list just pushed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.version == "" {
				c.version = "0.2.0"
			}
			if c.reg == "" {
				c.reg = "ghcr.io/knt048"
			}
			if c.plats == nil {
				c.plats = allPlatforms
			}
			if c.rf.head == "" {
				c.rf.head, c.rf.tag = "a", "a"
			}
			fr := &fakeRun{fn: c.rf.fn}
			out := t.TempDir()
			_, err := Push(context.Background(), fr.run, pushOpts{Version: c.version, Registry: c.reg, Platforms: c.plats, Repo: "repo", Out: out}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if left, _ := filepath.Glob(filepath.Join(out, "*")); len(left) > 0 {
				t.Errorf("left %v", left)
			}
		})
	}
}

func TestLoopbackRegistry(t *testing.T) {
	for reg, want := range map[string]bool{
		"127.0.0.1:5099": true, "127.0.0.1:5099/x": true, "localhost:5000": true, "[::1]:5000": true, "localhost": true,
		"ghcr.io/knt048": false, "10.0.0.1:5000": false, "127.0.0.1.nip.io:5000": false, "localhost.example:5000": false,
	} {
		if got := loopbackRegistry(reg); got != want {
			t.Errorf("%s: %v", reg, got)
		}
	}
}

// imagesFor is the images.json of a release whose index digests are the ones rig.cosignDir signs.
func imagesFor(version string) *ImagesDoc {
	d := &ImagesDoc{Version: version}
	for _, svc := range []string{"core", "sensor", "scan", "honeypot"} {
		d.Images = append(d.Images, PushedImage{Service: svc, Repo: "ghcr.io/knt048/vedette-" + svc, IndexDigest: digestOf(svc + version),
			Platforms: []PlatformDigest{{"linux/amd64", digestOf(svc + "a")}, {"linux/arm64", digestOf(svc + "b")}}})
	}
	return d
}

// localStore answers podman images and the local manifest lists with sizes per platform.
func localStore(argv []string) ([]byte, error) {
	a := strings.Join(argv, " ")
	switch {
	case a == "podman images --all --format json":
		var b strings.Builder
		b.WriteString("[")
		for i, l := range []string{"core", "sensor", "scan-base", "honeypot"} {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"Id":"x","Digest":%q,"Size":%d},{"Digest":%q,"Size":%d}`, digestOf("local "+l+"amd64"), 1000+i, digestOf("local "+l+"arm64"), 2000+i)
		}
		b.WriteString("]")
		return []byte(b.String()), nil
	case strings.HasPrefix(a, "podman manifest exists localhost/vedette-"):
		return nil, nil
	case strings.HasPrefix(a, "podman manifest inspect localhost/vedette-"):
		l := strings.TrimSuffix(strings.TrimPrefix(argv[3], "localhost/vedette-"), ":0.2.0")
		return listJSON(both("local " + l)), nil
	}
	return nil, fmt.Errorf("unexpected %q", a)
}

func debDir(t *testing.T, version string) string {
	dir := t.TempDir()
	for _, arch := range []string{"amd64", "arm64"} {
		must(t, os.WriteFile(filepath.Join(dir, "vedette-host_"+version+"_"+arch+".deb"), []byte("deb "+arch), 0o600))
	}
	return dir
}

func TestBuildInputsIsWhatManifestReads(t *testing.T) {
	r := newRig(t)
	cdir, _ := r.cosignDir("0.2.0", "core", "sensor", "scan", "honeypot")
	fr := &fakeRun{fn: localStore}
	in, err := BuildInputs(context.Background(), fr.run, imagesFor("0.2.0"), inputsOpts{Channel: "stable", RollbackSafe: "false", DebDir: debDir(t, "0.2.0")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshal(in)
	must(t, err)
	back, err := ParseInputs(b)
	must(t, err)
	if back.ReleasedAt != "" || !slices.Equal(back.InstallModes, []string{"appliance", "container"}) || back.Rollback.Safe || back.Channel != "stable" || back.Host.Version != "0.2.0" || len(back.Host.Files) != 2 {
		t.Errorf("%s", b)
	}
	sizes := map[string]int64{"core": 2000, "sensor": 2001, "scan": 2002, "honeypot": 2003} // the larger platform
	for _, im := range back.Images {
		if im.Size != sizes[im.Service] || im.Digest != digestOf(im.Service+"0.2.0") || !slices.Equal(im.Platforms, allPlatforms) {
			t.Errorf("%+v", im)
		}
	}
	if _, err := BuildManifest(back, Env{Now: t1, CosignDir: cdir, CurTree: addOnlyTree}); err != nil {
		t.Fatalf("release-manifest refuses what release-in wrote: %v", err)
	}
}

func TestBuildInputsRefusals(t *testing.T) {
	ok := inputsOpts{Channel: "beta", RollbackSafe: "false"}
	cases := map[string]struct {
		mut     func(*inputsOpts, *ImagesDoc)
		version string
		want    string
	}{
		"no channel":        {mut: func(o *inputsOpts, _ *ImagesDoc) { o.Channel = "" }, want: "channel"},
		"rollback not said": {mut: func(o *inputsOpts, _ *ImagesDoc) { o.RollbackSafe = "" }, want: "RELEASE_ROLLBACK_SAFE"},
		"rollback yes":      {mut: func(o *inputsOpts, _ *ImagesDoc) { o.RollbackSafe = "yes" }, want: "RELEASE_ROLLBACK_SAFE"},
		"safe without min":  {mut: func(o *inputsOpts, _ *ImagesDoc) { o.RollbackSafe = "true" }, want: "min_version"},
		"min not SemVer":    {mut: func(o *inputsOpts, _ *ImagesDoc) { o.MinUpgradeFrom = "v0.1" }, want: "SemVer"},
		"test version":      {version: "0.2.0-test.1", want: "-test."},
		"no arm64 package": {mut: func(o *inputsOpts, _ *ImagesDoc) {
			must(t, os.Remove(filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb")))
		}, want: "host file"},
		"local list is another": {mut: func(_ *inputsOpts, d *ImagesDoc) { d.Images[0].Platforms = d.Images[0].Platforms[:1] }, want: "platforms"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v := c.version
			if v == "" {
				v = "0.2.0"
			}
			o, d := ok, imagesFor(v)
			o.DebDir = debDir(t, v)
			if c.mut != nil {
				c.mut(&o, d)
			}
			_, err := BuildInputs(context.Background(), (&fakeRun{fn: localStore}).run, d, o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestReadImagesRefusals(t *testing.T) {
	good, err := marshal(imagesFor("0.2.0"))
	must(t, err)
	cases := map[string]struct{ from, to, want string }{
		"rehearsal repo":   {`"ghcr.io/knt048/vedette-core"`, `"127.0.0.1:5099/vedette-core"`, "rehearsal"},
		"unknown service":  {`"service": "honeypot"`, `"service": "greenbone"`, "unknown service"},
		"service twice":    {`"service": "honeypot"`, `"service": "core"`, "listed 2 times"},
		"unknown field":    {`"version"`, `"size": 1, "version"`, "unknown field"},
		"bad digest":       {`"index_digest": "sha256:`, `"index_digest": "sha256:A`, "malformed"},
		"another platform": {`"linux/arm64"`, `"linux/arm"`, "malformed platform"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "images.json")
			must(t, os.WriteFile(p, []byte(strings.Replace(string(good), c.from, c.to, 1)), 0o600))
			if _, err := readImages(p); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	p := filepath.Join(t.TempDir(), "images.json")
	must(t, os.WriteFile(p, good, 0o600))
	if _, err := readImages(p); err != nil {
		t.Fatal(err)
	}
}
