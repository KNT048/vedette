package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// listJSON is a manifest list as `podman manifest inspect` prints it (and as a registry serves it, in the tests).
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

var localNames = []string{"core", "sensor", "scan-base", "honeypot"}

// cfgID is the image ID (config digest, no sha256:) of a local platform image.
func cfgID(local, arch string) string {
	return strings.TrimPrefix(digestOf("cfg "+local+arch), "sha256:")
}

// localStore answers what podman says about the local lists of make images (version 0.2.0, label label): the lists, and
// `podman images --all --format json` with the ID, size and labels of each platform image.
func localStore(label string) func(argv []string) ([]byte, error) {
	return func(argv []string) ([]byte, error) {
		a := strings.Join(argv, " ")
		switch {
		case a == "podman images --all --format json":
			var b strings.Builder
			b.WriteString(`[{"Id":"` + strings.Repeat("e", 64) + `","Digest":"sha256:` + strings.Repeat("1", 64) + `","Size":1040}`)
			for i, l := range localNames {
				for j, arch := range []string{"amd64", "arm64"} {
					fmt.Fprintf(&b, `,{"Id":%q,"Digest":%q,"Size":%d,"Labels":{"org.opencontainers.image.version":%q}}`, cfgID(l, arch), digestOf("local "+l+arch), 1000*(j+1)+i, label)
				}
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
}

// registryFake is podman's local store, a registry (remote: repo -> the list it holds) and git; tweak changes one answer.
type registryFake struct {
	head, tag, status string
	label             string
	remote            map[string][]byte
	tweak             func(rf *registryFake, argv []string) ([]byte, error, bool)
}

func (rf *registryFake) fn(argv []string) ([]byte, error) {
	if rf.remote == nil {
		rf.remote = map[string][]byte{}
	}
	if rf.label == "" {
		rf.label = "0.2.0"
	}
	if rf.tweak != nil {
		if out, err, ok := rf.tweak(rf, argv); ok {
			return out, err
		}
	}
	a := strings.Join(argv, " ")
	last := argv[len(argv)-1]
	switch {
	case strings.HasPrefix(a, "git -C repo status"):
		return []byte(rf.status), nil
	case strings.HasPrefix(a, "git -C repo rev-parse --verify HEAD"):
		return []byte(rf.head + "\n"), nil
	case strings.HasPrefix(a, "git -C repo rev-parse --verify --quiet refs/tags/"):
		if rf.tag == "" {
			return nil, errors.New("exit status 1")
		}
		return []byte(rf.tag + "\n"), nil
	case strings.HasPrefix(a, "podman image exists"):
		return nil, errors.New("exit status 1")
	case strings.HasPrefix(a, "podman manifest push"):
		i := slices.Index(argv, "--digestfile")
		repo, _, _ := strings.Cut(strings.TrimPrefix(last, "docker://"), ":0.2.0")
		rf.remote[repo] = listJSON(both("remote " + repo))
		return nil, os.WriteFile(argv[i+1], []byte(digestBytes(rf.remote[repo])), 0o600)
	case strings.HasPrefix(a, "podman manifest inspect") && !strings.Contains(a, "localhost/"):
		repo, d, byDigest := strings.Cut(last, "@")
		if !byDigest {
			repo, _, _ = strings.Cut(last, ":0.2.0")
		}
		body, ok := rf.remote[repo]
		switch {
		case !ok:
			return nil, errors.New("reading manifest 0.2.0 in " + repo + ": manifest unknown")
		case byDigest && digestBytes(body) != d:
			return nil, errors.New("Manifest does not match provided manifest digest")
		}
		return body, nil
	}
	return localStore(rf.label)(argv)
}

var allPlatforms = []string{"linux/amd64", "linux/arm64"}

// gatesDoc is the record `release gates` writes for the local lists of localStore (config cfgID) and two packages (sums of the
// files in debDir, or placeholders when debDir is "").
func gatesDoc(t *testing.T, version, debDir string) *GatesDoc {
	t.Helper()
	g := &GatesDoc{Version: version, MinSequence: "1"}
	for _, arch := range debArchs {
		d := GatedDeb{Arch: arch, File: "vedette-host_" + version + "_" + arch + ".deb", SHA256: strings.Repeat("a", 64), Size: 1}
		if debDir != "" {
			var err error
			d.SHA256, d.Size, err = hashFile(filepath.Join(debDir, d.File))
			must(t, err)
		}
		g.Debs = append(g.Debs, d)
	}
	for _, im := range publishedImages {
		gi := GatedImage{Service: im.service, Local: im.local}
		for _, arch := range []string{"amd64", "arm64"} {
			gi.Platforms = append(gi.Platforms, GatedPlatform{Platform: "linux/" + arch, Config: "sha256:" + cfgID(im.local, arch)})
		}
		g.Images = append(g.Images, gi)
	}
	return g
}

// gatesPath writes g as release gates does (in a directory of its own) and returns the path.
func gatesPath(t *testing.T, g *GatesDoc) string {
	t.Helper()
	p, err := writeGates(t.TempDir(), g)
	must(t, err)
	return p
}

func TestPushWritesImagesJSON(t *testing.T) {
	for _, reg := range []string{"127.0.0.1:5099", "[::1]:5099", "ghcr.io/knt048"} {
		t.Run(reg, func(t *testing.T) {
			rf := &registryFake{head: "abc", tag: "abc"}
			fr := &fakeRun{fn: rf.fn}
			var out bytes.Buffer
			doc, err := Push(context.Background(), fr.run, pushOpts{Version: "0.2.0", Registry: reg, Platforms: allPlatforms, Repo: "repo", Out: t.TempDir(), Gates: gatesPath(t, gatesDoc(t, "0.2.0", ""))}, &out)
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
					"        {\n          \"platform\": \"linux/amd64\",\n          \"digest\": %q,\n          \"config\": %q\n        },\n"+
					"        {\n          \"platform\": \"linux/arm64\",\n          \"digest\": %q,\n          \"config\": %q\n        }\n      ]\n    }",
					svc, repo, digestBytes(listJSON(both("remote "+repo))), digestOf("remote "+repo+"amd64"), "sha256:"+cfgID(localNames[i], "amd64"),
					digestOf("remote "+repo+"arm64"), "sha256:"+cfgID(localNames[i], "arm64"))
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
			loop := reg != "ghcr.io/knt048"
			for _, c := range calls {
				if strings.HasPrefix(c, "podman manifest push") || (strings.HasPrefix(c, "podman manifest inspect") && !strings.Contains(c, "localhost/")) {
					if strings.Contains(c, "--tls-verify=false") != loop {
						t.Errorf("TLS verification off only for a loopback registry: %s", c)
					}
				}
			}
			if slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "git ") }) == loop {
				t.Errorf("git checks run for the real registry only: %v", calls)
			}
			push := fr.calls[slices.IndexFunc(fr.calls, func(c []string) bool { return len(c) > 2 && c[2] == "push" })]
			wantArgv := []string{"podman", "manifest", "push", "--all", "--quiet", "--compression-format=gzip", "--digestfile", "?", "localhost/vedette-core:0.2.0", "docker://" + reg + "/vedette-core:0.2.0"}
			if loop {
				wantArgv = slices.Insert(wantArgv, 6, "--tls-verify=false")
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
			// the existence check of the remote name comes before the push, and a local image of that name is looked for first
			ex := slices.Index(calls, "podman image exists "+reg+"/vedette-core:0.2.0")
			pu := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "podman manifest push") })
			if ex < 0 || ex > pu {
				t.Errorf("order: %v", calls)
			}
		})
	}
}

// remoteRegistry serves, anonymously, one list (repo vedette-honeypot, tag 0.2.0) whose platforms have config digests cfg[arch].
func remoteRegistry(t *testing.T, cfg map[string]string, status int) (*httptest.Server, []byte) {
	plat := map[string]string{}
	images := map[string][]byte{}
	for _, arch := range []string{"amd64", "arm64"} {
		m := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"` + cfg[arch] + `"},"layers":[]}`)
		plat["linux/"+arch] = digestBytes(m)
		images[digestBytes(m)] = m
	}
	list := listJSON(plat)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v2/vedette-honeypot/manifests/")
		switch {
		case ref == "0.2.0":
			_, _ = w.Write(list)
		case images[ref] != nil:
			_, _ = w.Write(images[ref])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, list
}

func TestPushReusesTheSameImagesAndRefusesOthers(t *testing.T) {
	same := map[string]string{"amd64": "sha256:" + cfgID("honeypot", "amd64"), "arm64": "sha256:" + cfgID("honeypot", "arm64")}
	other := map[string]string{"amd64": same["amd64"], "arm64": digestOf("rebuilt")}
	cases := map[string]struct {
		cfg    map[string]string
		status int
		want   string
	}{
		"same images":     {cfg: same},
		"other images":    {cfg: other, want: "never replaced"},
		"not anonymously": {cfg: same, status: http.StatusUnauthorized, want: "cannot be compared"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv, list := remoteRegistry(t, c.cfg, c.status)
			rf := &registryFake{remote: map[string][]byte{"127.0.0.1:5099/vedette-honeypot": list}}
			fr := &fakeRun{fn: rf.fn}
			doc, err := Push(context.Background(), fr.run, pushOpts{Version: "0.2.0", Registry: "127.0.0.1:5099", Platforms: allPlatforms, Repo: "repo", Out: t.TempDir(),
				Gates: gatesPath(t, gatesDoc(t, "0.2.0", "")), HTTP: registryHTTP{base: srv.URL, client: srv.Client()}}, &bytes.Buffer{})
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("got %v, want %q", err, c.want)
				}
				return
			}
			must(t, err)
			if slices.ContainsFunc(fr.joined(), func(c string) bool { return strings.Contains(c, "push") && strings.Contains(c, "vedette-honeypot") }) {
				t.Errorf("the same images were pushed again: %v", fr.joined())
			}
			if doc.Images[3].IndexDigest != digestBytes(list) {
				t.Errorf("%+v", doc.Images[3])
			}
		})
	}
}

func TestPushRefusals(t *testing.T) {
	only := func(prefix string, out []byte, err error) func(*registryFake, []string) ([]byte, error, bool) {
		return func(_ *registryFake, argv []string) ([]byte, error, bool) {
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
		gates        func(g *GatesDoc) // changes the record of the local lists
		noGates      bool              // no record at all
		want         string
	}{
		"no gates record":          {noGates: true, want: "no gates record"},
		"gates of another version": {gates: func(g *GatesDoc) { g.Version = "0.1.0" }, want: "the gates record is of version 0.1.0, not 0.2.0"},
		"a list rebuilt after the gates": {gates: func(g *GatesDoc) { g.Images[3].Platforms[1].Config = digestOf("before") },
			want: "localhost/vedette-honeypot:0.2.0 linux/arm64 is sha256:" + cfgID("honeypot", "arm64") + " now, the gates checked " + digestOf("before") + ": the images changed after the gates; run make release-gates VERSION=0.2.0 again"},
		"a platform the gates did not see": {gates: func(g *GatesDoc) { g.Images[1].Platforms = g.Images[1].Platforms[:1] },
			want: "localhost/vedette-sensor:0.2.0 linux/arm64 is sha256:" + cfgID("sensor", "arm64") + " now, the gates checked absent"},
		"another registry":        {reg: "docker.io/knt048", want: "pushed to ghcr.io/knt048 only"},
		"malformed registry":      {reg: "ghcr.io/KNT048", want: "malformed"},
		"other ipv6":              {reg: "[::2]:5000", want: "malformed"},
		"v prefix":                {version: "v0.2.0", want: "not SemVer"},
		"test version, real":      {version: "0.2.0-test.1", want: "-test."},
		"dirty tree":              {rf: registryFake{head: "a", tag: "a", status: " M go.mod\n"}, want: "uncommitted"},
		"no tag":                  {rf: registryFake{head: "a"}, want: "no tag v0.2.0"},
		"head is not the tag":     {rf: registryFake{head: "a", tag: "b"}, want: "is not v0.2.0"},
		"platform not a release":  {plats: []string{"linux/amd64", "linux/386"}, want: "linux/386"},
		"version label is not it": {rf: registryFake{label: "0.1.0"}, want: `org.opencontainers.image.version="0.1.0", not 0.2.0`},
		"local list lacks arm64": {rf: registryFake{tweak: only("podman manifest inspect localhost/vedette-sensor",
			listJSON(map[string]string{"linux/amd64": digestOf("local sensoramd64")}), nil)}, want: "platforms [linux/amd64]"},
		"no local list": {rf: registryFake{tweak: only("podman manifest exists localhost/vedette-core", nil, errors.New("exit status 1"))}, want: "no local manifest list"},
		"a single image, no list": {rf: registryFake{tweak: only("podman manifest inspect localhost/vedette-core",
			[]byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`), nil)}, want: "not a manifest list"},
		"no local platform image":      {rf: registryFake{tweak: only("podman images", []byte(`[]`), nil)}, want: "no local image"},
		"a local image of the remote":  {rf: registryFake{tweak: only("podman image exists ghcr.io/knt048/vedette-core:0.2.0", nil, nil)}, want: "a local image is named"},
		"registry login fails":         {rf: registryFake{tweak: only("podman manifest inspect ghcr.io/knt048/vedette-core:0.2.0", nil, errors.New("unauthorized"))}, want: "does ghcr.io/knt048/vedette-core:0.2.0 exist?"},
		"push fails":                   {rf: registryFake{tweak: only("podman manifest push", nil, errors.New("denied"))}, want: "denied"},
		"no digest written":            {rf: registryFake{tweak: only("podman manifest push", nil, nil)}, want: "wrote no digest"},
		"registry returns other bytes": {rf: registryFake{tweak: only("podman manifest inspect ghcr.io/knt048/vedette-core@", nil, errors.New("Manifest does not match provided manifest digest"))}, want: "read back"},
		"pushed list has another platform": {rf: registryFake{tweak: only("podman manifest inspect ghcr.io/knt048/vedette-scan@",
			listJSON(map[string]string{"linux/amd64": digestOf("1"), "linux/arm64": digestOf("2"), "linux/arm64/v8": digestOf("3")}), nil)}, want: "platforms"},
		"tag names another list": {rf: registryFake{tweak: func(rf *registryFake, argv []string) ([]byte, error, bool) {
			if strings.Join(argv, " ") == "podman manifest inspect ghcr.io/knt048/vedette-honeypot:0.2.0" && rf.remote["ghcr.io/knt048/vedette-honeypot"] != nil {
				return listJSON(both("other")), nil, true
			}
			return nil, nil, false
		}}, want: "does not name the list just pushed"},
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
			g := gatesDoc(t, "0.2.0", "")
			if c.gates != nil {
				c.gates(g)
			}
			gp := gatesPath(t, g)
			if c.noGates {
				must(t, os.Remove(gp))
			}
			_, err := Push(context.Background(), fr.run, pushOpts{Version: c.version, Registry: c.reg, Platforms: c.plats, Repo: "repo", Out: out, Gates: gp}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if left, _ := filepath.Glob(filepath.Join(out, "*")); len(left) > 0 {
				t.Errorf("left %v", left)
			}
			if c.gates != nil || c.noGates {
				// refused before anything is pushed or asked of the registry, for every list, not after the first ones
				if slices.ContainsFunc(fr.joined(), func(a string) bool {
					return strings.HasPrefix(a, "podman manifest push") || strings.HasPrefix(a, "podman image exists") || strings.HasPrefix(a, "podman manifest inspect ghcr.io")
				}) {
					t.Errorf("registry touched before the gates check: %v", fr.joined())
				}
				if c.noGates && len(fr.calls) > 0 {
					t.Errorf("no record: nothing should run: %v", fr.joined())
				}
			}
		})
	}
}

func TestLoopbackRegistry(t *testing.T) {
	for reg, want := range map[string]bool{
		"127.0.0.1:5099": true, "127.0.0.1:5099/x": true, "localhost:5000": true, "[::1]:5000": true, "[::1]": true, "localhost": true,
		"ghcr.io/knt048": false, "10.0.0.1:5000": false, "127.0.0.1.nip.io:5000": false, "localhost.example:5000": false,
	} {
		if got := loopbackRegistry(reg); got != want {
			t.Errorf("%s: %v", reg, got)
		}
		if !registryRE.MatchString(reg) {
			t.Errorf("%s does not match registryRE", reg)
		}
	}
	for reg, want := range map[string]string{"ghcr.io/knt048": "https://ghcr.io knt048", "127.0.0.1:5099": "http://127.0.0.1:5099 ", "[::1]:5000/a": "http://[::1]:5000 a"} {
		if b, ns := registryBase(reg); b+" "+ns != want {
			t.Errorf("%s: %s %s", reg, b, ns)
		}
	}
}

// imagesFor is the images.json of a release whose index digests are the ones rig.cosignDir signs.
func imagesFor(version string) *ImagesDoc {
	d := &ImagesDoc{Version: version}
	for _, svc := range []string{"core", "sensor", "scan", "honeypot"} {
		d.Images = append(d.Images, PushedImage{Service: svc, Repo: "ghcr.io/knt048/vedette-" + svc, IndexDigest: digestOf(svc + version),
			Platforms: []PlatformDigest{{"linux/amd64", digestOf(svc + "a"), "sha256:" + cfgID(localName(svc), "amd64")},
				{"linux/arm64", digestOf(svc + "b"), "sha256:" + cfgID(localName(svc), "arm64")}}})
	}
	return d
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
	fr := &fakeRun{fn: localStore("0.2.0")}
	dd := debDir(t, "0.2.0")
	in, err := BuildInputs(context.Background(), fr.run, imagesFor("0.2.0"), inputsOpts{Channel: "stable", RollbackSafe: "false", DebDir: dd, Gates: gatesPath(t, gatesDoc(t, "0.2.0", dd))})
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
		gates   func(*GatesDoc) // changes the record of what debDir and localStore hold
		version string
		want    string
	}{
		"no gates record":          {mut: func(o *inputsOpts, _ *ImagesDoc) { must(t, os.Remove(o.Gates)) }, want: "no gates record"},
		"gates of another version": {gates: func(g *GatesDoc) { g.Version = "0.2.1" }, want: "the gates record is of version 0.2.1, not 0.2.0"},
		"deb built again after the gates": {mut: func(o *inputsOpts, _ *ImagesDoc) {
			must(t, os.WriteFile(filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb"), []byte("deb arm64, rebuilt"), 0o600))
		}, want: "vedette-host_0.2.0_arm64.deb has sha256 "},
		"images.json is not what the gates saw": {mut: func(_ *inputsOpts, d *ImagesDoc) { d.Images[2].Platforms[0].Config = digestOf("x") },
			want: "images.json scan linux/amd64 is " + digestOf("x") + " now, the gates checked sha256:" + cfgID("scan-base", "amd64")},
		"local list rebuilt after the push": {mut: func(_ *inputsOpts, d *ImagesDoc) { d.Images[1].Platforms[1].Config = digestOf("pushed") },
			gates: func(g *GatesDoc) { g.Images[1].Platforms[1].Config = digestOf("pushed") },
			want:  "localhost/vedette-sensor:0.2.0 linux/arm64 is sha256:" + cfgID("sensor", "arm64") + " now, the gates checked " + digestOf("pushed")},
		"no channel":        {mut: func(o *inputsOpts, _ *ImagesDoc) { o.Channel = "" }, want: "channel"},
		"rollback not said": {mut: func(o *inputsOpts, _ *ImagesDoc) { o.RollbackSafe = "" }, want: "RELEASE_ROLLBACK_SAFE"},
		"rollback yes":      {mut: func(o *inputsOpts, _ *ImagesDoc) { o.RollbackSafe = "yes" }, want: "RELEASE_ROLLBACK_SAFE"},
		"safe without min":  {mut: func(o *inputsOpts, _ *ImagesDoc) { o.RollbackSafe = "true" }, want: "min_version"},
		"min not SemVer":    {mut: func(o *inputsOpts, _ *ImagesDoc) { o.MinUpgradeFrom = "v0.1" }, want: "SemVer"},
		"test version":      {version: "0.2.0-test.1", want: "-test."},
		"no arm64 package": {mut: func(o *inputsOpts, _ *ImagesDoc) {
			must(t, os.Remove(filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb")))
		}, want: "host file"},
		"images.json lacks a platform": {mut: func(_ *inputsOpts, d *ImagesDoc) { d.Images[0].Platforms = d.Images[0].Platforms[:1] }, want: "images.json core linux/arm64 is absent now"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v := c.version
			if v == "" {
				v = "0.2.0"
			}
			o, d := ok, imagesFor(v)
			o.DebDir = debDir(t, v)
			g := gatesDoc(t, v, o.DebDir)
			if c.gates != nil {
				c.gates(g)
			}
			o.Gates = gatesPath(t, g)
			if c.mut != nil {
				c.mut(&o, d)
			}
			_, err := BuildInputs(context.Background(), (&fakeRun{fn: localStore("0.2.0")}).run, d, o)
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
