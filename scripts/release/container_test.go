//nolint:gosec // test code: every path is in a directory the test made, or the repository's own template
package main

import (
	"bytes"
	"context"
	"os"
	"os/exec" //nolint:depguard // test of a release tool outside the product: only exec.LookPath("git")
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
)

// The real template of the repository (D-451): what the builder is tested on is what it ships.
func readTemplate(t *testing.T) map[string][]byte {
	t.Helper()
	src := map[string][]byte{}
	for _, n := range containerAssets {
		b, err := os.ReadFile(filepath.Join("..", "..", containerComposeIn, n))
		must(t, err)
		src[n] = b
	}
	return src
}

// copyContainerTemplate puts the real template into repo at the path the command reads it from.
func copyContainerTemplate(t *testing.T, repo string) {
	t.Helper()
	dir := filepath.Join(repo, containerComposeIn)
	must(t, os.MkdirAll(dir, 0o750))
	for n, b := range readTemplate(t) {
		must(t, os.WriteFile(filepath.Join(dir, n), b, 0o600))
	}
}

func containerInputs() Inputs {
	var imgs []ImageIn
	for _, s := range []string{"core", "sensor", "scan", "honeypot"} {
		imgs = append(imgs, ImageIn{Service: s, Digest: digestOf(s)})
	}
	return Inputs{Version: "0.2.0", Channel: "stable", InstallModes: []string{"appliance", "container"}, Images: imgs}
}

func TestBuildContainerAssetsOnTheRealTemplate(t *testing.T) {
	src := readTemplate(t)
	out, err := BuildContainerAssets(containerInputs(), src)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"compose.yaml", "compose.sensors.yaml", "compose.syslog.yaml"} {
		if !bytes.Equal(out[n], src[n]) {
			t.Errorf("%s changed: the compose files are copied unchanged", n)
		}
	}
	before := strings.Split(string(src[containerEnv]), "\n")
	after := strings.Split(string(out[containerEnv]), "\n")
	if len(before) != len(after) {
		t.Fatalf("vedette.env has %d lines, was %d", len(after), len(before))
	}
	changed := map[string]string{}
	for i := range before {
		if before[i] != after[i] {
			k, v, _ := strings.Cut(after[i], "=")
			changed[k] = v
		}
	}
	want := map[string]string{
		"VEDETTE_CORE_IMAGE":   "ghcr.io/knt048/vedette-core@" + digestOf("core"),
		"VEDETTE_SENSOR_IMAGE": "ghcr.io/knt048/vedette-sensor@" + digestOf("sensor"),
		"VEDETTE_SCAN_IMAGE":   "ghcr.io/knt048/vedette-scan@" + digestOf("scan"),
	}
	if len(changed) != 3 {
		t.Fatalf("changed lines: %v", changed)
	}
	for k, v := range want {
		if changed[k] != v || !containerImageRE.MatchString(v) {
			t.Errorf("%s=%s, want %s", k, changed[k], v)
		}
		// the Updates page checks the downloaded file with grep -cF for exactly this text (matchCmd, ContainerOnly.tsx)
		if strings.Count(string(out[containerEnv]), v) != 1 {
			t.Errorf("%s is not in vedette.env exactly once", v)
		}
	}
	// the customer's two lines stay empty: they copy theirs from the kept file
	for _, l := range []string{"\nVEDETTE_BIND_IP=\n", "\nVEDETTE_HOSTS=\n"} {
		if !bytes.Contains(out[containerEnv], []byte(l)) {
			t.Errorf("vedette.env lost %q", l)
		}
	}
	// deterministic, and the source is not modified in place
	again, _ := BuildContainerAssets(containerInputs(), src)
	if !bytes.Equal(again[containerEnv], out[containerEnv]) || bytes.Contains(src[containerEnv], []byte("@sha256:")) {
		t.Error("not deterministic, or the template was changed in place")
	}
}

func TestBuildContainerAssetsRefusals(t *testing.T) {
	env := func(f func(string) string) func(*Inputs, map[string][]byte) {
		return func(_ *Inputs, s map[string][]byte) { s[containerEnv] = []byte(f(string(s[containerEnv]))) }
	}
	cases := map[string]struct {
		mut  func(*Inputs, map[string][]byte)
		want string
	}{
		"no install modes":      {func(i *Inputs, _ map[string][]byte) { i.InstallModes = nil }, "install_modes is empty"},
		"unknown install mode":  {func(i *Inputs, _ map[string][]byte) { i.InstallModes = []string{"container", "vm"} }, "unknown mode"},
		"repeated install mode": {func(i *Inputs, _ map[string][]byte) { i.InstallModes = []string{"container", "container"} }, "twice"},
		"appliance only":        {func(i *Inputs, _ map[string][]byte) { i.InstallModes = []string{"appliance"} }, `does not list "container"`},
		"no scan image":         {func(i *Inputs, _ map[string][]byte) { i.Images = i.Images[:2] }, "no scan image"},
		"upper-case digest":     {func(i *Inputs, _ map[string][]byte) { i.Images[1].Digest = strings.ToUpper(i.Images[1].Digest) }, "malformed digest"},
		"tag before the digest": {func(i *Inputs, _ map[string][]byte) { i.Images[0].Digest = "0.2.0@" + i.Images[0].Digest }, "malformed digest"},
		"short digest":          {func(i *Inputs, _ map[string][]byte) { i.Images[0].Digest = i.Images[0].Digest[:30] }, "malformed digest"},
		"missing compose file":  {func(_ *Inputs, s map[string][]byte) { delete(s, "compose.syslog.yaml") }, "compose.syslog.yaml is missing"},
		"file that is JSON":     {func(_ *Inputs, s map[string][]byte) { s["compose.yaml"] = []byte(`{"services":{}}`) }, "# comment"},
		"template line not empty": {env(func(e string) string {
			return strings.Replace(e, "VEDETTE_CORE_IMAGE=\n", "VEDETTE_CORE_IMAGE=localhost/vedette-core:dev\n", 1)
		}), "must be empty"},
		"template line twice":   {env(func(e string) string { return e + "VEDETTE_SCAN_IMAGE=\n" }), "twice"},
		"template line missing": {env(func(e string) string { return strings.Replace(e, "VEDETTE_SENSOR_IMAGE=\n", "", 1) }), "no VEDETTE_SENSOR_IMAGE= line"},
		"unknown image line":    {env(func(e string) string { return e + "VEDETTE_HONEYPOT_IMAGE=\n" }), "does not fill"},
		"exported image line":   {env(func(e string) string { return e + "export VEDETTE_OTHER_IMAGE=x\n" }), "does not fill"},
		"carriage return": {env(func(e string) string {
			return strings.Replace(e, "VEDETTE_CORE_IMAGE=\n", "VEDETTE_CORE_IMAGE=\r\n", 1)
		}), "must be empty"},
	}
	for name, c := range cases {
		in := containerInputs()
		in.Images = append([]ImageIn(nil), in.Images...)
		src := readTemplate(t)
		c.mut(&in, src)
		if _, err := BuildContainerAssets(in, src); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// the manifest refuses what the box would refuse, before anything is signed
	r := newRig(t)
	cdir, imgs := r.cosignDir("0.1.0", "core")
	for _, modes := range [][]string{nil, {}, {"vm"}, {"appliance", "appliance"}} {
		in := Inputs{Version: "0.1.0", Channel: "beta", InstallModes: modes, Images: imgs, Host: hostIn(t, "0.1.0")}
		if _, err := BuildManifest(in, Env{Now: t1, CosignDir: cdir, CurTree: addOnlyTree}); err == nil || !strings.Contains(err.Error(), "install_modes") {
			t.Errorf("install_modes %v: %v", modes, err)
		}
	}
}

// writeAssets is the container-assets step of a rig build.
func writeAssets(t *testing.T) func(dir string, in Inputs) {
	return func(dir string, in Inputs) {
		out, err := BuildContainerAssets(in, readTemplate(t))
		must(t, err)
		for n, b := range out {
			must(t, os.WriteFile(filepath.Join(dir, n), b, 0o600))
		}
	}
}

var bothModes = []string{"appliance", "container"}

func TestContainerAssetsSignAndVerify(t *testing.T) {
	r := newRig(t)
	opts := buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree, services: []string{"core", "sensor", "scan"}, installModes: bothModes, beforeSign: writeAssets(t)}
	dir, err := r.build(opts)
	if err != nil {
		t.Fatal(err)
	}
	s, err := VerifyDir(dir, "", r.trust)
	if err != nil || !s.ContainerAssets {
		t.Fatalf("%+v %v", s, err)
	}
	for _, n := range containerAssets {
		sig, err := os.ReadFile(filepath.Join(dir, n+".minisig"))
		if err != nil || !strings.Contains(string(sig), "trusted comment: file:"+n+" version:0.1.0\n") {
			t.Errorf("%s: %v %s", n, err, sig)
		}
		if _, err := os.Stat(filepath.Join(dir, n+".backup.minisig")); err == nil {
			t.Errorf("the backup slot signed %s", n)
		}
	}

	// every way the published files can be wrong is refused by verify
	resign := func(dir, name, tc string) {
		must(t, testSigner{t, r.active}.SignFile(context.Background(), filepath.Join(dir, name), filepath.Join(dir, name+".minisig"), tc))
	}
	cases := map[string]struct {
		mut  func(dir string)
		want string
	}{
		"compose file changed": {func(d string) {
			p := filepath.Join(d, "compose.yaml")
			b, _ := os.ReadFile(p)
			must(t, os.WriteFile(p, append(b, "# more\n"...), 0o600))
		}, "compose.yaml"},
		"an asset missing":          {func(d string) { must(t, os.Remove(filepath.Join(d, "compose.sensors.yaml"))) }, "compose.sensors.yaml"},
		"a signature missing":       {func(d string) { must(t, os.Remove(filepath.Join(d, "vedette.env.minisig"))) }, "vedette.env"},
		"another release's comment": {func(d string) { resign(d, "compose.yaml", "file:compose.yaml version:0.0.9") }, "trusted comment"},
		"another file's comment":    {func(d string) { resign(d, "compose.yaml", "file:vedette.env version:0.1.0") }, "trusted comment"},
		"vedette.env names another digest, signed": {func(d string) {
			p := filepath.Join(d, containerEnv)
			b, _ := os.ReadFile(p)
			b = bytes.Replace(b, []byte("vedette-scan@"+digestOf("scan0.1.0")), []byte("vedette-scan@"+digestOf("evil")), 1)
			must(t, os.WriteFile(p, b, 0o600))
			resign(d, containerEnv, "file:vedette.env version:0.1.0")
		}, "vedette.env"},
		"vedette.env with a tag, signed": {func(d string) {
			p := filepath.Join(d, containerEnv)
			b, _ := os.ReadFile(p)
			b = bytes.Replace(b, []byte("vedette-core@"), []byte("vedette-core:0.1.0@"), 1)
			must(t, os.WriteFile(p, b, 0o600))
			resign(d, containerEnv, "file:vedette.env version:0.1.0")
		}, "vedette.env"},
		"signed by the backup key": {func(d string) {
			must(t, testSigner{t, r.backup}.SignFile(context.Background(), filepath.Join(d, "compose.yaml"), filepath.Join(d, "compose.yaml.minisig"), "file:compose.yaml version:0.1.0"))
		}, "signed by"},
	}
	for name, c := range cases {
		d, err := r.build(opts)
		must(t, err)
		c.mut(d)
		if _, err := VerifyDir(d, "", r.trust); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// a manifest that lists container needs the assets; one that does not must have none
	d, err := r.build(buildOpts{version: "0.1.0", cur: addOnlyTree, services: []string{"core", "sensor", "scan"}, installModes: bothModes})
	must(t, err)
	if _, err := VerifyDir(d, "", r.trust); err == nil || !strings.Contains(err.Error(), "make release-container-assets") {
		t.Errorf("container release without assets: %v", err)
	}
	d, err = r.build(buildOpts{version: "0.1.0", cur: addOnlyTree, services: []string{"core", "sensor", "scan"}, beforeSign: func(d string, in Inputs) {
		in.InstallModes = bothModes
		writeAssets(t)(d, in)
	}})
	must(t, err)
	if _, err := VerifyDir(d, "", r.trust); err == nil || !strings.Contains(err.Error(), "does not list install mode container") {
		t.Errorf("assets of an appliance-only release: %v", err)
	}
}

func TestSignReleaseContainerAssetRefusals(t *testing.T) {
	r := newRig(t)
	// some of the four, not all: refused before anything is signed
	d, err := r.build(buildOpts{version: "0.1.0", cur: addOnlyTree, services: []string{"core", "sensor", "scan"}, installModes: bothModes, beforeSign: func(d string, in Inputs) {
		writeAssets(t)(d, in)
		must(t, os.Remove(filepath.Join(d, "compose.syslog.yaml")))
	}})
	if err == nil || !strings.Contains(err.Error(), "not all of") || d != "" {
		t.Errorf("partial assets: %v", err)
	}
	// next to an index refresh (no manifest) there is no release to carry the version
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, indexFile), []byte(`{"sequence":3}`), 0o600))
	for n, b := range readTemplate(t) {
		must(t, os.WriteFile(filepath.Join(dir, n), b, 0o600))
	}
	if _, err := SignRelease(t.Context(), testSigner{t, r.active}, dir, slotActive); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Errorf("assets without a manifest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, indexFile+".minisig")); err == nil {
		t.Error("a refused run left a signature")
	}
}

// docs/INSTALL-CONTAINER.md hands the customer the public keys to save as vedette.pub and cosign.pub: they must be the keys
// compiled into this build (a key rotation that forgets the guide fails here, not at a customer's first update).
func TestInstallGuideKeysAreTheEmbeddedOnes(t *testing.T) {
	active, _, testOnly := release.EmbeddedMinisignKeys()
	if testOnly {
		t.Skip("a releasetestkeys build")
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "INSTALL-CONTAINER.md"))
	must(t, err)
	k, err := release.ParseMinisignPublicKey(active)
	must(t, err)
	if want := `printf 'untrusted comment: minisign public key ` + k.KeyID() + `\n` + active + `\n' > vedette.pub`; !bytes.Contains(doc, []byte(want)) {
		t.Errorf("the guide does not give the active minisign key as vedette.pub:\n%s", want)
	}
	trust, err := release.Embedded()
	must(t, err)
	_, rest, ok := strings.Cut(string(doc), "cat > cosign.pub <<'EOF'\n")
	pemText, _, ok2 := strings.Cut(rest, "EOF\n")
	if !ok || !ok2 {
		t.Fatal("the guide has no cosign.pub block")
	}
	c, err := release.ParseCosignPublicKey(pemText)
	if err != nil || len(trust.Cosign) == 0 || release.CosignKeyID(c) != release.CosignKeyID(trust.Cosign[0]) {
		t.Errorf("the guide's cosign.pub is not the embedded key: %v", err)
	}
}

// The command reads the files from git at the release tag, never from the working tree.
func TestContainerAssetsCommandReadsGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	copyContainerTemplate(t, repo)
	gitT(t, repo, "init", "-q")
	gitT(t, repo, "add", "-A")
	gitT(t, repo, "commit", "-q", "-m", "release")
	gitT(t, repo, "tag", "v0.2.0")
	// an edit after the tag is not what ships
	p := filepath.Join(repo, containerComposeIn, "compose.yaml")
	tagged, _ := os.ReadFile(p)
	must(t, os.WriteFile(p, append([]byte("# edited after the tag\n"), tagged...), 0o600))

	in := filepath.Join(t.TempDir(), "release.in.json")
	inputs := containerInputs()
	b, err := marshal(inputs)
	must(t, err)
	must(t, os.WriteFile(in, b, 0o600))
	run1 := func(extra ...string) (int, string, string) {
		out := t.TempDir()
		var o, e bytes.Buffer
		code := run(append([]string{"container-assets", "-in", in, "-out", out, "-repo", repo}, extra...), nil, &o, &e)
		return code, o.String() + e.String(), out
	}
	code, msg, out := run1()
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	got, _ := os.ReadFile(filepath.Join(out, "compose.yaml"))
	if !bytes.Equal(got, tagged) {
		t.Error("compose.yaml is not the tagged one")
	}
	env, _ := os.ReadFile(filepath.Join(out, containerEnv))
	if !bytes.Contains(env, []byte("\nVEDETTE_SCAN_IMAGE="+release.RegistryPrefix+"scan@"+digestOf("scan")+"\n")) {
		t.Errorf("%s", env)
	}
	if code, msg, _ := run1("-ref", "v9.9.9"); code != 1 || !strings.Contains(msg, "v9.9.9") {
		t.Errorf("a tag that does not exist: %d %s", code, msg)
	}
	if code, msg, _ := run1("-ref", "v0.2.0..HEAD"); code != 1 || !strings.Contains(msg, "plain") {
		t.Errorf("a range as ref: %d %s", code, msg)
	}
	if code, msg, _ := run1("-compose-dir", "../outside"); code != 1 || !strings.Contains(msg, "plain path") {
		t.Errorf("a path outside the repository: %d %s", code, msg)
	}
}
