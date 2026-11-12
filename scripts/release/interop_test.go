//nolint:gosec // test code: every path is in a directory the test made, or the pinned tool of the maintainer's cache
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec" //nolint:depguard // test of a release tool outside the product: fixed argv, no shell
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
)

// Interop with the real minisign tool (D-164): what the builder signs through the tool verifies with the tool and with the box's
// verifier, and what the Go signer of releasetest signs verifies with the tool. The tool is the pinned one of deploy/tools.env
// (scripts/release/minisign.sh downloads it; `make release-interop` runs this file). Without it the tests skip, so a machine
// that has not fetched it still passes `go test`; the maintainer's `make release-interop` fails if the tool is missing.

func pins(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../../deploy/tools.env")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.ContainsAny(v, " \t\"'$") {
			t.Fatalf("tools.env line %q: KEY=VALUE only", l)
		}
		out[k] = v
	}
	return out
}

func TestMinisignPinIsExact(t *testing.T) {
	p := pins(t)
	hex64 := func(k string) {
		if len(p[k]) != 64 || strings.Trim(p[k], "0123456789abcdef") != "" {
			t.Errorf("%s=%q must be 64 lower-case hex", k, p[k])
		}
	}
	for _, k := range []string{"MINISIGN_TARBALL_SHA256", "MINISIGN_X86_64_SHA256", "MINISIGN_AARCH64_SHA256"} {
		hex64(k)
	}
	v := p["MINISIGN_VERSION"]
	if strings.Trim(v, "0123456789.") != "" || strings.Count(v, ".") != 1 {
		t.Errorf("MINISIGN_VERSION=%q must be MAJOR.MINOR", v)
	}
	if want := "https://github.com/jedisct1/minisign/releases/download/" + v + "/minisign-" + v + "-linux.tar.gz"; p["MINISIGN_URL"] != want {
		t.Errorf("MINISIGN_URL=%q, want %q (an https release asset of the pinned version)", p["MINISIGN_URL"], want)
	}
	if _, err := release.ParseMinisignPublicKey(p["MINISIGN_AUTHOR_KEY"]); err != nil {
		t.Errorf("MINISIGN_AUTHOR_KEY: %v", err)
	}
}

func minisignBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("VEDETTE_MINISIGN_BIN"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	pin := pins(t)
	if runtime.GOOS != "linux" || arch == "" {
		t.Skip("the pinned minisign is for Linux; set VEDETTE_MINISIGN_BIN to test with your own")
	}
	bin := filepath.Join(home, ".cache", "vedette-minisign", pin["MINISIGN_VERSION"], "minisign-linux", arch, "minisign")
	b, err := os.ReadFile(bin)
	if err != nil {
		if os.Getenv("VEDETTE_REQUIRE_MINISIGN") == "1" {
			t.Fatalf("the pinned minisign is not at %s: run scripts/release/minisign.sh", bin)
		}
		t.Skipf("the pinned minisign is not at %s (run scripts/release/minisign.sh); skipping the interop test", bin)
	}
	sum := sha256.Sum256(b)
	want := pin["MINISIGN_X86_64_SHA256"]
	if arch == "aarch64" {
		want = pin["MINISIGN_AARCH64_SHA256"]
	}
	if hex.EncodeToString(sum[:]) != want {
		t.Fatalf("%s does not match the pin of deploy/tools.env", bin)
	}
	return bin
}

// ms runs the real tool with a deadline; stdin may be empty.
func ms(t *testing.T, bin, stdin string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // the pinned test tool
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func TestInteropMinisignCLI(t *testing.T) {
	bin := minisignBin(t)
	if out, err := ms(t, bin, "", "-v"); err != nil || !strings.HasPrefix(out, "minisign ") {
		t.Fatalf("%q %v", out, err)
	}
	keys := t.TempDir() // outside the working directory: SignFile refuses a key inside it
	pub := func(n string) string { return filepath.Join(keys, n) }
	// an unencrypted active key and a passphrase-protected backup key, both made by the real tool
	if out, err := ms(t, bin, "", "-G", "-W", "-p", pub("minisign.pub"), "-s", pub("active.key")); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	const bpw = "correct horse battery staple"
	if out, err := ms(t, bin, bpw+"\n"+bpw+"\n", "-G", "-p", pub("minisign-backup.pub"), "-s", pub("backup.key")); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cos := releasetest.NewCosign(t)
	must(t, os.WriteFile(pub("cosign.pub"), []byte(cos.PubPEM(t)), 0o600))

	// the description, the cosign files, and a migration tree
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	must(t, os.MkdirAll(filepath.Join(repo, "modules/a/migrations/sqlite"), 0o750))
	must(t, os.WriteFile(filepath.Join(repo, "modules/a/migrations/sqlite/0001_a.sql"), up("CREATE TABLE a (id INT);"), 0o600))
	copyContainerTemplate(t, repo) // D-451: the real compose files and vedette.env, read back from git at the tag
	// the migrations are read from git: a repository with the release tagged
	gitT(t, repo, "init", "-q")
	gitT(t, repo, "add", "-A")
	gitT(t, repo, "commit", "-q", "-m", "release")
	gitT(t, repo, "tag", "v0.1.0-beta.1")
	cdir := filepath.Join(work, "cosign")
	must(t, os.MkdirAll(cdir, 0o750))
	var imgs []string
	for _, s := range []string{"core", "sensor", "scan"} {
		d := digestOf(s + "interop")
		p := releasetest.Payload(release.RegistryPrefix+s, d)
		_, sig := cos.Sign(t, p)
		must(t, os.WriteFile(filepath.Join(cdir, s+".payload.json"), p, 0o600))
		must(t, os.WriteFile(filepath.Join(cdir, s+".sig"), []byte(sig+"\n"), 0o600))
		imgs = append(imgs, `{"service":"`+s+`","digest":"`+d+`","size":5,"platforms":["linux/amd64"]}`)
	}
	in := filepath.Join(work, "release.in.json")
	host, err := json.Marshal(hostIn(t, "0.1.0-beta.1"))
	must(t, err)
	must(t, os.WriteFile(in, []byte(`{"version":"0.1.0-beta.1","channel":"beta","notes":"interop","install_modes":["appliance","container"],"rollback":{"safe":false,"min_version":""},"images":[`+strings.Join(imgs, ",")+`],"host":`+string(host)+`}`), 0o600))
	out := filepath.Join(work, "out")

	do := func(stdin string, args ...string) (int, string) {
		var o, e bytes.Buffer
		code := run(args, strings.NewReader(stdin), &o, &e)
		return code, o.String() + e.String()
	}
	for _, step := range [][]string{
		{"manifest", "-in", in, "-cosign-dir", cdir, "-out", out, "-repo", repo},
		{"container-assets", "-in", in, "-out", out, "-repo", repo},
		{"index", "-out", out, "-manifest", filepath.Join(out, manifestFile)},
		{"sign", "-dir", out, "-key", pub("active.key"), "-minisign", bin, "-slot", "active"},
	} {
		if code, msg := do("", step...); code != 0 {
			t.Fatalf("%v: exit %d\n%s", step[0], code, msg)
		}
	}
	// the backup key has a passphrase: a wrong one signs nothing, the right one (on stdin) does
	if code, _ := do("not the passphrase\n", "sign", "-dir", out, "-key", pub("backup.key"), "-minisign", bin, "-slot", "backup", "-passphrase-stdin"); code == 0 {
		t.Fatal("a wrong passphrase signed")
	}
	if _, err := os.Stat(filepath.Join(out, "index.json.backup.minisig")); err == nil {
		t.Fatal("a wrong passphrase left a signature behind")
	}
	if code, msg := do(bpw+"\n", "sign", "-dir", out, "-key", pub("backup.key"), "-minisign", bin, "-slot", "backup", "-passphrase-stdin"); code != 0 {
		t.Fatalf("exit %d\n%s", code, msg)
	}
	// (1) builder signs through the tool; the box's verifier accepts it, with both signatures
	code, msg := do("", "verify", "-dir", out, "-keys-dir", keys)
	if code != 0 || !strings.Contains(msg, "backup signature true") || !strings.Contains(msg, "release 0.1.0-beta.1 (beta)") {
		t.Fatalf("verify: exit %d\n%s", code, msg)
	}
	// (2) the tool itself verifies what the builder signed
	for _, c := range []struct{ file, sig, pub string }{
		{"index.json", "index.json.minisig", "minisign.pub"},
		{"release-manifest.json", "release-manifest.json.minisig", "minisign.pub"},
		{"index.json", "index.json.backup.minisig", "minisign-backup.pub"},
		// the customer's own command for the container-only files (docs/INSTALL-CONTAINER.md, D-451)
		{"vedette.env", "vedette.env.minisig", "minisign.pub"},
		{"compose.yaml", "compose.yaml.minisig", "minisign.pub"},
		{"compose.sensors.yaml", "compose.sensors.yaml.minisig", "minisign.pub"},
		{"compose.syslog.yaml", "compose.syslog.yaml.minisig", "minisign.pub"},
	} {
		o, err := ms(t, bin, "", "-Vm", filepath.Join(out, c.file), "-x", filepath.Join(out, c.sig), "-p", pub(c.pub))
		if err != nil || !strings.Contains(o, "Signature and comment signature verified") {
			t.Errorf("minisign -V %s: %v\n%s", c.file, err, o)
		}
		if !strings.Contains(o, "Trusted comment: file:") {
			t.Errorf("trusted comment missing: %s", o)
		}
	}
	// the tool refuses a tampered document, and so does the box's verifier
	mp := filepath.Join(out, manifestFile)
	orig, _ := os.ReadFile(mp)
	must(t, os.WriteFile(mp, bytes.Replace(orig, []byte("interop"), []byte("hacked!"), 1), 0o600))
	if _, err := ms(t, bin, "", "-Vm", mp, "-x", mp+".minisig", "-p", pub("minisign.pub")); err == nil {
		t.Error("the tool accepted a tampered manifest")
	}
	if code, _ := do("", "verify", "-dir", out, "-keys-dir", keys); code == 0 {
		t.Error("verify accepted a tampered manifest")
	}
	must(t, os.WriteFile(mp, orig, 0o600))
	if code, msg := do("", "verify", "-dir", out, "-keys-dir", keys); code != 0 {
		t.Fatalf("restored: %s", msg)
	}
	// the weekly refresh (D-150): no manifest, signed by the real tool, verified against the published index
	refresh := filepath.Join(work, "refresh")
	for _, step := range [][]string{
		{"index", "-out", refresh, "-prev-index", out, "-keys-dir", keys},
		{"sign", "-dir", refresh, "-key", pub("active.key"), "-minisign", bin},
	} {
		if code, msg := do("", step...); code != 0 {
			t.Fatalf("refresh %v: exit %d\n%s", step[0], code, msg)
		}
	}
	if code, msg := do("", "verify", "-dir", refresh, "-prev-index", out, "-keys-dir", keys); code != 0 || !strings.Contains(msg, "index-only refresh, sequence 2") {
		t.Fatalf("refresh verify: exit %d\n%s", code, msg)
	}
	if _, err := os.Stat(filepath.Join(refresh, manifestFile+".minisig")); err == nil {
		t.Error("a refresh produced a manifest signature")
	}
	if o, err := ms(t, bin, "", "-Vm", filepath.Join(refresh, indexFile), "-p", pub("minisign.pub")); err != nil || !strings.Contains(o, "sequence:2") {
		t.Errorf("minisign -V of the refreshed index: %v\n%s", err, o)
	}
	// (3) the legacy "Ed" signature of the real tool is refused by the verifier (the verifier takes prehashed "ED" only)
	ip := filepath.Join(out, indexFile)
	if o, err := ms(t, bin, "", "-S", "-l", "-s", pub("active.key"), "-m", ip, "-x", ip+".minisig", "-t", "legacy"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if code, msg := do("", "verify", "-dir", out, "-keys-dir", keys); code == 0 || !strings.Contains(msg, "legacy") {
		t.Errorf("a legacy signature was accepted: %d %s", code, msg)
	}
	// (4) the other direction: what the Go signer of releasetest signs, the real tool verifies
	rt := releasetest.NewMinisign(t)
	doc := filepath.Join(work, "doc.json")
	must(t, os.WriteFile(doc, []byte(`{"schema":1,"sequence":7}`+"\n"), 0o600))
	raw, _ := os.ReadFile(doc)
	must(t, os.WriteFile(doc+".minisig", rt.SignComment(raw, "file:doc.json sequence:7\ttab"), 0o600))
	o, err := ms(t, bin, "", "-Vm", doc, "-P", rt.PubLine())
	if err != nil || !strings.Contains(o, "Signature and comment signature verified") || !strings.Contains(o, "sequence:7") {
		t.Fatalf("minisign -V of a releasetest signature: %v\n%s", err, o)
	}
	must(t, os.WriteFile(doc, []byte(`{"schema":1,"sequence":8}`+"\n"), 0o600))
	if _, err := ms(t, bin, "", "-Vm", doc, "-P", rt.PubLine()); err == nil {
		t.Error("the tool accepted a releasetest signature over another document")
	}
	// and the real tool's own signature, made by `minisign -S` with the ID of that key, parses in the verifier's key format
	k, err := release.ParseMinisignPublicKey(rt.PubLine())
	if err != nil || k.ID != rt.ID {
		t.Fatal(k, err)
	}
}
