//nolint:gosec // test code: every path is in a directory the test made, and the scripts it writes are fakes of the signing tool
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec" //nolint:depguard // test of a release tool outside the product: fixed argv (git), no shell
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/internal/release"
)

func with(base Tree, kv ...any) Tree {
	t := Tree{}
	for k, v := range base {
		t[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		t[kv[i].(string)] = kv[i+1].([]byte)
	}
	return t
}

const migA = "modules/a/migrations/sqlite/"

// H1: a box may roll back to any release from rollback.min_version, so the guard compares with the tree of that release. A guard
// that only looked at the step since the previous release would pass 0.3.0 below, although 0.2.0 dropped a table.
func TestRollbackGuardSpansReleases(t *testing.T) {
	r := newRig(t)
	v1 := Tree{migA + "0001_a.sql": up("CREATE TABLE a (id INT);")}
	v2 := with(v1, migA+"0002_a.sql", up("DROP TABLE a;")) // 0.2.0: not add-only, so it says safe=false
	v3 := with(v2, migA+"0003_a.sql", up("CREATE TABLE b (id INT);"))
	d1, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: v1})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := r.build(buildOpts{version: "0.2.0", channel: "stable", prevDir: d1, minVersion: "0.1.0", baseline: v1, cur: v2})
	if err != nil {
		t.Fatal(err)
	}
	// 0.3.0 against its own predecessor is add-only: the old, per-step guard said yes here
	if _, err := r.build(buildOpts{version: "0.3.0", channel: "stable", prevDir: d2, safe: true, minVersion: "0.2.0", baseline: v2, cur: v3}); err != nil {
		t.Fatalf("a safe rollback to 0.2.0 only: %v", err)
	}
	// but a box on 0.1.0 may roll back across 0.2.0's DROP: min_version 0.1.0 must be refused, naming the file
	_, err = r.build(buildOpts{version: "0.3.0", channel: "stable", prevDir: d2, safe: true, minVersion: "0.1.0", baseline: v1, cur: v3})
	var ge *GuardError
	if !errors.As(err, &ge) || !strings.Contains(err.Error(), "0002_a.sql") {
		t.Fatalf("a safe rollback across a DROP must be refused: %v", err)
	}
	// the floor is required, and the manifest of a safe release carries it
	if _, err := r.build(buildOpts{version: "0.3.0", channel: "stable", prevDir: d2, safe: true, baseline: v2, cur: v3}); err == nil || !strings.Contains(err.Error(), "needs rollback.min_version") {
		t.Fatalf("%v", err)
	}
	d3, err := r.build(buildOpts{version: "0.3.0", channel: "stable", prevDir: d2, safe: true, minVersion: "0.2.0", baseline: v2, cur: v3})
	if err != nil {
		t.Fatal(err)
	}
	mraw, _ := os.ReadFile(filepath.Join(d3, manifestFile))
	if !strings.Contains(string(mraw), `"min_version": "0.2.0"`) || !strings.Contains(string(mraw), `"safe": true`) {
		t.Errorf("%s", mraw)
	}
	// a beta after a stable: the version is judged against its own channel's latest, so it need not exceed another channel's
	if _, err := r.build(buildOpts{version: "0.4.0-beta.1", channel: "beta", prevDir: d3, safe: true, minVersion: "0.3.0", baseline: v3, cur: v3}); err != nil {
		t.Fatal(err)
	}
}

// M6: the published index is the only thing a release builds on: a stable hotfix after a beta continues from the index that
// holds both channels, and a previous release that was revoked does not block the next one.
func TestHotfixAfterBetaAndRevokedPrevious(t *testing.T) {
	r := newRig(t)
	d1, err := r.build(buildOpts{version: "1.0.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := r.build(buildOpts{version: "1.1.0-beta.1", channel: "beta", prevDir: d1, cur: addOnlyTree, mutateIndex: func(x *release.Index) {
		x.Revoked = append(x.Revoked, release.Revocation{Kind: release.KindRelease, ID: "1.0.0", Reason: "bad", Since: t1, Action: "block_install"})
	}})
	if err != nil {
		t.Fatal(err)
	}
	// 1.0.0 is revoked in the published index and the beta is newer than it: a stable hotfix still builds on this index
	d3, err := r.build(buildOpts{version: "1.0.1", channel: "stable", prevDir: d2, cur: addOnlyTree})
	if err != nil {
		t.Fatalf("a revoked previous release blocked the next one: %v", err)
	}
	s, err := VerifyDir(d3, d2, r.trust)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(d3, indexFile))
	for _, want := range []string{`"id": "1.0.0"`, `"latest": "1.1.0-beta.1"`, `"latest": "1.0.1"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the hotfix index lost %s", want)
		}
	}
	if s.Sequence != 3 {
		t.Errorf("sequence %d: the hotfix must continue from the newest index, not an older directory", s.Sequence)
	}
}

func writeIndex(t *testing.T, r *rig, dir string, x release.Index) {
	t.Helper()
	b, err := marshal(x)
	must(t, err)
	must(t, os.MkdirAll(dir, 0o750))
	must(t, os.WriteFile(filepath.Join(dir, indexFile), b, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, indexFile+".minisig"), r.active.SignComment(b, "t"), 0o600))
}

// M5: the weekly refresh of the index (D-150) has no manifest: it is signed and verified like a release.
func TestRefreshIndexSignsAndVerifies(t *testing.T) {
	r := newRig(t)
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	prev, err := LoadPrevIndex(pub, r.trust)
	if err != nil {
		t.Fatal(err)
	}
	files, err := BuildIndex(prev, IndexParams{Now: t1.Add(7 * 24 * time.Hour), Rollout: -1})
	if err != nil {
		t.Fatal(err)
	}
	ref := t.TempDir()
	must(t, os.WriteFile(filepath.Join(ref, indexFile), files[0].Data, 0o600))
	ctx := context.Background()
	written, err := SignRelease(ctx, testSigner{t, r.active}, ref, slotActive)
	if err != nil || len(written) != 1 || filepath.Base(written[0]) != "index.json.minisig" {
		t.Fatalf("a refresh signs the index alone: %v %v", written, err)
	}
	if _, err := SignRelease(ctx, testSigner{t, r.backup}, ref, slotBackup); err != nil {
		t.Fatal(err)
	}
	s, err := VerifyDir(ref, pub, r.trust)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IndexOnly || s.Sequence != 2 || !s.BackupSig || s.Version != "" {
		t.Fatalf("%+v", s)
	}
	if _, err := VerifyDir(ref, "", r.trust); err == nil || !strings.Contains(err.Error(), "published index") {
		t.Errorf("a refresh without the published index to compare with: %v", err)
	}
	// the index of a refresh must not go back in sequence
	if _, err := VerifyDir(pub, ref, r.trust); !errors.Is(err, release.ErrSequenceRegress) {
		t.Errorf("an older index after the refresh: %v", err)
	}
	var base release.Index
	must(t, json.Unmarshal(files[0].Data, &base))
	mutate := func(name string, f func(*release.Index), want string) {
		t.Helper()
		x := base
		x.Channels = map[string]release.Channel{}
		for k, v := range base.Channels {
			x.Channels[k] = v
		}
		f(&x)
		d := t.TempDir()
		writeIndex(t, r, d, x)
		if _, err := VerifyDir(d, pub, r.trust); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", name, want, err)
		}
	}
	mutate("a channel moves without a manifest", func(x *release.Index) {
		c := x.Channels["stable"]
		c.Latest = "0.9.0"
		x.Channels["stable"] = c
	}, "no manifest is here")
	mutate("a channel appears without a manifest", func(x *release.Index) {
		x.Channels["beta"] = x.Channels["stable"]
	}, "no manifest is here")
	mutate("a channel vanishes", func(x *release.Index) { delete(x.Channels, "stable"); x.Channels["beta"] = release.Channel{} }, "")
	mutate("the manifest hash of the same release changes", func(x *release.Index) {
		c := x.Channels["stable"]
		c.ManifestSHA256 = strings.Repeat("1", 64)
		x.Channels["stable"] = c
	}, "immutable")
	mutate("the rollout changes in a refresh", func(x *release.Index) {
		c := x.Channels["stable"]
		c.Rollout = &release.Rollout{Percent: 5}
		x.Channels["stable"] = c
	}, "no manifest is here")
	// a manifest of an earlier run next to a refresh: signed or not, verify does not wave it through
	stale := t.TempDir()
	must(t, os.WriteFile(filepath.Join(stale, indexFile), files[0].Data, 0o600))
	must(t, os.WriteFile(filepath.Join(stale, indexFile+".minisig"), r.active.SignComment(files[0].Data, "t"), 0o600))
	mraw, _ := os.ReadFile(filepath.Join(pub, manifestFile))
	must(t, os.WriteFile(filepath.Join(stale, manifestFile), mraw, 0o600))
	if _, err := VerifyDir(stale, pub, r.trust); err == nil {
		t.Error("a manifest without a signature next to a refresh passed")
	}
}

// Through the command line: a refresh needs the published index, and refuses a directory that holds a manifest.
func TestRefreshCommandRefusals(t *testing.T) {
	r := newRig(t)
	keys := t.TempDir()
	writeKeys(t, r, keys)
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	run1 := func(args ...string) (int, string) {
		var o, e bytes.Buffer
		c := run(args, nil, &o, &e)
		return c, o.String() + e.String()
	}
	out := t.TempDir()
	if c, msg := run1("index", "-out", out); c == 0 || !strings.Contains(msg, "-prev-index") {
		t.Errorf("a refresh without -prev-index: %d %s", c, msg)
	}
	// pub holds a manifest: a refresh written there would be signed together with it
	if c, msg := run1("index", "-out", pub, "-prev-index", pub, "-keys-dir", keys); c == 0 || !strings.Contains(msg, "earlier run") {
		t.Errorf("%d %s", c, msg)
	}
	if c, msg := run1("index", "-out", out, "-prev-index", pub, "-keys-dir", keys); c != 0 {
		t.Fatalf("%d %s", c, msg)
	}
	raw, _ := os.ReadFile(filepath.Join(out, indexFile))
	var x release.Index
	must(t, json.Unmarshal(raw, &x))
	if x.Sequence != 2 || x.Channels["stable"].Latest != "0.1.0" {
		t.Fatalf("%+v", x)
	}
	// L2 through the CLI: a time far from the clock, and a sequence that jumps
	if c, msg := run1("index", "-out", t.TempDir(), "-prev-index", pub, "-keys-dir", keys, "-now", "2020-01-01T00:00:00Z"); c == 0 || !strings.Contains(msg, "clock") {
		t.Errorf("a generated_at far from the clock: %d %s", c, msg)
	}
	if c, msg := run1("index", "-out", t.TempDir(), "-prev-index", pub, "-keys-dir", keys, "-sequence", "500"); c == 0 || !strings.Contains(msg, "above the previous") {
		t.Errorf("a sequence that jumps: %d %s", c, msg)
	}
}

func writeKeys(t *testing.T, r *rig, dir string) {
	t.Helper()
	must(t, os.WriteFile(filepath.Join(dir, "minisign.pub"), []byte(r.active.PubLine()+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "minisign-backup.pub"), []byte(r.backup.PubLine()+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "cosign.pub"), []byte(r.cos.PubPEM(t)), 0o600))
}

type failingSigner struct {
	inner  Signer
	failOn int
	n      int
}

func (f *failingSigner) SignFile(ctx context.Context, path, sigPath, tc string) error {
	f.n++
	if f.n == f.failOn {
		_ = os.WriteFile(sigPath, []byte("half"), 0o600) // a tool that dies after creating the file
		return errors.New("signer failed")
	}
	return f.inner.SignFile(ctx, path, sigPath, tc)
}

// M5: any error removes every signature written in the run, so a directory never holds the signature of the index
// without the signature of the manifest.
func TestSignFailureRemovesTheRunsSignatures(t *testing.T) {
	r := newRig(t)
	for failOn := 1; failOn <= 2; failOn++ {
		dir, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
		if err != nil {
			t.Fatal(err)
		}
		sigs, _ := filepath.Glob(filepath.Join(dir, "*.minisig"))
		for _, s := range sigs {
			must(t, os.Remove(s))
		}
		f := &failingSigner{inner: testSigner{t, r.active}, failOn: failOn}
		written, err := SignRelease(t.Context(), f, dir, slotActive)
		if err == nil || len(written) != 0 {
			t.Fatalf("failOn %d: %v %v", failOn, written, err)
		}
		if left, _ := filepath.Glob(filepath.Join(dir, "*.minisig")); len(left) != 0 {
			t.Errorf("failOn %d: signatures left behind: %v", failOn, left)
		}
	}
}

func TestIndexRulesOfRound2(t *testing.T) {
	man := []byte(`{"version":"1.0.0"}`)
	base, err := BuildIndex(nil, IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: man})
	if err != nil {
		t.Fatal(err)
	}
	var prev release.Index
	must(t, json.Unmarshal(base[0].Data, &prev))
	// L1: the same latest with other manifest bytes is a changed release
	other := []byte(`{"version":"1.0.0","notes":"changed"}`)
	if _, err := BuildIndex(&prev, IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: other}); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("a changed manifest under the same version: %v", err)
	}
	if _, err := BuildIndex(&prev, IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: man}); err != nil {
		t.Errorf("the same bytes again: %v", err)
	}
	// L2: an explicit sequence may step ahead a little, not far
	for seq, ok := range map[uint64]bool{2: true, 11: true, 12: false, 1000: false} {
		_, err := BuildIndex(&prev, IndexParams{Now: t1, Rollout: -1, Sequence: seq})
		if (err == nil) != ok {
			t.Errorf("sequence %d after 1: err=%v", seq, err)
		}
	}
	if _, err := BuildIndex(nil, IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: man, Sequence: 11}); err == nil {
		t.Error("a first index numbered 11")
	}
	for d, ok := range map[time.Duration]bool{0: true, 5 * time.Minute: true, -5 * time.Minute: true, 11 * time.Minute: false, -11 * time.Minute: false, 24 * time.Hour: false} {
		if err := checkClock(time.Now().Add(d), "x"); (err == nil) != ok {
			t.Errorf("clock offset %v: %v", d, err)
		}
	}
}

// L4: only "does not exist" means the backup signature is absent.
func TestUnreadableBackupSignatureIsAnError(t *testing.T) {
	r := newRig(t)
	dir, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	bs := filepath.Join(dir, indexFile+".backup.minisig")
	must(t, os.Remove(bs))
	if s, err := VerifyDir(dir, "", r.trust); err != nil || s.BackupSig {
		t.Fatalf("an absent backup signature is fine: %v %+v", s, err)
	}
	must(t, os.Mkdir(bs, 0o700)) // present, but not a readable file
	if _, err := VerifyDir(dir, "", r.trust); err == nil || !strings.Contains(err.Error(), "backup signature") {
		t.Errorf("an unreadable backup signature passed as absent: %v", err)
	}
	must(t, os.Remove(bs))
	must(t, os.WriteFile(bs, bytes.Repeat([]byte("x"), release.MaxSigBytes+10), 0o600))
	if _, err := VerifyDir(dir, "", r.trust); err == nil {
		t.Error("an oversized backup signature passed")
	}
}

// L5: a legacy index is a document of a schema this build cannot parse; until a verifier for its schema is registered next to
// the writer, a directory holding one does not verify.
func TestLegacyIndexNeedsAVerifier(t *testing.T) {
	r := newRig(t)
	dir, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "index.v1.json"), []byte(`{"schema":1}`), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "index.v1.json.minisig"), []byte("sig"), 0o600))
	if _, err := VerifyDir(dir, "", r.trust); err == nil || !strings.Contains(err.Error(), "no verifier") {
		t.Fatalf("%v", err)
	}
	t.Cleanup(func() { delete(legacyVerifiers, 1) })
	legacyVerifiers[1] = func(_, sig []byte, _ release.Trust) error {
		if string(sig) != "sig" {
			return errors.New("bad legacy signature")
		}
		return nil
	}
	if _, err := VerifyDir(dir, "", r.trust); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "index.v1.json.minisig"), []byte("forged"), 0o600))
	if _, err := VerifyDir(dir, "", r.trust); err == nil || !strings.Contains(err.Error(), "bad legacy signature") {
		t.Fatalf("%v", err)
	}
	must(t, os.Remove(filepath.Join(dir, "index.v1.json.minisig")))
	if _, err := VerifyDir(dir, "", r.trust); err == nil {
		t.Error("a legacy index without a signature file passed")
	}
}

func fakeMinisign(t *testing.T) (bin, argvFile string) {
	t.Helper()
	work := t.TempDir()
	argvFile = filepath.Join(work, "argv")
	bin = filepath.Join(work, "minisign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvFile + "\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -x ]; then echo sig > \"$2\"; fi; shift; done\n"
	must(t, os.WriteFile(bin, []byte(script), 0o755))
	return bin, argvFile
}

// L6: the key must stay out of the repository (its root, not the working directory), and the tool gets the resolved path.
func TestKeyPlacement(t *testing.T) {
	bin, argvFile := fakeMinisign(t)
	repo, outside := t.TempDir(), t.TempDir()
	doc := filepath.Join(outside, "doc.json")
	must(t, os.WriteFile(doc, []byte("{}"), 0o600))
	sig := doc + ".minisig"
	sign := func(key, root string) error {
		return MinisignCLI{Bin: bin, KeyPath: key, RepoRoot: root}.SignFile(t.Context(), doc, sig, "t")
	}
	inRepo := filepath.Join(repo, "k.key")
	must(t, os.WriteFile(inRepo, []byte("k"), 0o600))
	if err := sign(inRepo, repo); err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Errorf("a key inside the repository root (the working directory is elsewhere): %v", err)
	}
	away := filepath.Join(outside, "away.key")
	must(t, os.WriteFile(away, []byte("k"), 0o600))
	if err := sign(away, repo); err != nil {
		t.Fatalf("a key outside the repository: %v", err)
	}
	// a link inside the repository to a key outside: allowed, and minisign gets the real path
	link := filepath.Join(repo, "link.key")
	must(t, os.Symlink(away, link))
	if err := sign(link, repo); err != nil {
		t.Fatal(err)
	}
	realAway, _ := filepath.EvalSymlinks(away)
	argv, _ := os.ReadFile(argvFile)
	if !strings.Contains(string(argv), "\n"+realAway+"\n") || strings.Contains(string(argv), link) {
		t.Errorf("minisign must get the resolved path %s, got:\n%s", realAway, argv)
	}
	// a link outside to a key inside the repository: refused
	back := filepath.Join(outside, "back.key")
	must(t, os.Symlink(inRepo, back))
	if err := sign(back, repo); err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Errorf("a link into the repository: %v", err)
	}
	// RepoRoot from git
	if _, err := exec.LookPath("git"); err == nil {
		g := func(args ...string) { gitT(t, repo, args...) }
		g("init", "-q")
		sub := filepath.Join(repo, "deep", "er")
		must(t, os.MkdirAll(sub, 0o750))
		root, err := RepoRoot(t.Context(), sub)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := filepath.EvalSymlinks(repo)
		got, _ := filepath.EvalSymlinks(root)
		if got != want {
			t.Errorf("RepoRoot = %s, want %s", got, want)
		}
	}
}

func gitT(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestCheckClean(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	put := func(p, s string) {
		full := filepath.Join(repo, p)
		must(t, os.MkdirAll(filepath.Dir(full), 0o750))
		must(t, os.WriteFile(full, []byte(s), 0o600))
	}
	put("modules/a/migrations/sqlite/0001_a.sql", string(up("CREATE TABLE a (id INT);")))
	put("modules/a/code.go", "package a")
	gitT(t, repo, "init", "-q")
	gitT(t, repo, "add", "-A")
	gitT(t, repo, "commit", "-q", "-m", "one")
	if err := CheckClean(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
	put("modules/a/code.go", "package a // edited") // not a migration: does not matter
	put("modules/a/new_file.txt", "x")
	if err := CheckClean(t.Context(), repo); err != nil {
		t.Fatalf("a change outside the migration directories: %v", err)
	}
	for name, change := range map[string]func(){
		"a migration edited":          func() { put("modules/a/migrations/sqlite/0001_a.sql", string(up("CREATE TABLE a (id INT, x INT);"))) },
		"a migration added untracked": func() { put("modules/a/migrations/sqlite/0002_a.sql", string(up("CREATE TABLE b (id INT);"))) },
		"a migration deleted":         func() { must(t, os.Remove(filepath.Join(repo, "modules/a/migrations/sqlite/0001_a.sql"))) },
		"a migration staged only": func() {
			put("modules/a/migrations/sqlite/0003_a.sql", string(up("CREATE TABLE c (id INT);")))
			gitT(t, repo, "add", "modules/a/migrations/sqlite/0003_a.sql")
		},
	} {
		gitT(t, repo, "checkout", "-q", "--", ".")
		gitT(t, repo, "reset", "-q", "--hard")
		gitT(t, repo, "clean", "-q", "-fd", "modules/a/migrations")
		change()
		if err := CheckClean(t.Context(), repo); err == nil || !strings.Contains(err.Error(), "migrations/sqlite/000") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// M4 and H1 through the command line, on a real git repository: both trees come from tags, a dirty migration directory is
// refused, and a safe rollback across a DROP is refused with exit code 3.
func TestManifestCommandReadsGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := newRig(t)
	repo := t.TempDir()
	put := func(name, sql string) {
		full := filepath.Join(repo, migA, name)
		must(t, os.MkdirAll(filepath.Dir(full), 0o750))
		must(t, os.WriteFile(full, up(sql), 0o600))
	}
	commit := func(tag string) {
		gitT(t, repo, "add", "-A")
		gitT(t, repo, "commit", "-q", "-m", tag)
		gitT(t, repo, "tag", "v"+tag)
	}
	gitT(t, repo, "init", "-q")
	putProto(t, repo, "4") // D-410: the sensor protocol gate reads it at each tag
	put("0001_a.sql", "CREATE TABLE a (id INT);")
	commit("0.1.0")
	put("0002_a.sql", "DROP TABLE a;")
	commit("0.2.0")
	put("0003_a.sql", "CREATE TABLE b (id INT);")
	commit("0.3.0")

	manifest := func(version, minVersion string, safe bool, extra ...string) (int, string, string) {
		t.Helper()
		cdir, imgs := r.cosignDir(version, "core")
		type imgJSON struct {
			Service   string   `json:"service"`
			Digest    string   `json:"digest"`
			Size      int64    `json:"size"`
			Platforms []string `json:"platforms"`
		}
		var js []imgJSON
		for _, im := range imgs {
			js = append(js, imgJSON(im))
		}
		host := hostIn(t, version)
		doc, err := json.Marshal(map[string]any{
			"version": version, "channel": "beta", "install_modes": []string{"appliance"}, "images": js,
			"rollback": map[string]any{"safe": safe, "min_version": minVersion}, "host": host,
		})
		must(t, err)
		in := filepath.Join(t.TempDir(), "release.in.json")
		must(t, os.WriteFile(in, doc, 0o600))
		out := t.TempDir()
		var o, e bytes.Buffer
		gates := gatesPath(t, gatesDoc(t, version, filepath.Dir(host.Files[0]))) // the packages the gates checked; extra may name another record
		args := append([]string{"manifest", "-in", in, "-cosign-dir", cdir, "-out", out, "-repo", repo, "-gates", gates}, extra...)
		code := run(args, nil, &o, &e)
		return code, o.String() + e.String(), out
	}
	// 0.3.0 is add-only against 0.2.0 but 0.2.0 dropped a table: min_version 0.1.0 is refused (exit 3), 0.2.0 passes
	if code, msg, _ := manifest("0.3.0", "0.1.0", true); code != 3 || !strings.Contains(msg, "0002_a.sql") {
		t.Errorf("a safe rollback across a DROP: %d %s", code, msg)
	}
	code, msg, out := manifest("0.3.0", "0.2.0", true)
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	raw, _ := os.ReadFile(filepath.Join(out, manifestFile))
	if !strings.Contains(string(raw), `"db_schema": 3`) || !strings.Contains(string(raw), `"min_version": "0.2.0"`) {
		t.Errorf("%s", raw)
	}
	// the packages must be the bytes release gates checked (a make host-deb after step 3), of this version; no record, no manifest
	other := gatesDoc(t, "0.3.0", "") // the record of other packages
	for name, c := range map[string]struct{ gates, want string }{
		"package rebuilt after the gates": {gatesPath(t, other), "vedette-host_0.3.0_amd64.deb has sha256 "},
		"record of another version":       {gatesPath(t, gatesDoc(t, "0.2.0", "")), "the gates record is of version 0.2.0, not 0.3.0"},
		"no record":                       {filepath.Join(t.TempDir(), gatesFile), "no gates record"},
	} {
		if code, msg, out := manifest("0.3.0", "0.2.0", true, "-gates", c.gates); code != 1 || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %s", name, code, msg)
		} else if _, err := os.Stat(filepath.Join(out, manifestFile)); err == nil {
			t.Errorf("%s: a manifest was written", name)
		}
	}
	// safe=false across the DROP is allowed, and says why
	if code, msg, _ := manifest("0.3.0", "0.1.0", false); code != 0 || !strings.Contains(msg, "rollback.safe=false is right") {
		t.Errorf("%d %s", code, msg)
	}
	// a tag that does not exist is an error, not an empty tree
	if code, msg, _ := manifest("0.4.0", "0.3.0", true); code != 1 || !strings.Contains(msg, "migrations of v0.4.0") {
		t.Errorf("no tag for the release: %d %s", code, msg)
	}
	if code, msg, _ := manifest("0.3.0", "0.2.5", true); code != 1 || !strings.Contains(msg, "baseline") {
		t.Errorf("no tag for the baseline: %d %s", code, msg)
	}
	// the migration tree is the tag's, not the working tree's: an explicit ref is honoured
	if code, msg, out := manifest("0.3.0", "0.1.0", false, "-ref", "v0.2.0"); code != 0 {
		t.Errorf("%d %s", code, msg)
	} else if raw, _ := os.ReadFile(filepath.Join(out, manifestFile)); !strings.Contains(string(raw), `"db_schema": 2`) {
		t.Errorf("db_schema must be the count at -ref v0.2.0:\n%s", raw)
	}
	// M4: a migration edited in the working tree, or added and not committed, refuses the build
	put("0003_a.sql", "DROP TABLE b;")
	if code, msg, _ := manifest("0.3.0", "0.2.0", true); code != 1 || !strings.Contains(msg, "uncommitted") {
		t.Errorf("an edited migration passed: %d %s", code, msg)
	}
	gitT(t, repo, "checkout", "-q", "--", ".")
	put("0004_a.sql", "DROP TABLE b;")
	if code, msg, _ := manifest("0.3.0", "0.2.0", true); code != 1 || !strings.Contains(msg, "uncommitted") {
		t.Errorf("an untracked migration passed: %d %s", code, msg)
	}
	gitT(t, repo, "clean", "-q", "-fd", "modules")
	// L2: a time far from the clock is refused
	if code, msg, _ := manifest("0.3.0", "0.2.0", true, "-now", "2020-01-01T00:00:00Z"); code != 1 || !strings.Contains(msg, "clock") {
		t.Errorf("-now far from the clock: %d %s", code, msg)
	}
}
