//nolint:gosec // test code: every path is in a directory the test made, and the binaries are built from a main the test wrote
package main

import (
	"bytes"
	"context"
	"os"
	"os/exec" //nolint:depguard // test of a release helper outside the product: fixed argv (go build), no shell
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRefuseTestVersion(t *testing.T) {
	for _, v := range []string{"0.1.0-test.1", "1.2.3-test.20", "1.0.0-test"} {
		if refuseTestVersion(v) == nil {
			t.Errorf("%s accepted", v)
		}
	}
	for _, v := range []string{"0.1.0", "1.0.0-rc.1", "1.0.0-beta.2", "1.0.0-testing.1", "1.0.0-rc.1-test"} {
		if err := refuseTestVersion(v); err != nil {
			t.Errorf("%s refused: %v", v, err)
		}
	}
}

// A -test. version is refused by the manifest step and by the index step, before anything is written.
func TestBuilderRefusesTestPrerelease(t *testing.T) {
	r := newRig(t)
	cdir, imgs := r.cosignDir("0.1.0-test.1", "core")
	in := Inputs{Version: "0.1.0-test.1", Channel: "beta", InstallModes: []string{"appliance"}, Images: imgs}
	if _, err := BuildManifest(in, Env{Now: t1, CosignDir: cdir, CurTree: addOnlyTree}); err == nil || !strings.Contains(err.Error(), "-test.") {
		t.Errorf("manifest of a -test. version: %v", err)
	}
	p := IndexParams{Now: t1, Rollout: -1, Channel: "beta", ManifestVersion: "0.1.0-test.1", ManifestRaw: []byte(`{"version":"0.1.0-test.1"}`)}
	if _, err := BuildIndex(nil, p); err == nil || !strings.Contains(err.Error(), "-test.") {
		t.Errorf("index of a -test. version: %v", err)
	}
	p.ManifestVersion = "0.1.0-rc.1"
	if _, err := BuildIndex(nil, p); err != nil {
		t.Errorf("a real prerelease must pass: %v", err)
	}
}

// The index must be numbered above the floor compiled into vedette-host.
func TestIndexAboveMinSequence(t *testing.T) {
	r := newRig(t)
	prev, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := LoadPrevIndex(prev, r.trust)
	if err != nil {
		t.Fatal(err)
	}
	floor := idx.Sequence // what `min-sequence` prints and make passes as MIN_SEQUENCE
	p := IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "0.2.0", ManifestRaw: []byte(`{"version":"0.2.0"}`), MinSequence: floor}
	if _, err := BuildIndex(idx, p); err != nil {
		t.Fatalf("previous+1 is above the floor: %v", err)
	}
	p.Sequence = floor // explicit, equal to the floor (and the previous): refused either way
	if _, err := BuildIndex(idx, p); err == nil {
		t.Error("a sequence equal to the floor accepted")
	}
	p.Sequence, p.MinSequence = 0, floor+5 // a MIN_SEQUENCE typed too high
	if _, err := BuildIndex(idx, p); err == nil || !strings.Contains(err.Error(), "floor") {
		t.Errorf("floor above the new sequence: %v", err)
	}
}

func TestMinSequenceCommand(t *testing.T) {
	r := newRig(t)
	prev, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	if err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	must(t, os.WriteFile(filepath.Join(keys, "minisign.pub"), []byte("untrusted comment: x\n"+r.active.PubLine()+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(keys, "minisign-backup.pub"), []byte(r.backup.PubLine()+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(keys, "cosign.pub"), []byte(r.cos.PubPEM(t)), 0o600))
	var out, errb bytes.Buffer
	if code := run([]string{"min-sequence", "-prev-index", prev, "-keys-dir", keys}, nil, &out, &errb); code != 0 || out.String() != "1\n" {
		t.Fatalf("code %d, out %q, err %q", code, out.String(), errb.String())
	}
	// an index that does not verify gives no floor
	must(t, os.WriteFile(filepath.Join(prev, indexFile), []byte(`{"sequence":99}`), 0o600))
	out.Reset()
	if code := run([]string{"min-sequence", "-prev-index", prev, "-keys-dir", keys}, nil, &out, &errb); code == 0 || out.Len() != 0 {
		t.Errorf("a tampered index gave a floor: %q", out.String())
	}
	if code := run([]string{"min-sequence"}, nil, &out, &errb); code == 0 {
		t.Error("no -prev-index accepted")
	}
}

// buildProbe builds a tiny main into dir with the given -tags (empty: none) and returns its path. Never builds the repository's cmd.
func buildProbe(t *testing.T, tags string) string {
	t.Helper()
	src := t.TempDir()
	must(t, os.WriteFile(filepath.Join(src, "go.mod"), []byte("module probe\n\ngo 1.21\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600))
	bin := filepath.Join(t.TempDir(), "probe")
	args := []string{"build", "-o", bin}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", append(args, ".")...)
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func TestCheckBinaries(t *testing.T) {
	clean := buildProbe(t, "")
	other := buildProbe(t, "netgo,osusergo")
	dirty := buildProbe(t, "releasetestkeys")
	mixed := buildProbe(t, "netgo,releasetestkeys")
	for _, p := range []string{clean, other} {
		if err := CheckBinary(p); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{dirty, mixed} {
		if err := CheckBinary(p); err == nil || !strings.Contains(err.Error(), "releasetestkeys") {
			t.Errorf("%s accepted: %v", p, err)
		}
	}
	notGo := filepath.Join(t.TempDir(), "x")
	must(t, os.WriteFile(notGo, []byte("#!/bin/sh\n"), 0o700))
	if CheckBinary(notGo) == nil || CheckBinary(filepath.Join(t.TempDir(), "missing")) == nil {
		t.Error("a file without build information passed")
	}

	var out, errb bytes.Buffer
	if code := run([]string{"check-binaries", clean, other}, nil, &out, &errb); code != 0 {
		t.Errorf("clean binaries: code %d, %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"check-binaries", clean, dirty}, nil, &out, &errb); code != 1 || !strings.Contains(errb.String(), dirty) {
		t.Errorf("a dirty one among clean ones: code %d, %s", code, errb.String())
	}
	if code := run([]string{"check-binaries"}, nil, &out, &errb); code == 0 {
		t.Error("no binary accepted")
	}
}
