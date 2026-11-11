package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// blob writes content as <dir>/<sha256 hex> and returns "sha256:<hex>".
func blob(t *testing.T, dir, content string) string {
	t.Helper()
	h := sha256.Sum256([]byte(content))
	x := hex.EncodeToString(h[:])
	if err := os.WriteFile(filepath.Join(dir, x), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + x
}

func TestSignedDocumentsVerifyWithTheProductionVerifiers(t *testing.T) {
	keyDir, blobs := t.TempDir(), t.TempDir()
	if err := cmdKeys([]string{"-out", keyDir, "-repo", "/repo"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"minisign-active.seed", "cosign.key", "overlay.json", "keys_prod.go"} {
		st, err := os.Stat(filepath.Join(keyDir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, st, err)
		}
	}
	gen, _ := os.ReadFile(filepath.Join(keyDir, "keys_prod.go")) //nolint:gosec // the test's own temp folder
	if !strings.Contains(string(gen), "return \"RW") || strings.Contains(string(gen), "PRIVATE") {
		t.Fatal("generated source must hold public keys only")
	}
	ks, err := loadKeySet(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	core := blob(t, blobs, `{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	spec := signSpec{keys: ks, version: "0.0.1-test.1", platform: "linux/amd64", blobs: blobs, images: map[string]string{"core": core},
		now: time.Now().UTC().Truncate(time.Second), releaseURL: "https://github.com/KNT048/vedette/releases/download/v0.0.1-test.1"}
	idx, idxSig, man, manSig, err := spec.build()
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.check(idx, idxSig, man, manSig); err != nil {
		t.Fatal(err)
	}
	// the production keys are empty: the same documents must NOT verify against them
	if _, err := release.Embedded(); err == nil {
		t.Fatal("this build embeds production keys that were not expected here")
	}
	// another key set does not verify them
	other, _ := newKeySet()
	spec.keys = other
	if err := spec.check(idx, idxSig, man, manSig); err == nil {
		t.Fatal("documents signed by one throwaway key set verified under another")
	}
}

func TestRegistryServesByDigestOnly(t *testing.T) {
	dir := t.TempDir()
	m := blob(t, dir, `{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json"}`)
	b := blob(t, dir, "layer")
	srv := httptest.NewServer(registryHandler(dir))
	defer srv.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	// get returns the status line and headers; the body is closed before it returns
	type reply struct {
		StatusCode int
		Status     string
		Header     http.Header
	}
	get := func(method, path string) reply {
		req, _ := http.NewRequestWithContext(t.Context(), method, srv.URL+path, http.NoBody)
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		return reply{r.StatusCode, r.Status, r.Header}
	}
	if r := get("GET", "/v2/"); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	r := get("HEAD", "/v2/knt048/vedette-core/manifests/"+m)
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/vnd.docker.distribution.manifest.list.v2+json" || r.Header.Get("Docker-Content-Digest") != m {
		t.Fatalf("manifest: %s %v", r.Status, r.Header)
	}
	if r := get("GET", "/v2/x/blobs/"+b); r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatal(r.Status)
	}
	for _, p := range []string{"/v2/x/manifests/latest", "/v2/x/blobs/sha256:" + strings.Repeat("0", 64), "/v2/x/blobs/sha256:../../etc/passwd", "/v2/x/blobs/sha256:" + strings.Repeat("A", 64)} {
		if r := get("GET", p); r.StatusCode != 404 {
			t.Fatalf("%s: %s", p, r.Status)
		}
	}
	if r := get("DELETE", "/v2/x/blobs/"+b); r.StatusCode != 405 {
		t.Fatalf("delete: %s", r.Status)
	}
	if err := cmdServe([]string{"-dir", dir, "-listen", "0.0.0.0:1"}); err == nil {
		t.Fatal("a non-loopback listen address was accepted")
	}
}
