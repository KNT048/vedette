//go:build webui

package webui_test

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/knt048/vedette"
	"github.com/knt048/vedette/internal/webui"
)

// Run after `make webui-dist`: the embedded files are the release build, and the mock service worker is not in them.
func TestEmbeddedDist(t *testing.T) {
	if _, err := os.Stat("dist/index.html"); err != nil {
		t.Skip("internal/webui/dist/index.html is absent: run make webui-dist")
	}
	fsys := webui.FS()
	b, err := fs.ReadFile(fsys, "index.html")
	if err != nil || len(b) == 0 {
		t.Fatalf("embedded index.html: %v", err)
	}
	if _, err := fs.Stat(fsys, "mockServiceWorker.js"); err == nil {
		t.Error("mockServiceWorker.js is embedded: that is a mock build")
	}
}

// D-544: the interface shows the terms the box records as accepted. The version the web build computed from TERMS.md
// (web/vite.config.ts, virtual:terms) is the one core computes (vedette.TermsVersion): a different formula, or a dist built
// before TERMS.md changed, fails here.
func TestEmbeddedDistShowsTheTermsCoreRecords(t *testing.T) {
	if _, err := os.Stat("dist/index.html"); err != nil {
		t.Skip("internal/webui/dist/index.html is absent: run make webui-dist")
	}
	want := []byte(vedette.TermsVersion())
	found := false
	err := fs.WalkDir(webui.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") || found {
			return err
		}
		b, err := fs.ReadFile(webui.FS(), p)
		found = found || bytes.Contains(b, want)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no script of the embedded interface holds the terms version %s: rebuild it (make webui-dist) or align web/vite.config.ts with terms.go", want)
	}
}
