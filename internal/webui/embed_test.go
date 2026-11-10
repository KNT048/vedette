//go:build webui

package webui_test

import (
	"io/fs"
	"os"
	"testing"

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
