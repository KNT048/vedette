// Package webui serves the single-page interface from the core binary itself (D-149): same origin as /api/v1, no reverse proxy, no CDN.
// The files are embedded only in a build with the `webui` tag (embed.go, over the generated internal/webui/dist); every other build
// (dev, tests, CI) has no files and answers with a one-line page (stub.go).
package webui

import (
	"bytes"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// CSP is the Envelope's policy (core/server) plus two additions, both found by `make webui-csp-check` in a real browser on the release build (D-149):
//   - `font-src ... data:`: Vite inlines the two smallest font files into the stylesheet as data: URIs;
//   - `style-src 'self' 'sha256-...'`: two libraries append a <style> element at run time (sonner, react-style-singleton). Their text is fixed per
//     library version, so each is allowed by its hash, not by 'unsafe-inline'. A library upgrade that changes the text fails the check; re-take the
//     hash from the browser's message and replace it here.
//
// No unsafe-inline, no unsafe-eval, no remote origin.
const CSP = "default-src 'self'; style-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-StEaX+se6YS7pqjzrzMIA0KaX9zF/8zAhvQXZAe5epY='; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

const stubPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Vedette</title></head>
<body><p>This build has no web interface. Use the Vite dev server (make dev) or a release build.</p></body></html>
`

func init() {
	// A base image with no /etc/mime.types (distroless) knows no font types; Go's own table has the rest.
	for ext, typ := range map[string]string{".woff": "font/woff", ".woff2": "font/woff2"} {
		_ = mime.AddExtensionType(ext, typ)
	}
}

// Handler serves fsys, the built interface (index.html at its root). A nil fsys is the stub build. It answers only GET and HEAD, never lists a
// directory, and answers any other path with index.html (the router of the SPA decides), except paths under /api/ and paths that name a file
// (a last segment with an extension): those are 404, so a missing chunk is never answered with HTML.
func Handler(fsys fs.FS) http.Handler {
	return handler{fsys}
}

type handler struct{ fsys fs.FS }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", CSP)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("X-Frame-Options", "DENY") // older browsers; frame-ancestors covers the rest
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		hd.Set("Cache-Control", "no-store")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Rooted Clean resolves every ".." before the name reaches the FS (and fs.FS refuses a name with one anyway).
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "api" || strings.HasPrefix(name, "api/") {
		hd.Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	if h.fsys == nil {
		h.serve(w, r, "index.html", []byte(stubPage), "no-store")
		return
	}
	if name != "" && name != "index.html" { // index.html is the fallback itself: no-store, whichever way it was asked for
		if body, ok := h.file(name); ok {
			h.serve(w, r, name, body, cacheFor(name))
			return
		}
		if path.Ext(name) != "" {
			hd.Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
	}
	body, ok := h.file("index.html")
	if !ok {
		hd.Set("Cache-Control", "no-store")
		http.Error(w, "web interface files are missing", http.StatusInternalServerError)
		return
	}
	h.serve(w, r, "index.html", body, "no-store")
}

// cacheFor: Vite names everything under assets/ by content hash, so it never changes; other top-level files (the favicon) are revalidated.
func cacheFor(name string) string {
	if strings.HasPrefix(name, "assets/") {
		return "public, max-age=31536000, immutable"
	}
	return "no-cache"
}

// file returns the content of a regular file; a directory, a missing name and an invalid name are all "no".
func (h handler) file(name string) ([]byte, bool) {
	if !fs.ValidPath(name) {
		return nil, false
	}
	fi, err := fs.Stat(h.fsys, name)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	b, err := fs.ReadFile(h.fsys, name)
	return b, err == nil
}

func (handler) serve(w http.ResponseWriter, r *http.Request, name string, body []byte, cache string) {
	w.Header().Set("Cache-Control", cache)
	if path.Ext(name) == ".html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body)) // GET and HEAD, ranges; no body on HEAD
}
