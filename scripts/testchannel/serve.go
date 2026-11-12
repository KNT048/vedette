package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// A read-only registry for the blobs of a test release: manifests and blobs by digest, nothing else. The repository
// name in the path is ignored (there is one release in the folder); a tag is refused (the host pulls by digest).
var blobPath = regexp.MustCompile(`^/v2/[a-z0-9][a-z0-9/._-]*/(manifests|blobs)/sha256:([0-9a-f]{64})$`)

func registryHandler(dir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		if r.URL.Path == "/v2/" {
			_, _ = w.Write([]byte("{}"))
			return
		}
		m := blobPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(filepath.Join(dir, m[2])) //nolint:gosec // m[2] is 64 lower-case hex, nothing else gets here
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		ctype := "application/octet-stream"
		if m[1] == "manifests" {
			ctype = manifestType(f)
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Docker-Content-Digest", "sha256:"+m[2])
		http.ServeContent(w, r, "", time.Time{}, f)
	})
	return mux
}

// manifestType is the mediaType the manifest itself declares (OCI and Docker manifests both carry one).
func manifestType(f *os.File) string {
	var head struct {
		MediaType string `json:"mediaType"`
	}
	err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&head)
	_, _ = f.Seek(0, io.SeekStart)
	if err == nil && head.MediaType != "" {
		return head.MediaType
	}
	return "application/vnd.oci.image.manifest.v1+json"
}

// releasePath is the layout core reads a release from (core.DefaultReleaseBase): /release/index/<index document> and
// /release/v<version>/<manifest document or host package>, served from the one flat folder install-artifacts makes.
// Only a -test. version, only those file names. The documents are signed: this server is not trusted, core and the host verify.
var releasePath = regexp.MustCompile(`^/release/(index|v[0-9]+\.[0-9]+\.[0-9]+-test\.[0-9A-Za-z.-]{1,24})/(index\.json(?:\.minisig)?|release-manifest\.json(?:\.minisig)?|vedette-host_[0-9A-Za-z.-]+_(?:amd64|arm64)\.deb)$`)

func releaseHandler(dir string, next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v2/", next)
	mux.HandleFunc("/release/", func(w http.ResponseWriter, r *http.Request) {
		m := releasePath.FindStringSubmatch(r.URL.Path)
		if m == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.NotFound(w, r)
			return
		}
		if (m[1] == "index") != strings.HasPrefix(m[2], "index.json") {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(filepath.Join(dir, m[2])) //nolint:gosec // m[2] is one of the file names the pattern allows, no separator
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }()
		if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "", time.Time{}, f)
	})
	return mux
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fs.String("dir", "", "folder of blobs named by sha256 hex")
	listen := fs.String("listen", "127.0.0.1:5000", "address (loopback only; with -releases also a private LAN address)")
	releases := fs.String("releases", "", "folder made by install-artifacts: also serve its release documents and host package under /release/ (the update source of a test box, #469)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || *dir == "" {
		return errors.New("serve: -dir and -listen host:port are required")
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsLoopback() && (*releases == "" || !ip.IsPrivate())) {
		return errors.New("serve: -listen must be a loopback address (with -releases: or a private one, for the containers' bridge)")
	}
	handler := registryHandler(*dir)
	if *releases != "" {
		handler = releaseHandler(*releases, handler)
	}
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
