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

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fs.String("dir", "", "folder of blobs named by sha256 hex")
	listen := fs.String("listen", "127.0.0.1:5000", "address (loopback only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || *dir == "" {
		return errors.New("serve: -dir and -listen host:port are required")
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("serve: -listen must be a loopback address")
	}
	srv := &http.Server{Addr: *listen, Handler: registryHandler(*dir), ReadHeaderTimeout: 10 * time.Second}
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
