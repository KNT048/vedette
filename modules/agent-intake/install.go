package agentintake

import (
	"context"
	_ "embed" // the two install script templates
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
)

// OsqueryVersion is the osquery release the box ships and the scripts install. It equals OSQUERY_VERSION of
// web/src/features/inventory/installScripts.ts and OSQUERY_VERSION of deploy/osquery/PINS (TestInstall_VersionsAgree).
const OsqueryVersion = "5.12.1"

// The install scripts are the templates of the GUI (web/src/features/inventory/scripts/), copied here because go:embed cannot reach
// ../web; TestInstall_ScriptsEqualTheGUI fails when the copy and the GUI differ after the placeholders are filled.
//
//go:embed scripts/osquery.sh
var scriptSh string

//go:embed scripts/osquery.ps1
var scriptPs1 string

// ErrNoTrustAnchor is what Config.TrustAnchor returns when the box has no certificate (plain HTTP on loopback): there is nothing for
// osquery to pin, so the scripts and ca.pem are not served.
var ErrNoTrustAnchor = errors.New("agentintake: this box has no certificate to pin")

// fill puts the box address, the osquery version and the certificate into a template, in the order and with the trimming of the GUI's `fill`.
func fill(tpl, box string, ca []byte) string {
	s := strings.ReplaceAll(tpl, "@@BOX@@", box)
	s = strings.ReplaceAll(s, "@@VERSION@@", OsqueryVersion)
	return strings.ReplaceAll(s, "@@CA@@", strings.TrimSpace(string(ca)))
}

// caPlaceholder stands in the scripts shown by GET /inventory/agents when the box has no certificate; the scripts themselves are not
// served then.
const caPlaceholder = "-----BEGIN CERTIFICATE-----\n(this box has no certificate: it serves plain HTTP on loopback)\n-----END CERTIFICATE-----"

// boxPlaceholder is the address shown when the box does not know its own (CONTRACT PRE-3): never guessed.
const boxPlaceholder = "https://<VEDETTE_BOX_IP>:8443"

var (
	hostNameRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	authorityRE = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,260}$`) // what a configured box address may hold: nothing a shell or a PowerShell string would read
)

// boxURL is the address the scripts and the one-liners carry. It is one of: the request's Host when the server's allow-list lets it in
// (the same list that already let the request through; a loopback name or address never counts, a server cannot reach it), else the
// configured box address, else the placeholder. A Host is never copied as sent: it is rebuilt from a validated name or IP and a numeric
// port, so nothing that is not a host name or an address can reach a script (round 1 of the review: an arbitrary Host header must never be
// reflected).
func (s *Service) boxURL(host string) string {
	if u := s.hostURL(host); u != "" {
		return u
	}
	if u, ok := strings.CutPrefix(s.cfg.BoxURL, "https://"); ok && authorityRE.MatchString(u) {
		return s.cfg.BoxURL
	}
	return boxPlaceholder
}

func (s *Service) hostURL(host string) string {
	if s.cfg.HostAllowed == nil || !s.cfg.HostAllowed(host) {
		return ""
	}
	h, port := host, ""
	if hh, p, err := net.SplitHostPort(host); err == nil {
		h, port = hh, p
	}
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")), ".")
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return ""
		}
	}
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		if a.Zone() != "" || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			return ""
		}
		h = a.String()
		if a.Is6() {
			h = "[" + h + "]"
		}
	} else if h == "localhost" || !hostNameRE.MatchString(h) {
		return ""
	}
	if port != "" {
		h += ":" + port
	}
	return "https://" + h
}

func (s *Service) anchor() ([]byte, error) {
	if s.cfg.TrustAnchor == nil {
		return nil, ErrNoTrustAnchor
	}
	return s.cfg.TrustAnchor()
}

func noCertificate() *apierr.Error {
	return apierr.New(404, "no_certificate", "This box serves plain HTTP on loopback, so it has no certificate for osquery to trust. Open Vedette at its network address.")
}

// installFor renders both scripts for a request: the box address of its Host and the pinned certificate (the placeholder when there is none,
// for the admin's view only).
func (s *Service) installFor(host string, withPlaceholder bool) (sh, ps1 string, err error) {
	ca, err := s.anchor()
	switch {
	case errors.Is(err, ErrNoTrustAnchor) && withPlaceholder:
		ca = []byte(caPlaceholder)
	case err != nil:
		return "", "", err
	}
	box := s.boxURL(host)
	return fill(scriptSh, box, ca), fill(scriptPs1, box, ca), nil
}

// InstallHandlers are the public file operations of the module: the two install scripts, the certificate and the package mirror. Nothing here
// holds a secret (INV-5); the server answers 404 for all of them while the module is off (SYS-5).
type InstallHandlers struct{ s *Service }

// NewInstallHandlers wraps the service; nil gives 501 for every operation, like a module that is not wired.
func NewInstallHandlers(s *Service) *InstallHandlers { return &InstallHandlers{s: s} }

// text sends a small file: its length and type, and how long a cache may keep it.
func text(ctx context.Context, body, contentType, cacheControl string) (io.Reader, error) {
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	h := x.W.Header()
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", cacheControl)
	x.SetContentType(contentType)
	return strings.NewReader(body), nil
}

// The scripts are never cached: they carry the address the request came in at, and the SHA-256 the admin read in the GUI is of these bytes.
const noCache = "no-cache"

// InventoryGetInstallOsquerySh implements GET /install/osquery.sh.
func (h *InstallHandlers) InventoryGetInstallOsquerySh(ctx context.Context) (oas.InventoryGetInstallOsqueryShOK, error) {
	if h.s == nil {
		return oas.InventoryGetInstallOsqueryShOK{}, apierr.NotImplemented()
	}
	r, err := h.script(ctx, false, "text/x-shellscript; charset=utf-8")
	return oas.InventoryGetInstallOsqueryShOK{Data: r}, err
}

// InventoryGetInstallOsqueryPs1 implements GET /install/osquery.ps1.
func (h *InstallHandlers) InventoryGetInstallOsqueryPs1(ctx context.Context) (oas.InventoryGetInstallOsqueryPs1OK, error) {
	if h.s == nil {
		return oas.InventoryGetInstallOsqueryPs1OK{}, apierr.NotImplemented()
	}
	r, err := h.script(ctx, true, "text/plain; charset=utf-8")
	return oas.InventoryGetInstallOsqueryPs1OK{Data: r}, err
}

func (h *InstallHandlers) script(ctx context.Context, windows bool, contentType string) (io.Reader, error) {
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	sh, ps1, err := h.s.installFor(x.R.Host, false)
	if errors.Is(err, ErrNoTrustAnchor) {
		return nil, noCertificate()
	}
	if err != nil {
		return nil, fmt.Errorf("agentintake: the box certificate: %w", err)
	}
	body := sh
	if windows {
		body = ps1
	}
	return text(ctx, body, contentType, noCache)
}

// InventoryGetIntakeCaPem implements GET /intake/ca.pem: the box CA (or the chain the owner supplied), public. A cache may keep it for an
// hour; it changes only when the box's certificate is replaced.
func (h *InstallHandlers) InventoryGetIntakeCaPem(ctx context.Context) (oas.InventoryGetIntakeCaPemOK, error) {
	if h.s == nil {
		return oas.InventoryGetIntakeCaPemOK{}, apierr.NotImplemented()
	}
	ca, err := h.s.anchor()
	if errors.Is(err, ErrNoTrustAnchor) {
		return oas.InventoryGetIntakeCaPemOK{}, noCertificate()
	}
	if err != nil {
		return oas.InventoryGetIntakeCaPemOK{}, fmt.Errorf("agentintake: the box certificate: %w", err)
	}
	r, err := text(ctx, string(ca), "application/x-pem-file", "public, max-age=3600")
	return oas.InventoryGetIntakeCaPemOK{Data: r}, err
}

// ---- the package mirror ----

// The package files of the image (WP-26 slice 3, D-169 (10)): exactly these four names exist, whatever the request says. They are fixed
// text built from OsqueryVersion; a request's name is only a key into this table, and what is opened is the name stored in it.
const (
	mirrorSums         = "SHA256SUMS"
	maxMirrorDownloads = 4                // at most this many downloads at once (the packages are 20 to 30 MB each)
	mirrorRetryAfter   = 5 * time.Second  // what a refused download is told
	mirrorChunkWait    = 30 * time.Second // a client that takes no data for this long is cut
	mirrorMaxTime      = 10 * time.Minute // and none keeps a slot longer than this
)

type mirrorFile struct{ name, contentType string }

var mirrorFiles = func() map[string]mirrorFile {
	m := map[string]mirrorFile{}
	for _, f := range []mirrorFile{
		{"osquery_" + OsqueryVersion + "-1.linux_amd64.deb", "application/octet-stream"},
		{"osquery-" + OsqueryVersion + "-1.linux.x86_64.rpm", "application/octet-stream"},
		{"osquery-" + OsqueryVersion + ".msi", "application/octet-stream"},
		{mirrorSums, "text/plain; charset=utf-8"},
	} {
		m[f.name] = f
	}
	return m
}()

// InventoryGetInstallOsqueryFile implements GET /install/osquery/{file}: one of the four files of the image, streamed with its length.
func (h *InstallHandlers) InventoryGetInstallOsqueryFile(ctx context.Context, params oas.InventoryGetInstallOsqueryFileParams) (oas.InventoryGetInstallOsqueryFileOK, error) {
	none := oas.InventoryGetInstallOsqueryFileOK{}
	if h.s == nil {
		return none, apierr.NotImplemented()
	}
	f, ok := mirrorFiles[params.File] // the only use of the request's text: a key
	if !ok {
		return none, apierr.NotFound()
	}
	x, err := exchange(ctx)
	if err != nil {
		return none, err
	}
	s := h.s
	select {
	case s.mirror <- struct{}{}:
	default:
		return none, rateLimited(mirrorRetryAfter)
	}
	release := func() { <-s.mirror }
	file, size, err := s.openMirror(ctx, f.name)
	if err != nil {
		release()
		return none, err
	}
	hd := x.W.Header()
	hd.Set("Content-Length", strconv.FormatInt(size, 10))
	hd.Set("Cache-Control", "public, max-age=3600")
	x.SetContentType(f.contentType)
	return oas.InventoryGetInstallOsqueryFileOK{Data: &mirrorBody{f: file, rc: http.NewResponseController(x.W), start: time.Now(), release: release}}, nil
}

func missingMirror() *apierr.Error {
	return apierr.New(404, "mirror_missing", "This box has no copy of the osquery packages (a development build, or an install without them). Update Vedette to the release, or install osquery with the manual steps.")
}

// openMirror opens the named file of the mirror folder inside the folder only (os.Root refuses a name that leaves it, a link included) and
// answers with the file and its size. Whatever stops that (no folder, no such file, a link out of the folder, something that is not a regular
// file, no permission) is 404 mirror_missing, with the reason in a log line for the admin.
func (s *Service) openMirror(ctx context.Context, name string) (*os.File, int64, error) {
	if s.cfg.MirrorDir == "" {
		s.cfg.Log.WarnContext(ctx, "agent-intake: no osquery package folder is configured; the mirror answers 404", "file", name)
		return nil, 0, missingMirror()
	}
	f, size, err := openIn(s.cfg.MirrorDir, name)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "agent-intake: the osquery package is not in the folder; the mirror answers 404", "file", name, "dir", s.cfg.MirrorDir, "error", err)
		return nil, 0, missingMirror()
	}
	return f, size, nil
}

// openIn opens name inside dir (os.Root refuses a name or a link that leaves it) and checks it is a regular file.
func openIn(dir, name string) (*os.File, int64, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("open folder: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		return nil, 0, fmt.Errorf("open file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, errors.Join(err, errors.New("not a regular file"))
	}
	return f, fi.Size(), nil
}

// mirrorBody is the response body of a package: the file, a write deadline for each chunk (a client that stops reading cannot hold one of
// the four slots, and none holds it past mirrorMaxTime), and the slot given back on Close, which the generated encoder calls when the copy ends.
type mirrorBody struct {
	f       *os.File
	rc      *http.ResponseController
	start   time.Time
	release func()
	closed  atomic.Bool
}

func (b *mirrorBody) Read(p []byte) (int, error) {
	d := time.Now().Add(mirrorChunkWait)
	if end := b.start.Add(mirrorMaxTime); end.Before(d) {
		d = end
	}
	_ = b.rc.SetWriteDeadline(d) // not every writer supports it: then there is no deadline
	return b.f.Read(p)           //nolint:wrapcheck // the file's own error (io.EOF ends the copy)
}

// Close closes the file and gives the slot back; twice is harmless.
func (b *mirrorBody) Close() error {
	if b.closed.CompareAndSwap(false, true) {
		defer b.release()
	}
	return b.f.Close() //nolint:wrapcheck // the file's own error
}
