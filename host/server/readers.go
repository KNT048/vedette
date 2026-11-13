package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/knt048/vedette/host/api"
)

// ReadError is what a Readers function returns to answer with a specific status and code
// (spec section 11): 404 for an id the host does not know, 403 for a file that must not leave the box, 409 for a state
// that is changing right now (read it again later).
type ReadError struct {
	Status  int
	Code    string
	Message string
}

func (e *ReadError) Error() string { return "read refused: " + e.Code }

// NewReadError builds a ReadError. Programming error (panic) for a status outside 403, 404 and 409 or a bad code.
func NewReadError(status int, code, message string) *ReadError {
	if (status != http.StatusNotFound && status != http.StatusForbidden && status != http.StatusConflict) || !codeRE.MatchString(code) {
		panic(fmt.Sprintf("host: bad read error %d %q", status, code))
	}
	return &ReadError{Status: status, Code: code, Message: message}
}

// File is a download: the host opens it and the server streams it. Name is the download name
// (plain, chosen by the host).
type File struct {
	Body io.ReadCloser
	Size int64
	Name string
	Type string // media type, for example application/gzip
}

// Readers are the read-only state endpoints of spec section 5 that the system commands provide.
// A nil function means the endpoint does not exist yet and answers 404 unknown_command, like any
// other path outside the spec. Each function must only read.
type Readers struct {
	OS            func(ctx context.Context) (any, error) // GET /v1/state/os
	Backups       func(ctx context.Context) (any, error) // GET /v1/state/backups
	Net           func(ctx context.Context) (any, error) // GET /v1/state/net (WP-07b part 3, slice 3-3)
	Containers    func(ctx context.Context) (any, error) // GET /v1/state/containers (slice 3-6)
	Host          func(ctx context.Context) (any, error) // GET /v1/state/host (host.self_update, D-316)
	Packages      func(ctx context.Context) (any, error) // GET /v1/state/packages (the box's dpkg list, D-470)
	HPTouches     func(ctx context.Context) (any, error) // GET /v1/state/hp-touches (new connection attempts to the decoys, D-466 M2)
	BackupContent func(id string) (File, error)          // GET /v1/backups/{id}/content
	ExportContent func(id string) (File, error)          // GET /v1/exports/{id}/content
}

var hexIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// serveRead answers one state endpoint.
func (s *Server) serveRead(w http.ResponseWriter, r *http.Request, kind routeKind, arg string) {
	rd := s.o.Readers
	rc := http.NewResponseController(w)
	switch kind {
	case routeStateOS:
		s.serveState(w, r, rd.OS)
	case routeStateBackups:
		s.serveState(w, r, rd.Backups)
	case routeStateNet:
		s.serveState(w, r, rd.Net)
	case routeStateContainers:
		s.serveState(w, r, rd.Containers)
	case routeStateHost:
		s.serveState(w, r, rd.Host)
	case routeStatePackages:
		s.serveState(w, r, rd.Packages)
	case routeStateHPTouches:
		s.serveState(w, r, rd.HPTouches)
	case routeBackupContent:
		s.serveFile(w, rc, rd.BackupContent, arg)
	case routeExportContent:
		s.serveFile(w, rc, rd.ExportContent, arg)
	case routeNone, routeInfo, routeRuns, routeRun, routeEvents, routeAudit, routeCommand:
		// not a state route
	}
}

func (s *Server) serveState(w http.ResponseWriter, r *http.Request, fn func(context.Context) (any, error)) {
	if d := onlyParams(r.URL.Query()); d != nil {
		badQuery(w, d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	v, err := fn(ctx)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) readFailed(w http.ResponseWriter, r *http.Request, err error) {
	var re *ReadError
	if errors.As(err, &re) {
		writeError(w, re.Status, simpleError(re.Code, re.Message))
		return
	}
	s.log.ErrorContext(r.Context(), "state read failed", "error", err.Error())
	writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not read that state."))
}

// downloadWindow bounds one file transfer (a 256 MiB export over a unix socket takes seconds).
const downloadWindow = 5 * time.Minute

func (s *Server) serveFile(w http.ResponseWriter, rc *http.ResponseController, fn func(string) (File, error), id string) {
	if !hexIDRE.MatchString(id) {
		writeError(w, http.StatusNotFound, simpleError("not_found", "There is no such file."))
		return
	}
	f, err := fn(id)
	if err != nil {
		var re *ReadError
		if errors.As(err, &re) {
			writeError(w, re.Status, simpleError(re.Code, re.Message))
			return
		}
		s.log.Error("file read failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not read that file."))
		return
	}
	defer func() { _ = f.Body.Close() }()
	_ = rc.SetWriteDeadline(time.Now().Add(downloadWindow))
	h := w.Header()
	h.Set("Content-Type", f.Type)
	h.Set("Content-Length", strconv.FormatInt(f.Size, 10))
	h.Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, io.LimitReader(f.Body, f.Size)); err != nil {
		s.log.Warn("file download interrupted")
	}
}

// Note appends one host-originated line to the audit chain: something the host did on its own
// (a scheduled reboot, noticing that a reboot finished), not a request. Actor is "system", the
// result "ok", and detail (small, no secrets) goes to args_redacted. It fails when the chain is broken.
func (s *Server) Note(command, code string, detail map[string]any) error {
	return noteTo(s.audit, command, code, detail)
}

// NoteWriter appends host-originated lines to the audit chain without a running server: the bootstrap
// (D-142) writes release_index_stored and installed lines to the same file and chain the daemon uses.
type NoteWriter struct{ a *auditLog }

// OpenNoteWriter opens (creating it 0600) and verifies the audit log at path, owned by ownerUID.
func OpenNoteWriter(path string, ownerUID int) (*NoteWriter, error) {
	if err := ensureDir(filepath.Dir(path), ownerUID); err != nil {
		return nil, err
	}
	a, err := openAudit(path, ownerUID, time.Now)
	if err != nil {
		return nil, err
	}
	return &NoteWriter{a: a}, nil
}

// Note is Server.Note.
func (w *NoteWriter) Note(command, code string, detail map[string]any) error {
	return noteTo(w.a, command, code, detail)
}

// Close closes the file.
func (w *NoteWriter) Close() error { return w.a.close() }

func noteTo(a *auditLog, command, code string, detail map[string]any) error {
	id, err := newID("au_")
	if err != nil {
		return err
	}
	if detail == nil {
		detail = map[string]any{}
	}
	return a.append(auditEntry{
		ID: id, Actor: "system", Command: command, ArgsDigest: digestRaw(nil),
		ArgsRedacted: redactArgs(mustMarshal(detail)), Result: resultOK, Code: code,
	})
}

// WriteActive reports whether a write command holds the global write lock right now (a run that
// awaits confirmation holds it too).
func (s *Server) WriteActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active != "" || s.inflight != ""
}

// AwaitingConfirm reports whether a run is parked in awaiting_confirm (D-100). ops uses it as the
// network-change-pending check of os.reboot.
func (s *Server) AwaitingConfirm() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiting != nil
}

// ErrWriteBusy is what WithWriteLock answers while a write command, or a run awaiting
// confirmation, holds the global write lock.
var ErrWriteBusy = errors.New("host: another write command is running")

// WithWriteLock runs fn holding the global write lock, the way a command does (INV-3: never two
// writes at once): a command that arrives meanwhile gets 409 busy. It does not wait: when the lock
// is taken it returns ErrWriteBusy and the caller tries again later. It exists for the work the host
// does on its own after it is ready (the post-READY step of ops, D-123), which has no request.
func (s *Server) WithWriteLock(ctx context.Context, fn func(ctx context.Context)) error {
	id, err := newID("sys_")
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.active != "" || s.inflight != "" || s.waiting != nil || s.baseCtx.Err() != nil {
		s.mu.Unlock()
		return ErrWriteBusy
	}
	s.active = id
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.releaseLocked(id)
		s.mu.Unlock()
	}()
	fn(ctx)
	return nil
}
