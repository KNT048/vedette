package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/peer"
)

type routeKind int

const (
	routeNone routeKind = iota
	routeInfo
	routeRuns
	routeRun
	routeEvents
	routeAudit
	routeCommand
)

// route maps method and path to a handler kind; anything else is not part of the API (spec section 7).
func route(method, path string) (kind routeKind, arg string) {
	switch {
	case method == http.MethodGet && path == "/v1/info":
		return routeInfo, ""
	case method == http.MethodGet && path == "/v1/runs":
		return routeRuns, ""
	case method == http.MethodGet && path == "/v1/audit":
		return routeAudit, ""
	case method == http.MethodGet && strings.HasPrefix(path, "/v1/runs/"):
		rest := strings.TrimPrefix(path, "/v1/runs/")
		if id, ok := strings.CutSuffix(rest, "/events"); ok && !strings.Contains(id, "/") {
			return routeEvents, id
		}
		if !strings.Contains(rest, "/") {
			return routeRun, rest
		}
	case method == http.MethodPost && strings.HasPrefix(path, "/v1/commands/"):
		if name := strings.TrimPrefix(path, "/v1/commands/"); !strings.Contains(name, "/") {
			return routeCommand, name
		}
	}
	return routeNone, ""
}

var safeNameRE = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// safeCommandName is what an unknown command name is recorded as: the name when it is plain, else a marker.
func safeCommandName(name string) string {
	if safeNameRE.MatchString(name) {
		return name
	}
	return "(invalid)"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, ei api.ErrorInfo) {
	writeJSON(w, status, api.ErrorBody{Error: ei})
}

func simpleError(code, message string) api.ErrorInfo {
	return api.ErrorInfo{Code: code, Message: message}
}

// ServeHTTP is the whole API. The connection was authenticated at accept time.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	p, ok := peerFrom(r.Context())
	if !ok { // defence in depth: every connection comes through authListener
		writeError(w, http.StatusForbidden, simpleError(api.CodePeerNotAllowed, "The caller is not allowed."))
		return
	}
	if s.draining.Load() {
		writeError(w, http.StatusServiceUnavailable, simpleError(api.CodeShuttingDown, "The host is shutting down."))
		return
	}
	kind, arg := route(r.Method, r.URL.Path)
	if kind == routeNone {
		writeError(w, http.StatusNotFound, simpleError(api.CodeUnknownCommand, "There is no such endpoint or command."))
		return
	}
	if ok, wait := s.reqLim.allow(s.now()); !ok {
		s.rateLimited(w, p, kind, arg, wait)
		return
	}
	if kind == routeCommand {
		s.handleCommand(w, r, p, arg)
		return
	}
	if d := checkProto(r); len(d) > 0 {
		writeError(w, http.StatusBadRequest, api.ErrorInfo{Code: api.CodeInvalidArgs, Message: "Invalid request headers.", Details: d})
		return
	}
	rc := http.NewResponseController(w)
	if kind != routeEvents {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	switch kind {
	case routeInfo:
		s.handleInfo(w)
	case routeRuns:
		s.handleRuns(w, r)
	case routeRun:
		s.handleRun(w, arg)
	case routeEvents:
		s.handleEvents(w, r, arg)
	case routeAudit:
		s.handleAudit(w, r)
	case routeNone, routeCommand:
		// handled above
	}
}

func (s *Server) rateLimited(w http.ResponseWriter, p peer.Info, kind routeKind, arg string, wait time.Duration) {
	secs := max(1, int((wait+time.Second-1)/time.Second))
	command := "-"
	if kind == routeCommand {
		command = safeCommandName(arg)
	}
	s.auditThrottled("rate_limited", auditEntry{
		Peer: p, Actor: "-", Command: command, Result: resultRefused, Code: api.CodeRateLimited,
	})
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, api.ErrorInfo{Code: api.CodeRateLimited, Message: "Too many requests; slow down.", RetryAfterS: secs})
}

// auditThrottled writes a line for traffic anyone can generate, at most one per interval per key.
func (s *Server) auditThrottled(key string, e auditEntry) {
	ok, skipped := s.throttle.allow(key, s.now())
	if !ok {
		return
	}
	id, err := newID("au_")
	if err != nil {
		return
	}
	e.ID = id
	e.ArgsRedacted = map[string]any{"skipped": skipped}
	if err := s.audit.append(e); err != nil {
		s.log.Error("could not write an audit line", "code", e.Code)
	}
}

func checkProto(r *http.Request) []api.Detail {
	v := r.Header.Get(api.HeaderProto)
	n, err := strconv.Atoi(v)
	if v == "" || err != nil || n < api.MinProto || n > api.Proto {
		return []api.Detail{{Field: api.HeaderProto, Reason: fmt.Sprintf("must be %d..%d", api.MinProto, api.Proto)}}
	}
	return nil
}

// cmdHeaders are the validated headers of a command request.
type cmdHeaders struct {
	requestID string
	actor     string
}

// parseCommandHeaders validates proto, content type, actor and request id (spec section 3).
func parseCommandHeaders(r *http.Request) (cmdHeaders, string, []api.Detail) {
	var h cmdHeaders
	code := api.CodeInvalidArgs
	var details []api.Detail
	details = append(details, checkProto(r)...)
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		details = append(details, api.Detail{Field: "Content-Type", Reason: "must be application/json"})
	}
	actor := r.Header.Get(api.HeaderActor)
	if !actorRE.MatchString(actor) {
		details = append(details, api.Detail{Field: api.HeaderActor, Reason: "must match " + actorRE.String()})
		if len(details) == 1 {
			code = api.CodeInvalidActor
		}
	} else {
		h.actor = actor
	}
	rid := strings.ToLower(r.Header.Get(api.HeaderRequestID))
	if !reqIDRE.MatchString(rid) {
		details = append(details, api.Detail{Field: api.HeaderRequestID, Reason: "must be a UUID v4"})
		if len(details) == 1 {
			code = api.CodeInvalidRequestID
		}
	} else {
		h.requestID = rid
	}
	return h, code, details
}

// submission is what is known about a command request when it is recorded.
type submission struct {
	p         peer.Info
	actor     string
	requestID string
	command   string
	digest    string
	redacted  any
	write     bool
}

// handleCommand is POST /v1/commands/{name}: headers, lookup, body, idempotency, lock, run.
func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request, p peer.Info, name string) {
	if err := s.audit.brokenErr(); err != nil {
		writeError(w, http.StatusServiceUnavailable, simpleError(api.CodeAuditUnavailable, "The audit log is unavailable, so the host refuses to run commands."))
		return
	}
	hdr, code, details := parseCommandHeaders(r)
	if len(details) > 0 {
		s.auditOnly(p, safeCommandName(name), code)
		writeError(w, http.StatusBadRequest, api.ErrorInfo{Code: code, Message: "Invalid request headers.", Details: details})
		return
	}
	sub := submission{p: p, actor: hdr.actor, requestID: hdr.requestID, command: safeCommandName(name)}

	cmd, found := s.reg.Lookup(name)
	if !found {
		sub.digest = digestRaw(nil)
		s.refuse(w, sub, http.StatusNotFound, simpleError(api.CodeUnknownCommand, "There is no such command."))
		return
	}
	sub.write = cmd.write
	if cmd.write {
		if ok, wait := s.writeLim.allow(s.now()); !ok {
			secs := max(1, int((wait+time.Second-1)/time.Second))
			s.auditThrottled("rate_limited", auditEntry{
				Peer: p, Actor: sub.actor, RequestID: sub.requestID, Command: sub.command, Result: resultRefused, Code: api.CodeRateLimited,
			})
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeError(w, http.StatusTooManyRequests, api.ErrorInfo{Code: api.CodeRateLimited, Message: "Too many write commands; slow down.", RetryAfterS: secs})
			return
		}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		reason := "the body could not be read"
		if errors.As(err, &tooBig) {
			reason = fmt.Sprintf("the body is larger than %d KiB", maxBodyBytes>>10)
		}
		sub.digest = digestRaw(nil)
		s.refuse(w, sub, http.StatusBadRequest, api.ErrorInfo{Code: api.CodeInvalidArgs, Message: "The request body is not acceptable.", Details: []api.Detail{{Field: "body", Reason: reason}}})
		return
	}
	var req api.CommandRequest
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		derr := dec.Decode(&req)
		if derr == nil {
			if _, e := dec.Token(); !errors.Is(e, io.EOF) {
				derr = errors.New("trailing data")
			}
		}
		if derr != nil {
			sub.digest = digestRaw(body)
			s.refuse(w, sub, http.StatusBadRequest, api.ErrorInfo{Code: api.CodeInvalidArgs, Message: "The request body is not valid.", Details: []api.Detail{{Field: "body", Reason: "must be {\"args\": {...}} with no other fields"}}})
			return
		}
	}
	sub.redacted = redactArgs(req.Args)
	args, derr := cmd.decode(req.Args)
	if derr != nil {
		sub.digest = digestRaw(req.Args)
		var ae *ArgsError
		if !errors.As(derr, &ae) {
			ae = &ArgsError{Details: []api.Detail{{Field: "args", Reason: "invalid"}}}
		}
		s.refuse(w, sub, http.StatusBadRequest, api.ErrorInfo{Code: api.CodeInvalidArgs, Message: "The command arguments are not valid.", Details: ae.Details})
		return
	}
	if sub.digest, err = digestArgs(args); err != nil {
		s.log.ErrorContext(r.Context(), "could not digest args", "command", sub.command)
		writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not process the request."))
		return
	}
	s.submit(w, sub, cmd, args) //nolint:contextcheck // the run outlives the request: it runs under the server context, cancelled by Shutdown
}

// submit takes the write lock (or answers busy / a replay) and starts the run.
func (s *Server) submit(w http.ResponseWriter, sub submission, cmd Command, args any) {
	runID, err1 := newID("rn_")
	auditID, err2 := newID("au_")
	if err := errors.Join(err1, err2); err != nil {
		writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not process the request."))
		return
	}
	now := s.now().UTC()
	run := api.Run{RunID: runID, Command: sub.command, Status: api.StatusQueued, StartedAt: now, Actor: sub.actor, RequestID: sub.requestID, AuditID: auditID}

	s.mu.Lock()
	if rec, ok := s.runs.idemGet(sub.requestID); ok { // a request id is bound to one command and args, writes and reads alike
		s.mu.Unlock()
		if rec.Command != sub.command || rec.ArgsDigest != sub.digest {
			s.refuse(w, sub, http.StatusUnprocessableEntity, simpleError(api.CodeRequestIDReuse, "This request id was already used for a different command or arguments."))
			return
		}
		if prior, ok := s.runs.get(rec.RunID); ok {
			writeJSON(w, http.StatusOK, prior)
			return
		}
		s.refuse(w, sub, http.StatusUnprocessableEntity, simpleError(api.CodeRequestIDReuse, "This request id was already used and its run is gone."))
		return
	}
	if cmd.write {
		if s.active != "" {
			busy := s.active
			s.mu.Unlock()
			s.refuse(w, sub, http.StatusConflict, api.ErrorInfo{Code: api.CodeBusy, Message: "Another write command is already running.", RunID: busy})
			return
		}
		s.active = runID
		if err := s.runs.put(storedRun{Run: run, ArgsDigest: sub.digest, Write: true}); err != nil {
			s.active = ""
			s.mu.Unlock()
			s.log.Error("could not record a run", "command", sub.command)
			writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not record the request."))
			return
		}
		if err := s.runs.idemPut(idemRecord{RequestID: sub.requestID, Command: sub.command, ArgsDigest: sub.digest, RunID: runID, At: now}); err != nil {
			s.active = ""
			s.mu.Unlock()
			s.log.Error("could not record an idempotency key", "command", sub.command)
			writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not record the request."))
			return
		}
		s.mu.Unlock()
	} else {
		s.mu.Unlock()
		if err := s.runs.put(storedRun{Run: run, ArgsDigest: sub.digest}); err != nil {
			writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not record the request."))
			return
		}
	}

	lr := &liveRun{sr: storedRun{Run: run, ArgsDigest: sub.digest, Write: cmd.write}, sub: sub, ev: newEventLog(s.now)}
	s.mu.Lock()
	s.live[runID] = lr.ev
	s.mu.Unlock()

	if cmd.check != nil {
		ctx, cancel := context.WithTimeout(s.baseCtx, checkTimeout)
		cerr := cmd.check(ctx, args)
		cancel()
		if cerr != nil {
			s.finishCheck(w, lr, cerr)
			return
		}
	}
	lr.sr.Run.Status = api.StatusRunning
	if err := s.runs.put(lr.sr); err != nil {
		s.log.Error("could not record a run start", "run_id", runID)
		lr.finish(s, api.StatusFailed, nil, &api.RunError{Code: api.CodeInternal, Message: "The host could not record the run."})
		writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not record the request."))
		return
	}
	lr.ev.add(api.Event{Kind: api.KindState, Status: api.StatusRunning})
	snapshot := lr.sr.Run
	s.wg.Add(1)
	go s.execute(lr, cmd, args)
	writeJSON(w, http.StatusAccepted, snapshot)
}

// finishCheck ends a run whose synchronous precondition check refused or errored.
func (s *Server) finishCheck(w http.ResponseWriter, lr *liveRun, cerr error) {
	var ref *Refusal
	if errors.As(cerr, &ref) {
		if lr.sr.Write {
			s.runs.idemDelete(lr.sub.requestID) // a refused request may be retried with the same id
		}
		lr.finish(s, api.StatusRefused, nil, &api.RunError{Code: ref.Code, Message: ref.Message})
		writeError(w, ref.Status, simpleError(ref.Code, ref.Message))
		return
	}
	s.log.Error("command precondition check failed", "command", lr.sub.command, "error", cerr.Error())
	lr.finish(s, api.StatusFailed, nil, &api.RunError{Code: api.CodeCommandFailed, Message: "The command precondition check failed."})
	writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not check the command preconditions."))
}

// refuse records a refused run (run file, audit line) and answers with the error.
func (s *Server) refuse(w http.ResponseWriter, sub submission, status int, ei api.ErrorInfo) {
	runID, err1 := newID("rn_")
	auditID, err2 := newID("au_")
	if err := errors.Join(err1, err2); err != nil {
		writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not process the request."))
		return
	}
	now := s.now().UTC()
	run := api.Run{
		RunID: runID, Command: sub.command, Status: api.StatusRefused, StartedAt: now, FinishedAt: &now,
		Actor: sub.actor, RequestID: sub.requestID, Error: &api.RunError{Code: ei.Code, Message: ei.Message}, AuditID: auditID,
	}
	if err := s.audit.append(auditEntry{
		ID: auditID, RequestID: sub.requestID, Actor: sub.actor, Peer: sub.p, Command: sub.command,
		ArgsDigest: sub.digest, ArgsRedacted: sub.redacted, Result: resultRefused, Code: ei.Code, RunID: runID,
	}); err != nil {
		s.log.Error("could not audit a refusal", "code", ei.Code)
		writeError(w, http.StatusServiceUnavailable, simpleError(api.CodeAuditUnavailable, "The audit log is unavailable, so the host refuses to run commands."))
		return
	}
	if err := s.runs.put(storedRun{Run: run, ArgsDigest: sub.digest}); err != nil {
		s.log.Error("could not record a refused run", "run_id", runID)
	}
	s.runs.prune(now)
	writeError(w, status, ei)
}

// auditOnly records a refused request that could not become a run (its headers are not trustworthy).
func (s *Server) auditOnly(p peer.Info, command, code string) {
	id, err := newID("au_")
	if err != nil {
		return
	}
	if err := s.audit.append(auditEntry{
		ID: id, Actor: "-", Peer: p, Command: command, ArgsDigest: digestRaw(nil),
		ArgsRedacted: map[string]any{}, Result: resultRefused, Code: code,
	}); err != nil {
		s.log.Error("could not audit a bad request", "code", code)
	}
}

// liveRun is a run in progress: its stored form, who asked, and its event stream.
type liveRun struct {
	sr  storedRun
	sub submission
	ev  *eventLog
}

// finish records the end of the run in the required order: audit line, run file, then the write
// lock is released, and only then the final state event ends the stream. A client that sees the
// final event therefore also sees the lock free and the final run.
func (lr *liveRun) finish(s *Server, status api.Status, result json.RawMessage, rerr *api.RunError) {
	var once sync.Once
	release := func() {
		once.Do(func() {
			if lr.sr.Write {
				s.mu.Lock()
				if s.active == lr.sr.Run.RunID {
					s.active = ""
				}
				s.mu.Unlock()
			}
		})
	}
	defer release()
	now := s.now().UTC()
	run := &lr.sr.Run
	run.Status, run.FinishedAt, run.Result, run.Error, run.RevertAt = status, &now, result, rerr, nil
	e := auditEntry{
		ID: run.AuditID, RequestID: run.RequestID, Actor: run.Actor, Peer: lr.sub.p, Command: run.Command,
		ArgsDigest: lr.sub.digest, ArgsRedacted: lr.sub.redacted, Result: auditResult(status), RunID: run.RunID,
	}
	if rerr != nil {
		e.Code = rerr.Code
	}
	if err := s.audit.append(e); err != nil {
		s.log.Error("could not audit a finished run", "run_id", run.RunID)
	}
	if err := s.runs.put(lr.sr); err != nil {
		s.log.Error("could not save a finished run", "run_id", run.RunID)
	}
	release()
	line := ""
	if rerr != nil {
		line = rerr.Message
	}
	lr.ev.add(api.Event{Kind: api.KindState, Status: status, Line: line})
	lr.ev.finish()
	if err := writeJSONAtomic(s.runs.eventsPath(run.RunID), lr.ev.snapshot()); err != nil {
		s.log.Error("could not save run events", "run_id", run.RunID)
	}
	s.mu.Lock()
	delete(s.live, run.RunID)
	s.mu.Unlock()
	s.runs.prune(now)
}

func auditResult(st api.Status) string {
	switch st {
	case api.StatusSucceeded:
		return resultOK
	case api.StatusReverted:
		return resultReverted
	case api.StatusRefused:
		return resultRefused
	case api.StatusQueued, api.StatusRunning, api.StatusAwaitingConfirm, api.StatusFailed:
		return resultFailed
	}
	return resultFailed
}

// execute runs the command with its timeout (POST-4). A handler that ignores cancellation does
// not hold the lock for ever: after KillGrace the run is failed and the lock released.
func (s *Server) execute(lr *liveRun, cmd Command, args any) {
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(s.baseCtx, cmd.timeout)
	defer cancel()
	rc := &RunContext{
		RunID: lr.sr.Run.RunID, Actor: lr.sr.Run.Actor,
		log:  func(line string) { lr.ev.add(api.Event{Kind: api.KindLog, Line: line}) },
		prog: func(pc int) { v := min(max(pc, 0), 100); lr.ev.add(api.Event{Kind: api.KindProgress, Percent: &v}) },
	}
	type outcome struct {
		res any
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("command panicked", "command", lr.sub.command, "panic", fmt.Sprint(rec))
				done <- outcome{err: errors.New("panic")}
			}
		}()
		res, err := cmd.run(ctx, rc, args)
		done <- outcome{res, err}
	}()
	var out outcome
	abandoned := false
	select {
	case out = <-done:
	case <-ctx.Done():
		grace := time.NewTimer(s.o.KillGrace)
		select {
		case out = <-done:
			grace.Stop()
		case <-grace.C:
			abandoned = true
		}
	}
	if abandoned {
		s.log.Error("command ignored cancellation; releasing the write lock", "command", lr.sub.command, "run_id", lr.sr.Run.RunID)
		out.err = context.Cause(ctx)
	}
	status, result, rerr := s.outcome(ctx, out.res, out.err, abandoned)
	lr.finish(s, status, result, rerr)
}

// outcome maps what a command returned to the final status. Error text never reaches the run.
func (s *Server) outcome(ctx context.Context, res any, err error, abandoned bool) (api.Status, json.RawMessage, *api.RunError) {
	var (
		ref  *Refusal
		fail *Failure
	)
	switch {
	case err == nil && !abandoned:
		if res == nil {
			return api.StatusSucceeded, nil, nil
		}
		b, merr := json.Marshal(res)
		if merr != nil || len(b) > maxResultBytes {
			s.log.ErrorContext(ctx, "command result could not be stored")
			return api.StatusFailed, nil, &api.RunError{Code: api.CodeCommandFailed, Message: "The command result could not be stored."}
		}
		return api.StatusSucceeded, b, nil
	case s.baseCtx.Err() != nil:
		return api.StatusFailed, nil, &api.RunError{Code: api.CodeShuttingDown, Message: "The host is shutting down."}
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return api.StatusFailed, nil, &api.RunError{Code: api.CodeTimeout, Message: "The command timed out."}
	case errors.As(err, &ref):
		return api.StatusRefused, nil, &api.RunError{Code: ref.Code, Message: ref.Message}
	case errors.As(err, &fail):
		return api.StatusFailed, nil, &api.RunError{Code: fail.Code, Message: fail.Message}
	}
	s.log.WarnContext(ctx, "command failed", "error", fmt.Sprint(err))
	return api.StatusFailed, nil, &api.RunError{Code: api.CodeCommandFailed, Message: "The command failed."}
}

func (s *Server) handleInfo(w http.ResponseWriter) {
	now := s.now().UTC()
	distro, release := readOSRelease(s.o.OSReleasePath)
	kernel, booted := systemInfo(now)
	writeJSON(w, http.StatusOK, api.Info{
		HostVersion: s.o.Version, Proto: api.Proto, Commands: s.reg.Names(), Runner: "podman",
		OS:   api.OSInfo{Distro: distro, Release: release, Kernel: kernel},
		Arch: runtime.GOARCH, BootedAt: booted, Time: now, AuditOK: s.audit.ok(),
	})
}

const (
	defaultListLimit = 50
	maxListLimit     = 500
)

// intParam reads an optional integer query parameter within [lo, hi].
func intParam(q url.Values, name string, def, lo, hi int64) (int64, *api.Detail) {
	v := q.Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo || n > hi {
		return 0, &api.Detail{Field: name, Reason: fmt.Sprintf("must be an integer from %d to %d", lo, hi)}
	}
	return n, nil
}

// onlyParams rejects query parameters outside the allowed set (strict, like the args).
func onlyParams(q url.Values, allowed ...string) *api.Detail {
	for k := range q {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return &api.Detail{Field: clip(k, 32), Reason: "unknown query parameter"}
		}
	}
	return nil
}

func badQuery(w http.ResponseWriter, d *api.Detail) {
	writeError(w, http.StatusBadRequest, api.ErrorInfo{Code: api.CodeInvalidArgs, Message: "Invalid query parameters.", Details: []api.Detail{*d}})
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if d := onlyParams(q, "limit"); d != nil {
		badQuery(w, d)
		return
	}
	n, d := intParam(q, "limit", defaultListLimit, 1, maxListLimit)
	if d != nil {
		badQuery(w, d)
		return
	}
	writeJSON(w, http.StatusOK, api.RunList{Runs: s.runs.list(int(n))})
}

func (s *Server) handleRun(w http.ResponseWriter, id string) {
	run, ok := s.lookupRun(id)
	if !ok {
		writeError(w, http.StatusNotFound, simpleError(api.CodeRunNotFound, "There is no such run."))
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) lookupRun(id string) (api.Run, bool) {
	if !runIDRE.MatchString(id) {
		return api.Run{}, false
	}
	return s.runs.get(id)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if d := onlyParams(q, "since", "limit"); d != nil {
		badQuery(w, d)
		return
	}
	since, d := intParam(q, "since", 0, 0, 1<<53-1)
	if d != nil {
		badQuery(w, d)
		return
	}
	limit, d := intParam(q, "limit", 100, 1, maxListLimit)
	if d != nil {
		badQuery(w, d)
		return
	}
	page, err := s.audit.page(since, int(limit))
	if err != nil {
		s.log.ErrorContext(r.Context(), "could not read the audit log")
		writeError(w, http.StatusInternalServerError, simpleError(api.CodeInternal, "The host could not read the audit log."))
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// handleEvents streams a run's events as SSE with Last-Event-ID resume.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, id string) {
	run, ok := s.lookupRun(id)
	if !ok {
		writeError(w, http.StatusNotFound, simpleError(api.CodeRunNotFound, "There is no such run."))
		return
	}
	var after uint64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseUint(v, 10, 53)
		if err != nil {
			writeError(w, http.StatusBadRequest, api.ErrorInfo{Code: api.CodeInvalidArgs, Message: "Invalid Last-Event-ID.", Details: []api.Detail{{Field: "Last-Event-ID", Reason: "must be an event number"}}})
			return
		}
		after = n
	}
	s.mu.Lock()
	l := s.live[id]
	s.mu.Unlock()
	if l == nil {
		l = loadEventLog(s.runs, run, s.now)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		evs, wake, done := l.since(after)
		for _, ev := range evs {
			b, err := json.Marshal(ev)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.Seq, b); err != nil {
				return
			}
			after = ev.Seq
		}
		if len(evs) > 0 {
			if err := rc.Flush(); err != nil {
				return
			}
		}
		if done {
			return
		}
		select {
		case <-wake:
		case <-r.Context().Done():
			return
		case <-s.baseCtx.Done():
			return
		case <-keepalive.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}
