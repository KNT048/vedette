// Package write is the only path by which Vedette changes a device through a connection (D-93, D-94, response FORBID-1): one step
// of an approved response action, sent over the transport of the connection's kind. Only cmd/vedette may import it (a contract
// test walks the source tree), and cmd/vedette gives it to nobody but response.Config.Executor.
//
// The package trusts nothing it is handed. On every step it reloads the connection and refuses (nothing is sent) when the id is
// unknown, the connection is off, it is not the version the request was made against, a write tool is not on, the address is
// outside the target or the allow-list, a placeholder is left in the text, a header is one a template may not set, or a command
// holds a control character. Every dial goes through the policy dialer of core/conn/internal/transport; nothing else dials. One
// call runs at a time per connection. What a device printed is returned in Result.Output for the caller to compare and drop: it is
// never logged here and never stored; a failure is described in one cleaned line without any credential.
package write

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/cliban"
	"github.com/knt048/vedette/core/conn/internal/cred"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

// The phases of an action's steps. precheck and verify only read; run and rollback change the device.
const (
	PhasePrecheck = "precheck"
	PhaseRun      = "run"
	PhaseRollback = "rollback"
	PhaseVerify   = "verify"
)

// Status says how a step ended, in the terms response needs to decide what to record.
type Status string

// The ways a step ends.
const (
	// StatusOK: the step completed.
	StatusOK Status = "ok"
	// StatusNotSent: nothing reached the device, so nothing changed (a check refused it, the address could not be reached, the
	// certificate or host key was not the pinned one).
	StatusNotSent Status = "not_sent"
	// StatusConnectionChanged: the connection is not the version the request was made against; nothing was sent.
	StatusConnectionChanged Status = "connection_changed"
	// StatusFailed: the device refused the step by its status (an HTTP 4xx), or a step that only reads did not work: nothing was applied. The
	// wording of an error never makes a step "failed" (D-117).
	StatusFailed Status = "failed"
	// StatusUnknown: the step was sent and the outcome is not known (a time-out or a closed session after it left, an HTTP 3xx or 5xx, an MCP
	// tool that reported an error, a refused SSH line). The caller marks the state unknown and the device is read, not asked again.
	StatusUnknown Status = "unknown"
)

// Budgets (D-94): HTTP and MCP calls are bounded by transport.CallTimeout (15 s) in the client, an SSH line by
// transport.LineTimeout (20 s) and an SSH session by transport.SessionTimeout (60 s) in the session. StepBudget bounds one step of
// an item whatever the caller's context says; response adds its own 90 s for the item.
const (
	CallBudget    = transport.CallTimeout
	LineBudget    = transport.LineTimeout
	SessionBudget = transport.SessionTimeout
	StepBudget    = 90 * time.Second
)

// Limits of one step.
const (
	maxLines   = 64
	maxLineLen = 512
)

// Step is one step of one item, rendered by response from a stored template and checked values.
type Step struct {
	ConnectionID string
	ConnFP       string // conn.Fingerprint of the connection when the request was made: a run is held to it
	// ByIdentity marks a step of an undo (the rollback and the read-back after it) or a read-back that settles an unclear outcome. It is held to the connection's identity (conn.Identity: id,
	// kind, address), not to its fingerprint, and it ignores the write-tool switch: removing a change is the safe direction and a rotated
	// token or a renewed pin must not strand it. The connection must still be on and its certificate or host key must still pass.
	ByIdentity   bool
	ConnIdentity string
	Phase        string
	Tool         string // MCP only: the write tool to call
	Lines        []string
	Method       string
	URL          string
	Body         string
	Headers      map[string]string
	Args         json.RawMessage // MCP: the typed arguments, a JSON object
}

// Result is what a step did. Output is what a read step printed, capped; the caller compares it and drops it. Detail is one cleaned
// line of at most 200 characters, safe to show and to log.
type Result struct {
	Status Status
	Output string
	Detail string
}

// Config wires a Writer.
type Config struct {
	Conns *conn.Service
}

// Writer sends the steps.
type Writer struct {
	c               *conn.Service
	afterCredential func() // tests edit the connection here
}

// New returns a Writer.
func New(c Config) (*Writer, error) {
	if c.Conns == nil {
		return nil, errors.New("write: Config needs Conns")
	}
	return &Writer{c: c.Conns}, nil
}

var (
	placeholderRE = regexp.MustCompile(`\{[a-z_]+\}|<(seq|previous_vlan|found_id|expiry_s|timeout|rules_before)>`)
	headerNameRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,40}$`)
)

// shellChars may never be in a command (response INV-14b, SYS-1): the writer repeats the check response made when it rendered.
const shellChars = ";|&$`<>()\\!~^"

// writeTool is the fixed write tool of a connection kind; an MCP server's tool is named by the step.
func writeTool(kind string) string {
	switch kind {
	case conn.KindHTTP:
		return "send_request"
	case conn.KindRESTCONF:
		return "apply_config"
	case conn.KindAutomation:
		return "launch_job"
	case conn.KindSSH:
		return "run_approved_command"
	}
	return ""
}

func res(status Status, format string, args ...any) Result {
	return Result{Status: status, Detail: transport.CleanLine(fmt.Sprintf(format, args...))}
}

// Do sends one step. It never returns a Go error: how it ended is the Status.
func (w *Writer) Do(ctx context.Context, s Step) Result {
	ctx, cancel := context.WithTimeout(ctx, StepBudget)
	defer cancel()
	switch s.Phase {
	case PhasePrecheck, PhaseRun, PhaseRollback, PhaseVerify:
	default:
		return res(StatusNotSent, "the step has no known phase")
	}
	// An id that is not a connection is refused before it can cost a lock.
	if _, err := w.c.Get(ctx, s.ConnectionID); err != nil {
		return w.loadFailure(err)
	}
	release, ok := w.acquire(ctx, s.ConnectionID)
	if !ok {
		return res(StatusNotSent, "another step on this connection did not finish in time")
	}
	defer release()
	c, err := w.c.Get(ctx, s.ConnectionID) // fresh: what the connection is now, after waiting for its turn
	if err != nil {
		return w.loadFailure(err)
	}
	if r, bad := w.check(c, s); bad {
		return r
	}
	secret, err := w.c.OpenCredential(ctx, cred.Grant(), c)
	if err != nil {
		return res(StatusNotSent, "the sign-in of the connection could not be read")
	}
	if w.afterCredential != nil {
		w.afterCredential()
	}
	// The connection may have been edited while the credential was opened: what is sent is what the request was made against.
	if now, err := w.c.Get(ctx, s.ConnectionID); err != nil {
		return w.loadFailure(err)
	} else if (s.ByIdentity && now.Identity() != s.ConnIdentity) || (!s.ByIdentity && now.Fingerprint() != s.ConnFP) || !now.Enabled {
		return res(StatusConnectionChanged, "the connection was changed after the request was made")
	}
	redact := redactions(c, secret)
	if c.Kind == conn.KindSSH {
		return w.ssh(ctx, c, secret, s, redact)
	}
	return w.https(ctx, c, secret, s, redact)
}

func (w *Writer) loadFailure(err error) Result {
	if e, ok := apierr.As(err); ok && e.Status == http.StatusNotFound {
		return res(StatusNotSent, "the connection no longer exists")
	}
	return res(StatusNotSent, "the connection could not be read")
}

// acquire takes the connection's turn (shared with the reader), or gives up when ctx ends.
func (w *Writer) acquire(ctx context.Context, id string) (release func(), ok bool) {
	return w.c.LockConn(ctx, cred.Grant(), id)
}

// check is every refusal that stops a step before anything is sent. The second result is true when the step is refused.
func (w *Writer) check(c conn.Connection, s Step) (Result, bool) {
	refuse := func(format string, args ...any) (Result, bool) { return res(StatusNotSent, format, args...), true }
	if !c.Enabled {
		return refuse("the connection is turned off")
	}
	if s.ByIdentity {
		if s.Phase != PhaseRollback && s.Phase != PhaseVerify {
			return refuse("only a rollback and its read-back are steps of an undo")
		}
		if c.Identity() != s.ConnIdentity {
			return res(StatusConnectionChanged, "the connection is not the device that the change was made on"), true
		}
	} else if c.Fingerprint() != s.ConnFP {
		return res(StatusConnectionChanged, "the connection was changed after the request was made"), true
	}
	reads := s.Phase == PhasePrecheck || s.Phase == PhaseVerify
	// What starts a change (the check before and the run) needs a connection that passed its last Test; an undo and a read-back
	// need only that something is pinned: the safe direction must not stop because the last Test failed. Trust on first use is the
	// first Test's alone.
	if s.Phase == PhasePrecheck || s.Phase == PhaseRun {
		if why := conn.NotReady(c); why != "" {
			return refuse("%s", strings.TrimRight(why, "."))
		}
	}
	if c.Pin == nil {
		return refuse("the certificate or host key of the device is not pinned yet; test the connection first")
	}
	mcp := c.Kind == conn.KindMCP
	if !reads && !s.ByIdentity {
		tool := writeTool(c.Kind)
		if mcp {
			tool = s.Tool
		} else if s.Tool != "" {
			return refuse("a tool is named only for an MCP server")
		}
		if tool == "" {
			return refuse("the step names no write tool")
		}
		if !contains(conn.WriteTools(c), tool) {
			return refuse("the write tool %s is not turned on", tool)
		}
	} else if reads && (s.Tool != "" || mcp) {
		return refuse("a check or a read-back is not available on this connection")
	}
	if s.ByIdentity && !mcp && s.Tool != "" {
		return refuse("a tool is named only for an MCP server")
	}
	if s.ByIdentity && mcp && s.Phase == PhaseRollback && s.Tool == "" {
		return refuse("the step names no write tool")
	}
	if leftover(s) {
		return refuse("the step still holds a value that is not filled in")
	}
	switch {
	case c.Kind == conn.KindSSH:
		return checkLines(s)
	case mcp:
		return checkMCP(s)
	}
	return checkHTTP(c, s, reads)
}

// leftover reports a placeholder that was not filled in, anywhere in the step.
func leftover(s Step) bool {
	if placeholderRE.MatchString(s.URL + "\n" + s.Body + "\n" + s.Tool) {
		return true
	}
	for _, l := range s.Lines {
		if placeholderRE.MatchString(l) {
			return true
		}
	}
	for k, v := range s.Headers {
		if placeholderRE.MatchString(k + v) {
			return true
		}
	}
	return placeholderRE.Match(s.Args)
}

func checkLines(s Step) (Result, bool) {
	refuse := func(format string, args ...any) (Result, bool) { return res(StatusNotSent, format, args...), true }
	if s.Method != "" || s.URL != "" || s.Body != "" || len(s.Headers) > 0 || len(s.Args) > 0 {
		return refuse("an SSH step is command lines only")
	}
	if len(s.Lines) == 0 || len(s.Lines) > maxLines {
		return refuse("an SSH step holds 1 to %d command lines", maxLines)
	}
	if s.Phase == PhasePrecheck || s.Phase == PhaseVerify {
		// A read step is the last gate's to judge, whoever rendered it: the commands that change a device are the shared list (core/conn/cliban).
		if bad, err := cliban.ReadOnlyProblem(s.Lines); err != nil || bad != "" {
			return refuse("a check or a read-back may not type a command that can change the device")
		}
	}
	for _, l := range s.Lines {
		switch {
		case strings.TrimSpace(l) == "":
			return refuse("a command line is empty")
		case len(l) > maxLineLen:
			return refuse("a command line is longer than %d characters", maxLineLen)
		case strings.ContainsFunc(l, unicode.IsControl):
			return refuse("a command line holds a control character")
		case strings.ContainsAny(l, shellChars):
			return refuse("a command line holds a character that a command may not hold")
		}
	}
	return Result{}, false
}

func checkMCP(s Step) (Result, bool) {
	refuse := func(format string, args ...any) (Result, bool) { return res(StatusNotSent, format, args...), true }
	if len(s.Lines) > 0 || s.Method != "" || s.URL != "" || s.Body != "" || len(s.Headers) > 0 {
		return refuse("an MCP step is a tool and its arguments only")
	}
	if _, err := args(s.Args); err != nil {
		return refuse("the arguments of the tool are not a JSON object")
	}
	return Result{}, false
}

func checkHTTP(c conn.Connection, s Step, reads bool) (Result, bool) {
	refuse := func(format string, args ...any) (Result, bool) { return res(StatusNotSent, format, args...), true }
	if len(s.Lines) > 0 || len(s.Args) > 0 {
		return refuse("an API step is a method, an address, a body and headers only")
	}
	switch {
	case reads && (s.Method != http.MethodGet || s.Body != ""):
		return refuse("a check or a read-back is a GET without a body")
	case !reads && s.Method != http.MethodGet && s.Method != http.MethodPost && s.Method != http.MethodPut && s.Method != http.MethodPatch && s.Method != http.MethodDelete:
		return refuse("the method is not one that is allowed")
	}
	if strings.Contains(s.URL, "#") {
		return refuse("the address holds a fragment") // a ?query stays: it is part of the approved stored step, and the allow-list judges the path
	}
	if !conn.AllowsURL(c, s.URL) {
		return refuse("the address is outside the connection's address and its allow-list")
	}
	if len(s.Body) > transport.MaxRequest {
		return refuse("the body is larger than %d KB", transport.MaxRequest>>10)
	}
	for k, v := range s.Headers {
		switch {
		case !headerNameRE.MatchString(k):
			return refuse("a header name is not valid")
		case transport.ForbiddenHeader(k):
			return refuse("the header %s may not be set by an action", k)
		case strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) }):
			return refuse("a header holds a control character")
		}
	}
	return Result{}, false
}

func args(raw json.RawMessage) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // a number stays as it was written
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return nil, errors.New("not an object")
	}
	return m, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// redactions are the strings of the sign-in that must not appear in any text (transport.Secrets).
func redactions(c conn.Connection, secret secrets.Value) []string {
	user := ""
	if c.Username != nil {
		user = *c.Username
	}
	return transport.Secrets(c.Auth.Type, user, secret.Reveal())
}

func tlsPin(p *conn.Pin) string {
	if p != nil && p.Kind == "tls_sha256" {
		return p.Value
	}
	return ""
}

func (w *Writer) https(ctx context.Context, c conn.Connection, secret secrets.Value, s Step, redact []string) Result {
	acc := w.c.WriteAccess(cred.Grant())
	// TOFU is never on here: a certificate is trusted by the pin the first Test took, or by the system roots when that is what it recorded.
	cl := transport.NewHTTPS(transport.HTTPSConfig{Dialer: acc.Dialer, Pin: tlsPin(c.Pin), TOFU: false, Roots: acc.Roots})
	auth := transport.Auth{Type: c.Auth.Type, Header: deref(c.Auth.Header), Secret: secret}
	if c.Username != nil {
		auth.Username = *c.Username
	}
	reads := s.Phase == PhasePrecheck || s.Phase == PhaseVerify
	if c.Kind == conn.KindMCP {
		return w.mcp(ctx, cl, auth, c, s, redact)
	}
	h := http.Header{}
	for k, v := range s.Headers {
		h.Set(k, v)
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", "application/json")
	}
	var body []byte
	if s.Body != "" {
		body = []byte(s.Body)
		if h.Get("Content-Type") == "" {
			h.Set("Content-Type", "application/json") // response renders a body only as JSON
		}
	}
	resp, err := cl.Do(ctx, auth, transport.Request{Method: s.Method, URL: s.URL, Header: h, Body: body})
	if err != nil {
		return failure(err, cl.Seen().SPKISHA256 != "", reads, c, redact)
	}
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		r := Result{Status: StatusOK, Detail: fmt.Sprintf("HTTP %d", resp.Status)}
		if reads {
			r.Output = string(resp.Body)
		}
		return r
	case (resp.Status >= 500 || resp.Status >= 300 && resp.Status < 400) && !reads:
		// A redirect after a POST is often "done, look over there", and a 5xx may come after the work: neither says "refused".
		return res(StatusUnknown, "the device answered HTTP %d, so the step may or may not have been applied", resp.Status)
	}
	return res(StatusFailed, "the device answered HTTP %d", resp.Status)
}

func (w *Writer) mcp(ctx context.Context, cl *transport.Client, auth transport.Auth, c conn.Connection, s Step, redact []string) Result {
	a, err := args(s.Args)
	if err != nil {
		return res(StatusNotSent, "the arguments of the tool are not a JSON object")
	}
	m := transport.NewMCP(cl, c.Target, auth)
	defer m.Close(context.WithoutCancel(ctx))
	if err := m.Initialize(ctx); err != nil {
		return failure(err, false, false, c, redact) // nothing was called yet
	}
	out, err := m.CallTool(ctx, s.Tool, a)
	if err != nil {
		return failure(err, true, false, c, redact)
	}
	if out.IsError {
		// The tool ran and reported an error: the MCP specification puts business-logic failures here, which can come after part of the work.
		return res(StatusUnknown, "the server reported an error for the tool %s (%s), so the step may or may not have been applied", s.Tool, transport.CleanLine(out.Text, redact...))
	}
	return Result{Status: StatusOK, Detail: "the tool " + s.Tool + " answered"}
}

func (w *Writer) ssh(ctx context.Context, c conn.Connection, secret secrets.Value, s Step, redact []string) Result {
	acc := w.c.WriteAccess(cred.Grant())
	cfg := transport.SSHConfig{Dialer: acc.Dialer, TOFU: false}
	if c.Username != nil {
		cfg.Username = *c.Username
	}
	if c.Auth.Type == conn.AuthKey {
		cfg.Key = secret
	} else {
		cfg.Password = secret
	}
	if c.Pin != nil && c.Pin.Kind == "ssh_hostkey" {
		cfg.HostKey = c.Pin.Value
	}
	if cfg.HostKey == "" {
		return res(StatusNotSent, "the host key of the device is not pinned yet; test the connection first")
	}
	reads := s.Phase == PhasePrecheck || s.Phase == PhaseVerify
	sess, err := transport.DialSSH(ctx, c.Target, cfg)
	if err != nil {
		return failure(err, false, reads, c, redact) // the session never opened: no command was sent
	}
	defer sess.Close()
	var out []string
	for i, l := range s.Lines {
		o, err := sess.Run(ctx, l)
		if err != nil {
			r := failure(err, true, reads, c, redact)
			if i > 0 && !reads && r.Status == StatusFailed {
				// An earlier line was accepted: a refusal now leaves the device half way, which is not "nothing changed".
				r.Status = StatusUnknown
			}
			return r
		}
		out = append(out, o)
	}
	r := Result{Status: StatusOK, Detail: fmt.Sprintf("%d command%s sent", len(s.Lines), plural(len(s.Lines)))}
	if reads {
		r.Output = strings.Join(out, "\n")
	}
	return r
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// failure turns a transport error into a Result. sent says that the request (or a command) may have left the box: then a step that
// changes the device ends as unknown, because a time-out or a closed session proves nothing; a step that only reads just failed.
func failure(err error, sent, reads bool, c conn.Connection, redact []string) Result {
	var re *transport.RefusedError
	var de *transport.DeviceError
	switch {
	case errors.As(err, &re):
		return res(StatusNotSent, "%s", re.Error())
	case errors.Is(err, transport.ErrPinMismatch):
		what := "certificate"
		if c.Pin != nil && c.Pin.Kind == "ssh_hostkey" {
			what = "host key"
		}
		return res(StatusNotSent, "the %s of %s is not the one pinned at the first test, so nothing was sent", what, c.Target)
	case errors.Is(err, transport.ErrUnverified):
		return res(StatusNotSent, "the certificate of %s is not trusted and nothing is pinned for it, so nothing was sent", c.Target)
	}
	msg := "timed out"
	switch {
	case errors.As(err, &de):
		msg = transport.CleanLine(de.Msg, redact...)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
	default:
		if e := transport.CleanLine(err.Error(), redact...); e != "" && e != "timed out" {
			msg = e
		}
	}
	switch {
	case !sent:
		return res(StatusNotSent, "%s could not be reached: %s", c.Target, msg)
	case reads:
		return res(StatusFailed, "%s", msg)
	}
	return res(StatusUnknown, "%s: %s; the step may or may not have been applied", c.Target, msg)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
