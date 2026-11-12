package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/jsonstrict"
)

// Limits on a command definition: a timeout is mandatory (agent-safety, POST-4).
const (
	maxCommandTimeout = 2 * time.Hour
	maxCommandBody    = 4 << 20 // ceiling of Spec.MaxBody (ponytail: raise with the command that needs it)
)

var commandNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`)

// Command is one entry of the closed command table (INV-1). Build it with Define; the only way to
// put it in a Registry is NewRegistry, and a Registry cannot change afterwards.
type Command struct {
	name    string
	write   bool
	timeout time.Duration
	// decode parses the raw "args" object strictly into the command's own args type and validates it.
	decode func(raw json.RawMessage) (any, error)
	check  func(ctx context.Context, args any) error
	run    func(ctx context.Context, rc *RunContext, args any) (any, error)
	// whileAwaiting: may run, one at a time, while a run awaits confirmation, and only then;
	// runIDOf reads args.run_id of the decoded args.
	whileAwaiting bool
	runIDOf       func(args any) string
	awaits        bool  // may return Awaiting
	parks         bool  // may return Parked
	specErr       error // a mistake in the Spec, reported by NewRegistry
	maxBody       int64 // 0 = the default maxBodyBytes
}

// Name is the command name, for example "os.check".
func (c Command) Name() string { return c.name }

// hasRunIDField reports whether A is a struct with a string field encoded as "run_id".
func hasRunIDField[A any]() bool {
	t := reflect.TypeFor[A]()
	if t.Kind() != reflect.Struct {
		return false
	}
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "run_id" && f.Type.Kind() == reflect.String {
			return true
		}
	}
	return false
}

// bodyLimit is the largest request body the command accepts.
func (c Command) bodyLimit() int64 {
	if c.maxBody > 0 {
		return c.maxBody
	}
	return maxBodyBytes
}

// Write reports whether the command takes the global write lock.
func (c Command) Write() bool { return c.write }

// Spec describes a command; A is its args type (a struct of typed fields, or struct{} for none).
// Nothing in A may name a binary, an argv or a path: values reach argv only through the command's
// own code, after Validate (INV-2).
type Spec[A any] struct {
	Name    string
	Write   bool
	Timeout time.Duration // required, at most 2 h
	// WhileAwaiting marks net.confirm and net.revert: the only commands that run while a run awaits
	// confirmation (D-100), and only when args.run_id is that run's id. They must be Write commands
	// and take a run_id field in A. A write command without this flag gets 409 pending_confirm
	// while a run waits; a WhileAwaiting command with no matching waiting run gets 412
	// not_awaiting_confirm and never runs. One such command runs at a time (a second gets busy).
	WhileAwaiting bool
	// Awaits marks net.apply: the only kind of command whose Run may return Awaiting. It must be a
	// Write command and cannot also be WhileAwaiting; an Awaiting from any other command fails the
	// run as invalid (command_failed).
	Awaits bool
	// Parks marks host.self_update (D-316): the only kind of command whose Run may return Parked. It
	// must be a Write command and cannot also be Awaits or WhileAwaiting; a Parked from any other
	// command fails the run as invalid (command_failed).
	Parks bool
	// MaxBody is the largest request body in bytes; 0 means 512 KiB, at most 4 MiB.
	MaxBody int64
	// Validate checks the decoded args; return Invalid(...) for field errors. May be nil for no args.
	Validate func(*A) error
	// Check runs the cheap preconditions synchronously (five seconds at most) before the run starts.
	// It must only read: it must not change the system, because if it ignores its deadline the run
	// is failed but the write lock stays held until it returns. The one exception is container.pull
	// (D-130): it stores a newer verified release index even when it then refuses, so that a revocation
	// is not lost; that write is small and atomic, and is logged and audited (release_index_stored).
	// Return a *Refusal to refuse; the run is recorded as refused with the matching HTTP status.
	Check func(ctx context.Context, args A) error
	// Run does the work. It must obey ctx. Return nil error with a JSON-encodable result, an Awaiting
	// (the run waits for Settle and keeps the write lock), a Parked (the run stays running past the
	// process and keeps the write lock until SettleParked), a *Refusal, a *Failure, or any other error
	// (reported as command_failed without its text).
	Run func(ctx context.Context, rc *RunContext, args A) (any, error)
}

// Define turns a Spec into a Command.
func Define[A any](s Spec[A]) Command {
	c := Command{name: s.Name, write: s.Write, timeout: s.Timeout, whileAwaiting: s.WhileAwaiting, maxBody: s.MaxBody}
	c.awaits, c.parks = s.Awaits, s.Parks
	switch {
	case s.Parks && (s.Awaits || s.WhileAwaiting):
		c.specErr = errors.New("spec flag Parks excludes Awaits and WhileAwaiting")
	case s.Parks && !s.Write:
		c.specErr = errors.New("spec flag Parks needs a Write command")
	case s.Awaits && s.WhileAwaiting:
		c.specErr = errors.New("spec flags Awaits and WhileAwaiting exclude each other")
	case s.Awaits && !s.Write:
		c.specErr = errors.New("spec flag Awaits needs a Write command")
	case s.WhileAwaiting && !hasRunIDField[A]():
		c.specErr = errors.New(`WhileAwaiting needs a string field "run_id" in the args`)
	}
	if s.WhileAwaiting {
		c.runIDOf = func(args any) string {
			var v struct {
				RunID string `json:"run_id"`
			}
			if json.Unmarshal(mustMarshal(args), &v) != nil {
				return ""
			}
			return v.RunID
		}
	}
	c.decode = func(raw json.RawMessage) (any, error) {
		var a A
		if err := decodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if s.Validate != nil {
			if err := s.Validate(&a); err != nil {
				return nil, err
			}
		}
		return a, nil
	}
	if s.Check != nil {
		c.check = func(ctx context.Context, args any) error { return s.Check(ctx, args.(A)) } //nolint:forcetypeassert // decode produced an A
	}
	if s.Run != nil {
		c.run = func(ctx context.Context, rc *RunContext, args any) (any, error) { return s.Run(ctx, rc, args.(A)) } //nolint:forcetypeassert // decode produced an A
	}
	return c
}

// Registry is the closed command table: built once, read-only, no Register method.
type Registry struct {
	cmds map[string]Command
}

// NewRegistry validates and freezes the table.
func NewRegistry(cmds ...Command) (*Registry, error) {
	r := &Registry{cmds: make(map[string]Command, len(cmds))}
	for _, c := range cmds {
		switch {
		case !commandNameRE.MatchString(c.name):
			return nil, fmt.Errorf("host: command name %q must match %s", c.name, commandNameRE)
		case c.run == nil || c.decode == nil:
			return nil, fmt.Errorf("host: command %q has no Run", c.name)
		case c.timeout <= 0 || c.timeout > maxCommandTimeout:
			return nil, fmt.Errorf("host: command %q needs a timeout between 1ns and %s", c.name, maxCommandTimeout)
		case c.specErr != nil:
			return nil, fmt.Errorf("host: command %q: %w", c.name, c.specErr)
		case c.whileAwaiting && !c.write:
			return nil, fmt.Errorf("host: command %q is WhileAwaiting but not a write command", c.name)
		case c.maxBody < 0 || c.maxBody > maxCommandBody:
			return nil, fmt.Errorf("host: command %q needs a body limit between 0 and %d bytes", c.name, maxCommandBody)
		}
		if _, dup := r.cmds[c.name]; dup {
			return nil, fmt.Errorf("host: command %q listed twice", c.name)
		}
		r.cmds[c.name] = c
	}
	return r, nil
}

// Lookup finds a command by exact name.
func (r *Registry) Lookup(name string) (Command, bool) {
	c, ok := r.cmds[name]
	return c, ok
}

// Names lists the commands, sorted (the commands[] of GET /v1/info).
func (r *Registry) Names() []string {
	n := make([]string, 0, len(r.cmds))
	for k := range r.cmds {
		n = append(n, k)
	}
	slices.Sort(n)
	return n
}

// ArgsError is a validation failure of a command's args.
type ArgsError struct{ Details []api.Detail }

func (e *ArgsError) Error() string { return "invalid args" }

// Invalid builds an ArgsError for one field ("args.<name>"; an empty field means the whole args).
func Invalid(field, reason string) *ArgsError {
	if field == "" {
		return &ArgsError{Details: []api.Detail{{Field: "args", Reason: reason}}}
	}
	return &ArgsError{Details: []api.Detail{{Field: "args." + field, Reason: reason}}}
}

// Refusal makes a run end as refused. Status is the HTTP status (409 for a state conflict,
// 412 for a failed precondition, 404 for an id the host does not know, spec section 11).
type Refusal struct {
	Status  int
	Code    string
	Message string
	// RetryAfterS, when positive, is the hint "try again in this many seconds" (also sent as Retry-After).
	RetryAfterS int
}

func (e *Refusal) Error() string { return "refused: " + e.Code }

// Refuse builds a Refusal. Programming error (panic) if the status is not 404, 409 or 412 or the code is not snake_case.
func Refuse(status int, code, message string) *Refusal {
	if (status != http.StatusConflict && status != http.StatusPreconditionFailed && status != http.StatusNotFound) || !codeRE.MatchString(code) {
		panic(fmt.Sprintf("host: bad refusal %d %q", status, code))
	}
	return &Refusal{Status: status, Code: code, Message: message}
}

// RefuseRetry is Refuse with a retry hint in seconds.
func RefuseRetry(status int, code, message string, retryAfterS int) *Refusal {
	r := Refuse(status, code, message)
	r.RetryAfterS = retryAfterS
	return r
}

// Failure makes a run end as failed with a specific code and a message safe to show. Result, when
// not nil, is stored as the run's result next to the error (for example the health checks of a
// run that installed packages but left the box unhealthy).
type Failure struct {
	Code    string
	Message string
	Result  any
}

func (e *Failure) Error() string { return "failed: " + e.Code }

// Reverted makes a run end with status reverted: the command changed the system, it did not
// work, and the command put the previous state back. Result is stored like Failure.Result.
type Reverted struct {
	Code    string
	Message string
	Result  any
}

func (e *Reverted) Error() string { return "reverted: " + e.Code }

// Awaiting is what Run returns (as its result, with a nil error) to park the run in awaiting_confirm
// instead of finishing it (D-100): the run is stored with revert_at, an audit line awaiting_confirm is
// written, and the run KEEPS the global write lock until (*Server).Settle ends it. Result is stored
// as the run's result like Failure.Result. RevertAt must be set. The command arms its own timer
// (arm it in rc.OnParked) and ends the run with Claim and Finish, or Settle. RevertAt must be in
// the future and at most maxRevertWindow after the run started.
type Awaiting struct {
	RevertAt time.Time
	Result   any
}

// asAwaiting recognises an Awaiting returned by value or by pointer.
func asAwaiting(res any) (Awaiting, bool) {
	switch v := res.(type) {
	case Awaiting:
		return v, true
	case *Awaiting:
		if v != nil {
			return *v, true
		}
	}
	return Awaiting{}, false
}

var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// RunContext is what a running command gets to report progress.
type RunContext struct {
	RunID  string
	Actor  string
	log    func(line string)
	prog   func(percent int)
	after  []func(context.Context, api.Status)
	parked []func()
}

// AfterFinish registers fn to run once the run is recorded as final: audit line and run file
// written, write lock released, final event sent. fn gets the final status and a context that
// outlives the run and the server's shutdown (it is only ever cancelled by nothing: the callback
// is short and must finish its work). It runs on its own goroutine, and only when the command
// returned (a command that ignored its deadline gets no callbacks). Use it for effects that must
// not be part of the run, such as rebooting the machine after the run is recorded as succeeded.
// Call it from the command's Run goroutine only.
func (rc *RunContext) AfterFinish(fn func(ctx context.Context, st api.Status)) {
	rc.after = append(rc.after, fn)
}

// OnParked registers fn to run right after the run is parked (in awaiting_confirm, or running as
// Parked), when the write lock and the parked state are already published and stored: arm the
// revert timer here, or start the goroutine that does the work outside the process and settles the
// run, so that it can never find the run "not yet parked". fn must not block. It does not run when
// the run ends any other way (an invalid Awaiting or Parked included). Call it from Run only.
// Neither OnParked nor AfterFinish callbacks survive a host restart: after one, whoever resumed
// the run (Options.Resume, then Ops.Start from net/pending.json or the journal) must re-arm itself.
func (rc *RunContext) OnParked(fn func()) { rc.parked = append(rc.parked, fn) }

// Log appends one line (cut to 2 KiB, control characters removed) to the run's event stream.
func (rc *RunContext) Log(line string) { rc.log(line) }

// Progress reports 0..100 (clamped).
func (rc *RunContext) Progress(percent int) { rc.prog(percent) }

// decodeStrict decodes one JSON value into v: unknown fields, a null, trailing data are errors.
// Empty input means {}.
func decodeStrict(raw []byte, v any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if bytes.Equal(raw, []byte("null")) {
		return Invalid("", "args must be an object")
	}
	switch ambiguousKeys(raw) {
	case "":
	case jsonstrict.WhyDeep:
		return Invalid("", "the args are nested too deep")
	default:
		return Invalid("", "an object has keys that differ only by case or repeat")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &ArgsError{Details: []api.Detail{{Field: "args", Reason: jsonReason(err)}}}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Invalid("", "unexpected data after the args object")
	}
	return nil
}

// jsonReason turns a decoder error into a sentence that carries no internals.
func jsonReason(err error) string {
	var ute *json.UnmarshalTypeError
	var se *json.SyntaxError
	switch {
	case errors.As(err, &ute):
		if ute.Field != "" {
			return fmt.Sprintf("field %s has the wrong type", ute.Field)
		}
		return "the value has the wrong type"
	case errors.As(err, &se):
		return "not valid JSON"
	}
	if name, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return "unknown field " + clip(name, 64)
	}
	return "does not match the expected shape"
}

// ambiguousKeys returns a non-empty description when some JSON object in raw has two keys that are
// equal ignoring case (encoding/json matches field names case-insensitively, so such an object
// means different things to a reader and to the decoder) or repeat exactly. Malformed JSON gives "".
// Malformed JSON gives "": the decoder that follows reports the syntax error in the usual words.
func ambiguousKeys(raw []byte) string {
	if why := jsonstrict.Ambiguous(raw); why != jsonstrict.WhyMalformed {
		return why
	}
	return ""
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}
