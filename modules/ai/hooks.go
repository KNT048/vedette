package ai

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// HookWhen is the moment a hook runs (INV-12).
type HookWhen string

// The three moments: on the text sent to the AI, on the answer, and on a tool call the AI wants to make.
const (
	BeforeAI   HookWhen = "before_ai"
	AfterAI    HookWhen = "after_ai"
	BeforeTool HookWhen = "before_tool"
)

// HookAction is what a hook does when it matches: refuse, replace the matching text, or hold for a person.
type HookAction string

// The three actions.
const (
	ActionBlock   HookAction = "block"
	ActionMask    HookAction = "mask"
	ActionApprove HookAction = "approve"
)

// HookKind tells built-in hooks from customer-written ones.
type HookKind string

// Hook kinds.
const (
	KindBuiltin HookKind = "builtin"
	KindCustom  HookKind = "custom"
)

// IDs of the built-in hooks.
const (
	HookBlockPII      = "block-pii"
	HookSecurityOnly  = "security-only"
	HookWriteApproval = "write-approval"
)

// Outcome is the overall result of running the hooks of one moment on a text.
type Outcome string

// The four outcomes.
const (
	OutcomePass    Outcome = "pass"
	OutcomeMasked  Outcome = "masked"
	OutcomeBlocked Outcome = "blocked"
	OutcomeHeld    Outcome = "held"
)

// MaxHookInputBytes bounds the text a hook run scans. Go's regexp is RE2: no catastrophic backtracking, one search is linear in
// the text. A customer regex is searched again from the end of each match, and a leftmost-first pattern such as `.*z|a` reads to
// the end of the text on every search, so the cost is matches x text size, not text size (measured: 1,000 matches and 128 KiB of
// text take 6 s, so 1 MiB would take most of a minute). MaxMatchesPerScan stops a flood of matches (more is a block). It does not bound the
// time: the deadline does. Every hook pass (before_ai, after_ai, a test) runs under Service.hookTimeout, the context is checked
// inside a search, and a pass that runs out of time is a block. Anything over this size is refused rather than half-checked.
const MaxHookInputBytes = 1 << 20

// MaxMatchesPerScan is the most matches one custom regex may find in one text. More is a block: fail closed.
const MaxMatchesPerScan = 1000

// MaxRegexProgram is the largest compiled program (instructions, repeats expanded) a custom regex may have, and
// MaxCustomHooks the most custom hooks a box may have (30, the limit of the GUI mock). Together with the match cap and the
// context-aware scan (see scanRegexp) they bound the work of one Run; the deadline bounds its time.
const (
	MaxRegexProgram = 2000
	MaxCustomHooks  = 30
)

// Errors of the hook runner.
var (
	// ErrLocked: the hook is always on (write-approval) and cannot be turned off (API: 400 `locked`).
	ErrLocked = errors.New("ai: this hook is locked on")
	// ErrUnknownHook: no built-in hook has this ID.
	ErrUnknownHook = errors.New("ai: unknown built-in hook")
	// ErrHookInputTooLarge: the text is longer than MaxHookInputBytes. The caller must treat it as a block.
	ErrHookInputTooLarge = errors.New("ai: the text is too long to check against the hooks")
	// ErrTooManyHooks: more than MaxCustomHooks custom hooks.
	ErrTooManyHooks = errors.New("ai: too many custom hooks")
	// ErrInvalidHook is wrapped by every HookError.
	ErrInvalidHook = errors.New("ai: invalid hook")
)

// HookHit says which hook acted (shown in the answer, `hooks[]`, and named in the activity log).
type HookHit struct {
	ID, Name string
	Kind     HookKind
	When     HookWhen
	Action   HookAction
	Message  string
}

// HookResult is the text after the hooks ran (masked text, or the refusal message) and what happened.
type HookResult struct {
	Text    string
	Outcome Outcome
	Hits    []HookHit
}

// Names returns the distinct names of the hooks that acted, for the activity log.
func (r HookResult) Names() []string {
	names := []string{}
	seen := map[string]bool{}
	for _, h := range r.Hits {
		if !seen[h.Name] {
			seen[h.Name] = true
			names = append(names, h.Name)
		}
	}
	return names
}

// HiddenQuestion is stored in place of a question that a hook refused (INV-13).
const HiddenQuestion = "[question hidden: contains personal data]"

// QuestionForStorage returns what may be stored and shown in history for a question: the original text if no hook
// acted, the masked text if hooks masked it, and HiddenQuestion in every other case: blocked, held, a failed run
// (pass the zero HookResult) or an outcome it does not know. A refused question is never kept verbatim and costs
// no tokens, because the caller does not send it.
func QuestionForStorage(original string, r HookResult) string {
	switch r.Outcome {
	case OutcomePass:
		return original
	case OutcomeMasked:
		return r.Text
	}
	return HiddenQuestion // blocked, held, an error path (zero value) or anything unknown: never keep the text
}

// MatchType is how a custom hook matches.
type MatchType string

// The two match types.
const (
	MatchKeywords MatchType = "keywords" // comma-separated words, whole-word, case-insensitive
	MatchRegex    MatchType = "regex"    // Go (RE2) syntax, case-insensitive
)

// CustomHook is a customer-written hook (`ai_hooks`).
type CustomHook struct {
	ID      string
	Name    string
	When    HookWhen
	Match   HookMatch
	Action  HookAction
	Message string
	Enabled bool
}

// HookMatch is the pattern of a custom hook.
type HookMatch struct {
	Type    MatchType
	Pattern string
}

// HookError is a validation failure with a stable code.
type HookError struct{ Code, Msg string }

func (e *HookError) Error() string { return "ai: " + e.Msg }
func (e *HookError) Unwrap() error { return ErrInvalidHook }

func herr(code, format string, a ...any) error { return &HookError{code, fmt.Sprintf(format, a...)} }

const regexHint = "Patterns use Go (RE2) syntax. JavaScript-only syntax is not supported: lookahead (?=...) (?!...), lookbehind (?<=...) (?<!...), backreferences such as \\1, and \\u escapes. Rewrite the pattern without them."

// Validate checks a custom hook (name 1..40, pattern 1..200, message 3..200 characters) and compiles its
// pattern, so a broken pattern is rejected when saved and never reaches a run.
func (h CustomHook) Validate() error {
	_, err := h.compile()
	return err
}

func (h CustomHook) compile() (hookDef, error) {
	if n := utf8.RuneCountInString(strings.TrimSpace(h.Name)); n < 1 || n > 40 {
		return hookDef{}, herr("invalid_name", "Give the hook a name of 1 to 40 characters.")
	}
	if n := utf8.RuneCountInString(h.Message); n < 3 || n > 200 {
		return hookDef{}, herr("invalid_message", "The message must be 3 to 200 characters. It is shown to the person whose text the hook acted on.")
	}
	switch h.When {
	case BeforeAI, AfterAI, BeforeTool:
	default:
		return hookDef{}, herr("invalid_when", "Pick when the hook runs: before the AI, after the AI, or before a tool.")
	}
	switch h.Action {
	case ActionBlock, ActionMask, ActionApprove:
	default:
		return hookDef{}, herr("invalid_action", "Pick an action: block, mask or require approval.")
	}
	if n := utf8.RuneCountInString(h.Match.Pattern); n < 1 || n > 200 {
		return hookDef{}, herr("invalid_pattern", "The pattern must be 1 to 200 characters.")
	}
	d := hookDef{id: h.ID, name: h.Name, kind: KindCustom, when: h.When, action: h.Action, message: h.Message}
	switch h.Match.Type {
	case MatchKeywords:
		var words []string
		for _, w := range strings.Split(h.Match.Pattern, ",") {
			if w = strings.TrimSpace(w); w != "" {
				words = append(words, w)
			}
		}
		if len(words) == 0 {
			return hookDef{}, herr("invalid_pattern", "Enter at least one keyword; separate several with commas.")
		}
		d.find = func(ctx context.Context, t *scanText) ([]span, error) { return scanKeywords(ctx, t.orig, words) }
	case MatchRegex:
		if tree, perr := syntax.Parse("(?i)"+h.Match.Pattern, syntax.Perl); perr == nil {
			if estimateInsts(tree) > MaxRegexProgram {
				return hookDef{}, herr("pattern_too_large", "The pattern is too complex (a program of more than %d steps once repeats are expanded). Use fewer or smaller repeats such as {0,10}.", MaxRegexProgram)
			}
			if prog, cerr := syntax.Compile(tree.Simplify()); cerr == nil && len(prog.Inst) > MaxRegexProgram {
				return hookDef{}, herr("pattern_too_large", "The pattern is too complex (more than %d steps). Use fewer or smaller repeats.", MaxRegexProgram)
			}
		}
		re, err := regexp.Compile("(?i)" + h.Match.Pattern)
		if err != nil {
			var se *syntax.Error
			if errors.As(err, &se) {
				return hookDef{}, herr("unsupported_regex", "The pattern is not valid: %s (%s). %s", se.Code, se.Expr, regexHint)
			}
			return hookDef{}, herr("unsupported_regex", "The pattern is not valid. %s", regexHint)
		}
		if re.MatchString("") {
			return hookDef{}, herr("invalid_pattern", "The pattern matches empty text, so it would match everywhere. Make it require at least one character.")
		}
		d.find = func(ctx context.Context, t *scanText) ([]span, error) { return scanRegexp(ctx, re, t.orig) }
	default:
		return hookDef{}, herr("invalid_match_type", "Pick how the hook matches: keywords or a regular expression.")
	}
	return d, nil
}

// BuiltinHook is the view of a built-in hook for `GET /ai/hooks`.
type BuiltinHook struct {
	ID, Name, Description string
	Enabled, Locked       bool
}

var builtinInfo = []BuiltinHook{
	{ID: HookBlockPII, Name: "Block personal data", Description: "Masks email addresses, phone numbers and names written next to an account, and refuses text that contains an ID number."},
	{ID: HookSecurityOnly, Name: "Security work only", Description: "Refuses tasks that are not about this box's security job, for example writing a poem."},
	{ID: HookWriteApproval, Name: "Write tools need approval", Description: "A tool that changes something runs only through an action a person approves in the AI response module, never from a chat answer.", Locked: true},
}

// ValidateBuiltinToggle is the rule for `PUT /ai/hooks/builtin/{id}`: write-approval cannot be turned off.
func ValidateBuiltinToggle(id string, enabled bool) error {
	for _, b := range builtinInfo {
		if b.ID == id {
			if b.Locked && !enabled {
				return ErrLocked
			}
			return nil
		}
	}
	return ErrUnknownHook
}

// HookRunner runs the enabled built-in and custom hooks. It is immutable; build a new one when settings change.
type HookRunner struct {
	builtin map[string]bool
	defs    []hookDef
}

// NewHookRunner takes the enabled state of the built-in hooks (a missing ID means on) and the custom hooks.
// Turning write-approval off is refused with ErrLocked; a custom hook that fails Validate is refused.
// Disabled custom hooks are not compiled.
func NewHookRunner(builtinEnabled map[string]bool, custom []CustomHook) (*HookRunner, error) {
	if len(custom) > MaxCustomHooks {
		return nil, fmt.Errorf("%w: at most %d", ErrTooManyHooks, MaxCustomHooks)
	}
	r := &HookRunner{builtin: map[string]bool{}}
	for _, b := range builtinInfo {
		on := true
		if v, ok := builtinEnabled[b.ID]; ok {
			on = v
		}
		if err := ValidateBuiltinToggle(b.ID, on); err != nil {
			return nil, err
		}
		r.builtin[b.ID] = on
	}
	for id := range builtinEnabled {
		if _, ok := r.builtin[id]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownHook, id)
		}
	}
	if r.builtin[HookBlockPII] {
		r.defs = append(r.defs, piiDefs...)
	}
	if r.builtin[HookSecurityOnly] {
		r.defs = append(r.defs, offTopicDef)
	}
	for _, h := range custom {
		if !h.Enabled {
			continue
		}
		d, err := h.compile()
		if err != nil {
			return nil, err
		}
		r.defs = append(r.defs, d)
	}
	return r, nil
}

// Builtins returns the built-in hooks with their state (write-approval always on and locked).
func (r *HookRunner) Builtins() []BuiltinHook {
	out := make([]BuiltinHook, len(builtinInfo))
	for i, b := range builtinInfo {
		b.Enabled = r.builtin[b.ID]
		out[i] = b
	}
	return out
}

// Run applies the hooks of one moment to text, in order: built-ins first (ID numbers block before anything is
// masked), then custom hooks. A block or hold stops at once and the result text is the hook's message; a
// mask replaces each match with [masked] and later hooks see the masked text.
//
// Any error means the text must not go on: ErrHookInputTooLarge, or the context ending between hooks.
func (r *HookRunner) Run(ctx context.Context, when HookWhen, text string) (HookResult, error) {
	return r.run(ctx, text, func(d hookDef) bool { return d.when == when })
}

// RunPersonalData applies only the block-pii hook (if it is on) to text, whatever the moment. It is what
// tool results go through before they are sent back to the model (INV-12, INV-21).
func (r *HookRunner) RunPersonalData(ctx context.Context, text string) (HookResult, error) {
	return r.run(ctx, text, func(d hookDef) bool { return d.id == HookBlockPII && d.kind == KindBuiltin })
}

func (r *HookRunner) run(ctx context.Context, text string, use func(hookDef) bool) (HookResult, error) {
	if len(text) > MaxHookInputBytes {
		return HookResult{}, ErrHookInputTooLarge
	}
	res := HookResult{Text: text, Outcome: OutcomePass, Hits: []HookHit{}}
	scan := &scanText{orig: text}
	for _, d := range r.defs {
		if !use(d) {
			continue
		}
		spans, err := d.find(ctx, scan)
		if errors.Is(err, errTooManyMatches) { // fail closed: a text this full of matches is not passed on
			res.note(d)
			return HookResult{Text: fmt.Sprintf("The text has too many matches for the hook %q, so it was not used.", d.name), Outcome: OutcomeBlocked, Hits: res.Hits}, nil
		}
		if err != nil {
			return HookResult{}, err
		}
		if len(spans) == 0 {
			continue
		}
		res.note(d)
		switch d.action {
		case ActionBlock:
			return HookResult{Text: d.message, Outcome: OutcomeBlocked, Hits: res.Hits}, nil
		case ActionApprove:
			return HookResult{Text: d.message, Outcome: OutcomeHeld, Hits: res.Hits}, nil
		}
		res.Text = maskSpans(res.Text, spans)
		res.Outcome = OutcomeMasked
		scan = &scanText{orig: res.Text}
	}
	return res, nil
}

// CheckTool is the before_tool moment for one tool call the model asked for. A write tool (or any access
// value other than "read") is always held for approval by the locked write-approval hook; it never runs
// from here (INV-15, SYS-8). A read tool has its arguments checked by the before_tool hooks.
func (r *HookRunner) CheckTool(ctx context.Context, access Access, args string) (HookResult, error) {
	if access != AccessRead {
		info := builtinInfo[2]
		hit := HookHit{ID: info.ID, Name: info.Name, Kind: KindBuiltin, When: BeforeTool, Action: ActionApprove,
			Message: "This tool changes something. It runs only through an action a person approves in the AI response module."}
		return HookResult{Text: hit.Message, Outcome: OutcomeHeld, Hits: []HookHit{hit}}, nil
	}
	return r.Run(ctx, BeforeTool, args)
}

func (r *HookResult) note(d hookDef) {
	h := HookHit{ID: d.id, Name: d.name, Kind: d.kind, When: d.when, Action: d.action, Message: d.message}
	for _, x := range r.Hits {
		if x == h {
			return
		}
	}
	r.Hits = append(r.Hits, h)
}

// ---- definitions

type hookDef struct {
	id, name, message string
	kind              HookKind
	when              HookWhen
	action            HookAction
	find              func(context.Context, *scanText) ([]span, error)
}

func piiDef(action HookAction, message string, find func(context.Context, *scanText) ([]span, error)) hookDef {
	return hookDef{id: HookBlockPII, name: builtinInfo[0].Name, kind: KindBuiltin, when: BeforeAI, action: action, message: message, find: find}
}

// Blocking first, then masking: an ID number stops the text at once instead of being masked piecemeal.
var piiDefs = []hookDef{
	piiDef(ActionBlock, "The text contains an ID number. It was not sent to the AI. Remove the number and ask again.", plain(findIDNumbers)),
	piiDef(ActionMask, "An email address was masked before the text went to the AI.", plain(findEmails)),
	piiDef(ActionMask, "A phone number was masked before the text went to the AI.", plain(findPhones)),
	piiDef(ActionMask, "A person name next to an account was masked before the text went to the AI.", plain(findAccountNames)),
}

var offTopicDef = hookDef{id: HookSecurityOnly, name: builtinInfo[1].Name, kind: KindBuiltin, when: BeforeAI, action: ActionBlock,
	message: "This box's AI only helps with the security of this network, so it did not take this request. Ask about your devices, findings, logs or exposure.",
	find:    plain(findOffTopic)}
