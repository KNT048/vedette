package ai

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var bg = context.Background()

func runner(t *testing.T, builtin map[string]bool, custom ...CustomHook) *HookRunner {
	t.Helper()
	r, err := NewHookRunner(builtin, custom)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func run(t *testing.T, r *HookRunner, when HookWhen, text string) HookResult {
	t.Helper()
	res, err := r.Run(bg, when, text)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestBuiltinPII(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	res := run(t, r, BeforeAI, "Mail an.nguyen@example.com or call 0912 345 678 about account Nguyen Van An")
	if res.Outcome != OutcomeMasked || strings.Contains(res.Text, "example.com") || strings.Contains(res.Text, "0912") || strings.Contains(res.Text, "Nguyen") {
		t.Fatalf("%+v", res)
	}
	if res.Text != "Mail [masked] or call [masked] about account [masked]" {
		t.Fatalf("text: %q", res.Text)
	}
	if len(res.Hits) != 3 || res.Hits[0].Action != ActionMask || res.Hits[0].ID != HookBlockPII || res.Hits[0].Kind != KindBuiltin || res.Hits[0].When != BeforeAI {
		t.Fatalf("hits: %+v", res.Hits)
	}
	if got := res.Names(); len(got) != 1 || got[0] != "Block personal data" {
		t.Fatalf("names: %v", got)
	}
	if run(t, r, BeforeAI, "CCCD 079123456789 owns this laptop").Outcome != OutcomeBlocked {
		t.Fatal("12-digit ID number not blocked")
	}
	if run(t, r, BeforeAI, "CMND 123456789.").Outcome != OutcomeBlocked {
		t.Fatal("9-digit ID number not blocked")
	}
	if res := run(t, r, BeforeAI, "Which machines still expose RDP on 192.168.10.5?"); res.Outcome != OutcomePass || len(res.Hits) != 0 {
		t.Fatalf("%+v", res)
	}
	// Blocking wins over masking: an ID number next to an email stops the text, nothing is half-masked.
	if res := run(t, r, BeforeAI, "me@example.com 079123456789"); res.Outcome != OutcomeBlocked || strings.Contains(res.Text, "[masked]") {
		t.Fatalf("%+v", res)
	}
}

func TestIDNumberBoundaries(t *testing.T) {
	t.Parallel()
	for text, blocked := range map[string]bool{
		"079123456789": true, "id: 079123456789!": true, "123456789": true, "x 123456789 y": true,
		"12345678": false, "1234567890": false, "12345678901": false, "1234567890123": false, // not 9 or 12
		"1.123456789": false, "v2.079123456789": false, // after a dot: a decimal or a version
		"ab123456789": true, "123456789.5": true, "": false,
	} {
		if got := len(findIDNumbers(text)) > 0; got != blocked {
			t.Errorf("%q: blocked=%v, want %v", text, got, blocked)
		}
	}
}

func TestPhoneNumbers(t *testing.T) {
	t.Parallel()
	masked := map[string]string{
		"call 0912 345 678 now":       "call [masked] now",
		"0912345678":                  "[masked]",
		"call 090.123.4567.":          "call [masked].",
		"+84 912 345 678":             "[masked]",
		"84912345678 please":          "[masked] please",
		"+1 415-555-2671 office":      "[masked] office",
		"+442071234567":               "[masked]",
		"0912 345 678 9 tail":         "[masked] tail", // the separator before the last digit keeps it inside the match
		"two: 0912345678, 0987654321": "two: [masked], [masked]",
	}
	for in, want := range masked {
		if got := maskSpans(in, findPhones(in)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{
		"192.168.10.250", "10.0.0.138", "port 3389 open", "2026-11-09", "2026-11-09T10:11:12Z", "CVE-2024-12345",
		"0912345678901234",      // too many digits after the prefix
		"a0912345678",           // glued to a word
		"v1.0912345678",         // after a dot
		"1234567", "+1 234 567", // too short
		"build 8491234567890123", "0 1 2 3", "",
	} {
		if sp := findPhones(in); len(sp) != 0 {
			t.Errorf("%q wrongly matched %v", in, sp)
		}
	}
}

func TestSecurityOnly(t *testing.T) {
	t.Parallel()
	if res := run(t, runner(t, nil), BeforeAI, "Write a poem about my firewall"); res.Outcome != OutcomeBlocked || !strings.Contains(res.Text, "only helps with the security") {
		t.Fatalf("%+v", res)
	}
	r := runner(t, map[string]bool{HookSecurityOnly: false})
	if run(t, r, BeforeAI, "Write a poem about my firewall").Outcome != OutcomePass {
		t.Fatal("turned off, still blocked")
	}
}

func TestContract_INV12_HookMomentsActionsAndBuiltins(t *testing.T) {
	t.Parallel()
	hooks := []CustomHook{
		{ID: "h1", Name: "Falcon", When: BeforeAI, Match: HookMatch{MatchKeywords, "project falcon, falcon"}, Action: ActionBlock, Message: "No code names.", Enabled: true},
		{ID: "h2", Name: "Mask passwords", When: AfterAI, Match: HookMatch{MatchRegex, `password\s*[:=]\s*\S+`}, Action: ActionMask, Message: "A password was removed.", Enabled: true},
		{ID: "h3", Name: "Firewall tool", When: BeforeTool, Match: HookMatch{MatchKeywords, "delete policy"}, Action: ActionApprove, Message: "Needs a person.", Enabled: true},
		{ID: "h4", Name: "Off", When: BeforeAI, Match: HookMatch{MatchKeywords, "banana"}, Action: ActionBlock, Message: "Never fires.", Enabled: false},
	}
	r := runner(t, nil, hooks...)
	// Each hook runs only at its own moment.
	if res := run(t, r, BeforeAI, "about Project Falcon"); res.Outcome != OutcomeBlocked || res.Text != "No code names." || res.Hits[0].ID != "h1" || res.Hits[0].Kind != KindCustom {
		t.Fatalf("block: %+v", res)
	}
	if run(t, r, AfterAI, "about Project Falcon").Outcome != OutcomePass || run(t, r, BeforeTool, "about Project Falcon").Outcome != OutcomePass {
		t.Fatal("hook ran at the wrong moment")
	}
	if res := run(t, r, AfterAI, "the Password: hunter2 is in the log"); res.Outcome != OutcomeMasked || res.Text != "the [masked] is in the log" {
		t.Fatalf("mask: %+v", res)
	}
	if res := run(t, r, BeforeTool, `{"cmd":"Delete Policy 5"}`); res.Outcome != OutcomeHeld || res.Text != "Needs a person." {
		t.Fatalf("approve: %+v", res)
	}
	if run(t, r, BeforeAI, "banana").Outcome != OutcomePass {
		t.Fatal("disabled hook acted")
	}

	// Built-ins: write-approval is locked on; the other two can be turned off.
	if _, err := NewHookRunner(map[string]bool{HookWriteApproval: false}, nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("disabling write-approval: %v", err)
	}
	if !errors.Is(ValidateBuiltinToggle(HookWriteApproval, false), ErrLocked) || ValidateBuiltinToggle(HookWriteApproval, true) != nil ||
		ValidateBuiltinToggle(HookBlockPII, false) != nil || !errors.Is(ValidateBuiltinToggle("nope", true), ErrUnknownHook) {
		t.Fatal("ValidateBuiltinToggle")
	}
	if _, err := NewHookRunner(map[string]bool{"nope": true}, nil); !errors.Is(err, ErrUnknownHook) {
		t.Fatalf("unknown builtin: %v", err)
	}
	off := runner(t, map[string]bool{HookBlockPII: false, HookSecurityOnly: false, HookWriteApproval: true})
	if run(t, off, BeforeAI, "mail me@example.com, ID 079123456789, write a poem").Outcome != OutcomePass {
		t.Fatal("turned-off built-ins still acted")
	}
	b := off.Builtins()
	if len(b) != 3 || b[0].Enabled || b[1].Enabled || !b[2].Enabled || !b[2].Locked || b[0].Locked || b[2].ID != HookWriteApproval {
		t.Fatalf("builtins view: %+v", b)
	}
	// An invalid enabled custom hook stops the runner from being built; a disabled one is not compiled.
	bad := CustomHook{ID: "x", Name: "Bad", When: BeforeAI, Match: HookMatch{MatchRegex, `a(?=b)`}, Action: ActionBlock, Message: "msg ok", Enabled: true}
	if _, err := NewHookRunner(nil, []CustomHook{bad}); !errors.Is(err, ErrInvalidHook) {
		t.Fatalf("bad hook: %v", err)
	}
	bad.Enabled = false
	if _, err := NewHookRunner(nil, []CustomHook{bad}); err != nil {
		t.Fatalf("disabled bad hook: %v", err)
	}
}

// INV-15 (the part this library owns): a write tool call is never allowed through before_tool, even with
// every other hook off. It is held for the approval flow of the response module.
func TestCheckToolHoldsWriteTools(t *testing.T) {
	t.Parallel()
	all := runner(t, map[string]bool{HookBlockPII: false, HookSecurityOnly: false})
	for _, access := range []Access{AccessWrite, "", "WRITE", "exec"} {
		res, err := all.CheckTool(bg, access, `{"ip":"10.0.0.1"}`)
		if err != nil || res.Outcome != OutcomeHeld || len(res.Hits) != 1 || res.Hits[0].ID != HookWriteApproval || res.Hits[0].Action != ActionApprove {
			t.Errorf("access %q: %+v %v", access, res, err)
		}
	}
	read := runner(t, nil, CustomHook{ID: "h", Name: "No admin", When: BeforeTool, Match: HookMatch{MatchKeywords, "root"}, Action: ActionBlock, Message: "No root.", Enabled: true})
	if res, _ := read.CheckTool(bg, AccessRead, `{"user":"root"}`); res.Outcome != OutcomeBlocked {
		t.Fatalf("read tool args must go through before_tool hooks: %+v", res)
	}
	if res, _ := read.CheckTool(bg, AccessRead, `{"user":"bob"}`); res.Outcome != OutcomePass {
		t.Fatalf("%+v", res)
	}
}

// INV-13: a blocked question is not stored as typed and costs no tokens (nothing is sent).
func TestContract_INV13_BlockedQuestionHiddenAndFree(t *testing.T) {
	t.Parallel()
	r := runner(t, nil, CustomHook{ID: "h", Name: "Falcon", When: BeforeAI, Match: HookMatch{MatchKeywords, "falcon"}, Action: ActionBlock, Message: "No code names.", Enabled: true})
	sent := 0
	ask := func(q string) (stored string) {
		res := run(t, r, BeforeAI, q)
		if res.Outcome != OutcomeBlocked && res.Outcome != OutcomeHeld {
			sent++ // the only place a provider would be called
		}
		return QuestionForStorage(q, res)
	}
	if got := ask("Whose laptop is this? ID 079123456789"); got != "[question hidden: contains personal data]" {
		t.Fatalf("PII block: %q", got)
	}
	if got := ask("Tell me about falcon"); got != HiddenQuestion {
		t.Fatalf("custom block must hide too: %q", got)
	}
	if sent != 0 {
		t.Fatalf("a blocked question was sent %d times", sent)
	}
	if got := ask("Reply to me@example.com about RDP"); got != "Reply to [masked] about RDP" || sent != 1 {
		t.Fatalf("masked: %q sent=%d", got, sent)
	}
	if got := ask("Which machines expose RDP?"); got != "Which machines expose RDP?" {
		t.Fatalf("pass: %q", got)
	}
}

func TestCustomHookValidation(t *testing.T) {
	t.Parallel()
	ok := CustomHook{ID: "h", Name: "Name", When: BeforeAI, Match: HookMatch{MatchKeywords, "word"}, Action: ActionBlock, Message: "msg", Enabled: true}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*CustomHook)) CustomHook { h := ok; f(&h); return h }
	cases := map[string]struct {
		h    CustomHook
		code string
	}{
		"empty name":         {mut(func(h *CustomHook) { h.Name = "  " }), "invalid_name"},
		"name 41":            {mut(func(h *CustomHook) { h.Name = strings.Repeat("n", 41) }), "invalid_name"},
		"message 2":          {mut(func(h *CustomHook) { h.Message = "no" }), "invalid_message"},
		"message 201":        {mut(func(h *CustomHook) { h.Message = strings.Repeat("m", 201) }), "invalid_message"},
		"bad when":           {mut(func(h *CustomHook) { h.When = "during" }), "invalid_when"},
		"bad action":         {mut(func(h *CustomHook) { h.Action = "delete" }), "invalid_action"},
		"bad type":           {mut(func(h *CustomHook) { h.Match.Type = "glob" }), "invalid_match_type"},
		"empty pattern":      {mut(func(h *CustomHook) { h.Match.Pattern = "" }), "invalid_pattern"},
		"pattern 201":        {mut(func(h *CustomHook) { h.Match.Pattern = strings.Repeat("a", 201) }), "invalid_pattern"},
		"only commas":        {mut(func(h *CustomHook) { h.Match.Pattern = " , ,," }), "invalid_pattern"},
		"matches empty":      {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, "a*"} }), "invalid_pattern"},
		"unclosed":           {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, "(abc"} }), "unsupported_regex"},
		"lookahead":          {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `foo(?=bar)`} }), "unsupported_regex"},
		"negative lookahead": {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `foo(?!bar)`} }), "unsupported_regex"},
		"lookbehind":         {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `(?<=a)b`} }), "unsupported_regex"},
		"neg lookbehind":     {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `(?<!a)b`} }), "unsupported_regex"},
		"backreference":      {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `(a)\1`} }), "unsupported_regex"},
		"js unicode escape":  {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, "\\" + "u0041"} }), "unsupported_regex"},
		"huge repeat":        {mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `a{2000}`} }), "unsupported_regex"},
	}
	for name, c := range cases {
		err := c.h.Validate()
		var he *HookError
		if !errors.As(err, &he) || he.Code != c.code || !errors.Is(err, ErrInvalidHook) {
			t.Errorf("%s: want %s, got %v", name, c.code, err)
			continue
		}
		if c.code == "unsupported_regex" && !strings.Contains(he.Msg, "RE2") {
			t.Errorf("%s: the message must explain the syntax: %s", name, he.Msg)
		}
	}
	if err := mut(func(h *CustomHook) { h.Match = HookMatch{MatchRegex, `password\s*[:=]\s*\S+`} }).Validate(); err != nil {
		t.Errorf("valid RE2 pattern rejected: %v", err)
	}
	// Length is counted in characters, not bytes.
	if err := mut(func(h *CustomHook) { h.Name = strings.Repeat("đ", 40) }).Validate(); err != nil {
		t.Errorf("40 characters: %v", err)
	}
}

func TestKeywordMatching(t *testing.T) {
	t.Parallel()
	words := []string{"ab", "abc", "a.b", "C++"}
	cases := map[string]string{
		"abc":         "[masked]",
		"xabc abc":    "xabc [masked]",
		"say ABC now": "say [masked] now",
		"a.b and axb": "[masked] and axb",
		"learn c++!":  "learn [masked]!",
		"ab_c abcd":   "ab_c abcd",
		"(ab)":        "([masked])",
		"ab ab,abc":   "[masked] [masked],[masked]",
		"đab":         "đ[masked]", // a non-ASCII letter is not a word character in the original either
		"":            "",
	}
	for in, want := range cases {
		if got := maskSpans(in, findKeywords(in, words)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestRunLimits(t *testing.T) {
	t.Parallel()
	r := runner(t, nil, CustomHook{ID: "h", Name: "Nested", When: AfterAI, Match: HookMatch{MatchRegex, `(a+)+$`}, Action: ActionBlock, Message: "Blocked.", Enabled: true})
	big := strings.Repeat("a", 512<<10) + "!"
	start := time.Now()
	res, err := r.Run(bg, AfterAI, big)
	if err != nil || res.Outcome != OutcomePass {
		t.Fatalf("%+v %v", res, err)
	}
	if d := time.Since(start); d > 10*time.Second { // a backtracking engine would never finish; RE2 is linear
		t.Fatalf("pathological pattern took %v", d)
	}
	if _, err := r.Run(bg, AfterAI, strings.Repeat("a", MaxHookInputBytes+1)); !errors.Is(err, ErrHookInputTooLarge) {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := r.Run(bg, AfterAI, strings.Repeat("a", MaxHookInputBytes)); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := r.Run(ctx, AfterAI, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}

func TestMaskKeepsMultibyteTextValid(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	res := run(t, r, BeforeAI, "Gửi tới an@example.com cho tài khoản, số 0912 345 678 — cảm ơn")
	if !utf8.ValidString(res.Text) || res.Text != "Gửi tới [masked] cho tài khoản, số [masked] — cảm ơn" {
		t.Fatalf("%q", res.Text)
	}
}

func FuzzHookRun(f *testing.F) {
	custom := []CustomHook{
		{ID: "k", Name: "Keywords", When: BeforeAI, Match: HookMatch{MatchKeywords, "falcon, project x"}, Action: ActionMask, Message: "masked it", Enabled: true},
		{ID: "r", Name: "Regex", When: BeforeAI, Match: HookMatch{MatchRegex, `secret[:=]\s*\w+`}, Action: ActionMask, Message: "masked it", Enabled: true},
	}
	r, err := NewHookRunner(nil, custom)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"", "mail me@example.com", "call 0912 345 678", "+84 912 345 678", "ID 079123456789", "account Nguyen Van An", "secret: abc falcon", "write a poem", "0\x00\xff+", "1.123456789 x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		res, err := r.Run(bg, BeforeAI, text)
		if err != nil {
			t.Fatal(err)
		}
		switch res.Outcome {
		case OutcomePass:
			if res.Text != text || len(res.Hits) != 0 {
				t.Fatalf("pass changed the text: %q -> %q", text, res.Text)
			}
		case OutcomeMasked:
			if len(res.Hits) == 0 || !strings.Contains(res.Text, "[masked]") || len(res.Text) > len(text)+8*(len(text)+1) {
				t.Fatalf("masked inconsistently: %q -> %q", text, res.Text)
			}
		case OutcomeBlocked, OutcomeHeld:
			if len(res.Hits) == 0 || res.Text != res.Hits[len(res.Hits)-1].Message {
				t.Fatalf("blocked without its message: %+v", res)
			}
		default:
			t.Fatalf("outcome %q", res.Outcome)
		}
		for _, sp := range slices.Concat(findIDNumbers(text), findPhones(text)) {
			if sp.start < 0 || sp.end > len(text) || sp.start >= sp.end {
				t.Fatalf("bad span %v in %q", sp, text)
			}
		}
	})
}
