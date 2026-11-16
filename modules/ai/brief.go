package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/ai/provider"
)

// The brief is the small door the mitigation module uses (`mitigation.AI`): the AI explains a finding or drafts a
// recommendation for it, and the answer is a few paragraphs and steps. Like every AI output it is a suggestion: mitigation stores
// it as an AI result and the page labels it as AI-generated, never as a confirmed recommendation (INV-5, D-21).

// BriefRequest is one such call. Data holds the device and feed text of the finding; it is untrusted and goes into the prompt only
// as fenced data.
type BriefRequest struct {
	Job      Job // JobExplainFinding or JobMitigationConfig
	Actor    string
	Target   string // the CVE, for the activity summary
	Question string
	Data     []DataBlock
}

// BriefAnswer is the checked answer. Citations are not part of it: the caller builds them from the feed entry.
type BriefAnswer struct {
	Model      string
	Profile    string
	TokensIn   int
	TokensOut  int
	Paragraphs []string
	Steps      []string
	// Configs are the ready configuration blocks of a mitigation-config answer (none for explain-finding).
	Configs []BriefConfig
	// Shortened is set when a part of the answer was longer than the box keeps: a text was cut at a sentence end (never mid-sentence)
	// or a config block was left out whole (a cut config could be pasted half), so the page can say so (M2-2).
	Shortened  bool
	ActivityID string
}

// BriefConfig is one configuration block a person can paste as it is: the device-side workaround, or a rule for one firewall.
type BriefConfig struct {
	Title      string // the target: "Juniper EX4200-48T (Junos)", "FortiGate 60F"
	Code       string // the lines, joined with line breaks
	SideEffect string // what it can break, shown before the person copies it
	BasedOn    string // the source the change follows ("the vendor advisory linked in the entry")
}

type briefBody struct {
	Paragraphs []string        `json:"paragraphs"`
	Steps      []string        `json:"steps"`
	Configs    []briefConfigIn `json:"configs"`
}

type briefConfigIn struct {
	Title      string   `json:"title"`
	Lines      []string `json:"lines"`
	SideEffect string   `json:"side_effect"`
	BasedOn    string   `json:"based_on"`
}

const briefSchema = `{"type":"object","properties":{"paragraphs":{"type":"array","items":{"type":"string"}},"steps":{"type":"array","items":{"type":"string"}}},"required":["paragraphs","steps"],"additionalProperties":false}`

// briefConfigSchema is the mitigation-config answer: the explanation and the order of work, plus the config blocks themselves. Each
// line of a block is its own string, so every line goes through the after_ai hooks in the form that is kept (INV-12).
const briefConfigSchema = `{"type":"object","properties":{"paragraphs":{"type":"array","items":{"type":"string"}},"steps":{"type":"array","items":{"type":"string"}},"configs":{"type":"array","items":{"type":"object","properties":{"title":{"type":"string"},"lines":{"type":"array","items":{"type":"string"}},"side_effect":{"type":"string"},"based_on":{"type":"string"}},"required":["title","lines","side_effect","based_on"],"additionalProperties":false}}},"required":["paragraphs","steps","configs"],"additionalProperties":false}`

const (
	briefExplainTask = `Explain one finding for this company's network: a device the box matched to an exploited vulnerability. Use only the facts in the data blocks. In "paragraphs" write at most 4 short paragraphs of plain English: what the vulnerability is, whether it touches this device and why, and what an attacker could do. In "steps" write the steps a person should take, in order. Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`
	briefConfigTask  = `Write ready-to-paste configuration that reduces the risk of one exploited vulnerability on this device until it is patched. Use only the facts in the data blocks: the device block gives the device, its installed software and version, the affected range and the fixed releases, and its open ports; the network block lists the firewalls and routers in the company's inventory. In "paragraphs" write at most 3 short paragraphs of plain English: whether the installed version is inside the affected range and which release fixes it (say so from the data, do not ask the person to look it up when the data has it), what the configuration below does, and what it can break. In "configs" give the configuration blocks, each a "title" naming the target (vendor and model), its "lines" exactly as a person pastes them into that product's command line, one command per line, its "side_effect" (what stops working, and how not to lock yourself out), and "based_on" (which source in the data the change follows, or "general hardening" when none names it). First one block for the device itself in its own configuration language: the vendor's known workaround for this vulnerability, such as turning off or restricting the vulnerable service. Then one block for each firewall or router vendor in the network block, in that vendor's own syntax, that blocks or limits access from other networks to the vulnerable service of this device (its IP address and ports from the data). When the network block lists no firewall or router, or none whose vendor is known, give one block for a Linux gateway with nftables. Use the values in the data; write a named placeholder such as <ADMIN_NETWORK> only for what the data cannot know. In "steps" write at most 8 short steps: back up the current configuration, apply, verify, and how to undo. Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`
)

// briefMaxTokens is the output limit of an explanation. The answer itself (4 paragraphs and a list of steps, as JSON) runs to about
// 900 tokens, but the limit also covers what a model thinks before it answers (Claude Haiku 5.5 thinks by default; OpenAI reasoning
// models and Gemini count it the same way), which can be a few thousand. The meter counts what is really used, not this limit; a cut
// answer is asked again once with twice the limit (Router.retryCut). briefConfigMaxTokens is the same for mitigation-config, whose
// config blocks (the device's own and one per firewall vendor) add about 1,500 tokens.
const (
	briefMaxTokens       = 6000
	briefConfigMaxTokens = 8000
)

// Limits on what a brief keeps (the model's text is untrusted). A text over its limit is cut at the end of a sentence, never in the
// middle of one (M2-2: "No confirmed recommendation exists yet, and a" was a paragraph cut at 500 characters); a config block over its
// limits is left out whole. Either sets BriefAnswer.Shortened.
const (
	briefMaxParagraphs = 6
	briefParagraphRune = 1500
	briefMaxSteps      = 12
	briefStepRunes     = 600
	briefMaxConfigs    = 8
	briefMaxLines      = 80
	briefLineRunes     = 400
	briefTitleRunes    = 200
	briefSideRunes     = 800
)

func parseBrief(text string, job Job) (briefBody, error) {
	var b briefBody
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return briefBody{}, ErrBadOutput
	}
	keys := []string{"paragraphs", "steps"}
	if job == JobMitigationConfig {
		keys = append(keys, "configs")
	}
	if !hasKeys(text, keys...) {
		return briefBody{}, ErrBadOutput
	}
	if len(cleanList(b.Paragraphs)) == 0 {
		return briefBody{}, ErrBadOutput
	}
	if job == JobMitigationConfig { // the job is the config: an answer without one is not what was asked (M2-2)
		found := false
		for _, c := range b.Configs {
			for _, l := range c.Lines {
				found = found || strings.TrimSpace(l) != ""
			}
		}
		if !found {
			return briefBody{}, ErrBadOutput
		}
	} else {
		b.Configs = nil
	}
	return b, nil
}

// keptBrief is the answer as it is kept: texts within their limits, cut at a sentence end, and the config blocks that fit whole.
func keptBrief(b briefBody) (a BriefAnswer) {
	a.Paragraphs, a.Shortened = sentenceList(b.Paragraphs, briefMaxParagraphs, briefParagraphRune)
	var cut bool
	a.Steps, cut = sentenceList(b.Steps, briefMaxSteps, briefStepRunes)
	a.Shortened = a.Shortened || cut
	for _, c := range b.Configs {
		code, ok := codeBlock(c.Lines)
		if code == "" {
			continue
		}
		if !ok || len(a.Configs) == briefMaxConfigs {
			a.Shortened = true
			continue
		}
		title, c1 := clipSentence(cleanText(c.Title), briefTitleRunes)
		side, c2 := clipSentence(cleanText(c.SideEffect), briefSideRunes)
		basis, c3 := clipSentence(cleanText(c.BasedOn), briefTitleRunes)
		a.Shortened = a.Shortened || c1 || c2 || c3
		if title == "" {
			title = "Configuration"
		}
		a.Configs = append(a.Configs, BriefConfig{Title: title, Code: code, SideEffect: side, BasedOn: basis})
	}
	return a
}

// sentenceList cleans a list of texts, drops empty ones and keeps at most n, each cut at a sentence end within runes characters.
func sentenceList(in []string, n, runes int) ([]string, bool) {
	out, cut := []string{}, false
	for _, s := range in {
		s, c := clipSentence(cleanText(s), runes)
		if s == "" {
			continue
		}
		if len(out) == n {
			return out, true
		}
		cut = cut || c
		out = append(out, s)
	}
	return out, cut
}

// codeBlock joins the lines of a config block. A line may itself hold line breaks (the model put two commands in one string): it is
// split. Control characters go, a tab becomes two spaces, the indentation stays, and blank lines at the ends go. ok is false when the
// block is longer than the limits: it is then left out whole, because half a config can be pasted and do harm.
func codeBlock(lines []string) (string, bool) {
	var out []string
	for _, l := range lines {
		for _, part := range strings.Split(strings.ReplaceAll(l, "\r\n", "\n"), "\n") {
			part = strings.TrimRight(strings.Map(func(r rune) rune {
				switch {
				case r == '\t':
					return ' '
				case unicode.IsControl(r):
					return -1
				}
				return r
			}, strings.ToValidUTF8(part, "\uFFFD")), " ")
			if utf8.RuneCountInString(part) > briefLineRunes {
				return "", false
			}
			out = append(out, part)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if len(out) > briefMaxLines {
		return "", false
	}
	return strings.Join(out, "\n"), true
}

// clipSentence cuts s to at most n characters at the end of a sentence (". ", "! ", "? " or the end), so a kept text never stops in
// the middle of one; when no sentence ends in the last two thirds it cuts at a word and ends with "…". cut reports whether it cut.
func clipSentence(s string, n int) (string, bool) {
	r := []rune(s)
	if len(r) <= n {
		return s, false
	}
	r = r[:n]
	for i := len(r) - 1; i >= n/3; i-- {
		if (r[i] == '.' || r[i] == '!' || r[i] == '?') && (i+1 == len(r) || r[i+1] == ' ') {
			return string(r[:i+1]), true
		}
	}
	for i := len(r) - 1; i >= n/3; i-- {
		if r[i] == ' ' {
			return strings.TrimRight(string(r[:i]), " ,;:") + "…", true
		}
	}
	return string(r[:n-1]) + "…", true
}

// Available reports whether the ai module is on and a profile is assigned and allowed for the job.
func (s *Service) Available(job Job) bool {
	return s.moduleOn() && s.Ready(job) == nil
}

func (s *Service) moduleOn() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

// Brief runs an explain-finding or mitigation-config call for a finding. It returns the *apierr.Error of RunJob (409
// ai_unavailable, 429 budget_reached) so the caller can tell "cannot be used" from a failure.
func (s *Service) Brief(ctx context.Context, r BriefRequest) (BriefAnswer, error) {
	if !s.moduleOn() { // a door another module holds must not run the AI while the module is off
		return BriefAnswer{}, apiUnavailable("The AI assistant module is off. Turn it on in Settings, Modules.")
	}
	task, schema, limit := briefExplainTask, briefSchema, briefMaxTokens
	switch r.Job {
	case JobExplainFinding:
	case JobMitigationConfig:
		task, schema, limit = briefConfigTask, briefConfigSchema, briefConfigMaxTokens
	default:
		return BriefAnswer{}, fmt.Errorf("ai: brief: job %q is not a finding job", r.Job)
	}
	var body briefBody
	res, err := s.RunJob(ctx, JobSpec{
		Job: r.Job, Actor: r.Actor, Task: task, Question: r.Question, Data: r.Data,
		Schema: &provider.Schema{Name: "finding_brief", JSON: json.RawMessage(schema)}, MaxTokens: limit,
		Summary: fmt.Sprintf("%s for %s", strings.ToUpper(r.Job.Name()[:1])+r.Job.Name()[1:], clipRunes(cleanLine(r.Target, 40), 40)),
		Check: func(text string) error {
			var perr error
			body, perr = parseBrief(text, r.Job)
			return perr
		},
	})
	if err != nil {
		return BriefAnswer{}, err
	}
	a := keptBrief(body)
	a.Model, a.Profile, a.TokensIn, a.TokensOut, a.ActivityID = res.Model, res.Profile, res.TokensIn, res.TokensOut, res.ActivityID
	return a, nil
}

// Configured reports whether at least one AI profile can be used (a key, or a model inside the network): flow 3 of the Privacy page.
func (s *Service) Configured() bool {
	for _, p := range s.snap.Load().profiles {
		if p.Usable() {
			return true
		}
	}
	return false
}
