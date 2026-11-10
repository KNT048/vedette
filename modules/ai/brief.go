package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	ActivityID string
}

type briefBody struct {
	Paragraphs []string `json:"paragraphs"`
	Steps      []string `json:"steps"`
}

const briefSchema = `{"type":"object","properties":{"paragraphs":{"type":"array","items":{"type":"string"}},"steps":{"type":"array","items":{"type":"string"}}},"required":["paragraphs","steps"],"additionalProperties":false}`

const (
	briefExplainTask = `Explain one finding for this company's network: a device the box matched to an exploited vulnerability. Use only the facts in the data blocks. In "paragraphs" write at most 4 short paragraphs of plain English: what the vulnerability is, whether it touches this device and why, and what an attacker could do. In "steps" write the steps a person should take, in order. Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`
	briefConfigTask  = `Draft a recommendation for one finding that has no confirmed recommendation yet: how to reduce the risk of an exploited vulnerability on this device until it is patched. Use only the facts in the data blocks. In "paragraphs" write at most 3 short paragraphs of plain English that say what the configuration change is for and what side effects it can have. In "steps" write the configuration steps, one action per step, for the firewall or device type named in the data. Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`
)

func parseBrief(text string) (briefBody, error) {
	var b briefBody
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return briefBody{}, ErrBadOutput
	}
	if !hasKeys(text, "paragraphs", "steps") {
		return briefBody{}, ErrBadOutput
	}
	b.Paragraphs, b.Steps = cleanList(b.Paragraphs), cleanList(b.Steps)
	if len(b.Paragraphs) == 0 {
		return briefBody{}, ErrBadOutput
	}
	return b, nil
}

// Available reports whether the ai module is on and a profile is assigned and allowed for the job.
func (s *Service) Available(job Job) bool {
	return s.moduleOn() && s.Ready(job) == nil
}

func (s *Service) moduleOn() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

// Brief runs an explain-finding or mitigation-config call for a finding. It returns the *apierr.Error of RunJob (409
// ai_unavailable, 429 daily_cap) so the caller can tell "cannot be used" from a failure.
func (s *Service) Brief(ctx context.Context, r BriefRequest) (BriefAnswer, error) {
	if !s.moduleOn() { // a door another module holds must not run the AI while the module is off
		return BriefAnswer{}, apiUnavailable("The AI assistant module is off. Turn it on in Settings, Modules.")
	}
	var task string
	switch r.Job {
	case JobExplainFinding:
		task = briefExplainTask
	case JobMitigationConfig:
		task = briefConfigTask
	default:
		return BriefAnswer{}, fmt.Errorf("ai: brief: job %q is not a finding job", r.Job)
	}
	var body briefBody
	res, err := s.RunJob(ctx, JobSpec{
		Job: r.Job, Actor: r.Actor, Task: task, Question: r.Question, Data: r.Data,
		Schema: &provider.Schema{Name: "finding_brief", JSON: json.RawMessage(briefSchema)}, MaxTokens: 1000,
		Summary: fmt.Sprintf("%s for %s", strings.ToUpper(r.Job.Name()[:1])+r.Job.Name()[1:], clipRunes(cleanLine(r.Target, 40), 40)),
		Check: func(text string) error {
			var perr error
			body, perr = parseBrief(text)
			return perr
		},
	})
	if err != nil {
		return BriefAnswer{}, err
	}
	return BriefAnswer{Model: res.Model, Profile: res.Profile, TokensIn: res.TokensIn, TokensOut: res.TokensOut,
		Paragraphs: body.Paragraphs, Steps: body.Steps, ActivityID: res.ActivityID}, nil
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
