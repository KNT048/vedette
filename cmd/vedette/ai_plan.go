package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/response"
)

// responsePlanner is response.Planner over ai.Service.RunJob for the job response-plan (S-RESP-1). The model gets the finding, the
// device and the list of catalog actions it may propose, and answers with a JSON object of steps. It has no tool: it cannot read or change
// anything. What it names is checked by response (savePlan) before anything is stored; this adapter only moves text.
type responsePlanner struct {
	svc   *ai.Service
	facts ai.Facts // the exploited-list entry of the CVE; nil = the CVE id only
}

func (p responsePlanner) Available(context.Context) bool { return p.svc.Available(ai.JobResponsePlan) }

const planSchema = `{"type":"object","properties":{"steps":{"type":"array","items":{"type":"object","properties":{` +
	`"kind":{"type":"string","enum":["contain","check","patch"]},"title":{"type":"string"},"detail":{"type":"string"},` +
	`"action_id":{"type":"string"},"params":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"],"additionalProperties":false}}},` +
	`"required":["kind","title","detail","action_id","params"],"additionalProperties":false}}},"required":["steps"],"additionalProperties":false}`

const planTask = `Write a short response plan for one finding: a device that the box matched to an exploited vulnerability. Use only the facts in the data blocks. ` +
	`Give 2 to 5 steps, each with a kind: "contain" (limit exposure now), "check" (look for signs of compromise) or "patch" (fix it). ` +
	`A "contain" step may propose ONE action from the list of actions below: put its id in "action_id" and the values of its parameters in "params" as name and value pairs, using only the parameter names listed for it. ` +
	`Propose an action only when it clearly fits this device. For every other step set "action_id" to an empty string and "params" to an empty list. ` +
	`You cannot run anything: a person reads the plan and decides. Never invent addresses, ids, versions or links that are not in the data. Reply with one JSON object only.`

type draftWire struct {
	Steps []struct {
		Kind     string `json:"kind"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		ActionID string `json:"action_id"`
		Params   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"params"`
	} `json:"steps"`
}

func parsePlan(text string) (response.PlanDraft, error) {
	var w draftWire
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() || len(w.Steps) == 0 {
		return response.PlanDraft{}, ai.ErrBadOutput
	}
	var d response.PlanDraft
	for _, s := range w.Steps {
		x := response.DraftStep{Kind: s.Kind, Title: s.Title, Detail: s.Detail, ActionID: s.ActionID}
		for _, q := range s.Params {
			x.Params = append(x.Params, response.DraftParam{Name: q.Name, Value: q.Value})
		}
		d.Steps = append(d.Steps, x)
	}
	return d, nil
}

func (p responsePlanner) Plan(ctx context.Context, a response.PlanAsk) (response.PlanDraft, error) {
	t := a.Target
	var cat strings.Builder
	for _, ac := range a.Actions {
		fmt.Fprintf(&cat, "- id %q: %s. %s Risk %s, %s.", ac.ID, ac.Name, ac.Description, ac.Risk, map[bool]string{true: "can be undone", false: "cannot be undone"}[ac.Reversible])
		if len(ac.Params) == 0 {
			cat.WriteString(" No parameters.\n")
			continue
		}
		cat.WriteString(" Parameters:")
		for _, q := range ac.Params {
			fmt.Fprintf(&cat, " %s (%s)", q.Name, q.Label)
		}
		cat.WriteString("\n")
	}
	if cat.Len() == 0 {
		cat.WriteString("(none: propose no action)\n")
	}
	dev := fmt.Sprintf("Device: %s (%s), kind %s\nFinding: %s\n", t.AssetName, t.AssetIP, t.AssetKind, t.CVE)
	var d response.PlanDraft
	ready := p.svc.Ready(ai.JobResponsePlan)
	res, err := p.svc.RunJob(ctx, ai.JobSpec{
		Job: ai.JobResponsePlan, Actor: "system", Task: planTask,
		Question: "Write the response plan for this finding.",
		// The catalog is data, not Task: the before-AI hooks look at every data block, and they do not look at Task.
		Data: []ai.DataBlock{{Kind: ai.DataFeed, Source: "exploited list entry " + t.CVE, Text: p.factsOf(ctx, t.CVE)}, {Kind: "inventory", Source: "the device of the finding", Text: dev},
			{Kind: ai.DataDocument, Source: "actions you may propose", Text: cat.String()}},
		Schema: &provider.Schema{Name: "response_plan", JSON: json.RawMessage(planSchema)}, MaxTokens: 1500,
		Summary: "Response plan for " + t.CVE,
		Check: func(text string) error {
			var perr error
			d, perr = parsePlan(text)
			return perr
		},
	})
	if err != nil {
		return response.PlanDraft{}, planError(err, ready)
	}
	d.Model, d.Profile = res.Model, res.Profile
	return d, nil
}

// planError sorts a failure of RunJob. The AI is unavailable (the run stops) when no profile can run the job (ready != nil) or the daily cap
// is spent. Anything else, though it also arrives as 409 ai_unavailable (a format failure, a hook that stopped the answer, a provider
// that did not answer), is about this finding only: the caller backs the finding off and goes on.
func planError(err, ready error) error {
	if ae, ok := apierr.As(err); ok && (ready != nil || ae.Code == "daily_cap") {
		return fmt.Errorf("%w: %s", response.ErrPlanUnavailable, ae.Message)
	}
	return err
}

// factsOf is the exploited-list entry of a CVE as text; a lookup that fails or finds nothing gives the id alone (the plan is then thinner, not refused).
func (p responsePlanner) factsOf(ctx context.Context, cve string) string {
	if p.facts != nil {
		if c, ok, err := p.facts.CVE(ctx, cve); err == nil && ok {
			return fmt.Sprintf("CVE: %s\nVendor: %s\nProduct: %s\nName: %s\nDescription: %s\nRequired action (CISA): %s\nUsed in ransomware campaigns: %t\n", c.CVE, c.Vendor, c.Product, c.Name, c.Description, c.RequiredAction, c.Ransomware)
		}
	}
	return "CVE: " + cve + "\n"
}

// responseCritical lists the open critical findings with their device and the exploited-list facts, for the plan job.
type responseCritical struct {
	fnd *findings.Service
	inv findings.Inventory
}

func (r responseCritical) list(ctx context.Context) ([]response.PlanTarget, error) {
	recs, err := r.fnd.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var open []findings.Record
	var ids []string
	for _, f := range recs {
		if f.Severity == findings.SeverityCritical && f.Status.Open() {
			open = append(open, f)
			ids = append(ids, f.AssetID)
		}
	}
	if len(open) == 0 {
		return nil, nil
	}
	assets, err := r.inv.Assets(ctx, ids)
	if err != nil {
		return nil, err
	}
	var out []response.PlanTarget
	for _, f := range open {
		a, ok := assets[f.AssetID]
		if !ok {
			continue
		}
		name := a.IP
		if a.Hostname != nil && *a.Hostname != "" {
			name = *a.Hostname
		}
		t := response.PlanTarget{FindingID: f.ID, CVE: f.CVE, AssetID: f.AssetID, AssetName: name, AssetIP: a.IP, AssetKind: a.Kind}
		if a.IP == "—" { // unknown address
			t.AssetIP = ""
		}
		out = append(out, t)
	}
	return out, nil
}
