package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// afterHooks runs the after_ai hooks on an answer (INV-12). A plain-text answer goes through the hooks as it is. A structured answer
// (the job has a schema and the text parses as JSON) goes through them field by field: the hooks see each string value and nothing
// else, so a pattern that ends at white space cannot eat the quote, bracket or comma that closes a field and break the format.
// A block or hold in any field stops the answer; a mask changes that field; the masked answer is written out again as JSON.
// Map keys and non-string values are not hooked: the schemas are closed (additionalProperties false) and what is stored is re-marshalled
// from the parsed struct, so a key or a number never reaches a person or a prompt. The activity row hashes the model's raw answer, not this result.
func afterHooks(ctx context.Context, hooks *HookRunner, structured bool, text string) (HookResult, error) {
	if !structured {
		return hooks.Run(ctx, AfterAI, text)
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber() // numbers go back out as they came in
	var doc any
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return hooks.Run(ctx, AfterAI, text) // not JSON: the format check refuses it; until then it is plain text
	}
	res := HookResult{Text: text, Outcome: OutcomePass, Hits: []HookHit{}}
	var walk func(v any) (any, bool, error)
	walk = func(v any) (any, bool, error) {
		switch x := v.(type) {
		case string:
			x = cleanText(x) // the form that is stored (INV-12): control characters and line breaks cannot split a word past a hook
			r, err := hooks.Run(ctx, AfterAI, x)
			if err != nil {
				return nil, false, err
			}
			for _, h := range r.Hits {
				res.note(hookDef{id: h.ID, name: h.Name, kind: h.Kind, when: h.When, action: h.Action, message: h.Message})
			}
			switch r.Outcome {
			case OutcomeBlocked, OutcomeHeld:
				res.Text, res.Outcome = r.Text, r.Outcome
				return nil, true, nil
			case OutcomeMasked:
				res.Outcome = OutcomeMasked
				return r.Text, false, nil
			}
			return x, false, nil
		case []any:
			for i, e := range x {
				n, stop, err := walk(e)
				if err != nil || stop {
					return nil, stop, err
				}
				x[i] = n
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys) // the same answer always reports the same hook
			for _, k := range keys {
				n, stop, err := walk(x[k])
				if err != nil || stop {
					return nil, stop, err
				}
				x[k] = n
			}
		}
		return v, false, nil
	}
	out, stop, err := walk(doc)
	if err != nil {
		return HookResult{}, err
	}
	if stop || res.Outcome != OutcomeMasked {
		return res, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return HookResult{}, err
	}
	res.Text = strings.TrimSpace(buf.String())
	return res, nil
}
