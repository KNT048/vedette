package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
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
	var hookLines func(m map[string]any) (stop, refused bool, err error)
	walk = func(v any) (any, bool, error) {
		switch x := v.(type) {
		case string:
			x = cleanText(x) // the form that is stored (INV-12): control characters and line breaks cannot split a word past a hook
			r, err := hooks.Run(ctx, AfterAI, x)
			if err != nil {
				return nil, false, err
			}
			for _, h := range r.Hits {
				res.note(hookDef{id: h.ID, name: h.Name, kind: h.Kind, when: h.When, action: h.Action, message: h.Message, what: h.What})
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
			stop, refused, err := hookLines(x)
			if err != nil || stop {
				return nil, stop, err
			}
			for _, k := range keys {
				if k == "lines" && refused { // the refused marker stays as it is
					continue
				}
				var orig []any
				if k == "lines" {
					orig, _ = x[k].([]any)
					orig = slices.Clone(orig)
				}
				n, stop, err := walk(x[k])
				if err != nil || stop {
					return nil, stop, err
				}
				// a config line no hook changed keeps its indentation (codeLine, the form kept) when a mask elsewhere rewrites the answer
				if arr, ok := n.([]any); ok && len(arr) == len(orig) {
					for i, e := range arr {
						if o, ok := orig[i].(string); ok && e == cleanText(o) {
							arr[i] = codeLine(o)
						}
					}
				}
				x[k] = n
			}
		}
		return v, false, nil
	}
	// hookLines: a string array under the key "lines" is a config block, kept as its lines joined with line breaks (codeBlock,
	// briefConfigSchema). The hooks see that joined block too, so a pattern that spans lines (a password under `line vty`, a FortiGate
	// SNMP community) is caught (#897 r1 M2); a mask is put back line by line. A block with a line break inside a line is refused when
	// it is kept, so it is not hooked here: it becomes one line break, which keeps it refused even after a mask rewrites the answer
	// with spaces for line breaks.
	hookLines = func(m map[string]any) (bool, bool, error) {
		arr, ok := m["lines"].([]any)
		if !ok {
			return false, false, nil
		}
		lines := make([]string, 0, len(arr))
		for _, e := range arr {
			l, ok := e.(string)
			if !ok {
				return false, false, nil
			}
			if strings.ContainsAny(l, "\r\n") {
				m["lines"] = []any{"\n"}
				return false, true, nil
			}
			lines = append(lines, codeLine(l))
		}
		r, err := hooks.Run(ctx, AfterAI, strings.Join(lines, "\n"))
		if err != nil {
			return false, false, err
		}
		for _, h := range r.Hits {
			res.note(hookDef{id: h.ID, name: h.Name, kind: h.Kind, when: h.When, action: h.Action, message: h.Message, what: h.What})
		}
		switch r.Outcome {
		case OutcomeBlocked, OutcomeHeld:
			res.Text, res.Outcome = r.Text, r.Outcome
			return true, false, nil
		case OutcomeMasked:
			res.Outcome = OutcomeMasked
			masked := strings.Split(r.Text, "\n")
			out := make([]any, len(masked))
			for i, l := range masked {
				out[i] = l
			}
			m["lines"] = out
		}
		return false, false, nil
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
