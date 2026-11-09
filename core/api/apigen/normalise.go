package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Stats counts what each transformation changed (printed by the CLI, asserted in tests).
type Stats struct {
	MultiType       int
	ConstEnum       int
	Discriminator   int
	DateTimePattern int
}

// Parse decodes a JSON document keeping numbers exact (UseNumber) so re-encoding does not rewrite them.
func Parse(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("apigen: parse openapi: %w", err)
	}
	return doc, nil
}

// Marshal encodes with sorted keys (encoding/json sorts map keys), so output is deterministic.
func Marshal(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("apigen: encode openapi: %w", err)
	}
	return buf.Bytes(), nil
}

// Normalise rewrites constructs of the OpenAPI 3.1 contract that ogen v1.24.0 cannot generate.
// It works on a copy of the document, never on the committed file. Each rewrite keeps the meaning:
//
//  1. type [A,B,null] (more than one non-null type) -> anyOf of single types plus null.
//  2. anyOf of only const members -> enum.
//  3. oneOf whose members all carry properties.kind.const -> members hoisted to
//     components.schemas with a discriminator (propertyName kind) and mapping.
//  4. pattern on format date-time removed: ogen ignores it anyway (time.Time parsing enforces RFC 3339).
//
// Contract-side fixes that make this step unnecessary are listed in .ai/deferred/feat-core-codegen.md.
func Normalise(doc map[string]any) Stats {
	var st Stats
	comps := ensureMap(ensureMap(doc, "components"), "schemas")
	paths, _ := doc["paths"].(map[string]any)
	for _, p := range sortedKeys(paths) {
		item, _ := paths[p].(map[string]any)
		for _, m := range sortedKeys(item) {
			op, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			id, _ := op["operationId"].(string)
			w := &walker{st: &st, comps: comps, opID: id}
			w.walk(op)
		}
	}
	return st
}

type walker struct {
	st    *Stats
	comps map[string]any
	opID  string
	n     int // ordinal of the oneOf inside this operation, for stable hoisted names
}

func (w *walker) walk(v any) {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			w.walk(e)
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			w.walk(t[k])
		}
		w.multiType(t)
		w.constEnum(t)
		w.discriminator(t)
		w.dateTimePattern(t)
	}
}

func (w *walker) multiType(s map[string]any) {
	arr, ok := s["type"].([]any)
	if !ok {
		return
	}
	var kinds []any
	for _, e := range arr {
		if e != "null" {
			kinds = append(kinds, e)
		}
	}
	if len(kinds) < 2 {
		return
	}
	delete(s, "type")
	var alts []any
	for _, k := range kinds {
		alts = append(alts, map[string]any{"type": k})
	}
	s["anyOf"] = append(alts, map[string]any{"type": "null"})
	w.st.MultiType++
}

func (w *walker) constEnum(s map[string]any) {
	members, ok := s["anyOf"].([]any)
	if !ok || len(members) < 2 {
		return
	}
	var values []any
	types := map[any]bool{}
	var only any
	for _, m := range members {
		mm, ok := m.(map[string]any)
		if !ok {
			return
		}
		c, has := mm["const"]
		if !has {
			return
		}
		for k := range mm {
			if k != "const" && k != "type" {
				return
			}
		}
		values = append(values, c)
		if ty, has := mm["type"]; has {
			types[ty] = true
			only = ty
		}
	}
	delete(s, "anyOf")
	s["enum"] = values
	if len(types) == 1 {
		s["type"] = only
	}
	w.st.ConstEnum++
}

func (w *walker) discriminator(s map[string]any) {
	members, ok := s["oneOf"].([]any)
	if !ok || len(members) < 2 {
		return
	}
	kinds := make([]string, len(members))
	for i, m := range members {
		k, ok := constKind(m)
		if !ok {
			return
		}
		kinds[i] = k
	}
	w.n++
	mapping := map[string]any{}
	refs := make([]any, len(members))
	for i, m := range members {
		name := fmt.Sprintf("%s_%d_%s", w.opID, w.n, kinds[i])
		w.comps[name] = m
		ref := "#/components/schemas/" + name
		mapping[kinds[i]] = ref
		refs[i] = map[string]any{"$ref": ref}
	}
	s["oneOf"] = refs
	s["discriminator"] = map[string]any{"propertyName": "kind", "mapping": mapping}
	w.st.Discriminator++
}

func constKind(m any) (string, bool) {
	mm, ok := m.(map[string]any)
	if !ok {
		return "", false
	}
	props, _ := mm["properties"].(map[string]any)
	kind, _ := props["kind"].(map[string]any)
	c, ok := kind["const"].(string)
	return c, ok && c != ""
}

func (w *walker) dateTimePattern(s map[string]any) {
	if s["format"] == "date-time" {
		if _, has := s["pattern"]; has {
			delete(s, "pattern")
			w.st.DateTimePattern++
		}
	}
}

func ensureMap(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	v := map[string]any{}
	m[k] = v
	return v
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
