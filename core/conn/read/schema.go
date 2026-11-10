package read

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/conn/internal/transport"
)

// maxItems is how many elements an array argument holds.
const maxItems = 64

// checkSchema holds the arguments of an MCP call to the input schema the server gave: only the parameters it declares, every
// required one, and each value of the declared type (and enum, and maximum length). It is a JSON-schema subset on purpose: type,
// properties, required, items, enum, maxLength. A schema that is missing or is not an object declares no parameters, so no argument
// passes; additionalProperties is never taken as permission.
func checkSchema(raw json.RawMessage, args map[string]any) error {
	var root map[string]any
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&root); err != nil {
			root = nil
		}
	}
	if root == nil {
		root = map[string]any{}
	}
	return checkObject(root, args, 0)
}

func checkObject(schema map[string]any, v map[string]any, depth int) error {
	if unsupported(schema) {
		return errUnsupported
	}
	props, _ := schema["properties"].(map[string]any)
	for k := range v {
		if _, ok := props[k]; !ok {
			return fmt.Errorf("the tool has no argument %q", transport.CleanLine(k))
		}
	}
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if name, ok := r.(string); ok {
				if _, have := v[name]; !have {
					return fmt.Errorf("the argument %s is required", transport.CleanLine(name))
				}
			}
		}
	}
	for k, e := range v {
		sub, _ := props[k].(map[string]any)
		if err := checkValue(sub, e, depth+1, k); err != nil {
			return err
		}
	}
	return nil
}

func checkValue(schema map[string]any, v any, depth int, name string) error {
	if depth > maxDepth {
		return errors.New("the arguments are nested too deep")
	}
	name = transport.CleanLine(name)
	if unsupported(schema) {
		return fmt.Errorf("the argument %s uses a feature of JSON schema that Vedette does not support", name)
	}
	if types := typesOf(schema); len(types) > 0 && !slices.ContainsFunc(types, func(t string) bool { return isType(t, v) }) {
		return fmt.Errorf("the argument %s is not of type %s", name, strings.Join(types, " or "))
	}
	if enum, ok := schema["enum"].([]any); ok && !inEnum(enum, v) {
		return fmt.Errorf("the argument %s is not one of the values the tool lists", name)
	}
	switch x := v.(type) {
	case string:
		if n, ok := schema["maxLength"].(json.Number); ok {
			if m, err := n.Int64(); err == nil && int64(len([]rune(x))) > m {
				return fmt.Errorf("the argument %s is longer than %d characters", name, m)
			}
		}
	case []any:
		if len(x) > maxItems {
			return fmt.Errorf("the argument %s holds more than %d items", name, maxItems)
		}
		items, _ := schema["items"].(map[string]any)
		for _, e := range x {
			if err := checkValue(items, e, depth+1, name); err != nil {
				return err
			}
		}
	case map[string]any:
		return checkObject(schema, x, depth)
	}
	return nil
}

func typesOf(schema map[string]any) []string {
	switch t := schema["type"].(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func isType(t string, v any) bool {
	switch t {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "array":
		_, ok := v.([]any)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "number", "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(n.String())
		return ok && (t == "number" || r.IsInt())
	}
	return false
}

func inEnum(enum []any, v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	for _, e := range enum {
		if eb, err := json.Marshal(e); err == nil && bytes.Equal(b, eb) {
			return true
		}
	}
	return false
}

var errUnsupported = errors.New("the tool's schema uses a feature of JSON schema that Vedette does not support")

// unsupported is a schema that says something this checker does not enforce: a composition or a reference. Such a parameter is
// refused (and not offered), never half checked.
func unsupported(schema map[string]any) bool {
	for _, k := range []string{"anyOf", "oneOf", "allOf", "not", "$ref", "$defs", "definitions", "patternProperties", "if", "then", "else", "dependentSchemas", "dependencies"} {
		if _, ok := schema[k]; ok {
			return true
		}
	}
	return false
}

var scalarTypes = []string{"string", "integer", "number", "boolean", "array", "object", "null"}

// publicSchema is what the AI is shown of an MCP tool's input schema: only what checkSchema enforces (types, enums, bounds,
// required, nested properties and items), with no description, every string cleaned and capped at 200 characters and every secret
// of the sign-in replaced. A schema that is missing, is not an object or is too large declares no arguments. ok is false for a tool
// that has a required argument it cannot take (a composition, a reference): such a tool is not offered.
func publicSchema(raw json.RawMessage, redact []string) (json.RawMessage, bool) {
	var root map[string]any
	if len(raw) > 0 && len(raw) <= transport.MaxSchema {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&root) != nil {
			root = nil
		}
	}
	if root == nil {
		return json.RawMessage(noArgs), true
	}
	out, ok := subset(root, 0)
	if !ok {
		return nil, false
	}
	out["type"] = "object"
	if _, has := out["properties"]; !has {
		out["properties"] = map[string]any{}
	}
	out["additionalProperties"] = false
	b, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage(noArgs), true
	}
	s := transport.Redact(string(b), redact...)
	if !json.Valid([]byte(s)) {
		return json.RawMessage(noArgs), true
	}
	return json.RawMessage(s), true
}

func subset(node map[string]any, depth int) (map[string]any, bool) {
	if depth > maxDepth || unsupported(node) {
		return nil, false
	}
	out := map[string]any{}
	switch t := node["type"].(type) {
	case string:
		if slices.Contains(scalarTypes, t) {
			out["type"] = t
		}
	case []any:
		var ts []string
		for _, e := range t {
			if s, ok := e.(string); ok && slices.Contains(scalarTypes, s) {
				ts = append(ts, s)
			}
		}
		if len(ts) > 0 {
			out["type"] = ts
		}
	}
	if enum, ok := node["enum"].([]any); ok && len(enum) <= maxItems {
		var vals []any
		for _, e := range enum {
			switch x := e.(type) {
			case string:
				vals = append(vals, transport.CleanLine(x))
			case json.Number, bool:
				vals = append(vals, x)
			}
		}
		out["enum"] = vals
	}
	if n, ok := node["maxLength"].(json.Number); ok {
		out["maxLength"] = n
	}
	if items, ok := node["items"].(map[string]any); ok {
		sub, ok := subset(items, depth+1)
		if !ok {
			return nil, false
		}
		out["items"] = sub
	}
	if props, ok := node["properties"].(map[string]any); ok {
		kept := map[string]any{}
		for k, v := range props {
			m, isMap := v.(map[string]any)
			if !propNameRE.MatchString(k) || !isMap {
				continue
			}
			if sub, ok := subset(m, depth+1); ok {
				kept[k] = sub
			}
		}
		var req []string
		if r, ok := node["required"].([]any); ok {
			for _, e := range r {
				name, _ := e.(string)
				if _, have := kept[name]; !have {
					return nil, false // a required argument that cannot be taken
				}
				req = append(req, name)
			}
		}
		out["properties"] = kept
		if len(req) > 0 {
			out["required"] = req
		}
		out["additionalProperties"] = false
	}
	return out, true
}
