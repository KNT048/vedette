package feeds

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Bounds on feed JSON: nesting depth and total number of values, so a 5 MB
// document of "[0,0,0,...]" or "[{},{},...]" cannot become hundreds of MB of nodes.
const (
	maxJSONDepth = 100
	maxJSONNodes = 500_000
)

type jkind uint8

const (
	jNull jkind = iota
	jBool
	jNum
	jStr
	jArr
	jObj
)

// jnode is a parsed JSON value that keeps object key order (needed for `.*`).
// A leaf is 32 bytes; the children of a container live in a separate block
// that is only allocated when the first child is added.
type jnode struct {
	k jkind
	s string // jStr text, jNum literal, jBool "true"/"false"
	c *jcont
}

type jcont struct {
	kids []*jnode
	keys []string // objects only, parallel to kids, document order
}

var (
	errJSONDepth = errors.New("json nested too deeply")
	errJSONNodes = errors.New("json has too many values")
)

func (n *jnode) children() []*jnode {
	if n == nil || n.c == nil {
		return nil
	}
	return n.c.kids
}

func (n *jnode) keyNames() []string {
	if n == nil || n.c == nil {
		return nil
	}
	return n.c.keys
}

func decodeJSON(text string) (*jnode, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	budget := maxJSONNodes
	n, err := decodeJSONValue(dec, 0, &budget)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	return n, nil
}

func decodeJSONValue(dec *json.Decoder, depth int, budget *int) (*jnode, error) {
	if depth > maxJSONDepth {
		return nil, errJSONDepth
	}
	if *budget--; *budget < 0 {
		return nil, errJSONNodes
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		n := &jnode{k: jArr}
		if t == '{' {
			n.k = jObj
		}
		for dec.More() {
			key := ""
			if n.k == jObj {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ = kt.(string)
			}
			c, err := decodeJSONValue(dec, depth+1, budget)
			if err != nil {
				return nil, err
			}
			if n.c == nil {
				n.c = &jcont{}
			}
			n.c.kids = append(n.c.kids, c)
			if n.k == jObj {
				n.c.keys = append(n.c.keys, key)
			}
		}
		_, err := dec.Token() // closing delimiter
		return n, err
	case string:
		return &jnode{k: jStr, s: t}, nil
	case json.Number:
		return &jnode{k: jNum, s: string(t)}, nil
	case bool:
		return &jnode{k: jBool, s: strconv.FormatBool(t)}, nil
	}
	return &jnode{k: jNull}, nil
}

// get is JS `Object.hasOwn(v, key) ? v[key]`; the last duplicate key wins like JSON.parse.
func (n *jnode) get(key string) (*jnode, bool) {
	if n == nil || n.k != jObj {
		return nil, false
	}
	keys := n.keyNames()
	for i := len(keys) - 1; i >= 0; i-- {
		if keys[i] == key {
			return n.c.kids[i], true
		}
	}
	return nil, false
}

var arrayIndexRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// values is Object.values(JSON.parse(...)): a duplicated key keeps its first
// position with its last value; integer-like keys come first in ascending
// order, then the rest in document order.
func (n *jnode) values() []*jnode {
	type kv struct {
		idx uint64
		v   *jnode
	}
	keys := n.keyNames()
	last := make(map[string]int, len(keys))
	for i, k := range keys {
		last[k] = i
	}
	emitted := make(map[string]bool, len(keys))
	var ints []kv
	var rest []*jnode
	for _, k := range keys {
		if emitted[k] {
			continue
		}
		emitted[k] = true
		v := n.c.kids[last[k]]
		if arrayIndexRE.MatchString(k) {
			if x, err := strconv.ParseUint(k, 10, 64); err == nil && x < math.MaxUint32 {
				ints = append(ints, kv{x, v})
				continue
			}
		}
		rest = append(rest, v)
	}
	sort.SliceStable(ints, func(a, b int) bool { return ints[a].idx < ints[b].idx })
	out := make([]*jnode, 0, len(emitted))
	for _, e := range ints {
		out = append(out, e.v)
	}
	return append(out, rest...)
}

// ---------- JSONPath subset: $  .key  ['key']  ["key"]  [n]  [*]  .*
// No filters, no recursive descent.

type tok struct {
	star bool
	idx  int // used when isIx
	isIx bool
	key  string
}

var (
	dotTokRE     = regexp.MustCompile(`^\.(\*|[A-Za-z_][A-Za-z0-9_-]*)`)
	bracketTokRE = regexp.MustCompile(`^\[(\*|[0-9]+|'([^']*)'|"([^"]*)")\]`)
)

func near(p string, i int) string {
	end := i + 12
	if end > len(p) {
		end = len(p)
	}
	return jsSlice(p[i:end], 12)
}

// compilePath parses a JSONPath of the supported subset.
func compilePath(path string) ([]tok, error) {
	p := jsTrim(path)
	if len(p) > MaxPathLen {
		return nil, fail(ErrBadConfig, "JSONPath is longer than %d characters.", MaxPathLen)
	}
	if !strings.HasPrefix(p, "$") {
		return nil, fail(ErrBadConfig, "JSONPath must start with $ (got %s).", quoteVal(p))
	}
	var toks []tok
	i := 1
	for i < len(p) {
		switch p[i] {
		case '.':
			if i+1 < len(p) && p[i+1] == '.' {
				return nil, fail(ErrBadConfig, "Recursive descent (..) is not supported.")
			}
			m := dotTokRE.FindStringSubmatch(p[i:])
			if m == nil {
				return nil, fail(ErrBadConfig, "Bad JSONPath near %s.", quoteVal(near(p, i)))
			}
			if m[1] == "*" {
				toks = append(toks, tok{star: true})
			} else {
				toks = append(toks, tok{key: m[1]})
			}
			i += len(m[0])
		case '[':
			m := bracketTokRE.FindStringSubmatch(p[i:])
			if m == nil {
				return nil, fail(ErrBadConfig, "Bad JSONPath near %s.", quoteVal(near(p, i)))
			}
			switch {
			case m[1] == "*":
				toks = append(toks, tok{star: true})
			case m[1][0] == '\'':
				toks = append(toks, tok{key: m[2]})
			case m[1][0] == '"':
				toks = append(toks, tok{key: m[3]})
			default:
				n, err := strconv.Atoi(m[1])
				if err != nil {
					n = math.MaxInt // far beyond any array: never matches
				}
				toks = append(toks, tok{idx: n, isIx: true})
			}
			i += len(m[0])
		default:
			return nil, fail(ErrBadConfig, "Bad JSONPath near %s.", quoteVal(near(p, i)))
		}
	}
	return toks, nil
}

func evalPath(root *jnode, toks []tok) []*jnode {
	cur := []*jnode{root}
	for _, t := range toks {
		var next []*jnode
		for _, v := range cur {
			switch {
			case t.star:
				switch v.k {
				case jArr:
					next = append(next, v.children()...)
				case jObj:
					next = append(next, v.values()...)
				}
			case t.isIx:
				if kids := v.children(); v.k == jArr && t.idx < len(kids) {
					next = append(next, kids[t.idx])
				}
			default:
				if c, ok := v.get(t.key); ok {
					next = append(next, c)
				}
			}
		}
		cur = next
		if len(cur) == 0 {
			break
		}
	}
	return cur
}

// jsNumberText is String(Number(literal)) for a JSON number literal.
func jsNumberText(lit string) string {
	f, _ := strconv.ParseFloat(lit, 64) // out of range gives ±Inf, like JS
	return jsNumString(f)
}

// jsString is String(value) for the cases that reach a cell.
func jsString(n *jnode) string {
	switch n.k {
	case jStr, jBool:
		return n.s
	case jNum:
		return jsNumberText(n.s)
	case jArr:
		kids := n.children()
		parts := make([]string, len(kids))
		for i, c := range kids {
			if c.k != jNull {
				parts[i] = jsString(c)
			}
		}
		return strings.Join(parts, ",")
	case jObj:
		return "[object Object]"
	}
	return "null"
}

var errObject = rj("value is an object, not text")

// scalar converts a matched value to a cell. Objects are rejected, flat arrays
// are joined with ", " (parsers.ts scalar()).
func scalar(n *jnode) cell {
	if n == nil {
		return cell{}
	}
	switch n.k {
	case jNull:
		return cell{}
	case jStr, jNum, jBool:
		return cell{s: jsString(n), set: true}
	case jArr:
		kids := n.children()
		parts := make([]string, len(kids))
		for i, c := range kids {
			switch c.k {
			case jArr, jObj:
				return cell{reject: &errObject}
			case jNull:
			default:
				parts[i] = jsString(c)
			}
		}
		return cell{s: strings.Join(parts, ", "), set: true}
	}
	return cell{reject: &errObject}
}
