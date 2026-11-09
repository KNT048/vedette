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

// maxJSONDepth bounds nesting of feed JSON; deeper documents are rejected, not recursed into.
const maxJSONDepth = 100

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
type jnode struct {
	k    jkind
	s    string // jStr
	n    float64
	b    bool
	arr  []*jnode // jArr
	keys []string // jObj, document order
	vals []*jnode
}

var errJSONDepth = errors.New("json nested too deeply")

func decodeJSON(text string) (*jnode, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	n, err := decodeJSONValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	return n, nil
}

func decodeJSONValue(dec *json.Decoder, depth int) (*jnode, error) {
	if depth > maxJSONDepth {
		return nil, errJSONDepth
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '[' {
			n := &jnode{k: jArr}
			for dec.More() {
				c, err := decodeJSONValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, c)
			}
			_, err := dec.Token() // ]
			return n, err
		}
		n := &jnode{k: jObj}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := kt.(string)
			c, err := decodeJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			n.keys = append(n.keys, key)
			n.vals = append(n.vals, c)
		}
		_, err = dec.Token() // }
		return n, err
	case string:
		return &jnode{k: jStr, s: t}, nil
	case json.Number:
		f, _ := strconv.ParseFloat(string(t), 64) // out of range gives ±Inf, like JS
		return &jnode{k: jNum, n: f}, nil
	case bool:
		return &jnode{k: jBool, b: t}, nil
	}
	return &jnode{k: jNull}, nil
}

// get is JS `Object.hasOwn(v, key) ? v[key]`; the last duplicate key wins like JSON.parse.
func (n *jnode) get(key string) (*jnode, bool) {
	if n == nil || n.k != jObj {
		return nil, false
	}
	for i := len(n.keys) - 1; i >= 0; i-- {
		if n.keys[i] == key {
			return n.vals[i], true
		}
	}
	return nil, false
}

var arrayIndexRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// values is Object.values(): integer-like keys first in ascending order, then document order.
func (n *jnode) values() []*jnode {
	type kv struct {
		idx uint64
		v   *jnode
	}
	var ints []kv
	var rest []*jnode
	for i, k := range n.keys {
		if arrayIndexRE.MatchString(k) {
			if x, err := strconv.ParseUint(k, 10, 64); err == nil && x < math.MaxUint32 {
				ints = append(ints, kv{x, n.vals[i]})
				continue
			}
		}
		rest = append(rest, n.vals[i])
	}
	sort.SliceStable(ints, func(a, b int) bool { return ints[a].idx < ints[b].idx })
	out := make([]*jnode, 0, len(n.keys))
	for _, e := range ints {
		out = append(out, e.v)
	}
	return append(out, rest...)
}

// ---------- JSONPath subset: $  .key  ['key']  ["key"]  [n]  [*]  .*
// No filters, no recursive descent.

type tok struct {
	star bool
	idx  int // used when key == "" and !star and isIdx
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
		return nil, fail(ErrBadConfig, "JSONPath must start with $ (got %q).", jsSlice(p, 40))
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
				return nil, fail(ErrBadConfig, "Bad JSONPath near %q.", near(p, i))
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
				return nil, fail(ErrBadConfig, "Bad JSONPath near %q.", near(p, i))
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
			return nil, fail(ErrBadConfig, "Bad JSONPath near %q.", near(p, i))
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
					next = append(next, v.arr...)
				case jObj:
					next = append(next, v.values()...)
				}
			case t.isIx:
				if v.k == jArr && t.idx < len(v.arr) {
					next = append(next, v.arr[t.idx])
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

// jsString is String(value) for the cases that reach a cell.
func jsString(n *jnode) string {
	switch n.k {
	case jStr:
		return n.s
	case jNum:
		return jsNumString(n.n)
	case jBool:
		return strconv.FormatBool(n.b)
	case jArr:
		parts := make([]string, len(n.arr))
		for i, c := range n.arr {
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

// scalar converts a matched value to a cell. Objects are rejected, flat arrays
// are joined with ", " (parsers.ts scalar()).
func scalar(n *jnode) cell {
	if n == nil {
		return cell{}
	}
	switch n.k {
	case jNull:
		return cell{}
	case jStr:
		return cell{s: n.s, set: true}
	case jNum, jBool:
		return cell{s: jsString(n), set: true}
	case jArr:
		parts := make([]string, len(n.arr))
		for i, c := range n.arr {
			switch c.k {
			case jArr, jObj:
				return cell{reject: "value is an object, not text"}
			case jNull:
			default:
				parts[i] = jsString(c)
			}
		}
		return cell{s: strings.Join(parts, ", "), set: true}
	}
	return cell{reject: "value is an object, not text"}
}
