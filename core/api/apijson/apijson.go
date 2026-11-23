// Package apijson turns a module's own value into a generated API type through its JSON form, the one way handlers that keep their
// own structs answer: the generated decoder rejects anything that does not fit the OpenAPI schema, so a drift fails loudly.
//
// encoding/json writes a nil slice or map as null, and an array or object of the schema then refuses it ("[" expected): an empty
// list answered 500. Into writes every nil slice and map as empty ([] and {}) before the schema reads it, except a field the
// value marks as meaning "none" with the tag nullable:"true" (the schema says array or null), and a field tagged omitempty (left
// out, as encoding/json does). The rule holds at every depth: fields of structs, elements of slices, arrays and maps, pointers and
// interfaces. A type with its own MarshalJSON or MarshalText is written by itself, untouched.
package apijson

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Into encodes v (with its nil slices and maps as empty ones, see the package comment) and decodes the JSON into a new T. For a
// generated type, the decoder is the schema's.
func Into[T any](v any) (*T, error) {
	b, err := json.Marshal(Filled(v))
	if err != nil {
		return nil, fmt.Errorf("encoding response: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("response does not fit the API schema: %w", err)
	}
	return out, nil
}

// Filled is a copy of v whose nil slices and maps are empty ones, by the rules of the package comment; v itself is not changed.
func Filled(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	out := fill(rv, 0)
	if out.Kind() == reflect.Slice && out.IsNil() {
		out = reflect.MakeSlice(out.Type(), 0, 0)
	}
	if out.Kind() == reflect.Map && out.IsNil() {
		out = reflect.MakeMap(out.Type())
	}
	return out.Interface()
}

// maxDepth bounds the walk (a value of the API is a tree a few levels deep; a cycle would never end).
const maxDepth = 64

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// own says values of t write themselves (MarshalJSON or MarshalText, on the value or its pointer).
func own(t reflect.Type) bool {
	return t.Implements(jsonMarshaler) || t.Implements(textMarshaler) ||
		reflect.PointerTo(t).Implements(jsonMarshaler) || reflect.PointerTo(t).Implements(textMarshaler)
}

func fill(v reflect.Value, depth int) reflect.Value {
	if depth > maxDepth || !v.IsValid() {
		return v
	}
	t := v.Type()
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || own(t) || own(t.Elem()) {
			return v
		}
		p := reflect.New(t.Elem())
		p.Elem().Set(fill(v.Elem(), depth+1))
		return p
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		inner := fillElem(v.Elem(), depth+1) // a nil list held in an interface is written as null too
		out := reflect.New(t).Elem()
		out.Set(inner)
		return out
	case reflect.Struct:
		if own(t) {
			return v
		}
		out := reflect.New(t).Elem()
		out.Set(v)
		fillFields(out, depth)
		return out
	case reflect.Slice:
		if v.IsNil() || own(t) || isBytes(t) {
			return v
		}
		out := reflect.MakeSlice(t, v.Len(), v.Len())
		for i := range v.Len() {
			out.Index(i).Set(fillElem(v.Index(i), depth+1))
		}
		return out
	case reflect.Array:
		if own(t) {
			return v
		}
		out := reflect.New(t).Elem()
		for i := range v.Len() {
			out.Index(i).Set(fillElem(v.Index(i), depth+1))
		}
		return out
	case reflect.Map:
		if v.IsNil() || own(t) {
			return v
		}
		out := reflect.MakeMapWithSize(t, v.Len())
		it := v.MapRange()
		for it.Next() {
			out.SetMapIndex(it.Key(), fillElem(it.Value(), depth+1))
		}
		return out
	}
	return v
}

// fillFields fills the fields of the struct sv in place (sv is addressable). The fields of an embedded struct whose type is not
// exported are filled where they are: encoding/json writes them inline, and they can be set although the struct itself cannot.
func fillFields(sv reflect.Value, depth int) {
	t := sv.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Tag.Get("json") == "-" {
			continue
		}
		fv := sv.Field(i)
		if !f.IsExported() {
			if f.Anonymous && f.Type.Kind() == reflect.Struct && !own(f.Type) && depth < maxDepth {
				fillFields(fv, depth+1)
			}
			continue
		}
		keepNil := f.Tag.Get("nullable") == "true" || omitEmpty(f)
		switch {
		case (fv.Kind() == reflect.Slice || fv.Kind() == reflect.Map) && fv.IsNil():
			if keepNil || isBytes(fv.Type()) {
				continue
			}
			if fv.Kind() == reflect.Slice {
				fv.Set(reflect.MakeSlice(fv.Type(), 0, 0))
			} else {
				fv.Set(reflect.MakeMap(fv.Type()))
			}
		case keepNil && fv.Kind() == reflect.Interface && !fv.IsNil() && nilList(fv.Elem()):
			continue // an interface field marked nullable or omitempty keeps the nil list it holds
		default:
			fv.Set(fill(fv, depth+1))
		}
	}
}

// nilList says v is a nil slice or map.
func nilList(v reflect.Value) bool {
	return (v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && v.IsNil()
}

// fillElem is fill of an element of a list or a map: a nil slice or map there is written empty too.
func fillElem(v reflect.Value, depth int) reflect.Value {
	switch {
	case v.Kind() == reflect.Slice && v.IsNil() && !isBytes(v.Type()):
		return reflect.MakeSlice(v.Type(), 0, 0)
	case v.Kind() == reflect.Map && v.IsNil():
		return reflect.MakeMap(v.Type())
	}
	return fill(v, depth)
}

func omitEmpty(f reflect.StructField) bool {
	_, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
	for o := range strings.SplitSeq(opts, ",") {
		if o == "omitempty" || o == "omitzero" {
			return true
		}
	}
	return false
}

// isBytes: []byte is written as base64 text, never as a list.
func isBytes(t reflect.Type) bool {
	return t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8
}
