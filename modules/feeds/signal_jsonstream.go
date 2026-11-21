package feeds

import (
	"encoding/json"
	"errors"
	"io"
)

// jsonStream reads a JSON document of a known shape token by token, so that every count bound holds while the document is read,
// before anything is kept: a decode into slices would first fill them (gigabytes for 32 MB of "[{},{},…]") and only then be
// checked. A value of another type than the one asked for is skipped and read as empty (the caller's own checks then refuse what it
// needs); a string is cut to the length asked for.
type jsonStream struct {
	dec   *json.Decoder
	who   string // names the document in errors ("The advisory document")
	depth *int   // objects and arrays open now
}

// jsonMaxDepth bounds the nesting of a document (CSAF needs fewer than 15 levels): the decoder keeps a stack entry per open level.
const jsonMaxDepth = 64

func newJSONStream(r io.Reader, who string) jsonStream {
	return jsonStream{dec: json.NewDecoder(r), who: who, depth: new(int)}
}

// open counts a level opened; close, one closed.
func (j jsonStream) open() error {
	if *j.depth++; *j.depth > jsonMaxDepth {
		return fail(ErrBadSample, "%s is nested more than %d levels deep.", j.who, jsonMaxDepth)
	}
	return nil
}

func (j jsonStream) close() { *j.depth-- }

func (j jsonStream) fail(err error) error {
	return readFail(err, "%s could not be read: %v.", j.who, err)
}

// object reads an object, calling fn for each key (fn must read the value). ok is false when the value was not an object (it was
// skipped).
func (j jsonStream) object(fn func(key string) error) (ok bool, err error) {
	tok, err := j.dec.Token()
	if err != nil {
		return false, j.fail(err)
	}
	if tok != json.Delim('{') {
		return false, j.skipRest(tok)
	}
	if err := j.open(); err != nil {
		return false, err
	}
	defer j.close()
	for j.dec.More() {
		k, err := j.dec.Token()
		if err != nil {
			return false, j.fail(err)
		}
		key, _ := k.(string)
		if err := fn(key); err != nil {
			return false, err
		}
	}
	if _, err := j.dec.Token(); err != nil {
		return false, j.fail(err)
	}
	return true, nil
}

// array reads an array, calling fn for each element (fn must read it); more than limit elements fails with "more than limit what".
// count, when not nil, is shared by several arrays and bounds them together. A value that is not an array is skipped.
func (j jsonStream) array(limit int, count *int, what string, fn func() error) error {
	_, err := j.arrayOK(limit, count, what, fn)
	return err
}

// arrayOK is array, saying whether the value was an array.
func (j jsonStream) arrayOK(limit int, count *int, what string, fn func() error) (bool, error) {
	tok, err := j.dec.Token()
	if err != nil {
		return false, j.fail(err)
	}
	if tok != json.Delim('[') {
		return false, j.skipRest(tok)
	}
	if err := j.open(); err != nil {
		return false, err
	}
	defer j.close()
	n := 0
	if count == nil {
		count = &n
	}
	for j.dec.More() {
		if *count++; *count > limit {
			return false, fail(ErrBadSample, "%s has more than %s %s.", j.who, grouped(limit), what)
		}
		if err := fn(); err != nil {
			return false, err
		}
	}
	if _, err := j.dec.Token(); err != nil {
		return false, j.fail(err)
	}
	return true, nil
}

// str reads a string cut to at most limit bytes; another value is skipped and read as "".
func (j jsonStream) str(limit int) (string, error) {
	tok, err := j.dec.Token()
	if err != nil {
		return "", j.fail(err)
	}
	s, ok := tok.(string)
	if !ok {
		return "", j.skipRest(tok)
	}
	if len(s) > limit {
		s = s[:limit]
	}
	return s, nil
}

// skip reads one value and keeps nothing of it.
func (j jsonStream) skip() error {
	tok, err := j.dec.Token()
	if err != nil {
		return j.fail(err)
	}
	return j.skipRest(tok)
}

// skipRest reads the rest of a value whose first token was tok, within the nesting bound.
func (j jsonStream) skipRest(tok json.Token) error {
	if tok != json.Delim('{') && tok != json.Delim('[') {
		return nil
	}
	base := *j.depth
	defer func() { *j.depth = base }()
	for depth := 1; depth > 0; {
		if *j.depth = base + depth; *j.depth > jsonMaxDepth {
			return fail(ErrBadSample, "%s is nested more than %d levels deep.", j.who, jsonMaxDepth)
		}
		t, err := j.dec.Token()
		if err != nil {
			return j.fail(err)
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

// end checks that nothing follows the document.
func (j jsonStream) end() error {
	if _, err := j.dec.Token(); !errors.Is(err, io.EOF) {
		return readFail(err, "%s has data after its end.", j.who)
	}
	return nil
}
