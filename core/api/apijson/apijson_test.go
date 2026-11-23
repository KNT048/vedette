package apijson_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/apijson"
)

type leaf struct {
	Tags []string `json:"tags"`
}

type page struct {
	Items    []leaf            `json:"items"`
	Nested   *leaf             `json:"nested"`
	Lists    [][]string        `json:"lists"`
	ByKey    map[string][]int  `json:"by_key"`
	Labels   map[string]string `json:"labels"`
	Any      any               `json:"any"`
	Gone     []string          `json:"gone,omitempty"`
	Unknown  []string          `json:"unknown" nullable:"true"` // the schema says array or null: nil means "not known"
	At       time.Time         `json:"at"`
	Raw      []byte            `json:"raw"`
	hidden   []string
	Embedded `json:"embedded"`
}

type Embedded struct {
	More []string `json:"more"`
}

// Every nil slice and map of a response is written as an empty one at every depth, except a field marked nullable (null means
// "none") and an omitted one; the value given is not changed.
func TestNilListsAreWrittenEmpty(t *testing.T) {
	t.Parallel()
	in := page{Items: []leaf{{}}, Nested: &leaf{}, Lists: [][]string{nil}, ByKey: map[string][]int{"a": nil}, Any: leaf{}, hidden: nil}
	b, err := json.Marshal(apijson.Filled(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"items":[{"tags":[]}],"nested":{"tags":[]},"lists":[[]],"by_key":{"a":[]},"labels":{},"any":{"tags":[]},"unknown":null,` +
		`"at":"0001-01-01T00:00:00Z","raw":null,"embedded":{"more":[]}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	if in.Items[0].Tags != nil || in.Nested.Tags != nil || in.ByKey["a"] != nil {
		t.Fatal("the value given was changed")
	}
	if b, _ := json.Marshal(apijson.Filled([]leaf(nil))); string(b) != "[]" {
		t.Fatalf("a nil list at the top: %s", b)
	}
}

type strict struct {
	Items []leaf `json:"items"`
}

// UnmarshalJSON refuses null where the schema wants an array, as the generated decoders do.
func (s *strict) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if string(raw["items"]) == "null" {
		return &json.UnsupportedValueError{Str: "items: \"[\" expected"}
	}
	type plain strict
	return json.Unmarshal(b, (*plain)(s))
}

func TestIntoFitsAnEmptyListToTheSchema(t *testing.T) {
	t.Parallel()
	out, err := apijson.Into[strict](struct {
		Items []leaf `json:"items"`
	}{})
	if err != nil || out.Items == nil {
		t.Fatalf("%+v, %v", out, err)
	}
}

type innerView struct {
	Items []string          `json:"items"`
	ByKey map[string]string `json:"by_key"`
}

// A view that adds a field to another by embedding it (encoding/json writes the embedded fields inline, also when the embedded
// type is not exported): its nil lists are written empty too.
func TestNilListsOfAnEmbeddedViewAreWrittenEmpty(t *testing.T) {
	t.Parallel()
	in := struct {
		innerView
		Applied int `json:"applied"`
	}{}
	b, err := json.Marshal(apijson.Filled(in))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"items":[],"by_key":{},"applied":0}`; string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	if in.Items != nil {
		t.Fatal("the value given was changed")
	}
}
