package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// wrap puts a schema in a minimal operation response.
func wrap(schema string) string {
	return `{"paths":{"/x":{"get":{"operationId":"op_x","responses":{"200":{"content":{"application/json":{"schema":` + schema + `}}}}}}}}`
}

func schemaOf(t *testing.T, d map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(d)
	var v struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct{ Schema map[string]any }
			}
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v.Paths["/x"]["get"].Responses["200"].Content["application/json"].Schema
}

func TestNormalise(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		stats Stats
	}{
		{"multi type", `{"type":["string","number","null"]}`, `{"anyOf":[{"type":"string"},{"type":"number"},{"type":"null"}]}`, Stats{MultiType: 1}},
		{"single type with null untouched", `{"type":["string","null"]}`, `{"type":["string","null"]}`, Stats{}},
		{"const numbers to enum", `{"anyOf":[{"type":"number","const":7},{"type":"number","const":30}]}`, `{"type":"number","enum":[7,30]}`, Stats{ConstEnum: 1}},
		{"mixed const types keep no type", `{"anyOf":[{"type":"number","const":7},{"type":"string","const":"a"}]}`, `{"enum":[7,"a"]}`, Stats{ConstEnum: 1}},
		{"anyOf with a non-const member untouched", `{"anyOf":[{"type":"number","const":7},{"type":"string"}]}`, `{"anyOf":[{"type":"number","const":7},{"type":"string"}]}`, Stats{}},
		{"const member with extra keys untouched", `{"anyOf":[{"type":"number","const":7,"minimum":1},{"type":"number","const":8}]}`, `{"anyOf":[{"type":"number","const":7,"minimum":1},{"type":"number","const":8}]}`, Stats{}},
		{"date-time pattern dropped", `{"type":"string","format":"date-time","pattern":"^x$"}`, `{"type":"string","format":"date-time"}`, Stats{DateTimePattern: 1}},
		{"other pattern kept", `{"type":"string","pattern":"^x$"}`, `{"type":"string","pattern":"^x$"}`, Stats{}},
		{"large integer kept exact", `{"type":"integer","minimum":-9007199254740991}`, `{"type":"integer","minimum":-9007199254740991}`, Stats{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := parse(t, wrap(tc.in))
			st := Normalise(d)
			if st != tc.stats {
				t.Fatalf("stats = %+v, want %+v", st, tc.stats)
			}
			got := schemaOf(t, d)
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("schema = %v, want %v", got, want)
			}
		})
	}
}

func TestNormaliseDiscriminator(t *testing.T) {
	t.Parallel()
	in := `{"oneOf":[
		{"type":"object","properties":{"kind":{"type":"string","const":"fix"},"cve":{"type":"string"}}},
		{"type":"object","properties":{"kind":{"type":"string","const":"verify"},"cve":{"type":"string"}}}]}`
	d := parse(t, wrap(in))
	if st := Normalise(d); st.Discriminator != 1 {
		t.Fatalf("stats = %+v", st)
	}
	s := schemaOf(t, d)
	disc, _ := s["discriminator"].(map[string]any)
	if disc["propertyName"] != "kind" {
		t.Fatalf("discriminator = %v", disc)
	}
	mapping, _ := disc["mapping"].(map[string]any)
	if mapping["fix"] != "#/components/schemas/op_x_1_fix" || mapping["verify"] != "#/components/schemas/op_x_1_verify" {
		t.Fatalf("mapping = %v", mapping)
	}
	comps := d["components"].(map[string]any)["schemas"].(map[string]any)
	if _, ok := comps["op_x_1_fix"]; !ok || len(comps) != 2 {
		t.Fatalf("components = %v", comps)
	}
	refs := s["oneOf"].([]any)
	if refs[0].(map[string]any)["$ref"] != "#/components/schemas/op_x_1_fix" {
		t.Fatalf("oneOf = %v", refs)
	}
}

func TestNormaliseDiscriminatorSkipsOtherOneOf(t *testing.T) {
	t.Parallel()
	in := `{"oneOf":[{"type":"string"},{"type":"number"}]}`
	d := parse(t, wrap(in))
	if st := Normalise(d); st.Discriminator != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestMarshalDeterministic(t *testing.T) {
	t.Parallel()
	a, err := Marshal(parse(t, `{"b":1,"a":{"d":2,"c":3}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Marshal(parse(t, `{"a":{"c":3,"d":2},"b":1}`))
	if string(a) != string(b) {
		t.Fatalf("not deterministic:\n%s\n%s", a, b)
	}
}
