package exposure

import (
	"reflect"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
)

// N44-3: the snapshot of a deep scan (testing terms accepted, nuclei deep rows with a name and a severity and no CVE) is read
// through the real handler and the generated encoder: 200 with the rows, not 500 "does not fit the API schema".
func TestSnapshotOfADeepScanFitsTheAPISchema(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	no := false
	e.terms = &no
	f.results = []TemplateResult{
		{Port: 80, Template: "git-config", Outcome: OutcomeMatched, Name: "Git Configuration - Detect", Severity: "medium"},
		{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched, Name: "Apache 2.4.49 - Path Traversal", Severity: "critical"},
	}
	s := e.scanIP(Content{})
	h := httpOn(e)
	code, b := h.call("GET", "/exposure/targets", "viewer", "")
	items := list(b, "items")
	if code != 200 || len(items) != 1 {
		t.Fatalf("targets: %d %v", code, b)
	}
	id, _ := items[0].(map[string]any)["id"].(string)
	code, b = h.call("GET", "/exposure/targets/"+id+"/snapshots/"+s.Date, "viewer", "")
	if code != 200 {
		t.Fatalf("snapshot of a deep scan: %d %v", code, b)
	}
	var deep map[string]any
	for _, r := range list(b, "templates") {
		if m, _ := r.(map[string]any); m["template"] == "git-config" {
			deep = m
		}
	}
	if deep["name"] != "Git Configuration - Detect" || deep["severity"] != "medium" || deep["cve"] != "" || deep["outcome"] != "matched" {
		t.Fatalf("deep row %v (all %v)", deep, list(b, "templates"))
	}
}

// Every field a stored snapshot or a target can carry fits the API schema: a field added on the Go side without contract.ts,
// api/openapi.json and core/api/oas (the drift of N44-3) fails here, not as a 500 on the customer's box.
func TestEveryFieldFitsTheAPISchema(t *testing.T) {
	t.Parallel()
	var s Snapshot
	fillAll(reflect.ValueOf(&s).Elem(), "")
	if _, err := into[oas.ExposureGetExposureTargetsIDSnapshotsDateOK](s); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var v TargetView
	fillAll(reflect.ValueOf(&v).Elem(), "")
	if _, err := into[oas.ExposureGetExposureTargetsIDOK](v); err != nil {
		t.Fatalf("target: %v", err)
	}
	var d Diff
	fillAll(reflect.ValueOf(&d).Elem(), "")
	if _, err := into[oas.ExposureGetExposureTargetsIDDiffOK](d); err != nil {
		t.Fatalf("diff: %v", err)
	}
}

// fillAll sets every exported field that JSON writes (one element in each list, every pointer set) so that omitempty fields are
// in the body too. Times get an RFC 3339 value, the rest "x" or 1: the generated decoder checks field names and formats.
func fillAll(v reflect.Value, name string) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillAll(v.Elem(), name)
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" {
				continue
			}
			fillAll(v.Field(i), strings.Split(f.Tag.Get("json"), ",")[0])
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillAll(v.Index(0), name)
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
	case reflect.String:
		v.SetString(sampleOf(name))
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Float64:
		v.SetFloat(1)
	case reflect.Bool:
		v.SetBool(true)
	}
}

func sampleOf(name string) string {
	switch {
	case name == "at" || strings.HasSuffix(name, "_at") || name == "last_deep" || name == "last_tried":
		return "2026-11-14T10:00:00.000Z"
	case name == "date" || name == "date_added" || name == "last_seen" || name == "from" || name == "to":
		return "2026-11-14"
	}
	return "x"
}
