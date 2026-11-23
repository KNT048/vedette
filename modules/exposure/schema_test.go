package exposure

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
)

// Every field a target, a run or a row can carry fits the API schema: a field added on the Go side without contract.ts,
// api/openapi.json and core/api/oas fails here, not as a 500 on the customer's box.
func TestEveryFieldFitsTheAPISchema(t *testing.T) {
	t.Parallel()
	var v TargetView
	fillAll(reflect.ValueOf(&v).Elem(), "")
	if _, err := into[oas.ExposureGetExposureTargetsIDOK](v); err != nil {
		t.Fatalf("target: %v", err)
	}
	var r ScanRun
	fillAll(reflect.ValueOf(&r).Elem(), "")
	r.Progress = nil // core/progress's own shape, tested there
	if _, err := into[oas.ExposurePostExposureTargetsIDOpenvasAccepted](r); err != nil {
		t.Fatalf("run: %v", err)
	}
	for name, check := range map[string]func() error{
		"scan": func() error {
			var v ScanView
			fillAll(reflect.ValueOf(&v).Elem(), "")
			v.Status, v.Trigger, v.Mode = "done", "manual", "deep"
			return fits[oas.ExposurePostExposureTreeIDScanAccepted](v)
		},
		"host": func() error {
			var v HostView
			fillAll(reflect.ValueOf(&v).Elem(), "")
			v.Source, v.FirstSeen, v.LastSeen = SourceCT, "2026-11-14T10:00:00.000Z", "2026-11-14T10:00:00.000Z"
			return fits[oas.ExposureGetExposureTreeIDHostsOK](items[HostView]{[]HostView{v}})
		},
		"address": func() error {
			var v AddressView
			fillAll(reflect.ValueOf(&v).Elem(), "")
			v.Family, v.Class, v.FirstSeen, v.LastSeen = "ipv4", ClassBox, "2026-11-14T10:00:00.000Z", "2026-11-14T10:00:00.000Z"
			return fits[oas.ExposureGetExposureTreeIDAddressesOK](items[AddressView]{[]AddressView{v}})
		},
		"service": func() error {
			var v ServiceView
			fillAll(reflect.ValueOf(&v).Elem(), "")
			v.Proto, v.Ident, v.State, v.FirstSeen, v.LastSeen = "tcp", identProbed, ServiceOpen, "2026-11-14T10:00:00.000Z", "2026-11-14T10:00:00.000Z"
			return fits[oas.ExposureGetExposureTreeIDServicesOK](items[ServiceView]{[]ServiceView{v}})
		},
		"issue": func() error {
			var v IssueView
			fillAll(reflect.ValueOf(&v).Elem(), "")
			v.Engine, v.Severity, v.State, v.CVEs = EngineZAP, "high", IssueHandled, []IssueCVE{{CVE: "CVE-2024-1234", Severity: []byte("null")}}
			v.FirstSeen, v.LastSeen = "2026-11-14T10:00:00.000Z", "2026-11-14T10:00:00.000Z"
			r := "patched"
			v.Resolution = &r
			return fits[oas.ExposureGetExposureTreeIDIssuesOK](items[IssueView]{[]IssueView{v}})
		},
	} {
		if err := check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// fits says v encodes into the generated response type T.
func fits[T any, P interface {
	*T
	json.Unmarshaler
}](v any) error {
	_, err := into[T, P](v)
	return err
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
	case name == "accepted_until":
		return "2026-11-14"
	case name == "at" || strings.HasSuffix(name, "_at") || name == "last_deep" || name == "last_tried":
		return "2026-11-14T10:00:00.000Z"
	case name == "date" || name == "date_added" || name == "last_seen" || name == "from" || name == "to":
		return "2026-11-14"
	}
	return "x"
}
