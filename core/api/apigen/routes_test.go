package main

import (
	"strings"
	"testing"
)

func opDoc(op string) string {
	return `{"paths":{"/a":{"get":` + op + `}}}`
}

func TestOperationsRefuseBadRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, op, wantErr string
	}{
		{"missing role", `{"operationId":"a","tags":["core"]}`, "x-min-role"},
		{"unknown role", `{"operationId":"a","tags":["core"],"x-min-role":"root"}`, "x-min-role"},
		{"empty role", `{"operationId":"a","tags":["core"],"x-min-role":""}`, "x-min-role"},
		{"no operationId", `{"tags":["core"],"x-min-role":"admin"}`, "operationId"},
		{"no tag", `{"operationId":"a","x-min-role":"admin"}`, "no tag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Operations(parse(t, opDoc(tc.op)))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestOperationsDuplicateID(t *testing.T) {
	t.Parallel()
	d := parse(t, `{"paths":{"/a":{"get":{"operationId":"x","tags":["t"],"x-min-role":"viewer"}},"/b":{"get":{"operationId":"x","tags":["t"],"x-min-role":"viewer"}}}}`)
	if _, err := Operations(d); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v", err)
	}
}

func TestRoutesSourceSortedAndFormatted(t *testing.T) {
	t.Parallel()
	d := parse(t, `{"paths":{
		"/z":{"post":{"operationId":"b_op","tags":["m"],"x-min-role":"admin"}},
		"/a":{"get":{"operationId":"a_op","tags":["m"],"x-min-role":"public"},"delete":{"operationId":"c_op","tags":["n"],"x-min-role":"operator"}}}}`)
	ops, err := Operations(d)
	if err != nil {
		t.Fatal(err)
	}
	src, err := RoutesSource(ops)
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	ia, ib, ic := strings.Index(s, `"a_op"`), strings.Index(s, `"b_op"`), strings.Index(s, `"c_op"`)
	if ia <= 0 || ia >= ib || ib >= ic {
		t.Fatalf("not sorted by operationId:\n%s", s)
	}
	for _, want := range []string{`Method: "DELETE", Path: "/a", MinRole: Operator, Tag: "n"`, `MinRole: Public`, `MinRole: Admin`, "DO NOT EDIT."} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
}
