package main

import "testing"

// D-512 (lab finding on #715): an SNMP credential with no scope is refused by the handler's own check, through the real router and
// the OpenAPI validator, so the person reads scope_required and why, not the schema's generic "invalid". A credential with a scope
// is saved.
func TestSNMPCredentialWithoutAScopeSaysWhy(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	code, v := s.do("POST", "/inventory/snmp", "admin", `{"name":"Core switches","version":"v2c","community":"s3cret-community","scope":[]}`)
	if code != 400 || at(v, "error", "code") != "scope_required" {
		t.Fatalf("empty scope: %d %v, want 400 scope_required", code, v)
	}
	if msg, _ := at(v, "error", "message").(string); msg == "" {
		t.Fatalf("no message: %v", v)
	}
	code, v = s.do("POST", "/inventory/snmp", "admin", `{"name":"Core switches","version":"v2c","community":"s3cret-community","scope":["192.168.10.0/24"]}`)
	if code != 201 || v["secret_last4"] != "nity" {
		t.Fatalf("with a scope: %d %v", code, v)
	}
}
