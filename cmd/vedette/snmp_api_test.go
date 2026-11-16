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

// #849: Read now is for administrators (D-512: a credential goes only where an admin points it). An operator or a viewer gets 403
// before anything runs; an administrator reaches the service, which answers what blocks the read on this stack (no scan worker, or
// scanning not set up) instead of a role error. The read of a credential nobody read is null.
func TestSNMPReadNowIsForAdministrators(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	code, v := s.do("POST", "/inventory/snmp", "admin", `{"name":"Core switches","version":"v2c","community":"s3cret-community","scope":["192.168.10.0/24"]}`)
	if code != 201 {
		t.Fatalf("add: %d %v", code, v)
	}
	id, _ := v["id"].(string)
	for _, role := range []string{"operator", "viewer"} {
		for _, m := range []string{"POST", "GET"} {
			if code, v := s.do(m, "/inventory/snmp/"+id+"/read", role, ""); code != 403 || at(v, "error", "code") != "forbidden" {
				t.Errorf("%s as %s: %d %v", m, role, code, v)
			}
		}
	}
	if code, v := s.do("POST", "/inventory/snmp/"+id+"/read", "admin", ""); code != 409 {
		t.Errorf("admin: %d %v, want 409 (nothing can be sent on this stack)", code, v)
	}
	if code, v := s.do("GET", "/inventory/snmp/"+id+"/read", "admin", ""); code != 200 || v != nil {
		t.Errorf("admin read of a credential never read: %d %v, want 200 null", code, v)
	}
}
