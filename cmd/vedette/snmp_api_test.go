package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// D-607: SNMP is set up per device, by administrators only, through the real router and the OpenAPI validator. An operator or a viewer
// gets 403 before anything runs. The answer never holds the community, only its last 4 characters; Read from is the device's IP by
// default. A wrong read address is refused with its own code and words, not the schema's generic "invalid". Copy from copies the
// settings and the secret on the box: the secret is in no answer.
func TestSNMPPerDeviceIsForAdministratorsAndNeverShowsTheSecret(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	sw := s.seen(t, "192.168.10.20", "3c:22:fb:00:00:20", "switch")
	other := s.seen(t, "192.168.10.21", "3c:22:fb:00:00:21", "switch")
	body := `{"version":"v2c","community":"s3cret-community"}`
	for _, role := range []string{"operator", "viewer"} {
		for _, call := range [][2]string{{"PUT", ""}, {"GET", ""}, {"POST", "/check"}, {"DELETE", ""}} {
			b := ""
			if call[0] == "PUT" {
				b = body
			}
			if code, v := s.do(call[0], "/inventory/snmp/devices/"+sw+call[1], role, b); code != 403 || at(v, "error", "code") != "forbidden" {
				t.Errorf("%s%s as %s: %d %v", call[0], call[1], role, code, v)
			}
		}
	}
	noSecret := func(what string, v map[string]any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "s3cret") {
			t.Errorf("%s shows the community: %s", what, b)
		}
	}
	code, v := s.do("PUT", "/inventory/snmp/devices/"+sw, "admin", body)
	if code != 200 || v["secret_last4"] != "nity" || v["read_from"] != "192.168.10.20" || v["read_from_default"] != true || v["state"] != "waiting" {
		t.Fatalf("set up: %d %v", code, v)
	}
	noSecret("PUT", v)
	code, v = s.do("GET", "/inventory/snmp/devices/"+sw, "admin", "")
	if code != 200 || v["version"] != "v2c" || v["port"] != float64(161) {
		t.Fatalf("get: %d %v", code, v)
	}
	noSecret("GET", v)
	code, v = s.do("PUT", "/inventory/snmp/devices/"+sw, "admin", `{"version":"v2c","read_from":"224.0.0.1","community":"s3cret-community"}`)
	if code != 400 || at(v, "error", "code") != "bad_read_from" {
		t.Fatalf("a multicast read address: %d %v, want 400 bad_read_from", code, v)
	}
	if msg, _ := at(v, "error", "message").(string); !strings.Contains(msg, "224.0.0.1") {
		t.Errorf("no plain message: %v", v)
	}
	code, v = s.do("PUT", "/inventory/snmp/devices/"+other, "admin", `{"copy_from":"`+sw+`","read_from":"192.168.10.31"}`)
	if code != 200 || v["secret_last4"] != "nity" || v["read_from"] != "192.168.10.31" || v["read_from_default"] != false {
		t.Fatalf("copy from: %d %v", code, v)
	}
	noSecret("copy", v)
	code, v = s.do("GET", "/inventory/snmp", "admin", "")
	if devs, _ := v["devices"].([]any); code != 200 || len(devs) != 2 {
		t.Fatalf("list: %d %v", code, v)
	}
	noSecret("list", v)
	// Check now reaches the service, which says what blocks the read on this stack (scanning not set up), in words.
	code, v = s.do("POST", "/inventory/snmp/devices/"+sw+"/check", "admin", "")
	if code != 200 || v["ok"] != false || v["message"] == "" {
		t.Fatalf("check: %d %v", code, v)
	}
	if code, v := s.do("DELETE", "/inventory/snmp/devices/"+other, "admin", ""); code != 204 {
		t.Fatalf("remove: %d %v", code, v)
	}
	if code, v := s.do("GET", "/inventory/snmp/devices/"+other, "admin", ""); code != 200 || v["state"] != "not_set_up" {
		t.Fatalf("after remove: %d %v", code, v)
	}
}
