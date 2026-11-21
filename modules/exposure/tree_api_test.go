package exposure

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// node reads a node of an answer.
func node(b map[string]any) (id string, proof map[string]any) {
	id, _ = b["id"].(string)
	proof, _ = b["proof"].(map[string]any)
	return id, proof
}

// The target tree over HTTP: add, read, edit, check, accept the terms and delete a node. Every answer goes through the generated
// encoder, which refuses a body that does not fit the API schema, so each 2xx here is also a check of the contract.
func TestHandlers_TheTreeAnswersTheContract(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	code, b := e.call("GET", "/exposure/tree", "viewer", "")
	if code != 200 || len(list(b, "items")) != 0 || b["box_ip"] == nil {
		t.Fatalf("the empty tree: %d %v", code, b)
	}
	// a subdomain first, then its apex: the subdomain moves under the apex
	code, b = e.call("POST", "/exposure/tree", "admin", `{"value":"git.acme.example","scope_mode":"self"}`)
	if code != 201 || b["scope_mode"] != "self" || b["parent_id"] != nil || b["blocked"] != "proof" {
		t.Fatalf("add a subdomain: %d %v", code, b)
	}
	git, _ := node(b)
	if b["schedule_key"] != "exposure.target:"+git {
		t.Fatalf("schedule key: %v", b["schedule_key"])
	}
	code, b = e.call("POST", "/exposure/tree", "admin", `{"value":"acme.example"}`)
	apex, proof := node(b)
	if code != 201 || b["scope_mode"] != "all" || proof["state"] != "missing" {
		t.Fatalf("add the apex: %d %v", code, b)
	}
	if dns, _ := proof["dns"].(map[string]any); dns["zone"] != "acme.example" || dns["host"] != "@" || !strings.HasPrefix(fmt.Sprint(dns["value"]), "vedette-verify=") {
		t.Fatalf("where the record goes: %v", proof)
	}
	if code, b = e.call("POST", "/exposure/tree", "admin", `{"value":"198.51.100.7","scope_mode":"all"}`); code != 400 || errCode(b) != "bad_value" {
		t.Fatalf("a scope for an IP: %d %v", code, b)
	}
	code, b = e.call("GET", "/exposure/tree", "viewer", "")
	items := list(b, "items")
	if code != 200 || len(items) != 2 {
		t.Fatalf("the tree: %d %v", code, b)
	}
	first, _ := items[0].(map[string]any)
	second, _ := items[1].(map[string]any)
	if first["id"] != apex || second["id"] != git || second["parent_id"] != apex {
		t.Fatalf("tree order (parent first, child under it): %v", items)
	}
	// the apex proved: its child is covered by it
	tok := strings.TrimPrefix(fmt.Sprint(proof["dns"].(map[string]any)["value"]), "vedette-verify=")
	e.dns.put("acme.example", txtRecord(tok))
	code, b = e.call("POST", "/exposure/tree/"+apex+"/verify", "operator", "")
	if n, _ := b["node"].(map[string]any); code != 200 || b["verified"] != true || n["proof"].(map[string]any)["state"] != "proven" {
		t.Fatalf("check the apex: %d %v", code, b)
	}
	if code, b = e.call("POST", "/exposure/tree/"+git+"/verify", "operator", ""); code != 200 || b["verified"] != true {
		t.Fatalf("check the child: %d %v", code, b)
	}
	code, b = e.call("GET", "/exposure/tree/"+git, "viewer", "")
	_, proof = node(b)
	if cov, _ := proof["covered_by"].(map[string]any); code != 200 || proof["state"] != "covered" || cov["id"] != apex || proof["dns"] != nil || proof["method"] != nil {
		t.Fatalf("the child is covered by the apex: %d %v", code, proof)
	}
	if b["blocked"] != "no_commitment" || b["commitment_notice"] == nil {
		t.Fatalf("the child needs its confirmation: %v", b)
	}
	// edit: the switch, the scope and the chosen names
	if code, b = e.call("PATCH", "/exposure/tree/"+git, "admin", `{"enabled":false}`); code != 200 || b["enabled"] != false || b["blocked"] != "disabled" {
		t.Fatalf("switch off: %d %v", code, b)
	}
	if code, b = e.call("PATCH", "/exposure/tree/"+apex, "admin", `{"scope_mode":"selected","selected":[]}`); code != 200 || b["scope_mode"] != "selected" {
		t.Fatalf("scope selected: %d %v", code, b)
	}
	ids := make([]string, MaxSelected+1)
	for i := range ids {
		ids[i] = fmt.Sprintf(`"xh-%d"`, i)
	}
	code, b = e.call("PATCH", "/exposure/tree/"+apex, "admin", `{"selected":[`+strings.Join(ids, ",")+`]}`)
	if m, _ := b["error"].(map[string]any); code != 400 || !strings.Contains(fmt.Sprint(m["message"]), "one scan reads at most 300 names") {
		t.Fatalf("300 names chosen: %d %v", code, b)
	}
	if code, b = e.call("PATCH", "/exposure/tree/"+apex, "admin", `{"selected":[`+strings.Join(ids[:MaxSelected], ",")+`]}`); code != 400 || errCode(b) != "bad_value" {
		t.Fatalf("299 names that are not its own: %d %v", code, b)
	}
	// the terms, then withdrawn
	code, b = e.call("PUT", "/exposure/tree/"+apex+"/terms", "admin", `{"version":"`+TermsVersion+`","disruptive":false}`)
	if terms, _ := b["terms"].(map[string]any); code != 200 || b["deep"] != true || terms["version"] != TermsVersion || b["commitment"] == nil {
		t.Fatalf("accept the terms: %d %v", code, b)
	}
	if code, b = e.call("DELETE", "/exposure/tree/"+apex+"/terms", "admin", ""); code != 200 || b["deep"] != false || b["terms"] != nil {
		t.Fatalf("withdraw the terms: %d %v", code, b)
	}
	// delete the apex: the child moves up and needs a proof of its own
	if code, b = e.call("DELETE", "/exposure/tree/"+apex, "admin", ""); code != 204 {
		t.Fatalf("delete: %d %v", code, b)
	}
	if code, _ = e.call("GET", "/exposure/tree/"+apex, "viewer", ""); code != 404 {
		t.Fatalf("a deleted node: %d", code)
	}
	code, b = e.call("GET", "/exposure/tree/"+git, "viewer", "")
	if _, proof = node(b); code != 200 || b["parent_id"] != nil || proof["state"] == "covered" {
		t.Fatalf("the child after its parent left: %d %v", code, b)
	}
}

// A public IP the box found is proven by the box's own egress, and its node says so.
func TestHandlers_TheBoxIPIsAProvenNode(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	ip := e.detect(ipA)[0]
	code, b := e.call("GET", "/exposure/tree/"+ip.ID, "viewer", "")
	_, proof := node(b)
	if code != 200 || b["origin"] != "box" || b["scope_mode"] != nil || proof["state"] != "proven" || proof["method"] != "box_egress" || proof["expires_at"] == nil {
		t.Fatalf("the box's IP: %d %v", code, b)
	}
}
