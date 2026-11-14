package sensorlink

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// FULL-4 (D-527, protocol 5 before its first release): the depth of an own_ip nuclei job and full in the nuclei heartbeat. Every
// other job keeps its shape (no depth, no disruptive); a full job round-trips; a decoder of the D-520 shape, which knows scope but no
// depth, refuses a full job (strict decoding: fail closed, nothing runs).
func TestNucleiDepthOnTheWire(t *testing.T) {
	t.Parallel()
	own, err := json.Marshal(Job{ID: strings.Repeat("c", 32), Kind: KindNuclei, TimeoutS: 60, Nuclei: &NucleiJob{Templates: []string{"CVE-2024-1"}, Scope: "own_ip"}})
	if err != nil || strings.Contains(string(own), "depth") || strings.Contains(string(own), "disruptive") {
		t.Fatalf("an own_ip job of D-520: %s %v", own, err)
	}
	full := strings.Replace(nucleiJobJSON, `"rate":5`, `"rate":20,"scope":"own_ip","depth":"full","disruptive":true`, 1)
	rep, err := decodeReply(t, full)
	if err != nil || rep.Jobs[0].Nuclei.Depth != "full" || !rep.Jobs[0].Nuclei.Disruptive {
		t.Fatalf("decoded %v %+v", err, rep)
	}
	out, err := json.Marshal(rep.Jobs[0])
	var back Job
	if err != nil || json.Unmarshal(out, &back) != nil || back.Nuclei.Depth != "full" || !back.Nuclei.Disruptive || back.Nuclei.Scope != "own_ip" {
		t.Fatalf("round trip %s %v %+v", out, err, back)
	}
	type nucleiJobD520 struct { // the nuclei job of D-520: scope, no depth
		ID            string         `json:"id"`
		Kind          string         `json:"kind"`
		TimeoutS      int            `json:"timeout_s"`
		Pack          JobPack        `json:"pack"`
		Templates     []string       `json:"templates"`
		Targets       []NucleiTarget `json:"targets"`
		Rate          int            `json:"rate"`
		MaxHostErrors int            `json:"max_host_errors"`
		Scope         string         `json:"scope,omitempty"`
	}
	var old nucleiJobD520
	if err := jsonstrict.Decode([]byte(full), &old); err == nil {
		t.Error("an older decoder accepted a full job")
	}
	if err := jsonstrict.Decode([]byte(strings.Replace(full, `,"disruptive":true`, "", 1)), &old); err == nil {
		t.Error("an older decoder accepted a full job without the tick")
	}
	if err := jsonstrict.Decode(own, &old); err != nil {
		t.Errorf("an older decoder refused an own_ip job of D-520: %v", err)
	}
	if _, err := decodeReply(t, strings.Replace(full, `"depth":"full"`, `"depth":"full","depth":""`, 1)); err == nil {
		t.Error("a repeated depth was accepted")
	}
	hb, err := decodeActiveHeartbeat([]byte(`{"version":"1.0.0","nmap":{"present":true,"version":"7.94"},"nuclei":{"present":true,"version":"v3.11.1","pack":{"version":"","sha256":""},"own_ip":true,"full":true}}`))
	if err != nil || !hb.Nuclei.Full {
		t.Fatalf("heartbeat %v %+v", err, hb)
	}
	if hb, err := decodeActiveHeartbeat([]byte(`{"version":"1.0.0","nmap":{"present":true,"version":"7.94"},"nuclei":{"present":true,"version":"v3.11.1","pack":{"version":"","sha256":""},"own_ip":true}}`)); err != nil || hb.Nuclei.Full {
		t.Fatalf("an older heartbeat: %v %+v", err, hb)
	}
}
