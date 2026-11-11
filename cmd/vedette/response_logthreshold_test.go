package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/logs"
)

// #332, D-287, #348, D-288: the log_threshold trigger reads the Logs module's counts and addresses through cmd/vedette. Lines of
// one signature from a declared source reach the threshold, and the address that sent them is banned; an address under the
// threshold is not. With the Logs module off there is no event.
func TestWiringResponseLogThreshold(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	s.setModule("logs", true)
	ctx := t.Context()
	lg := logsService(*s.d)
	src, err := lg.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.30.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	vpn := func(remip string) string {
		return `logid="0101039426" type="event" subtype="vpn" level="alert" logdesc="SSL VPN login fail" action="ssl-login-fail" user="bob" remip=` + remip + ` reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"`
	}
	var batch []logs.Line
	for _, ip := range []string{"203.0.113.7", "203.0.113.7", "203.0.113.7", "198.51.100.4"} {
		batch = append(batch, logs.Line{SourceID: src.ID, At: time.Now().Add(-time.Second), Text: vpn(ip)})
	}
	if res, err := lg.Ingest(ctx, batch); err != nil || res.Stored != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	rule := `{"name":"Failed VPN logins: ban","enabled":true,"live":false,"trigger":"log_threshold","match":"all",` +
		`"conditions":[{"field":"signature","op":"count_window","value":"logid=0101039426 action=ssl-login-fail","n":3,"window_min":5}],` +
		`"actions":[{"action_id":"blocklist_add","params":{"ip":"{{trigger.source_ip}}"},"ttl_min":60}],"pre_approved":false,"max_per_hour":5,"schedule_min":null}`
	c, v := s.do("POST", "/response/rules", "admin", rule)
	if c != 201 {
		t.Fatalf("add rule: %d %v", c, v)
	}
	if c, v := s.do("PUT", "/response/rules/"+v["id"].(string), "admin", strings.Replace(rule, `"live":false`, `"live":true`, 1)); c != 200 {
		t.Fatalf("rule live: %d %v", c, v)
	}

	s.setModule("logs", false) // off: the adapter answers no source, so no event
	if srcs, err := (responseLogCounts{svc: lg, reg: s.d.Reg}).Sources(ctx); err != nil || len(srcs) != 0 {
		t.Fatalf("Logs off: %v %v", srcs, err)
	}
	if top, err := (responseLogCounts{svc: lg, reg: s.d.Reg}).TopAddresses(ctx, src.ID, "logid=0101039426 action=ssl-login-fail", 5*time.Minute, 50); err == nil || len(top) != 0 {
		t.Fatalf("Logs off, TopAddresses: %v %v", top, err)
	}
	s.setModule("logs", true)
	if err := s.d.Response.PollLogs(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Response.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	c, v = s.do("GET", "/response/actions", "admin", "")
	reqs, _ := v["items"].([]any)
	if c != 200 || len(reqs) != 1 {
		t.Fatalf("one request from the log count (203.0.113.7 only): %d %v", c, v)
	}
	if got := at(reqs[0], "items", 0, "change", "cli"); got != "blocklist add 203.0.113.7" {
		t.Errorf("request: %v", got)
	}
}
