package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/logs"
)

// #332, D-287: the log_threshold trigger reads the Logs module's counts through cmd/vedette. Lines of one signature from a declared
// source reach the threshold, the rule makes a request naming the log source; with the Logs module off there is no event.
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
	line := `logid="0100032002" type="event" subtype="system" level="alert" user="admin" action="login" msg="Administrator admin login failed from https(10.0.0.9) because of invalid password"`
	batch := make([]logs.Line, 3)
	for i := range batch {
		batch[i] = logs.Line{SourceID: src.ID, At: time.Now().Add(-time.Second), Text: line}
	}
	if res, err := lg.Ingest(ctx, batch); err != nil || res.Stored != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	rule := `{"name":"Admin login failures","enabled":true,"live":false,"trigger":"log_threshold","match":"all",` +
		`"conditions":[{"field":"signature","op":"count_window","value":"logid=0100032002 action=login","n":3,"window_min":5}],` +
		`"actions":[{"action_id":"msg_send","params":{"text":"{{trigger.count}} admin login failures on {{trigger.source_device}}"},"ttl_min":null}],"pre_approved":false,"max_per_hour":5,"schedule_min":null}`
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
		t.Fatalf("a request from the log count: %d %v", c, v)
	}
	if got := at(reqs[0], "items", 0, "change", "cli"); got != "notify 3 admin login failures on FW-HQ" {
		t.Errorf("request: %v", got)
	}
}
