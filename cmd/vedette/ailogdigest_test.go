package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

// The log-digest job reads the digest of the logs module through aiLogDigest (S-AI-4, D-221): signatures and counts, never a line.
func TestAILogDigestReadsKindsAndCountsNotLines(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	read := aiLogDigest(s.d)
	// the logs module off: the port says so, and the route answers the documented 409
	if _, on, err := read(ctx); err != nil || on {
		t.Fatalf("logs off: on=%v err=%v", on, err)
	}
	s.setModule("ai", true)
	s.setModule("logs", true)
	if _, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: "fw-hq", IP: "192.168.30.1"}); err != nil {
		t.Fatal(err)
	}
	svc := logsService(*s.d)
	src, err := svc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.30.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	const mark = "SAMPLELINEMARK"
	if res, err := svc.Ingest(ctx, []logs.Line{{SourceID: src.ID, At: time.Now().Add(-time.Second), Text: "type=traffic srcip=10.0.0.1 " + mark}}); err != nil || res.Stored != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	d, on, err := read(ctx)
	if err != nil || !on || d.Lines24h != 1 {
		t.Fatalf("digest = %+v on=%v err=%v", d, on, err)
	}
	if raw, _ := json.Marshal(d); strings.Contains(string(raw), mark) || strings.Contains(string(raw), "sample") {
		t.Fatalf("the digest handed to the AI carries a line: %s", raw)
	}
	// events_around of log investigation (D-223): the kinds and counts of the address the line named, never the line
	vpn := `logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" user="bob" remip=203.0.113.2 ` + mark
	if res, err := svc.Ingest(ctx, []logs.Line{{SourceID: src.ID, At: time.Now().Add(-time.Second), Text: vpn}}); err != nil || res.Stored != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	around, on, err := aiLogAround(s.d)(ctx, netip.MustParseAddr("203.0.113.2"), time.Now().Add(-time.Hour), time.Now())
	if err != nil || !on || around.Lines != 1 || len(around.Kinds) != 1 {
		t.Fatalf("around = %+v on=%v err=%v", around, on, err)
	}
	if raw, _ := json.Marshal(around); strings.Contains(string(raw), mark) {
		t.Fatalf("events_around carries a line: %s", raw)
	}
	// the routes: nothing generated yet is null (no AI call); no profile assigned, generating is the documented 409
	if code, m := s.do("GET", "/ai/logs/digest", "viewer", ""); code != 200 || m["digest"] != nil {
		t.Fatalf("GET = %d %v", code, m)
	}
	if code, m := s.do("POST", "/ai/logs/digest", "operator", ""); code != 409 || at(m, "error", "code") != "ai_unavailable" {
		t.Fatalf("POST = %d %v", code, m)
	}
	s.setModule("logs", false)
	if _, on, err := aiLogAround(s.d)(ctx, netip.MustParseAddr("10.0.0.1"), time.Now().Add(-time.Hour), time.Now()); err != nil || on {
		t.Fatalf("around with logs off: on=%v err=%v", on, err)
	}
	if code, m := s.do("GET", "/ai/logs/digest", "viewer", ""); code != 409 || at(m, "error", "code") != "ai_unavailable" {
		t.Fatalf("GET with logs off = %d %v", code, m)
	}
}
