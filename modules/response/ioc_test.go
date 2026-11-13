package response_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/response"
)

// #376 (D-335, D-336, D-339): a known-bad connection of the Logs module (logs.ioc_hit.detected, the IocHit of logs L4) is an event of the
// ioc_connection trigger. The hit is read from a syslog line, which a LAN host can forge, so every field is checked at the edge, at most
// 60 hits an hour reach the rules, and a pre-approved rule leaves a domain-only hit and an action on the device to a person.

func pubIoc(e *env, data map[string]any) {
	e.t.Helper()
	e.must(e.bus.Publish(context.Background(), events.Event{Name: response.EventIocHit, Data: data}))
}

func iocHit(id, src, dest, kind string) map[string]any {
	return map[string]any{"id": id, "ts": "2026-11-12T10:00:00.250Z", "asset_id": "a-pc", "asset_name": "PC-SALES-02", "src_ip": src, "dest": dest,
		"dest_kind": kind, "seen_via": "syslog:Office firewall", "feeds": []string{"IPsum", "Tor exit list"}, "confidence": 0.92}
}

func TestIocHitEvent(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC-SALES-02", IP: "192.168.10.105", Kind: "pc", Approved: true}
	e.svc.Subscribe(e.bus)
	pubIoc(e, iocHit("h1", "192.168.10.105", "185.220.101.47", "ip"))
	pubIoc(e, iocHit("h1", "192.168.10.105", "185.220.101.47", "ip")) // the same hit again: one event
	pubIoc(e, iocHit("h2", "::ffff:192.168.10.105", "CDN-Update.BadHost.example", "domain"))
	for name, bad := range map[string]map[string]any{
		"no id":             iocHit("", "192.168.10.105", "185.220.101.47", "ip"),
		"id with a newline": iocHit("h\n3", "192.168.10.105", "185.220.101.47", "ip"),
		"public source":     iocHit("h4", "8.8.8.8", "185.220.101.47", "ip"),
		"100/8 source":      iocHit("h15", "100.128.0.5", "185.220.101.47", "ip"), // only 100.64/10 is local (D-461)
		"shell in source":   iocHit("h5", "192.168.10.105; reboot", "185.220.101.47", "ip"),
		"domain as ip":      iocHit("h6", "192.168.10.105", "badhost.example", "ip"),
		"ip with a quote":   iocHit("h7", "192.168.10.105", "185.220.101.47\"", "ip"),
		"private dest":      iocHit("h10", "192.168.10.105", "10.0.0.5", "ip"),
		"CGNAT dest":        iocHit("h11", "192.168.10.105", "100.100.1.2", "ip"), // a Tailscale peer
		"documentation":     iocHit("h12", "192.168.10.105", "198.51.100.7", "ip"),
		"benchmarking":      iocHit("h13", "192.168.10.105", "198.18.0.9", "ip"),
		"6to4 dest":         iocHit("h14", "192.168.10.105", "2002:c000:204::1", "ip"),
		"unknown kind":      iocHit("h8", "192.168.10.105", "185.220.101.47", "url"),
		"confidence > 1": func() map[string]any {
			h := iocHit("h9", "192.168.10.105", "185.220.101.47", "ip")
			h["confidence"] = 92
			return h
		}(),
	} {
		pubIoc(e, bad)
		if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'ioc_connection'`); n != 2 {
			t.Fatalf("%s: %d events stored, want 2", name, n)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'ioc:h1' AND ts = '2026-11-12T10:00:00.250Z' AND asset_id = 'a-pc' AND device_kind = 'pc'
		AND fields LIKE '%"dest_ip":"185.220.101.47"%' AND fields LIKE '%"dest_domain":""%' AND fields LIKE '%"confidence":"0.92"%' AND fields LIKE '%"feeds":"IPsum, Tor exit list"%'`); n != 1 {
		t.Fatal("the fields of an address hit were not kept")
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'ioc:h2' AND fields LIKE '%"src_ip":"192.168.10.105"%' AND fields LIKE '%"dest_domain":"cdn-update.badhost.example"%' AND fields LIKE '%"dest_ip":""%'`); n != 1 {
		t.Fatal("the mapped source or the domain in its canonical spelling was not kept")
	}
	// A rule on the trigger fields: block the listed address.
	e.rule("Block", "ioc_connection", blockAction(60), func(in *response.RuleInput) {
		in.Conditions = []response.Condition{{Field: "dest_kind", Op: "eq", Value: "ip"}}
	})
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	if l := e.actions(); sum.Requests != 1 || len(l) != 1 || !strings.Contains(l[0].Items[0].Title, "185.220.101.47") {
		t.Fatalf("summary %+v, requests %+v", sum, l)
	}
}

// D-461: a device in the RFC 6598 shared address space is a LAN device, as logs reads it (signature.LocalOK).
func TestIocHitFromASharedAddressSpaceDevice(t *testing.T) {
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	pubIoc(e, iocHit("h1", "100.65.254.7", "185.220.101.47", "ip"))
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'ioc:h1' AND fields LIKE '%"src_ip":"100.65.254.7"%'`); n != 1 {
		t.Fatalf("%d events from a 100.64/10 device, want 1", n)
	}
}

func TestIocPreApprovalOnlyBlocksAListedAddress(t *testing.T) {
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	e.rule("Block destination", "ioc_connection", blockAction(60), func(in *response.RuleInput) { in.PreApproved = true })
	e.rule("Block the device", "ioc_connection", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.src_ip}}"}, TTLMin: intp(60)}},
		func(in *response.RuleInput) { in.PreApproved = true })
	pubIoc(e, iocHit("h1", "192.168.10.105", "185.220.101.47", "ip"))
	pubIoc(e, iocHit("h2", "192.168.10.106", "badhost.example", "domain"))
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	got := map[string]response.ActionRequest{}
	for _, a := range e.actions() {
		got[a.Items[0].Title] = a
	}
	for title, a := range got {
		auto := strings.Contains(title, "185.220.101.47") // only the listed address of an address hit runs without a person
		if auto && (a.Status == "pending" || !a.PreApproved) || !auto && (a.Status != "pending" || a.PreApproved) {
			t.Errorf("%s: status %s, pre-approved %v", title, a.Status, a.PreApproved)
		}
	}
	if len(got) < 2 {
		t.Fatalf("requests: %+v", got)
	}
	for _, why := range []string{"names a domain only", "device of a syslog line"} {
		if !e.logHas("request", why) && !e.logHas("proposal", why) && e.count(`SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%' || ? || '%'`, why) == 0 {
			t.Errorf("no log line says %q", why)
		}
	}
}

func TestIocHourlyCap(t *testing.T) {
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	for i := 0; i < 70; i++ {
		pubIoc(e, iocHit("flood-"+strconv.Itoa(i), "192.168.10.105", "185.220.102."+strconv.Itoa(i), "ip"))
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'ioc_connection'`); n != 60 {
		t.Errorf("%d events stored this hour, want the cap of 60", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE detail LIKE 'ioc_cap:%'`); n != 1 {
		t.Errorf("%d cap lines in the log, want 1", n)
	}
	e.clock.Advance(61 * time.Minute) // the next hour lets hits through again
	pubIoc(e, iocHit("next-hour", "192.168.10.105", "185.220.103.1", "ip"))
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'ioc:next-hour'`); n != 1 {
		t.Error("a hit of the next hour did not reach the rules")
	}
}
