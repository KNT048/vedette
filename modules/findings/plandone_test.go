package findings

import (
	"testing"
)

// A person marks a recommended update done (the plan was wrong, or they updated it and no agent reported yet): the item leaves the plan
// and the device's To fix card, is listed under Done with who and when, is audited, and comes back by itself once the device reports
// another version of that software. A viewer cannot mark it; Undo puts it back.
func TestPlanDone_HiddenUntilTheVersionChanges(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.inv.assets["a-u"] = AssetView{ID: "a-u", Hostname: ptr("web-u"), IP: "192.168.10.31", Kind: "server", Name: "web-u"}
	e.inv.match["a-u"] = Asset{ID: "a-u", Name: "web-u", OS: "Ubuntu 24.04 LTS", Software: []Software{debRow("s1", "libssl3", "openssl", "3.0.13-0ubuntu3.4")}}
	e.feeds.distro = []TierVuln{distroV("CVE-2026-50001", "likely", 30, 0.4, noble("openssl", "3.0.13-0ubuntu3.5", false))}
	e.feeds.covered = map[string]bool{"ubuntu/24.04": true}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	e.feeds.stamp = "s1"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	items := func(q string) ([]any, map[string]any) {
		t.Helper()
		c, b := e.call("GET", "/findings/plan?asset=a-u"+q, "viewer", "")
		if c != 200 {
			t.Fatalf("%d %v", c, b)
		}
		l, _ := b["items"].([]any)
		counts, _ := b["counts"].(map[string]any)
		return l, counts
	}
	l, _ := items("")
	if len(l) != 1 || l[0].(map[string]any)["done"] != nil {
		t.Fatalf("plan %v", l)
	}
	group := l[0].(map[string]any)["group"].(string)
	if c, _ := e.call("POST", "/findings/plan/done", "viewer", `{"group":"`+group+`","note":""}`); c != 403 {
		t.Fatalf("viewer: %d", c)
	}
	if c, b := e.call("POST", "/findings/plan/done", "operator", `{"group":"nope","note":""}`); c != 404 {
		t.Fatalf("unknown item: %d %v", c, b)
	}
	if c, b := e.call("POST", "/findings/plan/done", "operator", `{"group":"`+group+`","note":" updated by hand "}`); c != 200 || b["by"] != "it@acme.example" || b["note"] != "updated by hand" || b["version"] != "3.0.13-0ubuntu3.4" {
		t.Fatalf("mark: %d %v", c, b)
	}
	if l, counts := items(""); len(l) != 0 || counts["done"] != 1.0 {
		t.Fatalf("after the mark: %v %v", l, counts)
	}
	l, _ = items("&done=true")
	if len(l) != 1 || l[0].(map[string]any)["done"].(map[string]any)["by"] != "it@acme.example" {
		t.Fatalf("done list %v", l)
	}
	if u, _, _ := e.svc.DeviceUpdates(t.Context(), "a-u", true); len(u.Planned) != 0 {
		t.Fatalf("To fix still lists it: %+v", u.Planned)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.plan_done'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	// the device reports another (still affected) release: the mark no longer holds, the item is back and the mark is gone
	e.inv.match["a-u"] = Asset{ID: "a-u", Name: "web-u", OS: "Ubuntu 24.04 LTS", Software: []Software{debRow("s1", "libssl3", "openssl", "3.0.13-0ubuntu3.4.1")}}
	e.feeds.stamp = "s2"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if l, counts := items(""); len(l) != 1 || counts["done"] != 0.0 {
		t.Fatalf("after a new version: %v %v", l, counts)
	}
	if n := e.count(`SELECT count(*) FROM fnd_plan_done`); n != 0 {
		t.Fatalf("stale mark kept: %d", n)
	}
	// mark again, then Undo
	if c, _ := e.call("POST", "/findings/plan/done", "operator", `{"group":"`+group+`","note":""}`); c != 200 {
		t.Fatalf("mark again: %d", c)
	}
	if c, b := e.call("POST", "/findings/plan/undone", "operator", `{"group":"`+group+`"}`); c != 200 || b["group"] != group {
		t.Fatalf("undo: %d %v", c, b)
	}
	if l, _ := items(""); len(l) != 1 {
		t.Fatalf("after undo: %v", l)
	}
	if c, _ := e.call("POST", "/findings/plan/undone", "operator", `{"group":"`+group+`"}`); c != 404 {
		t.Fatalf("undo twice: %d", c)
	}
}
