package findings

import "testing"

// What a device of a distribution sees on the plan while that distribution's data is loaded, loaded with no row, or lacks its release:
// only a feed that has never completed a pull makes the device wait; after a pull, a package the data does not name, and a release it
// holds no row for, get the honest "Check <distro>'s security updates" item.
func TestPlan_DistroLoadedStatesAsTheCustomerSeesThem(t *testing.T) {
	t.Parallel()
	tier := []TierVuln{nvdSSH("CVE-2026-71001"), nvdSSH("CVE-2026-71002")}
	alpine := Asset{ID: "fw", Name: "fw", AgentOS: "Alpine Linux v3.23", OS: "Alpine Linux v3.23", Software: []Software{sshAgentRow("10.2_p1-r1", "openssh")}}
	ubuntu := Asset{ID: "u", Name: "u", OS: "Ubuntu 22.04 LTS", Software: []Software{sshAgentRow("1:8.9p1-3ubuntu0.10", "openssh")}}
	tier = append(tier, tierV("CVE-2026-71003", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.3"}}))
	for name, tc := range map[string]struct {
		a        Asset
		loading  map[string]bool
		known    map[string]bool
		covered  map[string]bool
		distro   []TierVuln
		wantItem string // the sentence of the one item, "" for none
		compared bool
	}{
		"never pulled: the device waits, unchecked":                    {a: alpine, loading: map[string]bool{DistroAlpine: true}},
		"pull completed with zero rows: the fallback item, not a wait": {a: alpine, wantItem: "Check Alpine Linux's security updates for OpenSSH", compared: true},
		"the data names no such package: the fallback item": {a: alpine, known: map[string]bool{"alpine/curl": true}, covered: map[string]bool{"alpine/": true},
			wantItem: "Check Alpine Linux's security updates for OpenSSH", compared: true},
		"package known, no row for the device's release: the fallback item": {a: ubuntu, known: map[string]bool{"ubuntu/openssh": true},
			covered: map[string]bool{"ubuntu/24.04": true}, distro: []TierVuln{distroV("CVE-2026-71009", "recent", 30, 0.01, noble("openssh", "1:9.6p1-3ubuntu13.9", false))},
			wantItem: "Check Ubuntu's security updates for OpenSSH", compared: true},
		"package known, release still loading: the device waits": {a: ubuntu, loading: map[string]bool{"ubuntu": true}, known: map[string]bool{"ubuntu/openssh": true},
			covered: map[string]bool{"ubuntu/24.04": true}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x := newTierIndex(tier).withKnown(tc.known, tc.loading).withDistro(tc.distro, tc.covered)
			items, compared := matchTiers(tc.a, x, nil, t0)
			if compared != tc.compared {
				t.Fatalf("compared %v, items %+v", compared, items)
			}
			if tc.wantItem == "" {
				if len(items) != 0 {
					t.Fatalf("items %+v", items)
				}
				return
			}
			if len(items) != 1 || items[0].DistroData != DistroDataNone {
				t.Fatalf("items %+v", items)
			}
			if s := updateSentence(planAction(items[0])); s != tc.wantItem {
				t.Fatalf("sentence %q, want %q", s, tc.wantItem)
			}
		})
	}
}

func planEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := newHTTPEnv(t)
	e.inv.assets["a-u"] = AssetView{ID: "a-u", Hostname: ptr("web-u"), IP: "192.168.10.31", Kind: "server", Name: "web-u"}
	e.inv.match["a-u"] = Asset{ID: "a-u", Name: "web-u", OS: "Ubuntu 24.04 LTS", Software: []Software{debRow("s1", "libssl3", "openssl", "3.0.13-0ubuntu3.4")}}
	e.feeds.distro = []TierVuln{distroV("CVE-2026-50001", "likely", 30, 0.4, noble("openssl", "3.0.13-0ubuntu3.5", false))}
	e.feeds.covered = map[string]bool{"ubuntu/24.04": true}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	e.feeds.stamp = "s1"
	return e
}

// A "Mark as done" mark survives a pass that lacked its data (nvd-recent loading again, a distribution feed re-pulling): the item is
// missing only for that reason, not because the update was installed.
func TestPlanDone_MarkSurvivesAPassWithoutData(t *testing.T) {
	t.Parallel()
	e := planEnv(t)
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, b := e.call("GET", "/findings/plan?asset=a-u", "viewer", "")
	group := b["items"].([]any)[0].(map[string]any)["group"].(string)
	if c, b := e.call("POST", "/findings/plan/done", "operator", `{"group":"`+group+`","note":""}`); c != 200 {
		t.Fatalf("mark: %d %v", c, b)
	}
	pass := func(stamp string) {
		t.Helper()
		e.feeds.stamp = stamp
		if err := e.svc.RefreshPlan(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// nvd-recent loading again: TierDistro keeps nothing but Loading, TierVulns nothing
	saved := *e.feeds
	e.feeds.tier.Recent, e.feeds.distro, e.feeds.covered = "loading", nil, nil
	pass("s2")
	if n := e.count(`SELECT count(*) FROM fnd_plan_done`); n != 1 {
		t.Fatalf("the mark was pruned while nvd-recent had no data: %d", n)
	}
	// a distribution feed that holds no row while it re-pulls
	e.feeds.tier, e.feeds.distro, e.feeds.covered = saved.tier, nil, nil
	pass("s3")
	if n := e.count(`SELECT count(*) FROM fnd_plan_done`); n != 1 {
		t.Fatalf("the mark was pruned while the distribution feed had no data: %d", n)
	}
	// a distribution the plan still waits for
	e.feeds.distro, e.feeds.covered, e.feeds.loading = saved.distro, saved.covered, map[string]bool{"ubuntu": true}
	pass("s4")
	if n := e.count(`SELECT count(*) FROM fnd_plan_done`); n != 1 {
		t.Fatalf("the mark was pruned while the distribution was loading: %d", n)
	}
	// the data is back: the item is still marked done
	e.feeds.loading = nil
	pass("s5")
	_, b = e.call("GET", "/findings/plan?asset=a-u&done=true", "viewer", "")
	if l, _ := b["items"].([]any); len(l) != 1 {
		t.Fatalf("done list after the data returned: %v", b)
	}
	// with its data, an update that fixed the item prunes the mark
	e.inv.match["a-u"] = Asset{ID: "a-u", Name: "web-u", OS: "Ubuntu 24.04 LTS", Software: []Software{debRow("s1", "libssl3", "openssl", "3.0.13-0ubuntu3.5")}}
	pass("s6")
	if n := e.count(`SELECT count(*) FROM fnd_plan_done`); n != 0 {
		t.Fatalf("the mark of an installed update stays: %d", n)
	}
}

// The Done tab's number is the number of items its list shows, for the tier asked.
func TestPlanDone_CountEqualsTheDoneList(t *testing.T) {
	t.Parallel()
	e := planEnv(t)
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, b := e.call("GET", "/findings/plan?asset=a-u", "viewer", "")
	group := b["items"].([]any)[0].(map[string]any)["group"].(string)
	if c, b := e.call("POST", "/findings/plan/done", "operator", `{"group":"`+group+`","note":""}`); c != 200 {
		t.Fatalf("mark: %d %v", c, b)
	}
	for tier, want := range map[string]int{"all": 1, "likely": 1, "recent": 0} { // the item's CVE is likely
		for _, done := range []string{"false", "true"} {
			_, b := e.call("GET", "/findings/plan?asset=a-u&tier="+tier+"&done="+done, "viewer", "")
			counts := b["counts"].(map[string]any)
			l, _ := b["items"].([]any)
			if int(counts["done"].(float64)) != want || done == "true" && len(l) != want {
				t.Fatalf("tier %s done=%s: done count %v, list %d, want %d", tier, done, counts["done"], len(l), want)
			}
		}
	}
}
