package findings

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"
)

// installLines is a Windows PC whose agent reports the lines a test box held on 2026-11-26 (Thunderbird 115.9.0 "(x64 vi)", SQL Server
// 2022 RTM "(64-bit)", Node.js 22.19.0, Visual Studio Code, FortiClient VPN, Firefox 160.0, Notepad++ without an architecture in its
// name), its Windows release row stating x64, and a second PC on Thunderbird 153.0.1 (an M.0.x build of an ESR major: either edition).
// Each CVE carries NVD's real rows for those products (sw_edition, target_sw, target_hw as NVD writes them). cause names each CVE's
// shape, for the counts.
func installLines(t *testing.T) (e *env, cause map[string]string, notAffected map[string]int, notes map[string]string) {
	t.Helper()
	recent := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	upTo := func(cpe, start, end string) Affected {
		return Affected{CPE: cpe, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	cve := func(id string, aff ...Affected) Vuln {
		return Vuln{CVE: id, NVDAnswered: true, Published: recent, Affected: aff}
	}
	const (
		tb    = "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:%s:*:*:*"
		ff    = "cpe:2.3:a:mozilla:firefox:*:*:*:*:%s:*:*:*"
		sql   = "cpe:2.3:a:microsoft:sql_server_2022:*:*:*:*:*:*:x64:*"
		sql25 = "cpe:2.3:a:microsoft:sql_server_2025:*:*:*:*:*:*:x64:*"
		nd    = "cpe:2.3:a:nodejs:node.js:*:*:*:*:%s:*:*:*"
		vsc   = "cpe:2.3:a:microsoft:visual_studio_code:*:*:*:*:*:-:*:*"
		fc    = "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:%s:*:*"
		npp   = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:x64:*"
	)
	f := fmt.Sprintf
	cases := []struct {
		cause string
		v     Vuln
	}{
		{"Thunderbird: plain rows only", cve("CVE-2025-14332", upTo(f(ff, "-"), "", "146.0"), upTo(f(tb, "-"), "", "146.0"))},
		{"Thunderbird: ESR rows only", cve("CVE-2026-14899", upTo(f(tb, "esr"), "", "140.13.0"))},
		{"Thunderbird: plain and two ESR branches", cve("CVE-2026-100779", upTo(f(tb, "-"), "", "157.0"),
			upTo(f(tb, "esr"), "140.0", "140.17.0"), upTo(f(tb, "esr"), "153.0", "153.4.0"))},
		{"Thunderbird: plain and ESR, both cover", cve("CVE-2025-14328", upTo(f(ff, "esr"), "", "140.6.0"), upTo(f(ff, "-"), "", "146.0"),
			upTo(f(tb, "esr"), "", "140.6.0"), upTo(f(tb, "-"), "", "146.0"))},
		{"Thunderbird: plain, and ESR from 140", cve("CVE-2099-0310", upTo(f(tb, "-"), "", "157.0"), upTo(f(tb, "esr"), "140.0", "140.17.0"))},
		{"Firefox: plain and ESR", cve("CVE-2099-0311", upTo(f(ff, "esr"), "", "140.17.0"), upTo(f(ff, "-"), "", "161.0"))},
		{"SQL Server 2022: pinned to x64", cve("CVE-2026-20803", upTo(sql, "16.0.1000.6", "16.0.1165.1"), upTo(sql, "16.0.4003.1", "16.0.4230.2"))},
		// NVD's rows of SQL Server 2025 only, the first with no start: a 2022 build is not a 2025 one
		{"SQL Server 2025 rows only", cve("CVE-2026-67369", upTo(sql25, "", "17.0.1135.8"), upTo(sql25, "17.0.4006.2", "17.0.4085.5"))},
		{"Node.js: plain edition", cve("CVE-2025-55130", upTo(f(nd, "-"), "20.0.0", "20.20.0"), upTo(f(nd, "-"), "22.0.0", "22.22.0"))},
		{"Node.js: LTS edition", cve("CVE-2099-0312", upTo(f(nd, "lts"), "22.11.0", "22.22.0"))},
		{"VS Code: no target software", cve("CVE-2026-102231", upTo(vsc, "", "1.141.1"))},
		{"FortiClient: Windows build", cve("CVE-2025-62676", upTo(f(fc, "windows"), "7.0.0", "7.2.13"), upTo(f(fc, "windows"), "7.4.0", "7.4.5"))},
		{"FortiClient: Linux build", cve("CVE-2026-24018", upTo(f(fc, "linux"), "7.2.2", "7.2.13"), upTo(f(fc, "linux"), "7.4.0", "7.4.5"))},
		{"Notepad++: pinned to x64", cve("CVE-2099-0313", upTo(npp, "", "8.6.6"))},
	}
	e = newEnv(t)
	cause = map[string]string{}
	for _, c := range cases {
		e.feeds.vulns = append(e.feeds.vulns, c.v)
		cause[c.v.CVE] = c.cause
	}
	win := "Microsoft Windows 11 Pro 10.0.26100.4652"
	agent := func(id, display, vendor, product, ver string) Software {
		return Software{ID: id, Display: display, Vendor: vendor, Product: product, Version: ver, Source: "agent"}
	}
	pc := Asset{ID: "pc-01", Name: "DESKTOP-01", OS: win, AgentOS: win, Software: []Software{
		{ID: "s-win", Display: "Windows 11 24H2", Vendor: "Microsoft", Product: "Windows 11 24H2", Version: "10.0.26100.4652", Source: "agent",
			CPE: "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.4652:*:*:*:*:*:x64:*"},
		agent("s-tb", "Mozilla Thunderbird (x64 vi)", "Mozilla", "Thunderbird", "115.9.0"),
		agent("s-sql", "Microsoft SQL Server 2022 (64-bit)", "Microsoft", "SQL Server", "16.0.1000.6"),
		agent("s-node", "Node.js", "Node.js", "Node.js", "22.19.0"),
		agent("s-vsc", "Microsoft Visual Studio Code (User)", "Microsoft", "Visual Studio Code", "1.140.0"),
		agent("s-fc", "FortiClient VPN", "Fortinet", "FortiClient", "7.4.3.4726"),
		agent("s-ff", "Mozilla Firefox (x64 en-US)", "Mozilla", "Firefox", "160.0"),
		agent("s-npp", "Notepad++", "Notepad-plus-plus", "Notepad++", "8.6.5"),
	}}
	pc2 := Asset{ID: "pc-02", Name: "DESKTOP-02", OS: win, AgentOS: win, Software: []Software{
		agent("s-tb2", "Mozilla Thunderbird (x64 en-US)", "Mozilla", "Thunderbird", "153.0.1"),
	}}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	notAffected, notes = map[string]int{}, map[string]string{}
	for i, a := range []Asset{pc, pc2} {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Name: a.Name, Hostname: ptr(a.Name), IP: fmt.Sprintf("192.0.2.%d", 90+i), Kind: "workstation", Approved: true}
		e.inv.match[a.ID] = a
		have := map[string]bool{} // as if the device had a finding for every CVE: the proofs that would close it
		for c := range cause {
			have[c] = true
		}
		for _, m := range MatchAsset(a, e.feeds.vulns, have, t0).NotAffected {
			notAffected[a.Name+" / "+cause[m.CVE]]++
			if a.ID == "pc-01" {
				notes[m.CVE] = m.Evidence.Summary
			}
		}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e, cause, notAffected, notes
}

// Class count: what the box asks, finds and rules out for lines whose NVD rows pin a build attribute (edition, platform, architecture)
// the line does not state.
//
// Before: 13 questions, every one "the version cannot be compared … type it as the vendor writes it", although the version compares
// and retyping it changes nothing: Thunderbird 115.9.0 for the plain-only, ESR-only, plain+two-ESR and plain+ESR-from-140 rows (4),
// Firefox 160.0, SQL Server 2022 RTM (x64), Node.js 22.19.0 ("-" and "lts", 2), VS Code (target software "-"), FortiClient's Windows
// and Linux rows (2), Notepad++ (x64), and Thunderbird 153.0.1 for the plain+ESR-from-140 rows. Open findings 2, both suspected
// (Thunderbird inside every edition's range).
//
// After: 2 questions, each naming the attribute: Notepad++ (is it the 64-bit build? the name does not say, and a 64-bit Windows runs
// 32-bit programs) and Thunderbird 153.0.1 (an M.0.x build of an ESR major: ESR or the normal release?). Findings on the device's own
// word: Thunderbird 115.9.0 is an ESR build (2: ESR-only, both-cover), Firefox 160.0 a normal release, SQL Server 2022 the x64 build
// (named "64-bit"), Node.js by its version (2), VS Code ("-" is no specific system), FortiClient's Windows build. Not affected, with
// the build named: Thunderbird 115.9.0 for the plain-only, plain+two-ESR and plain+ESR-from-140 rows (NVD lists ESR rows whenever an
// ESR is affected), FortiClient's Linux build.
func TestQueue_Count_InstallAttributes(t *testing.T) {
	t.Parallel()
	e, cause, notAffected, notes := installLines(t)
	in, err := e.svc.Input(t.Context(), "", "", Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	items, findings := map[string]int{}, map[string]int{}
	var walk func(its []InputItemJS)
	walk = func(its []InputItemJS) {
		for _, it := range its {
			switch {
			case it.Kind == "question":
				c, attr := "", ""
				if it.CVE != nil {
					c = cause[*it.CVE]
				}
				if it.Attr != nil {
					attr = " (" + *it.Attr + ")"
				}
				items[it.Device.Name+" "+it.Question+attr+" / "+c]++
			case len(it.Entries) > 0 || len(it.Questions) > 0:
				walk(it.Entries)
				walk(it.Questions)
			default:
				items[it.Kind]++
			}
		}
	}
	walk(in.Items)
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve, verified, evidence FROM fnd_finding WHERE state = 'open'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	evidence := map[string]string{}
	for rows.Next() {
		var c, verified, ev string
		if err := rows.Scan(&c, &verified, &ev); err != nil {
			t.Fatal(err)
		}
		findings[verified+" / "+cause[c]]++
		evidence[c] = ev
	}
	t.Logf("Needs your input by device, kind / cause:%s", countLines(items))
	t.Logf("open findings by verification / cause:%s", countLines(findings))
	t.Logf("not affected by device / cause:%s", countLines(notAffected))
	wantItems := map[string]int{
		"DESKTOP-01 not_comparable (architecture) / Notepad++: pinned to x64":        1,
		"DESKTOP-02 not_comparable (edition) / Thunderbird: plain, and ESR from 140": 1,
	}
	if !maps.Equal(items, wantItems) {
		t.Errorf("queue %v, want %v", items, wantItems)
	}
	wantFindings := map[string]int{
		"device / Thunderbird: ESR rows only":             1,
		"device / Thunderbird: plain and ESR, both cover": 1,
		"device / Firefox: plain and ESR":                 1,
		"device / SQL Server 2022: pinned to x64":         1,
		"device / Node.js: plain edition":                 1,
		"device / Node.js: LTS edition":                   1,
		"device / VS Code: no target software":            1,
		"device / FortiClient: Windows build":             1,
		"no / Thunderbird: plain and two ESR branches":    1, // 153.0.1 is inside the plain range and the 153 ESR range: either edition
	}
	if !maps.Equal(findings, wantFindings) {
		t.Errorf("findings %v, want %v", findings, wantFindings)
	}
	wantNot := map[string]int{
		"DESKTOP-01 / Thunderbird: plain rows only":            1,
		"DESKTOP-01 / Thunderbird: plain and two ESR branches": 1,
		"DESKTOP-01 / Thunderbird: plain, and ESR from 140":    1,
		"DESKTOP-01 / FortiClient: Linux build":                1,
		"DESKTOP-01 / SQL Server 2025 rows only":               1,
	}
	for k, n := range wantNot {
		if notAffected[k] != n {
			t.Errorf("not affected %q = %d, want %d", k, notAffected[k], n)
		}
	}
	// the closing note names the build the rows were read for
	for c, want := range map[string]string{"CVE-2025-14332": "NVD's rows for other builds do not apply: this is the ESR edition (Mozilla numbers only ESR builds 115.N.x",
		"CVE-2026-24018": "NVD's rows for other builds do not apply: the device runs Microsoft Windows 11 Pro"} {
		if !strings.Contains(notes[c], want) {
			t.Errorf("%s note %q does not say %q", c, notes[c], want)
		}
	}
	// the evidence names the build the rows were read for
	for c, want := range map[string]string{"CVE-2026-14899": "this is the ESR edition", "CVE-2099-0311": "the normal release, not ESR",
		"CVE-2026-20803": "this is the x64 build (its name says x64)", "CVE-2025-62676": "the device runs Microsoft Windows 11 Pro"} {
		if !strings.Contains(evidence[c], want) {
			t.Errorf("%s evidence %q does not say %q", c, evidence[c], want)
		}
	}
}
