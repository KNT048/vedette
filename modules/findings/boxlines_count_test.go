package findings

import (
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// officeLines is a small office's network as a test box held it on 2026-11-25, with NVD's real configurations for one or two CVEs of
// each software line: a Windows PC whose agent reports Thunderbird 115.9.0, SQL Server 2022 RTM (16.0.1000.6) and Java 8 Update 491;
// a Juniper EX4200-48T switch whose Junos release (15.1R7.9) a person typed; and a FortiGate whose FortiOS release (7.2.13) a person
// typed. cause names each CVE's line and shape, for the counts.
func officeLines(t *testing.T) (*env, map[string]string) {
	t.Helper()
	upTo := func(cpe, start, end string) Affected {
		return Affected{CPE: cpe, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	recent := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	offList := func(cve string, aff ...Affected) Vuln { // a CVE on no exploited list
		return Vuln{CVE: cve, NVDAnswered: true, Published: recent, Affected: vendorCNARows(aff)}
	}
	listed := func(cve, vendor, product, name string, aff ...Affected) Vuln {
		return Vuln{CVE: cve, Vendor: vendor, Product: product, Name: name, NVDAnswered: true, Published: recent, DateAdded: recent, Affected: vendorCNARows(aff)}
	}
	const (
		tb     = "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:%s:*:*:*"
		ff     = "cpe:2.3:a:mozilla:firefox:*:*:*:*:%s:*:*:*"
		sql22  = "cpe:2.3:a:microsoft:sql_server_2022:*:*:*:*:*:*:x64:*"
		sql19  = "cpe:2.3:a:microsoft:sql_server_2019:*:*:*:*:*:*:x64:*"
		junos  = "cpe:2.3:o:juniper:junos:"
		forti  = "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"
		jre8   = "cpe:2.3:a:oracle:jre:1.8.0:update441:*:*:%s:*:*:*"
		jdk8   = "cpe:2.3:a:oracle:jdk:1.8.0:update441:*:*:%s:*:*:*"
		jre11  = "cpe:2.3:a:oracle:jre:11.0.26:*:*:*:*:*:*:*"
		jre17  = "cpe:2.3:a:oracle:jre:17.0.14:*:*:*:*:*:*:*"
		jre21  = "cpe:2.3:a:oracle:jre:21.0.6:*:*:*:*:*:*:*"
		epp    = "enterprise_performance_pack"
		esrEnd = "140.9.0"
	)
	junosRows := func(rels ...string) []Affected {
		var out []Affected
		for _, r := range rels {
			out = append(out, Affected{CPE: junos + r + ":*:*:*:*:*:*"})
		}
		return out
	}
	cases := []struct {
		cause string
		v     Vuln
	}{
		// Thunderbird and Firefox: NVD pins the ESR edition and the plain one ("-"); 115.9.0 is inside both
		{"Thunderbird 115.9.0: inside the ESR and the plain range", offList("CVE-2026-4718",
			upTo(fmt.Sprintf(ff, "esr"), "", esrEnd), upTo(fmt.Sprintf(ff, "*"), "", "149.0"),
			upTo(fmt.Sprintf(tb, "esr"), "", esrEnd), upTo(fmt.Sprintf(tb, "-"), "", "149.0"))},
		{"Thunderbird 115.9.0: inside the ESR and the plain range", offList("CVE-2026-4694",
			upTo(fmt.Sprintf(ff, "esr"), "", "115.34.0"), upTo(fmt.Sprintf(ff, "-"), "", "149.0"), upTo(fmt.Sprintf(ff, "esr"), "128.0", esrEnd),
			upTo(fmt.Sprintf(tb, "esr"), "", esrEnd), upTo(fmt.Sprintf(tb, "-"), "", "149.0"))},
		// SQL Server: NVD pins the x64 target, which the line does not state
		{"SQL Server 2022 RTM: inside a range pinned to x64", offList("CVE-2025-49719",
			upTo(sql19, "15.0.2000.5", "15.0.2135.5"), upTo(sql22, "16.0.1000.6", "16.0.1140.6"), upTo(sql22, "16.0.4003.1", "16.0.4200.1"))},
		// Java: Oracle's newest affected release of each train, as exact versions; 8u491 is later than 8u441
		{"Java 8u491: NVD lists 8u441 and other trains", offList("CVE-2025-21587",
			Affected{CPE: fmt.Sprintf(jre8, "-")}, Affected{CPE: fmt.Sprintf(jre8, epp)}, Affected{CPE: fmt.Sprintf(jdk8, "-")},
			Affected{CPE: fmt.Sprintf(jdk8, epp)}, Affected{CPE: jre11}, Affected{CPE: jre17}, Affected{CPE: jre21})},
		// Junos: NVD enumerates the 24.4 and 25.2 releases only; Juniper's record says nothing before 24.4R1 is affected
		{"Junos 15.1R7.9: NVD lists only 24.4 and 25.2 releases", juniperRecord(t, offList("CVE-2026-21913",
			junosRows("24.4:-", "24.4:r1", "24.4:r1-s2", "24.4:r1-s3", "25.2:-", "25.2:r1", "25.2:r1-s1", "25.2:r2")...))},
		{"Junos 15.1R7.9: before 20.4 (exploited)", listed("CVE-2023-36844", "Juniper", "Junos OS",
			"Juniper Junos OS EX Series PHP External Variable Modification Vulnerability",
			append([]Affected{upTo(junos+"*:*:*:*:*:*:*:*", "", "20.4")}, junosRows("20.4:-", "20.4:r1", "20.4:r3-s8", "21.1:r1", "22.4:r2", "23.2:r1")...)...)},
		// FortiOS: 6.4.0 up to before 7.4.10 (exploited)
		{"FortiOS 7.2.13: 6.4.0 to before 7.4.10 (exploited)", listed("CVE-2025-61624", "Fortinet", "FortiOS",
			"Fortinet FortiOS Stack-Based Buffer Overflow Vulnerability", upTo(forti, "6.4.0", "7.4.10"))},
	}
	e := newEnv(t)
	cause := map[string]string{}
	for _, c := range cases {
		e.feeds.vulns = append(e.feeds.vulns, c.v)
		cause[c.v.CVE] = c.cause
	}
	const admin = "admin@example.test"
	pc := Asset{ID: "pc-01", Name: "DESKTOP-55UKKFV", OS: "Microsoft Windows 11 Pro", AgentOS: "Microsoft Windows 11 Pro", Software: []Software{
		{ID: "s-tb", Display: "Mozilla Thunderbird (x64 en-US)", Vendor: "Mozilla", Product: "Thunderbird", Version: "115.9.0", Source: "agent"},
		{ID: "s-sql", Display: "Microsoft SQL Server 2022 (64-bit)", Vendor: "Microsoft", Product: "SQL Server", Version: "16.0.1000.6", Source: "agent",
			KevKeys: []string{"microsoft|sql server"}},
		{ID: "s-java", Display: "Java 8 Update 491", Vendor: "Oracle", Product: "Java SE", Version: "8.0.4910.10", Source: "agent",
			KevKeys: []string{"oracle|java se"}},
	}}
	sw := Asset{ID: "sw-01", Name: "EX4200-48T", Model: "EX4200-48T", Software: []Software{
		{ID: "s-junos", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7.9", Source: "manual", SetBy: admin,
			KevKeys: []string{"juniper|junos os"}}}}
	fw := Asset{ID: "fw-01", Name: "FortiGate", Software: []Software{
		{ID: "s-fos", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.13", Source: "manual", SetBy: admin,
			KevKeys: []string{"fortinet|fortios"}}}}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for i, a := range []Asset{pc, sw, fw} {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Name: a.Name, Hostname: ptr(a.Name), IP: fmt.Sprintf("192.0.2.%d", 80+i), Kind: "server", Approved: true}
		e.inv.match[a.ID] = a
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e, cause
}

// juniperRecord is v with the rows Juniper's CVE record for CVE-2026-21913 gives the Junos scheme (feeds.StatementScheme): its entry
// is limited to EX4000 models, says versions it does not list are unaffected, states "unaffected" from 0 before 24.4R1, and lists
// 24.4 before 24.4R2 and 25.2 before 25.2R1-S2 as affected.
func juniperRecord(t *testing.T, v Vuln) Vuln {
	t.Helper()
	p, ok := productid.ResolveStored("Juniper", "Junos OS", "Juniper Junos OS", "")
	if !ok {
		t.Fatal("Junos OS is not in the product catalogue")
	}
	for _, r := range schemedRows(t, "juniper-junos", p.Key, [3]string{"", "24.4R1", ""}) {
		r.Unaffected = true
		v.Schemed = append(v.Schemed, r)
	}
	for _, r := range schemedRows(t, "juniper-junos", p.Key, [3]string{"24.4", "24.4R2", ""}, [3]string{"25.2", "25.2R1-S2", ""}) {
		r.ModelOnly = true
		v.Schemed = append(v.Schemed, r)
	}
	return v
}

// officeCounts is officeLines' Needs your input by item (a question by its kind and cause, an unconfirmed finding by its basis and cause)
// and its open findings by cause and verification.
func officeCounts(t *testing.T) (items, findings map[string]int) {
	t.Helper()
	e, cause := officeLines(t)
	in, err := e.svc.Input(t.Context(), "", "", Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	items, findings = map[string]int{}, map[string]int{}
	// The queue groups a device's questions in one card and a software line's questions in one entry: count what is asked, the
	// questions and unconfirmed findings inside them, not the cards.
	var walk func(its []InputItemJS)
	walk = func(its []InputItemJS) {
		for _, it := range its {
			c := ""
			if it.CVE != nil {
				c = cause[*it.CVE]
			}
			switch {
			case it.Kind == "question":
				items["question "+it.Question+" / "+c]++
			case it.Kind == "unconfirmed":
				items["unconfirmed, basis "+it.Basis+" / "+c]++
			case len(it.Entries) > 0 || len(it.Questions) > 0:
				walk(it.Entries)
				walk(it.Questions)
			default:
				items[it.Kind]++
			}
		}
	}
	walk(in.Items)
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve, verified FROM fnd_finding WHERE state = 'open'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cve, verified string
		if err := rows.Scan(&cve, &verified); err != nil {
			t.Fatal(err)
		}
		findings[verified+" / "+cause[cve]]++
	}
	return items, findings
}

// Class count: Needs your input and the open findings of officeLines.
//
// Before: 7 items, every one of them something the box already knew. Thunderbird 115.9.0 asked "cannot be compared" for both Mozilla
// CVEs although it is inside the ESR range and the plain one (2); Junos 15.1R7.9 asked for CVE-2026-21913, whose NVD list enumerates
// only 24.4 and 25.2 releases, and Java 8u491 for CVE-2025-21587, listed at 8u441 and at Java 11, 17 and 21 (2); SQL Server 2022 RTM
// asked because NVD pins x64 (1); and the two exploited findings on the versions a person typed (Junos, FortiOS) asking that same
// person to confirm them (2, basis statement). Open findings: 2, both unconfirmed.
//
// After: 0 items. The Thunderbird CVEs are version findings on the device's word (115.9.0 is an ESR build, and inside the ESR range;
// on no exploited list, so not queued); SQL Server 2022 RTM is the x64 build its name says ("64-bit"), a version finding; Java 8u491 is of a line newer than NVD's exact list names for its train, so it is not asked; Junos 15.1R7.9 is
// older than every line NVD lists (so NVD's list alone would still ask), and Juniper's own record decides it: "unaffected" from 0
// before 24.4R1, whatever the model; the findings on a version a person typed are confirmed by that person's word.
func TestQueue_Count_OfficeLines(t *testing.T) {
	t.Parallel()
	items, findings := officeCounts(t)
	t.Logf("Needs your input by kind / cause:%s", countLines(items))
	t.Logf("open findings by verification / cause:%s", countLines(findings))
	const (
		tb    = "Thunderbird 115.9.0: inside the ESR and the plain range"
		sql   = "SQL Server 2022 RTM: inside a range pinned to x64"
		junos = "Junos 15.1R7.9: before 20.4 (exploited)"
		forti = "FortiOS 7.2.13: 6.4.0 to before 7.4.10 (exploited)"
	)
	wantItems := map[string]int{}
	if !maps.Equal(items, wantItems) {
		t.Errorf("queue %v, want %v", items, wantItems)
	}
	wantFindings := map[string]int{
		"device / " + tb:    2,
		"device / " + sql:   1,
		"person / " + junos: 1,
		"person / " + forti: 1,
	}
	if !maps.Equal(findings, wantFindings) {
		t.Errorf("findings %v, want %v", findings, wantFindings)
	}
}
