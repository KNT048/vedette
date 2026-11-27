package findings

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// The hardware a vendor's record limits a row to (CVE JSON 5 affected[].platforms) against the model a device states: a row is for
// other hardware only when every platform it names is read as a family or a model and none can be the device's. Synthetic names:
// the rule reads the shape of the names (a family "<letters> Series", a model "<letters><number>"), never a list of products.
func TestOtherHardware(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		model     string
		platforms []string
		other     bool
	}{
		{"ZX4200-48T", []string{"QRX Series"}, true},
		{"Acme Networks ZX4200-48T", []string{"QRX Series"}, true},               // vendor words before the model
		{"ZX4200-48T", []string{"QRX Series with SPC3"}, true},                   // a qualifier narrows the family only
		{"ZX4200-48T", []string{"QRX 5000 Series with SPC3", "MZ Series"}, true}, // every family is another
		{"ZX4200-48T", []string{"QRX1600", "QRX2300", "QRX4300"}, true},
		{"ZX4200-48T", []string{"ZX4100", "ZX4300-MP (Multigigabit)", "ZX2300", "ZX4400", "ZX4000"}, true}, // ZX4000 is one model of a list
		{"ZX204", []string{"ZX10k Series"}, true},
		{"ZX4200-48T", []string{"ZX Series"}, false},
		{"ZX4200-48T", []string{"QRX Series", "ZX Series"}, false},
		{"ZX4200-48T", []string{"ZX4200"}, false},
		{"ZX4300-48MP", []string{"ZX4300-MP (Multigigabit)"}, false},
		{"ZX4200-48T", []string{"ZX4000"}, false},         // alone, a round number may name a series
		{"ZX4200-48T", []string{"ZX 4000 Series"}, false}, // the 4000 series holds 4200
		{"ZX4200-48T", []string{"ZX4k Series"}, false},    // so does the 4k series
		{"ZX9204", []string{"ZX9200 Series"}, false},
		{"ZX10003", []string{"ZX10k Series"}, false},
		{"QRX345", []string{"vQRX Series"}, false},             // one name inside the other: not told apart
		{"ZX4200-48T", []string{"QRX Series", "Cloud"}, false}, // a platform the rule cannot read
		{"ZX4200-48T", []string{"Linux"}, false},
		{"ZX4200-48T", []string{"Windows", "MacOS"}, false},
		{"Workstation 440 G10", []string{"Tablet 17"}, false}, // a name with a blank before its number is not read as a model
		{"ZX4200-48T", nil, false},
		{"", []string{"QRX Series"}, false},                 // the device's model is not known
		{"Virtual Platform", []string{"QRX Series"}, false}, // no model number
	} {
		if got := otherHardware(tc.model, tc.platforms); got != tc.other {
			t.Errorf("model %q, platforms %q: other %v, want %v", tc.model, tc.platforms, got, tc.other)
		}
	}
}

// A vendor's own record that lists the product as affected only on other hardware than the device's model proves the device not
// affected, inside the listed ranges too; it never does for hardware it may name, a model the box does not know, a third party's list,
// or a version an NVD row or an every-device row of the vendor calls affected.
func TestMatchAsset_ModelRowsOfOtherHardware(t *testing.T) {
	t.Parallel()
	p, ok := productid.ResolveStored("Juniper", "Junos OS", "Juniper Junos OS", "")
	if !ok || p.Scheme == "" {
		t.Fatal("no product with a version scheme")
	}
	rows := func(platforms []string, complete bool, spans ...[3]string) []SchemedRange {
		out := schemedRows(t, p.Scheme, p.Key, spans...)
		for i := range out {
			out[i].ModelOnly, out[i].Platforms, out[i].Complete = true, platforms, complete
		}
		return out
	}
	other := []string{"QRX Series", "MZ Series with SPC3"}
	limited := rows(other, true, [3]string{"24.2", "24.2R2-S2", ""}, [3]string{"25.2", "25.2R2", ""})
	vuln := func(cve string, schemed []SchemedRange, nvd ...Affected) Vuln {
		return Vuln{CVE: cve, Vendor: "Juniper", Product: "Junos OS", NVDAnswered: true, Published: uncNew, DateAdded: uncNew, Schemed: schemed, Affected: nvd}
	}
	device := func(model, ver string) Asset {
		return Asset{ID: "sw", Name: "sw", Model: model, Software: []Software{{ID: "s", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS",
			Version: ver, Source: "manual", SetBy: "admin@example.test", KevKeys: []string{"juniper|junos os"}}}}
	}
	for _, tc := range []struct {
		name, model, ver string
		v                Vuln
		want             string // "none", "finding", "kept"
	}{
		{"an older line, rows for other hardware", "ZX4200-48T", "15.1R7.9", vuln("CVE-2099-0501", limited), "none"},
		{"inside a listed range, rows for other hardware", "ZX4200-48T", "24.2R1", vuln("CVE-2099-0502", limited), "none"},
		{"rows that may name the device's hardware", "ZX4200-48T", "24.2R1", vuln("CVE-2099-0503", rows([]string{"ZX Series"}, true, [3]string{"24.2", "24.2R2-S2", ""})), "kept"},
		{"the device's model is not known", "", "24.2R1", vuln("CVE-2099-0504", limited), "kept"},
		{"a third party's list (no default)", "ZX4200-48T", "24.2R1", vuln("CVE-2099-0505", rows(other, false, [3]string{"24.2", "24.2R2-S2", ""})), "kept"},
		{"an every-device row of the vendor covers it", "ZX4200-48T", "24.2R1",
			vuln("CVE-2099-0506", append(schemedRows(t, p.Scheme, p.Key, [3]string{"24.2", "24.2R2-S1", ""}), limited...)), "finding"},
		{"the device's hardware, older than where the flaw came in", "ZX4200-48T", "15.1R7.9",
			vuln("CVE-2099-0508", rows([]string{"ZX Series", "QRX Series"}, true, [3]string{"23.4R2-S6", "23.4R2-S7", ""}, [3]string{"24.2R2-S3", "24.2R2-S4", ""})), "none"},
		{"the device's hardware, rows from a branch start", "ZX4200-48T", "15.1R7.9",
			vuln("CVE-2099-0509", rows([]string{"ZX Series"}, true, [3]string{"23.4", "23.4R2-S7", ""})), "kept"},
		{"the device's hardware, a third party's starts", "ZX4200-48T", "15.1R7.9",
			vuln("CVE-2099-0510", rows([]string{"ZX Series"}, false, [3]string{"23.4R2-S6", "23.4R2-S7", ""})), "kept"},
		{"an NVD row covers it", "ZX4200-48T", "24.2R1",
			vuln("CVE-2099-0507", limited, Affected{CPE: "cpe:2.3:o:juniper:junos:24.2:r1:*:*:*:*:*:*"}), "kept"},
	} {
		r := MatchAsset(device(tc.model, tc.ver), []Vuln{tc.v}, nil, t0)
		got := "none"
		switch {
		case len(r.New) == 1 && r.New[0].Basis == BasisVersion && tc.want == "finding":
			got = "finding"
		case len(r.New)+len(r.Unchecked)+len(r.NameOnly)+len(r.NotComparable) > 0:
			got = "kept"
		}
		if got != tc.want {
			t.Errorf("%s: %s, want %s (%+v)", tc.name, got, tc.want, r)
		}
	}
	// the proof names the hardware the record lists and the device's model
	r := MatchAsset(device("ZX4200-48T", "15.1R7.9"), []Vuln{vuln("CVE-2099-0501", limited)}, map[string]bool{"CVE-2099-0501": true}, t0)
	if len(r.NotAffected) != 1 {
		t.Fatalf("not affected %+v, want the open finding closed", r.NotAffected)
	}
	if n := r.NotAffected[0].Evidence.Summary; !strings.HasPrefix(n, "Not affected:") || !strings.Contains(n, "QRX Series") || !strings.Contains(n, "ZX4200-48T") {
		t.Errorf("note %q", n)
	}
}

// A record that lists its affected releases one by one and states the fixed release above them (LineFix: "7.23.1" above 7.20.8) bounds
// the line: a release past the fix on that line is not affected, also when only the record's rows name the product; a release between
// the last affected one and the fix stays undecided, and so does a listed release on this path (an exact release a CVE on no list
// names decides nothing by itself, viaNVD).
func TestMatchAsset_ExactRowsWithALineFix(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2099-0601"
	cpe := "cpe:2.3:o:acme:gateway_os:*:*:*:*:*:*:*:*"
	var aff []Affected
	for _, v := range []string{"6.0", "6.44", "7.20.0", "7.20.8"} {
		aff = append(aff, Affected{CPE: cpe, Range: VersionRange{StartIncl: v, EndIncl: v}})
	}
	aff[len(aff)-1].LineFix = "7.23.1"
	v := Vuln{CVE: cve, NVDAnswered: true, Published: uncNew, Affected: aff, RangesFrom: RangesCVEOrgPartial, Origin: RangeCNA}
	for _, tc := range []struct {
		ver, want string // "none" (proved not affected), "finding", "open" (neither)
	}{
		{"7.25.2", "none"},
		{"7.23.1", "none"},
		{"7.22.0", "open"},
		{"7.20.8", "open"},
	} {
		a := Asset{ID: "gw", Name: "gw", Software: []Software{{ID: "s", Display: "Acme Gateway OS", Vendor: "Acme", Product: "Gateway OS",
			Version: tc.ver, Source: "snmp", CPE: cpe}}}
		r := MatchAsset(a, []Vuln{v}, map[string]bool{cve: true}, t0)
		got := "open"
		switch {
		case len(r.NotAffected) == 1:
			got = "none"
		case len(r.Existing) == 1 && r.Existing[0].Basis == BasisVersion:
			got = "finding"
		}
		if got != tc.want {
			t.Errorf("%s: %s, want %s (%+v)", tc.ver, got, tc.want, r)
		}
	}
}
