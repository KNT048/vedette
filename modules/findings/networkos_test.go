package findings

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// Every row of network-os.json compiles, and names every CISA KEV product of its OS (kev-products.json): a new spelling CISA uses
// ("FortiOS and FortiProxy SSL-VPN") must be added to the row, or the OS row misses its entries by key.
func TestNetworkOS_DataIsValid(t *testing.T) {
	t.Parallel()
	if osRowsErr != nil {
		t.Fatal(osRowsErr)
	}
	var kev []struct{ Vendor, Product string }
	if err := json.Unmarshal(catalogdata.KEVProducts, &kev); err != nil {
		t.Fatal(err)
	}
	// Per row: which KEV products of its vendor name the OS, and the ones that name it only as a word of another product.
	mentions := map[string]struct {
		re  *regexp.Regexp
		not []string
	}{
		"Juniper Junos OS":  {re: regexp.MustCompile(`(?i)\bjunos\b`)},
		"Fortinet FortiOS":  {re: regexp.MustCompile(`(?i)\bfortios\b`)},
		"Cisco IOS XE":      {re: regexp.MustCompile(`(?i)\bxe\b`)},
		"Cisco IOS":         {re: regexp.MustCompile(`(?i)^(?:cisco )?ios\b`), not: []string{"cisco|ios xr", "cisco|ios xe software", "cisco|ios xe web ui", "cisco|cisco ios xe web ui"}},
		"MikroTik RouterOS": {re: regexp.MustCompile(`(?i)\bRouter ?OS\b`)},
	}
	for _, d := range osRows {
		m, ok := mentions[d.Display]
		if !ok {
			t.Fatalf("%s: add the row to this test", d.Display)
		}
		for _, k := range kev {
			key := KevKey(k.Vendor, k.Product)
			if !strings.EqualFold(k.Vendor, d.Vendor) || !m.re.MatchString(k.Product) || slices.Contains(m.not, key) {
				continue
			}
			if !slices.Contains(d.KevKeys, key) {
				t.Errorf("%s: KEV product %q is not in kev_keys", d.Display, key)
			}
		}
	}
	if _, err := loadNetworkOS([]byte(`{"os":[{"display":"X","vendor":"X","product":"X","cpe":"o:x:x","statement":"^X$","from":"snmp","scheme":"dotted","kev_keys":["x|x"]}]}`)); err == nil {
		t.Fatal("a statement without the version group must be refused")
	}
}

// snmpDevice is a device that states os in answer to Vedette's SNMP read of its address.
func snmpDevice(id, os string) Asset {
	return Asset{ID: id, Name: id, OS: os, StatedOS: os, SNMPOS: os}
}

// #910 phase 1, PR 3: each OS of network-os.json, read over SNMP, is compared with the real NVD rows of one exploited CVE.
func TestNetworkOS_910_EachOSGetsItsExploitedCVEsByVersion(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-snmp-os.json")
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		os, display, ver string
		want             []string // CVEs of findings, basis version
	}{
		{"FortiOS 7.0.1", "Fortinet FortiOS", "7.0.1", []string{"CVE-2022-42475"}},    // 7.0.0 to 7.0.9
		{"FortiOS 7.0.12", "Fortinet FortiOS", "7.0.12", nil},                         // fixed in 7.0.10
		{"Cisco IOS XE 17.3.1", "Cisco IOS XE", "17.3.1", []string{"CVE-2023-20198"}}, // 17.3 to 17.3.8a
		{"Cisco IOS XE 17.12.4", "Cisco IOS XE", "17.12.4", nil},                      // no 17.12 range
		{"RouterOS 6.48", "MikroTik RouterOS", "6.48", []string{"CVE-2026-67277"}},    // 6.0 to 6.49.21; not CVE-2018-14847 (before 6.42)
		{"RouterOS 6.41", "MikroTik RouterOS", "6.41", []string{"CVE-2018-14847", "CVE-2026-67277"}},
	} {
		a := snmpDevice("d", tc.os)
		sws := deviceSoftware(a)
		if len(sws) != 1 || sws[0].ID != osSoftwareID("d") || sws[0].Display != tc.display || sws[0].Version != tc.ver || sws[0].Source != "snmp" || sws[0].CPE == "" {
			t.Fatalf("%s: rows %+v", tc.os, sws)
		}
		res := MatchAsset(a, vulns, nil, now)
		var got []string
		for _, m := range res.New {
			if m.Basis != BasisVersion || m.SoftwareID != osSoftwareID("d") {
				t.Errorf("%s: %s basis %s on %s", tc.os, m.CVE, m.Basis, m.SoftwareID)
			}
			got = append(got, m.CVE)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) || len(res.NeedVersion) != 0 || len(res.NotComparable) != 0 {
			t.Errorf("%s: findings %v, want %v; need version %+v; not comparable %+v", tc.os, got, tc.want, res.NeedVersion, res.NotComparable)
		}
	}
}

// Classic Cisco IOS "15.2(4)M3" has no order Vedette can compare (#910 phase 2): no finding, no "add the version", and its
// entries are listed as not comparable instead of being silent. A RouterOS release candidate is not comparable either.
func TestNetworkOS_910_ClassicIOSIsNotComparedButListed(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-snmp-os.json")
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ os, ver string }{{"Cisco IOS 15.2(4)M3", "15.2(4)M3"}, {"Cisco IOS 15.2(5)E", "15.2(5)E"}} {
		a := snmpDevice("ios", tc.os)
		if sws := deviceSoftware(a); len(sws) != 0 {
			t.Fatalf("%s: a not-comparable OS is not compared: %+v", tc.os, sws)
		}
		res := MatchAsset(a, vulns, nil, now)
		want := []NotComparable{{CVE: "CVE-2018-0171", SoftwareID: osSoftwareID("ios"), Software: "Cisco IOS", Version: tc.ver}}
		if len(res.New) != 0 || len(res.NeedVersion) != 0 || len(res.NotAffected) != 0 || !slices.Equal(res.NotComparable, want) {
			t.Errorf("%s: %+v", tc.os, res)
		}
	}
	res := MatchAsset(snmpDevice("mt", "RouterOS 7.14rc1"), vulns, nil, now)
	if len(res.New) != 0 || len(res.NotComparable) != 2 {
		t.Errorf("RouterOS 7.14rc1: %+v", res)
	}
}

// Only the device's own SNMP answer counts for these OSes (D-549): an LLDP frame can carry another device's MAC. Its own agent
// reporting another OS wins. A recorded row of the OS decides when its version is readable; one without gives way.
func TestNetworkOS_910_WhoseStatementCounts(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-snmp-os.json")
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	lldp := Asset{ID: "d", StatedOS: "FortiOS 7.0.1"}
	if res := MatchAsset(lldp, vulns, nil, now); len(res.New) != 0 || len(deviceSoftware(lldp)) != 0 {
		t.Errorf("LLDP only: %+v", res.New)
	}
	agent := snmpDevice("d", "FortiOS 7.0.1")
	agent.AgentOS = "Ubuntu 24.04.3 LTS"
	if sws := deviceSoftware(agent); len(sws) != 0 {
		t.Errorf("agent's OS wins: %+v", sws)
	}
	picked := Software{ID: "s", Display: "FortiGate", Vendor: "Fortinet", Product: "FortiOS", Source: "manual", KevKeys: []string{"fortinet|fortios", "fortinet|multiple products"}}
	a := snmpDevice("d", "FortiOS 7.0.1")
	a.Software = []Software{picked, {ID: "fa", Display: "FortiAnalyzer", Vendor: "Fortinet", Product: "FortiAnalyzer", Version: "7.2.1", KevKeys: []string{"fortinet|multiple products"}}}
	if sws := deviceSoftware(a); len(sws) != 2 || sws[0].ID != "fa" || sws[1].ID != osSoftwareID("d") {
		t.Errorf("a picked FortiGate without a version gives way, FortiAnalyzer stays: %+v", sws)
	}
	picked.Version = "7.0.12"
	a.Software = []Software{picked}
	if sws := deviceSoftware(a); len(sws) != 1 || sws[0].ID != "s" {
		t.Errorf("a typed readable version wins: %+v", sws)
	}
	ios := snmpDevice("d", "Cisco IOS 15.2(4)M3")
	ios.Software = []Software{{ID: "s", Display: "Cisco IOS", Vendor: "Cisco", Product: "IOS", Version: "15.2(4)M3", Source: "manual", KevKeys: []string{"cisco|ios and ios xe"}}}
	if res := MatchAsset(ios, vulns, nil, now); len(res.NotComparable) != 0 {
		t.Errorf("a recorded IOS row decides as before: %+v", res.NotComparable)
	}
}
