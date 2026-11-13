package sensoractive

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	snmpdata "github.com/knt048/vedette/content/snmp"
	"github.com/knt048/vedette/core/sensorlink"
)

// D-512: what the common answers say. Shapes from recordings of real devices (LibreNMS snmprec of a FortiGate 1500D and a Juniper EX,
// a Cisco IOS switch) and from the vendors' MIBs.
func TestIdentifySNMP(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		in   sensorlink.SNMPValues
		want SNMPFacts
	}{
		"juniper ex4200, no ENTITY-MIB": {
			sensorlink.SNMPValues{SysDescr: "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9, Build date: 2019-08-30 12:00:00 UTC Copyright (c) 1996-2019 Juniper Networks, Inc.",
				SysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.31", SysName: "SW-CORE-01"},
			SNMPFacts{Vendor: "Juniper Networks", Product: "Junos", Model: "EX4200-48T", OS: "JUNOS 15.1R7.9", Kind: "switch", Hostname: "SW-CORE-01"},
		},
		"fortigate: empty sysDescr, the model and FortiOS from ENTITY-MIB": {
			sensorlink.SNMPValues{SysObjectID: "1.3.6.1.4.1.12356.101.1.15000", SysName: "FGT-HQ", EntClass: "3", EntModel: "FGT_1500D",
				EntSoftware: "FortiGate-1500D v6.4.8,build1914,211117 (GA)", EntSerial: "FG1K5D3I00000000"},
			SNMPFacts{Vendor: "Fortinet", Product: "FortiGate", Model: "FortiGate-1500D", OS: "FortiOS 6.4.8", Kind: "firewall", Hostname: "FGT-HQ", Serial: "FG1K5D3I00000000",
				Firmware: "FortiGate-1500D v6.4.8,build1914,211117 (GA)"},
		},
		"an old fortigate under fortinetProducts": {
			sensorlink.SNMPValues{SysDescr: "our firewall", SysObjectID: ".1.3.6.1.4.1.12356.15"},
			SNMPFacts{Vendor: "Fortinet"},
		},
		"fortiswitch: no FortiOS": {
			sensorlink.SNMPValues{SysObjectID: ".1.3.6.1.4.1.12356.106.1.2482", EntClass: "3", EntSoftware: "FortiSwitch-248D v3.6.9,build0470,190507 (GA)"},
			SNMPFacts{Vendor: "Fortinet", Product: "FortiSwitch", Model: "FortiSwitch-248D", Kind: "switch", Firmware: "FortiSwitch-248D v3.6.9,build0470,190507 (GA)"},
		},
		"cisco ios": {
			sensorlink.SNMPValues{SysDescr: "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\r\nTechnical Support: http://www.cisco.com/techsupport",
				SysObjectID: ".1.3.6.1.4.1.9.1.1208", SysName: "sw2.corp.example", EntClass: "3", EntModel: "WS-C2960X-48FPD-L"},
			SNMPFacts{Vendor: "Cisco", Model: "WS-C2960X-48FPD-L", OS: "Cisco IOS 15.0(2)SE11", Hostname: "sw2.corp.example"},
		},
		"hp printer": {
			sensorlink.SNMPValues{SysDescr: "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153,EEPROM JSI23900", SysObjectID: ".1.3.6.1.4.1.11.2.3.9.1"},
			SNMPFacts{Vendor: "HP", Product: "JetDirect printer", Kind: "printer"},
		},
		"a module, not the chassis, at index 1: its model is not the device's": {
			sensorlink.SNMPValues{SysObjectID: ".1.3.6.1.4.1.25461.2.3.38", EntClass: "9", EntModel: "PAN-PWR-AC"},
			SNMPFacts{Vendor: "Palo Alto Networks", Kind: "firewall"},
		},
		"net-snmp on Linux: nothing about the maker": {
			sensorlink.SNMPValues{SysDescr: "Linux nas 5.10.0 #1 SMP x86_64", SysObjectID: ".1.3.6.1.4.1.8072.3.2.10", SysName: "nas"},
			SNMPFacts{Hostname: "nas"},
		},
		"hostile text": {
			sensorlink.SNMPValues{SysDescr: "<script>alert(1)</script>\x1b[2J", SysObjectID: "1.3.6.1.4.1.9; rm -rf /", SysName: "a b\u202e", EntClass: "3", EntModel: "x\u0000<b>"},
			SNMPFacts{},
		},
	} {
		got := identifySNMP(c.in)
		got.SysDescr, got.SysObjectID, got.SysName = "", "", ""
		if got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, c.want)
		}
	}
}

func TestCleanSNMP(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"  a\r\n\tb  ":           "a b",
		"x\u202ey\u200bz":        "x y z",
		"\xff\xfeok":             "ok",
		strings.Repeat("é", 300): strings.Repeat("é", maxSNMPText),
	} {
		if got := cleanSNMP(in); got != want {
			t.Errorf("cleanSNMP(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every row of content/snmp is checked when it is read; a broken one is refused, not half read.
func TestSNMPTable(t *testing.T) {
	t.Parallel()
	tb, err := parseSNMPTable(snmpdata.Enterprises)
	if err != nil || len(tb.byNumber) < 30 {
		t.Fatalf("%v (%d rows)", err, len(tb.byNumber))
	}
	for _, n := range []int{12356, 2636, 9, 11, 14823, 47196, 14988, 41112, 6574, 24681, 39165, 37496, 318, 2435, 4526, 11863, 890, 2604, 25461, 2620, 8741, 2011, 4881, 25506, 7367} {
		if _, ok := tb.byNumber[n]; !ok {
			t.Errorf("enterprise %d is missing", n)
		}
	}
	for name, raw := range map[string]string{
		"a kind the inventory does not have": `{"enterprises":[{"number":1,"vendor":"x","kind":"toaster"}]}`,
		"a number twice":                     `{"enterprises":[{"number":1,"vendor":"x"},{"number":1,"vendor":"y"}]}`,
		"no vendor":                          `{"enterprises":[{"number":1,"vendor":""}]}`,
		"a prefix that is not an OID tail":   `{"enterprises":[{"number":1,"vendor":"x","families":[{"prefix":"1.x","product":"p"}]}]}`,
		"a phrase in capitals":               `{"enterprises":[],"descr":[{"phrase":"Switch","kind":"switch"}]}`,
		"an unknown field":                   `{"enterprises":[{"number":1,"vendor":"x","oid":"1"}]}`,
	} {
		if _, err := parseSNMPTable([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The answer of a device is untrusted (SYS-6): whatever it says, what is kept is short printable text, the kind is one of the
// inventory's, the host name looks like one.
func FuzzIdentifySNMP(f *testing.F) {
	f.Add("Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9, Build date: x", ".1.3.6.1.4.1.2636.1.1.1.2.31", "SW-1", "3", "", "FortiGate-60F v7.2.5,build1517,230606 (GA.F)", "FGT60F")
	f.Add("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE", "1.3.6.1.4.1.12356.101.1.1", "\u202e", "11", "FGT_60F", "", "\x00")
	f.Fuzz(func(t *testing.T, descr, oid, name, class, model, software, serial string) {
		got := identifySNMP(sensorlink.SNMPValues{SysDescr: descr, SysObjectID: oid, SysName: name, EntClass: class, EntModel: model, EntSoftware: software, EntSerial: serial})
		for _, v := range []string{got.SysDescr, got.SysObjectID, got.SysName, got.Vendor, got.Product, got.Model, got.OS, got.Kind, got.Hostname, got.Serial, got.Firmware} {
			if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxSNMPText || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
				t.Fatalf("unsafe value %q", v)
			}
		}
		if got.Kind != "" && !slices.Contains(snmpKinds, got.Kind) {
			t.Fatalf("kind %q", got.Kind)
		}
		if got.Hostname != "" && !hostnameRE.MatchString(got.Hostname) {
			t.Fatalf("hostname %q", got.Hostname)
		}
	})
}
