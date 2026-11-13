package sensoractive

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	snmpdata "github.com/knt048/vedette/content/snmp"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// What an SNMP answer says about a device (D-512). Every value is the device's own text and untrusted (SYS-6): it is cleaned first
// (valid UTF-8, no control or format character, spaces collapsed, at most maxSNMPText runes) and then only read through fixed
// layouts: the vendor from the enterprise number of sysObjectID (content/snmp), the model and OS from the sysDescr layouts LLDP
// uses too (capture.ParseSysDesc), the chassis model of ENTITY-MIB only for a chassis or a stack, FortiOS from the FortiGate's
// firmware text. A value that fits no layout gives nothing; nothing is ever taken verbatim but the host name, which must look like one.

// maxSNMPText is the longest cleaned value kept (the inventory takes at most 200).
const maxSNMPText = 200

// SNMPFacts is what one answer says. Product is the family of the sysObjectID ("FortiGate"); Serial and Firmware are shown in the
// answer of a Test and not stored (the inventory has no field for them).
type SNMPFacts struct {
	SysDescr, SysObjectID, SysName                               string // cleaned, as the device said them
	Vendor, Product, Model, OS, Kind, Hostname, Serial, Firmware string
}

type snmpFamily struct {
	Prefix  string `json:"prefix"`
	Product string `json:"product"`
	Kind    string `json:"kind"`
}

type snmpEnterprise struct {
	Number   int          `json:"number"`
	Vendor   string       `json:"vendor"`
	Kind     string       `json:"kind"`
	Families []snmpFamily `json:"families"`
}

type snmpDescrRule struct {
	Phrase string `json:"phrase"`
	Kind   string `json:"kind"`
}

type snmpTable struct {
	Enterprises []snmpEnterprise `json:"enterprises"`
	Descr       []snmpDescrRule  `json:"descr"`
	byNumber    map[int]snmpEnterprise
}

// snmpKinds are the inventory's device kinds the table may name (the inventory refuses any other).
var snmpKinds = []string{"firewall", "router", "switch", "ap", "nas", "server", "pc", "printer", "camera", "nvr", "iot", "web"}

var loadSNMPTable = sync.OnceValues(func() (*snmpTable, error) { return parseSNMPTable(snmpdata.Enterprises) })

// parseSNMPTable reads the table and checks every row: a positive number once, a vendor, a known kind, a dotted prefix.
func parseSNMPTable(raw []byte) (*snmpTable, error) {
	var t snmpTable
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&struct {
		About string `json:"about"`
		*snmpTable
	}{snmpTable: &t}); err != nil {
		return nil, fmt.Errorf("sensoractive: content/snmp: %w", err)
	}
	t.byNumber = map[int]snmpEnterprise{}
	kindOK := func(k string) bool { return k == "" || slices.Contains(snmpKinds, k) }
	for _, e := range t.Enterprises {
		if _, dup := t.byNumber[e.Number]; dup || e.Number < 1 || e.Vendor == "" || !kindOK(e.Kind) {
			return nil, fmt.Errorf("sensoractive: content/snmp: enterprise %d", e.Number)
		}
		for _, f := range e.Families {
			if !oidTailRE.MatchString("."+f.Prefix) || f.Product == "" || !kindOK(f.Kind) {
				return nil, fmt.Errorf("sensoractive: content/snmp: enterprise %d family %q", e.Number, f.Prefix)
			}
		}
		t.byNumber[e.Number] = e
	}
	for _, d := range t.Descr {
		if d.Phrase == "" || d.Phrase != strings.ToLower(d.Phrase) || d.Kind == "" || !kindOK(d.Kind) {
			return nil, fmt.Errorf("sensoractive: content/snmp: descr %q", d.Phrase)
		}
	}
	return &t, nil
}

var (
	// enterpriseOID is an object identifier under 1.3.6.1.4.1 (private enterprises): the number, then the rest.
	enterpriseOID = regexp.MustCompile(`^\.?1\.3\.6\.1\.4\.1\.([1-9][0-9]{0,9})((?:\.[0-9]{1,10}){0,40})$`)
	oidTailRE     = regexp.MustCompile(`^(?:\.[0-9]{1,10}){1,40}$`)
	anyOID        = regexp.MustCompile(`^\.?[0-2](?:\.[0-9]{1,10}){1,60}$`)
	// hostnameRE is what a sysName must look like to be the device's name (the NTLM rule of INV-14).
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	// modelRE is what an ENTITY-MIB model name must look like to be the model.
	modelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._/+()-]{0,63}$`)
	// fortiFirmware is a Fortinet device's entPhysicalSoftwareRev: "FortiGate-1500D v6.4.8,build1914,211117 (GA)".
	fortiFirmware = regexp.MustCompile(`^(Forti[A-Za-z]{2,12}-[A-Za-z0-9]{1,16}) v([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3})\b`)
)

// cleanSNMP makes a device's value safe text: valid UTF-8, no control, format (bidi) or separator character, runs of spaces as one,
// trimmed, at most maxSNMPText runes.
func cleanSNMP(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			r = ' '
		case unicode.IsSpace(r):
			r = ' '
		}
		if r == ' ' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if r := []rune(out); len(r) > maxSNMPText {
		out = strings.TrimSpace(string(r[:maxSNMPText]))
	}
	return out
}

// identifySNMP reads the values of one answer.
func identifySNMP(v sensorlink.SNMPValues) SNMPFacts {
	f := SNMPFacts{SysDescr: cleanSNMP(v.SysDescr), SysObjectID: cleanSNMP(v.SysObjectID), SysName: cleanSNMP(v.SysName)}
	if !anyOID.MatchString(f.SysObjectID) {
		f.SysObjectID = ""
	}
	if t, err := loadSNMPTable(); err == nil {
		if m := enterpriseOID.FindStringSubmatch(f.SysObjectID); m != nil {
			n, _ := strconv.Atoi(m[1])
			if e, ok := t.byNumber[n]; ok {
				f.Vendor, f.Kind = e.Vendor, e.Kind
				for _, fam := range e.Families {
					if m[2] == "."+fam.Prefix || strings.HasPrefix(m[2], "."+fam.Prefix+".") {
						f.Product = fam.Product
						if fam.Kind != "" {
							f.Kind = fam.Kind
						}
					}
				}
			}
		}
		if f.Kind == "" {
			low := strings.ToLower(f.SysDescr)
			for _, d := range t.Descr {
				if strings.Contains(low, d.Phrase) {
					f.Kind = d.Kind
					break
				}
			}
		}
	}
	model, os := capture.ParseSysDesc(f.SysDescr)
	if class := strings.TrimSpace(v.EntClass); class == "3" || class == "11" { // chassis, stack (ENTITY-MIB PhysicalClass)
		if m := cleanSNMP(v.EntModel); modelRE.MatchString(m) {
			model = m
		}
		f.Firmware, f.Serial = cleanSNMP(v.EntSoftware), cleanSNMP(v.EntSerial)
		if !modelRE.MatchString(f.Serial) {
			f.Serial = ""
		}
	}
	if m := fortiFirmware.FindStringSubmatch(cleanSNMP(v.EntSoftware)); m != nil && f.Vendor == "Fortinet" {
		model = m[1]
		if os == "" && (strings.HasPrefix(m[1], "FortiGate-") || strings.HasPrefix(m[1], "FortiWiFi-")) { // FortiSwitch and FortiAP run other systems
			os = "FortiOS " + m[2]
		}
	}
	f.Model, f.OS = model, os
	if hostnameRE.MatchString(f.SysName) {
		f.Hostname = f.SysName
	}
	return f
}
