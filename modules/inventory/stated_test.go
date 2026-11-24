package inventory_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

const (
	switchIP   = "192.168.1.20"
	juniperMAC = "3c:8a:b0:9c:85:ff" // an IEEE block of Juniper Networks
	vmwareMAC  = "00:0c:29:9c:85:ff" // another vendor's card
)

// junosGuess is what nmap stores for a Juniper switch it fingerprints: the OS observation and its Guess row (no version, no key).
var junosGuess = observe.Software{Display: "Juniper EX2200 switch (JUNOS 12)", Vendor: "juniper", Product: "junos", CPE: "cpe:/o:juniper:junos",
	Confidence: 0.95, Guess: true}

// scanSwitch records what one nmap run says about the device at switchIP with mac: its OS guess, the guess row and one service row.
func scanSwitch(e *env, mac, osGuess string) {
	e.t.Helper()
	h := observe.AssetHint{IP: netip.MustParseAddr(switchIP), MAC: mac}
	e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: osGuess, Source: observe.Nmap, Confidence: 0.95})
	guess := junosGuess
	guess.Display = osGuess
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, nil, []observe.Software{guess,
		{Display: "OpenSSH 6.9", Vendor: "openbsd", Product: "openssh", Version: "6.9", CPE: "cpe:/a:openbsd:openssh:6.9", Confidence: 0.95}}); err != nil {
		e.t.Fatal(err)
	}
}

// announce records what the device's LLDP frame says (sensor-passive: the chassis MAC, the model and OS read from its
// system description, confidence 0.5).
func announce(e *env, mac, model, os string) {
	e.t.Helper()
	e.record(obsv(mac, observe.MAC, mac, observe.Passive, 0.9), obsv(mac, observe.Model, model, observe.Passive, 0.5),
		obsv(mac, observe.OS, os, observe.Passive, 0.5))
}

func osObservation(t *testing.T, d inventory.Detail, source string) inventory.ObservationRow {
	t.Helper()
	i := slices.IndexFunc(d.Observations, func(o inventory.ObservationRow) bool { return o.Field == "os" && o.Source == source })
	if i < 0 {
		t.Fatalf("no %s OS observation in %+v", source, d.Observations)
	}
	return d.Observations[i]
}

// INV-44: what a device announces about itself ranks above a scan's guess. A switch states "JUNOS 15.1R7.9" over LLDP on a
// Juniper card while nmap's fingerprint guesses "JUNOS 12": the statement is the OS everywhere (the device, its list row, the
// matcher's OS, a software line of its own), the guess row leaves the software list and matching, and the guess stays in Observations
// as a guess.
// Whichever arrives first, the result is the same.
func TestStatedOSOutranksTheScanGuess(t *testing.T) {
	for _, order := range []string{"scan first", "frame first"} {
		t.Run(order, func(t *testing.T) {
			e := newEnv(t)
			const ip = switchIP
			if order == "scan first" {
				scanSwitch(e, juniperMAC, junosGuess.Display)
				announce(e, juniperMAC, "EX4200-48T", "JUNOS 15.1R7.9")
			} else {
				announce(e, juniperMAC, "EX4200-48T", "JUNOS 15.1R7.9")
				scanSwitch(e, juniperMAC, junosGuess.Display)
			}
			id := e.idOf(ip)
			d, err := e.svc.Device(e.ctx(), id)
			if err != nil {
				t.Fatal(err)
			}
			if d.OS == nil || d.OS.Value != "JUNOS 15.1R7.9" || d.OS.Source != "passive" || d.OS.Basis != "stated" {
				t.Fatalf("OS %+v, want JUNOS 15.1R7.9 stated over LLDP", d.OS)
			}
			if d.Model == nil || d.Model.Value != "EX4200-48T" || d.Model.Basis != "stated" {
				t.Errorf("model %+v, want EX4200-48T stated over LLDP like the OS of its frame", d.Model)
			}
			list, match := shown(e, id)
			for _, l := range [][]string{list, match} { // the stated OS is a software line of its own
				if len(l) != 2 || l[0] != "Junos OS" || l[1] != "openssh" {
					t.Errorf("software %v, want Junos OS (the statement) and openssh: the scan's guess row is outranked", l)
				}
			}
			m, _, err := e.svc.MatchInput(e.ctx(), id)
			if err != nil || m.OS != "JUNOS 15.1R7.9" || m.StatedOS != "JUNOS 15.1R7.9" {
				t.Errorf("matcher OS %q, stated %q (%v); want the statement", m.OS, m.StatedOS, err)
			}
			det := e.detail(id)
			if g := osObservation(t, det, "nmap"); g.Current || g.Basis != "guess" {
				t.Errorf("scan's OS observation %+v, want kept, not current, a guess", g)
			}
			if s := osObservation(t, det, "passive"); !s.Current || s.Basis != "stated" {
				t.Errorf("LLDP OS observation %+v, want current and stated", s)
			}
			if i := slices.IndexFunc(det.Observations, func(o inventory.ObservationRow) bool { return o.Field == "model" }); i < 0 || det.Observations[i].Basis != "stated" {
				t.Errorf("model observations %+v, want the LLDP model stated", det.Observations)
			}
			// A later scan that guesses another release changes nothing.
			scanSwitch(e, juniperMAC, "Juniper Networks J2320 or MX5-T router; or EX2200, EX3200, EX4200, or EX8200 switch (JUNOS 8.5 - 11.2)")
			if got := osOf(e, id); got != "JUNOS 15.1R7.9" {
				t.Errorf("after another scan guess: OS %q, want the statement", got)
			}
		})
	}
}

// INV-44: the statement outranks the guess only when the device's card vouches for it (an LLDP frame can carry another device's
// MAC), only for an OS network-os.json lets LLDP state, and never above the device's own SNMP answer. A passive hint that is not
// a statement (a DHCP client's OS family) stays below the scan.
func TestStatedOSCountsOnlyOnItsVendorsCard(t *testing.T) {
	cases := []struct {
		name, mac, frameOS string
		frameConf          float64
		snmpOS             string
		want, wantBasis    string
		frameBasis         string // the statement is still marked as one when the SNMP answer outranks it
	}{
		{name: "statement on another vendor's card", mac: vmwareMAC, frameOS: "JUNOS 15.1R7.9", frameConf: 0.5, want: junosGuess.Display, wantBasis: "guess"},
		{name: "an OS LLDP may not state", mac: juniperMAC, frameOS: "Ubuntu 22.04.3 LTS", frameConf: 0.5, want: junosGuess.Display, wantBasis: "guess"},
		{name: "DHCP family hint", mac: juniperMAC, frameOS: "Linux", frameConf: 0.4, want: junosGuess.Display, wantBasis: "guess"},
		{name: "SNMP answer above the statement", mac: juniperMAC, frameOS: "JUNOS 15.1R7.9", frameConf: 0.5, snmpOS: "JUNOS 15.1R7.10", want: "JUNOS 15.1R7.10", frameBasis: "stated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			const ip = switchIP
			scanSwitch(e, c.mac, junosGuess.Display)
			e.record(obsv(c.mac, observe.OS, c.frameOS, observe.Passive, c.frameConf))
			id := e.idOf(ip)
			if c.snmpOS != "" {
				e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: c.snmpOS, Source: observe.SNMP, Confidence: 0.9})
			}
			d, err := e.svc.Device(e.ctx(), id)
			if err != nil {
				t.Fatal(err)
			}
			if d.OS == nil || d.OS.Value != c.want || d.OS.Basis != c.wantBasis {
				t.Errorf("OS %+v, want %q basis %q", d.OS, c.want, c.wantBasis)
			}
			if s := osObservation(t, e.detail(id), "passive"); s.Basis != c.frameBasis || s.Current {
				t.Errorf("passive OS %+v, want basis %q, not current", s, c.frameBasis)
			}
		})
	}
}

// A scan's OS fingerprint is shown as a guess wherever it is shown (the device's OS, its observation, its software row), never as
// a confidence level; the device's own NTLM answer is not a guess.
func TestScanOSFingerprintIsMarkedAGuess(t *testing.T) {
	e := newEnv(t)
	const ip = switchIP
	scanSwitch(e, juniperMAC, junosGuess.Display)
	id := e.idOf(ip)
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	if d.OS == nil || d.OS.Basis != "guess" {
		t.Errorf("OS %+v, want a guess", d.OS)
	}
	det := e.detail(id)
	for _, sw := range det.Asset.Software {
		if want := map[string]string{"junos": "guess", "openssh": ""}[sw.Product]; sw.Basis != want {
			t.Errorf("software %s basis %q, want %q", sw.Display, sw.Basis, want)
		}
	}

	ntlm := "Microsoft Windows 11 24H2 / Server 2025 (build 26100)"
	wid := guessEnv(e, "192.168.1.34", ntlm, observe.Software{Display: ntlm, Vendor: "microsoft", Product: "windows", Version: "10.0.26100",
		CPE: "cpe:/o:microsoft:windows", Confidence: 0.95, Guess: true})
	w := e.detail(wid)
	if w.Asset.OS == nil || w.Asset.OS.Basis != "" {
		t.Errorf("NTLM OS %+v, want no guess mark (the device's own answer)", w.Asset.OS)
	}
	for _, sw := range w.Asset.Software {
		if sw.Basis != "" {
			t.Errorf("software %s basis %q, want none", sw.Display, sw.Basis)
		}
	}
}

// The model of an LLDP frame reads as announced by the device only under the same card check as its OS: on another vendor's card,
// and for a model no OS statement came with (an mDNS or SSDP model), it keeps the passive wording.
func TestStatedModelNeedsTheFramesStatementOnItsVendorsCard(t *testing.T) {
	for _, c := range []struct {
		name, mac, os, want string
	}{
		{"statement on its vendor's card", juniperMAC, "JUNOS 15.1R7.9", "stated"},
		{"statement on another vendor's card", vmwareMAC, "JUNOS 15.1R7.9", ""},
		{"a model without a statement", juniperMAC, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			scanSwitch(e, c.mac, junosGuess.Display)
			if c.os != "" {
				announce(e, c.mac, "EX4200-48T", c.os)
			} else {
				e.record(obsv(c.mac, observe.Model, "EX4200-48T", observe.Passive, 0.5))
			}
			id := e.idOf(switchIP)
			d, err := e.svc.Device(e.ctx(), id)
			if err != nil {
				t.Fatal(err)
			}
			if d.Model == nil || d.Model.Source != "passive" || d.Model.Basis != c.want {
				t.Errorf("model %+v, want passive with basis %q", d.Model, c.want)
			}
			det := e.detail(id)
			if i := slices.IndexFunc(det.Observations, func(o inventory.ObservationRow) bool { return o.Field == "model" }); i < 0 || det.Observations[i].Basis != c.want {
				t.Errorf("model observation basis, want %q: %+v", c.want, det.Observations)
			}
		})
	}
}

// Of two scans, the newer guess is the device's OS even when nmap was less sure of it (its accuracy varies from scan to scan): the
// OS everywhere and the Software tab's guess row name the same scan's guess, never one each.
func TestScanGuessTheNewerScanWinsOverAMoreConfidentOlderOne(t *testing.T) {
	e := newEnv(t)
	scan := func(name string, conf float64) {
		h := observe.AssetHint{IP: netip.MustParseAddr(switchIP), MAC: vmwareMAC}
		e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: name, Source: observe.Nmap, Confidence: conf})
		row := junosGuess
		row.Display, row.Confidence = name, conf
		if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, nil, []observe.Software{row}); err != nil {
			t.Fatal(err)
		}
	}
	scan("Juniper Networks J2320 or MX5-T router; or EX2200, EX3200, EX4200, or EX8200 switch (JUNOS 8.5 - 11.2)", 0.95)
	e.tick(time.Hour)
	scan(junosGuess.Display, 0.90)
	id := e.idOf(switchIP)
	det := e.detail(id)
	if det.Asset.OS == nil || det.Asset.OS.Value != junosGuess.Display || det.Asset.OS.Basis != "guess" {
		t.Errorf("OS %+v, want the newer scan's guess", det.Asset.OS)
	}
	var rows []string
	for _, sw := range det.Asset.Software {
		rows = append(rows, sw.Display)
	}
	if len(rows) != 1 || rows[0] != junosGuess.Display {
		t.Errorf("software %v, want the one guess row of the newer scan, the same as the OS", rows)
	}
	if m, _, err := e.svc.MatchInput(e.ctx(), id); err != nil || m.OS != junosGuess.Display {
		t.Errorf("matcher OS %q (%v), want the newer scan's guess", m.OS, err)
	}
}

// DeviceRefs gives the OS the ranking chose with its source and basis, so another page (a device check's words in History) can tell
// whether the page shows the scan's guess: a stated OS wins over the guess (source passive, basis stated); without a statement the
// guess is the OS (source nmap, basis guess).
func TestDeviceRefsNameTheSourceOfTheOS(t *testing.T) {
	e := newEnv(t)
	scanSwitch(e, juniperMAC, junosGuess.Display)
	id := e.idOf(switchIP)
	refs, err := e.svc.DeviceRefs(e.ctx(), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if r := refs[id]; r.OS != junosGuess.Display || r.OSSource != "nmap" || r.OSBasis != "guess" {
		t.Fatalf("scan only: %+v, want the guess from nmap", r)
	}
	announce(e, juniperMAC, "EX2300-24T", "JUNOS 15.1R7.9")
	if refs, err = e.svc.DeviceRefs(e.ctx(), []string{id}); err != nil {
		t.Fatal(err)
	}
	if r := refs[id]; r.OS != "JUNOS 15.1R7.9" || r.OSSource != "passive" || r.OSBasis != "stated" {
		t.Fatalf("stated: %+v, want the LLDP statement", r)
	}
}

// INV-44: a device's own statement without a login (an iLO's firmware, an ESXi's version) is written by a scan as source nmap. It
// outranks nmap's fingerprint guess of the same device (the guess row leaves the software list, the statement's own row stays and
// is matched), says how the device stated it, and still loses to the device's SNMP answer read with the customer's settings.
func TestSelfStatedFirmwareOutranksTheScanGuessButNotSNMP(t *testing.T) {
	e := newEnv(t)
	const mac = "aa:bb:cc:00:00:31"
	h := observe.AssetHint{IP: netip.MustParseAddr(switchIP), MAC: mac}
	guess := "Linux 3.2 - 4.14"
	e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: guess, Source: observe.Nmap, Confidence: 0.9})
	fw := "HPE iLO 4 firmware 2.77"
	e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: fw, Source: observe.Nmap, Confidence: 0.95})
	rows := []observe.Software{
		{Display: guess, Vendor: "linux", Product: "linux_kernel", CPE: "cpe:/o:linux:linux_kernel", Confidence: 0.9, Guess: true},
		{Display: fw, Vendor: "hp", Product: "integrated lights-out 4 firmware", Version: "2.77", CPE: "cpe:2.3:o:hp:integrated_lights-out_4_firmware:2.77:*:*:*:*:*:*:*", Confidence: 0.95},
	}
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, nil, rows); err != nil {
		t.Fatal(err)
	}
	id := e.idOf(switchIP)
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	if d.OS == nil || d.OS.Value != fw || d.OS.Source != "nmap" || d.OS.Basis != "stated_web" {
		t.Fatalf("OS %+v, want the iLO's own statement, stated on its web page", d.OS)
	}
	list, match := shown(e, id)
	for _, l := range [][]string{list, match} {
		if len(l) != 1 || l[0] != "integrated lights-out 4 firmware" {
			t.Errorf("software %v, want only the firmware row: the fingerprint guess is outranked, the statement is not", l)
		}
	}
	if g := osObservation(t, e.detail(id), "nmap"); g.Basis != "guess" && g.Basis != "stated_web" {
		t.Errorf("OS observation %+v", g)
	}
	// the customer's SNMP settings read the device: that answer is the OS, the statement stays an observation
	e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "iLO 4 v2.77", Source: observe.SNMP, Confidence: 0.9})
	if got := osOf(e, id); got != "iLO 4 v2.77" {
		t.Errorf("after an SNMP read: OS %q, want the SNMP answer", got)
	}
}

// A device's own firmware row (CPE 2.3, with its update) gets the KEV keys of the curated product that names its CPE, like an nmap
// row with a CPE 2.2 URI does; a product no curated entry names keeps its vendor|product key.
func TestSelfStatedFirmwareRowGetsKevKeysFromItsCPE(t *testing.T) {
	e := newEnv(t)
	h := observe.AssetHint{IP: netip.MustParseAddr(switchIP), MAC: "aa:bb:cc:00:00:32"}
	e.record(observe.Observation{AssetHint: h, Field: observe.Vendor, Value: "VMware, Inc.", Source: observe.Nmap, Confidence: 0.6})
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, nil, []observe.Software{
		{Display: "VMware ESXi 8.0 Update 3 (build 24022510)", Vendor: "vmware", Product: "esxi", Version: "8.0", CPE: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	var keys string
	for _, sw := range matchRows(t, e, deviceAt(t, e, h.IP)) {
		keys += strings.Join(sw.KevKeys, " ") + " "
	}
	if !strings.Contains(keys, "vmware|esxi") {
		t.Fatalf("KEV keys %q, want vmware|esxi", keys)
	}
}

// nmap's fingerprint name of a hypervisor that starts like a statement is a guess: it is not marked stated, and it does not
// outrank another scan guess or hide its rows.
func TestFingerprintNamedEsxiStaysAGuess(t *testing.T) {
	e := newEnv(t)
	h := observe.AssetHint{IP: netip.MustParseAddr(switchIP), MAC: "aa:bb:cc:00:00:33"}
	e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: "VMware ESXi 5.5 - 6.7", Source: observe.Nmap, Confidence: 0.9})
	d, err := e.svc.Device(e.ctx(), e.idOf(switchIP))
	if err != nil {
		t.Fatal(err)
	}
	if d.OS == nil || d.OS.Basis != "guess" {
		t.Fatalf("OS %+v, want a guess", d.OS)
	}
}
