package inventory_test

import (
	"net/netip"
	"slices"
	"testing"

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
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, []observe.Software{guess,
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
// matcher's OS), the guess row leaves the software list and matching, and the guess stays in Observations as a guess.
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
			if d.Model == nil || d.Model.Value != "EX4200-48T" {
				t.Errorf("model %+v, want EX4200-48T", d.Model)
			}
			list, match := shown(e, id)
			for _, l := range [][]string{list, match} {
				if len(l) != 1 || l[0] != "openssh" {
					t.Errorf("software %v, want only openssh: the scan's guess row is outranked", l)
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
