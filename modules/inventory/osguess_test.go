package inventory_test

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// guessEnv records a device at ip that nmap fingerprinted as osName, with the Guess OS rows nmap stores for it and one
// matched OpenSSH row, and returns its id.
func guessEnv(e *env, ip, osName string, rows ...observe.Software) string {
	e.t.Helper()
	addr := netip.MustParseAddr(ip)
	h := observe.AssetHint{IP: addr, MAC: fmt.Sprintf("00:0c:29:aa:bb:%02x", addr.As4()[3])}
	e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: osName, Source: observe.Nmap, Confidence: 0.86})
	rows = append(rows, observe.Software{Display: "OpenSSH 9.6", Vendor: "openbsd", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", Confidence: 0.8})
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, nil, rows); err != nil {
		e.t.Fatal(err)
	}
	return e.idOf(ip)
}

// androidRows are what nmap stores for a firewall it takes for Android: one Guess row per CPE of "Android 9 - 10 (Linux 4.9 - 4.14)".
var androidRows = []observe.Software{
	{Display: "Android 9 - 10 (Linux 4.9 - 4.14)", Vendor: "google", Product: "android", CPE: "cpe:/o:google:android", Confidence: 0.86, Guess: true},
	{Display: "Android 9 - 10 (Linux 4.9 - 4.14)", Vendor: "linux", Product: "linux kernel", CPE: "cpe:/o:linux:linux_kernel", Confidence: 0.86, Guess: true},
}

// shown lists the products of a device's software list and of its matching input.
func shown(e *env, id string) (list, match []string) {
	e.t.Helper()
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, s := range d.Software {
		list = append(list, s.Product)
	}
	m, ok, err := e.svc.MatchInput(e.ctx(), id)
	if err != nil || !ok {
		e.t.Fatalf("match input: %v %v", ok, err)
	}
	for _, s := range m.Software {
		match = append(match, s.Product)
	}
	return list, match
}

func osOf(e *env, id string) string {
	e.t.Helper()
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	if d.OS == nil {
		return ""
	}
	return d.OS.Value
}

// Rule 1 (INV-1: manual > agent > snmp > nmap): nmap's OS guess rows leave a device's software, its matching and its name
// once a person, the agent or SNMP states the OS. The rows stay stored, and with nmap alone they are listed as before.
func TestOSGuessGoesWhenAStrongerSourceStatesTheOS(t *testing.T) {
	for _, src := range []string{"snmp", "agent", "manual"} {
		t.Run(src, func(t *testing.T) {
			e := newEnv(t)
			id := guessEnv(e, "10.142.0.21", "Android 9 - 10 (Linux 4.9 - 4.14)", androidRows...)
			if list, match := shown(e, id); len(list) != 3 || len(match) != 3 {
				t.Fatalf("with nmap alone: software %v, matching %v; want the guesses listed as before", list, match)
			}
			hint := observe.AssetHint{IP: netip.MustParseAddr("10.142.0.21")}
			switch src {
			case "snmp":
				e.record(observe.Observation{AssetHint: hint, Field: observe.OS, Value: "Alpine Linux", Source: observe.SNMP, Confidence: 0.9})
			case "agent":
				e.record(observe.Observation{AssetHint: hint, Field: observe.OS, Value: "Alpine Linux v3.23", Source: observe.Agent, Confidence: 0.95})
			case "manual":
				if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{OS: ptr("Alpine Linux 3.23")}); err != nil {
					t.Fatal(err)
				}
			}
			list, match := shown(e, id)
			for _, l := range [][]string{list, match} {
				if len(l) != 1 || l[0] != "openssh" {
					t.Errorf("after %s stated the OS: %v, want only openssh", src, l)
				}
			}
			if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND source = 'nmap'`, id); n != 3 {
				t.Errorf("%d nmap rows stored, want the 3 kept (a read rule, not a delete)", n)
			}
		})
	}
}

// The Windows release of a device's NTLM answer is stored as a Guess too: an agent's Windows reading replaces it (the agent reads
// 10.0.26300.9974, the NTLM row says build 26100).
func TestOSGuessNTLMWindowsRowGoesWhenTheAgentStatesTheOS(t *testing.T) {
	e := newEnv(t)
	ntlm := "Microsoft Windows 11 24H2 / Server 2025 (build 26100)"
	id := guessEnv(e, "10.142.0.34", ntlm, observe.Software{Display: ntlm, Vendor: "microsoft", Product: "windows", Version: "10.0.26100",
		CPE: "cpe:/o:microsoft:windows", Confidence: 0.95, Guess: true})
	if list, _ := shown(e, id); len(list) != 2 {
		t.Fatalf("with nmap alone: %v, want the NTLM row listed", list)
	}
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.142.0.34")}, Field: observe.OS,
		Value: "Microsoft Windows 11 Pro 10.0.26300.9974", Source: observe.Agent, Confidence: 0.95})
	if list, match := shown(e, id); len(list) != 1 || len(match) != 1 {
		t.Errorf("after the agent: software %v, matching %v; want only openssh", list, match)
	}
}

// Rule 2: a fingerprint guess the device's type rules out (a firewall a person typed, nmap said Android) is neither the
// OS nor software, even with nmap alone; it stays in Observations marked as not used. Typing the type after the guess re-decides the
// OS and matches the device again; typing it back to a type the guess fits brings the guess back.
func TestOSGuessTheTypeRulesOutIsNotUsed(t *testing.T) {
	e := newEnv(t)
	id := guessEnv(e, "10.142.0.1", "Android 9 - 10 (Linux 4.9 - 4.14)", androidRows...)
	if got := osOf(e, id); got != "Android 9 - 10 (Linux 4.9 - 4.14)" {
		t.Fatalf("with nmap alone and no type the OS is the guess, got %q", got)
	}
	if ok, err := e.svc.HasDevice(e.ctx(), []string{"firewall", "router"}, "google"); err != nil || ok {
		t.Fatalf("no firewall yet: %v %v", ok, err)
	}
	e.ev.reset()
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{Kind: ptr("firewall")}); err != nil {
		t.Fatal(err)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || !ev[0].Data.(inventory.AssetEvent).Match {
		t.Fatalf("a type that changes the OS must match the device again: %+v", ev)
	}
	if got := osOf(e, id); got != "" {
		t.Errorf("OS of a firewall nmap guessed Android: %q, want none", got)
	}
	list, match := shown(e, id)
	for _, l := range [][]string{list, match} {
		if len(l) != 1 || l[0] != "openssh" {
			t.Errorf("software of a firewall nmap guessed Android: %v, want only openssh", l)
		}
	}
	if ok, err := e.svc.HasDevice(e.ctx(), []string{"firewall", "router"}, "google"); err != nil || ok {
		t.Errorf("a Google firewall from a guess the type rules out: %v %v", ok, err)
	}
	d, err := e.svc.Detail(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(d.Observations, func(o inventory.ObservationRow) bool { return o.Field == "os" })
	if i < 0 || d.Observations[i].Current || !d.Observations[i].ContradictsType || d.Observations[i].Value != "Android 9 - 10 (Linux 4.9 - 4.14)" {
		t.Errorf("the guess stays in Observations, not used, marked: %+v", d.Observations)
	}
	// Another reading of the OS still wins; a later nmap scan re-decides the same way.
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.142.0.1")}, Field: observe.OS,
		Value: "Android 9 - 10 (Linux 4.9 - 4.14)", Source: observe.Nmap, Confidence: 0.9})
	if got := osOf(e, id); got != "" {
		t.Errorf("after a rescan: OS %q, want none", got)
	}
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.142.0.1")}, Field: observe.OS,
		Value: "Linux", Source: observe.Passive, Confidence: 0.4})
	if got := osOf(e, id); got != "Linux" {
		t.Errorf("a weaker reading the type allows wins over the ruled-out guess: %q", got)
	}
	// Smart TVs run Android: the guess is back as soon as the type allows it.
	e.tick(time.Minute)
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{Kind: ptr("smart_tv")}); err != nil {
		t.Fatal(err)
	}
	if got := osOf(e, id); got != "Android 9 - 10 (Linux 4.9 - 4.14)" {
		t.Errorf("on a smart TV the guess is the OS again: %q", got)
	}
	if list, _ := shown(e, id); len(list) != 3 {
		t.Errorf("on a smart TV the guess rows are listed again: %v", list)
	}
	if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND source = 'nmap'`, id); n != 3 {
		t.Errorf("%d nmap rows stored, want the 3 kept", n)
	}
}

// The contradiction table (osguess.go guessFamilies), each pair through the OS decision and the software read: only a type a source
// other than a scan gave counts, and only a fingerprint guess, never the device's own NTLM answer.
func TestOSGuessContradictionTable(t *testing.T) {
	cases := []struct {
		kind, os string
		ruledOut bool
	}{
		{"firewall", "Android 9 - 10 (Linux 4.9 - 4.14)", true},
		{"switch", "Apple iOS 15.0 - 16.1", true},
		{"printer", "Android 5.0 - 6.0", true},
		{"camera", "Android 7.1", true},
		{"nas", "Apple iPadOS 16", true},
		{"server", "Android 10", true},
		{"pc", "Android 10", true},
		{"printer", "Microsoft Windows 10 1607", true},
		{"router", "Apple macOS 11 (Big Sur) - 13 (Ventura)", true},
		{"smartphone", "Microsoft Windows 7 or 8.1", true},
		{"laptop", "Cisco IOS 12.4", true},
		{"printer", "Juniper JUNOS 12.1", true},
		// Real devices of these types run that family: kept.
		{"ip_phone", "Android 9", false},      // Android desk phones
		{"smart_tv", "Android 9", false},      // Android TV
		{"pos_terminal", "Android 11", false}, // Android point of sale
		{"video_conferencing", "Android 10", false},
		{"tablet", "Microsoft Windows 10", false}, // Surface
		{"nvr", "Microsoft Windows 10", false},    // NVR software on Windows
		{"printer", "Microsoft Windows CE 6.0", false},
		{"switch", "Juniper JUNOS 8.5 - 11.2", false},
		{"firewall", "Linux 4.15 - 5.19", false},
		{"printer", "Microsoft Windows 11 24H2 (build 26100)", false}, // the device's own NTLM answer, not a fingerprint
		{"unknown", "Android 9", false},
		// nmap's joint Apple names may be either family: neither an iPhone nor a Mac rules them out.
		{"smartphone", "Apple macOS 10.13 (High Sierra) - 10.15 (Catalina) or iOS 11.0 - 13.4 (Darwin 17.0.0 - 19.6.0)", false},
		{"pc", "Apple iOS 12.0 - 13.4 or macOS 10.14 (Darwin 18.0.0 - 19.4.0)", false},
		{"smartphone", "Apple macOS 12 (Monterey)", true},
		{"laptop", "Apple iOS 15.0 - 16.1", true},
		// Print controllers and video encoders run Windows 10 IoT or Embedded, which nmap names plain Windows.
		{"mfp", "Microsoft Windows 10 1607", false},
		{"video_encoder", "Microsoft Windows 7", false},
	}
	for _, c := range cases {
		t.Run(c.kind+"/"+c.os, func(t *testing.T) {
			e := newEnv(t)
			id := guessEnv(e, "10.142.0.50", c.os, observe.Software{Display: c.os, Vendor: "v", Product: "os", CPE: "cpe:/o:v:os", Confidence: 0.86, Guess: true})
			if c.kind != "unknown" {
				if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{Kind: ptr(c.kind)}); err != nil {
					t.Fatal(err)
				}
			}
			list, match := shown(e, id)
			got := osOf(e, id) == "" && len(list) == 1 && len(match) == 1
			kept := osOf(e, id) == c.os && len(list) == 2 && len(match) == 2
			if c.ruledOut && !got || !c.ruledOut && !kept {
				t.Errorf("%s on a %s: OS %q, software %v, matching %v; ruled out = %v", c.os, c.kind, osOf(e, id), list, match, c.ruledOut)
			}
		})
	}
}

// A type nmap gave from the same fingerprint never rules its OS out: with nmap alone the device is as before.
func TestOSGuessNmapsOwnTypeNeverRulesOutItsOS(t *testing.T) {
	e := newEnv(t)
	id := guessEnv(e, "10.142.0.60", "Android 9 - 10 (Linux 4.9 - 4.14)", androidRows...)
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.142.0.60")}, Field: observe.Kind, Value: "router",
		Source: observe.Nmap, Confidence: 0.7})
	if got := osOf(e, id); got != "Android 9 - 10 (Linux 4.9 - 4.14)" {
		t.Errorf("OS %q, want the guess: nmap's own type", got)
	}
	if list, _ := shown(e, id); len(list) != 3 {
		t.Errorf("software %v, want the guesses listed", list)
	}
}

// Only a type a person, the agent or SNMP gave rules a guess out: a Mac that shares a printer announces an mDNS printer service, and
// that passive type ranks below nmap's own reading of the OS.
func TestOSGuessAPassiveTypeNeverRulesOutTheGuess(t *testing.T) {
	e := newEnv(t)
	mac := "Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0)"
	id := guessEnv(e, "10.142.0.70", mac, observe.Software{Display: mac, Vendor: "apple", Product: "macos", CPE: "cpe:/o:apple:macos", Confidence: 0.86, Guess: true})
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.142.0.70")}, Field: observe.Kind, Value: "printer",
		Source: observe.Passive, Confidence: 0.6})
	if d, err := e.svc.Device(e.ctx(), id); err != nil || d.Kind != "printer" {
		t.Fatalf("kind %q %v, want the passive printer", d.Kind, err)
	}
	if got := osOf(e, id); got != mac {
		t.Errorf("OS %q, want nmap's macOS: a passive type does not overrule it", got)
	}
	if list, _ := shown(e, id); len(list) != 2 {
		t.Errorf("software %v, want the macOS guess listed", list)
	}
}

// When the latest guess is ruled out, an older nmap guess the type allows does not come back: the OS is another source's, else none.
func TestOSGuessRuledOutNeverFallsBackToAnOlderGuess(t *testing.T) {
	e := newEnv(t)
	hint := observe.AssetHint{IP: netip.MustParseAddr("10.142.0.80"), MAC: "00:0c:29:aa:bb:50"}
	e.record(observe.Observation{AssetHint: hint, Field: observe.OS, Value: "Linux 3.2 - 4.9", Source: observe.Nmap, Confidence: 0.5})
	e.tick(time.Hour)
	e.record(observe.Observation{AssetHint: hint, Field: observe.OS, Value: "Android 9 - 10 (Linux 4.9 - 4.14)", Source: observe.Nmap, Confidence: 0.86})
	id := e.idOf("10.142.0.80")
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{Kind: ptr("firewall")}); err != nil {
		t.Fatal(err)
	}
	if got := osOf(e, id); got != "" {
		t.Errorf("OS %q, want none: the older guess is not the device's OS either", got)
	}
}
