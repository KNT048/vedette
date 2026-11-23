package inventory

import (
	"slices"
	"strings"

	"github.com/knt048/vedette/core/observe"
)

// nmap's OS guesses. nmap names an OS from the shape of a device's TCP/IP
// answers: a guess, stored as an OS observation of source nmap and as Guess software rows (an OS CPE, no match keys). Two read
// rules keep a wrong guess off the device without deleting anything, so a later scan or a change of source decides again:
//
//  1. Outranked (INV-1: manual > agent > snmp > LLDP statement > nmap, INV-44): once a person, the device's agent, its SNMP answer or
//     its LLDP statement on its vendor's card gives the OS, every OS row nmap stored as a guess (the fingerprint's, and the Windows
//     release of an NTLM answer) leaves the device's software, its matching and its name: a device whose SNMP answer says Alpine no
//     longer lists "Android 9 - 10 (Linux 4.9 - 4.14)", a switch stating "JUNOS 15.1R7.9" no longer lists "Juniper EX2200 switch (JUNOS 12)".
//  2. Contradicted: a fingerprint guess (never the device's own NTLM answer) of a family the device's type never runs (guessFamilies)
//     is neither its OS nor its software, even when nmap is the only source. The type counts only when a person, the agent or SNMP
//     gave it (sources INV-1 ranks above nmap); nmap's own type comes from the same fingerprint, and a frame the device sent ranks
//     below nmap. The
//     observation stays, shown as not used (ObservationRow.ContradictsType): a firewall a person typed, which nmap took for Android.
//
// With nmap alone and no contradiction, the guess is the device's OS and software as before.

// guessFamily is one family of operating systems and the device types it never runs on. The table is kept narrow on purpose: only
// pairs no real device of the type has (an Android desk phone, a Windows print server, an Android point of sale do exist, so those
// types are not listed).
type guessFamily struct {
	name  string
	words []string // lower-case words of nmap's OS name that place it in the family
	// not are lower-case words that take it out again: Windows CE, Windows Mobile (embedded Windows does run on printers), and the
	// other family of one of nmap's joint Apple names ("Apple macOS 10.13 - 10.15 or iOS 11.0 - 13.4"), which may be either.
	not   []string
	types []string // device type ids (content/devicetypes) the family never runs on
}

var (
	networkGear = []string{"router", "switch", "modem", "sd_wan", "firewall", "ap", "wifi_extender", "mesh_node", "industrial_switch"}
	printers    = []string{"printer", "mfp", "label_printer", "plotter"}
)

var guessFamilies = []guessFamily{
	{
		name:  "mobile", // Android, iOS, iPadOS
		words: []string{"android", "apple ios", "iphone os", "ipados"},
		not:   []string{"macos", "mac os x"},
		types: concat(networkGear, []string{"load_balancer", "vpn_gateway", "wireless_controller"}, printers,
			[]string{"camera", "nvr", "dvr", "video_encoder", "nas", "san", "server", "hypervisor", "domain_controller", "mail_server",
				"database_server", "backup_server", "pc", "laptop", "workstation"}),
	},
	{
		name:  "desktop", // Windows, macOS
		words: []string{"microsoft windows", "mac os x", "macos"},
		not:   []string{"windows ce", "mobile", "phone", "embedded", "iot", "ios"},
		// not mfp or video_encoder: print controllers and encoders run Windows 10 IoT or Embedded, which nmap names plain Windows
		types: concat(networkGear, []string{"printer", "label_printer", "plotter", "camera", "doorbell", "smartphone", "smartwatch", "ip_phone"}),
	},
	{
		// the OS of a router, switch or firewall
		name:  "network",
		words: []string{"cisco ios", "nx-os", "junos", "fortios", "routeros", "pan-os"}, //nolint:misspell // MikroTik RouterOS
		types: concat(printers, []string{"pc", "laptop", "workstation", "smartphone", "tablet", "smartwatch", "camera", "doorbell"}),
	},
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// ntlmMark is in the OS name of a device's own NTLM answer ("Microsoft Windows 11 24H2 / Server 2025 (build 26100)"): the
// device's statement, never a fingerprint guess, so never contradicted.
const ntlmMark = "(build "

// ntlmAnswer says whether an nmap OS name is the device's own NTLM answer (ntlmMark), not a fingerprint guess.
func ntlmAnswer(name string) bool { return strings.Contains(strings.ToLower(name), ntlmMark) }

// typeSources are the sources of a type that can rule out nmap's guess (rule 2).
var typeSources = map[string]bool{"manual": true, "agent": true, "snmp": true}

// guessContradicts says whether nmap's OS name contradicts a device of this type (rule 2). kindSource is the source of the type:
// only a type a person, the agent or SNMP gave counts (INV-1 ranks them above nmap); a frame the device sent (an mDNS printer
// service a Mac announces when it shares a printer) ranks below nmap and never overrules its guess.
func guessContradicts(kind, kindSource, osName string) bool {
	if !typeSources[kindSource] {
		return false
	}
	if ntlmAnswer(osName) {
		return false
	}
	name := strings.ToLower(osName)
	for _, f := range guessFamilies {
		if slices.Contains(f.types, kind) && containsAny(name, f.words) && !containsAny(name, f.not) {
			return true
		}
	}
	return false
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// dropContradictedOS is the OS decision of RecomputeAsset with rule 2: when nmap's OS wins and contradicts the device's type, the
// best OS of another source wins instead, else none. An older nmap guess the type allows never comes back: its rows are gone, and
// the latest scan said otherwise. list is the device's observations, best their winners.
func dropContradictedOS(list []obs, best map[string]obs) {
	o, ok := best["os"]
	k, kok := best["kind"]
	if !ok || !kok || o.source != "nmap" || !guessContradicts(k.value, k.source, o.value) {
		return
	}
	delete(best, "os")
	for _, c := range list {
		if c.field != "os" || c.source == "nmap" {
			continue
		}
		if b, ok := best["os"]; !ok || better(c, b) {
			best["os"] = c
		}
	}
}

// osGuessRow is the SQL condition on a software line (alias s) that it is nmap's OS guess: a guess line of an OS CPE.
const osGuessRow = `(s.cpe LIKE 'cpe:/o:%' AND ` + guessLine + `)`

// outrankedGuess (rule 1): a person, the agent, SNMP or the device's LLDP statement gave the device's OS. A passive OS wins over
// nmap's only as the device's LLDP statement (INV-44); a passive hint (a DHCP client's OS family) never outranks a guess.
var outrankedGuess = `EXISTS (SELECT 1 FROM inv_asset ga JOIN inv_observation gob ON gob.id = ga.os_obs_id WHERE ga.id = s.asset_id
	AND (gob.source IN ('manual', 'declared', 'agent', 'snmp', 'passive') OR (gob.source = 'nmap' AND ` + selfStatedSQL("gob.value") + ` AND NOT ` + selfStatedSQL("s.display") + `)))`

// selfStatedSQL is the condition on column col that it is the device's own statement without a login (observe.SelfStatedLike): such an
// OS outranks nmap's fingerprint too, so its guess rows leave the device (rule 1); the row that holds the statement itself stays
// (the same condition on s.display).
func selfStatedSQL(col string) string {
	likes := observe.SelfStatedLike()
	c := make([]string, len(likes))
	for i, l := range likes {
		c[i] = col + " LIKE '" + strings.ReplaceAll(l, "'", "''") + "'"
	}
	return "(" + strings.Join(c, " OR ") + ")"
}

// fingerprintRow is the SQL condition on a software row (alias s) that it is nmap's OS fingerprint guess: an OS guess row with no
// version that is not the device's own NTLM answer (its basis is a guess, contract.ts Software.basis).
const fingerprintRow = `(` + osGuessRow + ` AND s.version IS NULL AND instr(lower(s.display), '` + ntlmMark + `') = 0)`

// hiddenGuess is the SQL condition on a software row (alias s) that it is an nmap OS guess the device does not show or match (rules 1
// and 2). Every reader of a device's software leaves these rows out: the software list, matching, the "Do you have it?" lists, the
// device's name, HasDevice.
var hiddenGuess = `(` + osGuessRow + ` AND (` + outrankedGuess + ` OR ` + contradictedGuessSQL() + `))`

// contradictedGuessSQL is rule 2 in SQL for a fingerprint row (no version: the NTLM answer's row has its build), from guessFamilies
// (fixed words and type ids, no input).
func contradictedGuessSQL() string {
	quote := func(l []string) string {
		q := make([]string, len(l))
		for i, v := range l {
			q[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
		}
		return strings.Join(q, ", ")
	}
	has := func(words []string) string {
		w := make([]string, len(words))
		for i, v := range words {
			w[i] = "instr(lower(s.display), '" + strings.ReplaceAll(v, "'", "''") + "') > 0"
		}
		return "(" + strings.Join(w, " OR ") + ")"
	}
	fams := make([]string, 0, len(guessFamilies))
	for _, f := range guessFamilies {
		c := "(ga.kind IN (" + quote(f.types) + ") AND " + has(f.words)
		if len(f.not) > 0 {
			c += " AND NOT " + has(f.not)
		}
		fams = append(fams, c+")")
	}
	return `(s.version IS NULL AND instr(lower(s.display), '` + ntlmMark + `') = 0 AND EXISTS (SELECT 1 FROM inv_asset ga JOIN inv_observation gko
	ON gko.id = ga.kind_obs_id WHERE ga.id = s.asset_id AND gko.source IN ('manual', 'agent', 'snmp') AND (` + strings.Join(fams, " OR ") + `)))`
}
