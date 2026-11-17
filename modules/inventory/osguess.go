package inventory

import (
	"slices"
	"strings"
)

// nmap's OS guesses. nmap names an OS from the shape of a device's TCP/IP
// answers: a guess, stored as an OS observation of source nmap and as Guess software rows (an OS CPE, no match keys). Two read
// rules keep a wrong guess off the device without deleting anything, so a later scan or a change of source decides again:
//
//  1. Outranked (INV-1: manual > agent > snmp > nmap): once a person, the device's agent or its SNMP answer states the OS, every OS
//     row nmap stored as a guess (the fingerprint's, and the Windows release of an NTLM answer) leaves the device's software,
//     its matching and its name: a device whose SNMP answer says Alpine no longer lists "Android 9 - 10 (Linux 4.9 - 4.14)".
//  2. Contradicted: a fingerprint guess (never the device's own NTLM answer) of a family the device's type never runs (guessFamilies)
//     is neither its OS nor its software, even when nmap is the only source. The type counts only when a source other than a scan
//     gave it (a person, the agent, SNMP, a frame the device sent); nmap's type comes from the same fingerprint as its OS. The
//     observation stays, shown as not used (ObservationRow.ContradictsType): a firewall a person typed, which nmap took for Android.
//
// With nmap alone and no contradiction, the guess is the device's OS and software as before.

// guessFamily is one family of operating systems and the device types it never runs on. The table is kept narrow on purpose: only
// pairs no real device of the type has (an Android desk phone, a Windows print server, an Android point of sale do exist, so those
// types are not listed).
type guessFamily struct {
	name  string
	words []string // lower-case words of nmap's OS name that place it in the family
	not   []string // lower-case words that take it out again (Windows CE, Windows Mobile: embedded Windows does run on printers)
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
		types: concat(networkGear, []string{"load_balancer", "vpn_gateway", "wireless_controller"}, printers,
			[]string{"camera", "nvr", "dvr", "video_encoder", "nas", "san", "server", "hypervisor", "domain_controller", "mail_server",
				"database_server", "backup_server", "pc", "laptop", "workstation"}),
	},
	{
		name:  "desktop", // Windows, macOS
		words: []string{"microsoft windows", "mac os x", "macos"},
		not:   []string{"windows ce", "mobile", "phone", "embedded", "iot"},
		types: concat(networkGear, printers, []string{"camera", "video_encoder", "doorbell", "smartphone", "smartwatch", "ip_phone"}),
	},
	{
		name:  "network", // the OS of a router, switch or firewall
		words: []string{"cisco ios", "nx-os", "junos", "fortios", "routeros", "pan-os"},
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

// guessContradicts says whether nmap's OS name contradicts a device of this type (rule 2). kindSource is the source of the type.
func guessContradicts(kind, kindSource, osName string) bool {
	if kindSource == "" || kindSource == "nmap" || kindSource == "scan" {
		return false
	}
	name := strings.ToLower(osName)
	if strings.Contains(name, ntlmMark) {
		return false
	}
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
// next OS that does not wins instead (another source's reading, else none). list is the device's observations, best their winners.
func dropContradictedOS(list []obs, best map[string]obs) {
	o, ok := best["os"]
	k, kok := best["kind"]
	if !ok || !kok || o.source != "nmap" || !guessContradicts(k.value, k.source, o.value) {
		return
	}
	delete(best, "os")
	for _, c := range list {
		if c.field != "os" || c.source == "nmap" && guessContradicts(k.value, k.source, c.value) {
			continue
		}
		if b, ok := best["os"]; !ok || better(c, b) {
			best["os"] = c
		}
	}
}

// osGuessRow is the SQL condition on a software row (alias s) that nmap stored it as an OS guess: source nmap, an OS CPE, no match
// key (observe.Software.Guess).
const osGuessRow = `(s.source = 'nmap' AND s.cpe LIKE 'cpe:/o:%' AND NOT EXISTS (SELECT 1 FROM inv_software_kev gk WHERE gk.software_id = s.id))`

// outrankedGuess (rule 1): a person, the agent or SNMP gave the device's OS.
const outrankedGuess = `EXISTS (SELECT 1 FROM inv_asset ga JOIN inv_observation gob ON gob.id = ga.os_obs_id WHERE ga.id = s.asset_id
	AND gob.source IN ('manual', 'agent', 'snmp'))`

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
	ON gko.id = ga.kind_obs_id WHERE ga.id = s.asset_id AND gko.source NOT IN ('nmap', 'scan') AND (` + strings.Join(fams, " OR ") + `)))`
}
