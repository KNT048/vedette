package observe

import "strings"

// What a device states about itself without a login: the firmware version in a page or an API it serves to anyone (an iLO's
// /xmldata, an ESXi's SOAP service content) or in the answer to a SIP OPTIONS request. Sensors write it as an OS observation of
// source nmap whose value has one of the shapes below; the inventory ranks such a value above nmap's OS fingerprint guess and below
// anything a person, an agent or an SNMP read with the customer's settings gives (inventory INV-44), and the device page says
// how the device stated it (Basis*). One table, so the writer, the ranking and the SQL that hides outranked guesses agree.

// The bases of a self-statement, as the device page labels them: the device said it on its web interface, or in a SIP answer.
const (
	BasisStatedWeb = "stated_web"
	BasisStatedSIP = "stated_sip"
)

// selfStatement is one shape of OS value a sensor writes for a device's own statement: it starts with Prefix and holds Contains, a
// marker nmap's OS fingerprint names never have ("VMware ESXi 5.5 - 6.7" is a guess, not a statement).
type selfStatement struct{ prefix, contains, basis string }

var selfStatements = []selfStatement{
	{"HPE iLO ", " firmware ", BasisStatedWeb},
	{"VMware ESXi ", " (build ", BasisStatedWeb}, // the build is written always: no fingerprint name of nmap has it
	{"Grandstream ", " firmware ", BasisStatedSIP},
}

// SelfStatedBasis is the basis of an OS value written as a device's own statement (BasisStatedWeb, BasisStatedSIP), "" when it is not one.
func SelfStatedBasis(os string) string {
	for _, s := range selfStatements {
		if strings.HasPrefix(os, s.prefix) && strings.Contains(os, s.contains) {
			return s.basis
		}
	}
	return ""
}

// SelfStatedLike lists the SQL LIKE patterns that match a self-stated OS value (for a query on inv_observation.value). The patterns hold no
// escape character: the table's texts have no % or _.
func SelfStatedLike() []string {
	out := make([]string, len(selfStatements))
	for i, s := range selfStatements {
		out[i] = s.prefix + "%" + s.contains + "%"
	}
	return out
}
