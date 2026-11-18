package inventory

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/oui"
	"github.com/knt048/vedette/core/observe"
)

// What a device announces about itself ranks above what a scan guesses (INV-44). A switch's LLDP system description states its
// OS with the exact release ("JUNOS 15.1R7.9"); nmap's OS fingerprint guesses a family and a range, and the guess can change
// between two scans ("JUNOS 8.5 - 11.2", then "JUNOS 12"). So the OS ranking is: a person > the device's agent > its SNMP
// answer > its LLDP statement > nmap's fingerprint > any other passive hint (a DHCP client's OS family).
//
// An LLDP frame can carry another device's MAC as its chassis id, so a statement counts only when the device's own network card
// is the stating vendor's: the rows of content/catalog/network-os.json with lldp_oui, the same rows and the same check the
// findings matcher reads an LLDP statement with (findings networkos.go, lldpCard). A new vendor is one row of that data.

// lldpStatement is one OS an LLDP description may state, with the IEEE vendor its device's card must have.
type lldpStatement struct {
	re     *regexp.Regexp
	vendor string
}

var lldpStatements = func() []lldpStatement {
	var f struct {
		OS []struct {
			Statement string `json:"statement"`
			LLDPOUI   string `json:"lldp_oui"`
		} `json:"os"`
	}
	if err := json.Unmarshal(catalogdata.NetworkOS, &f); err != nil {
		panic(fmt.Sprintf("inventory: network-os.json: %v", err)) // embedded data, checked by TestStatedOSReadsTheNetworkOSTable
	}
	var out []lldpStatement
	for _, r := range f.OS {
		if r.LLDPOUI == "" {
			continue
		}
		out = append(out, lldpStatement{re: regexp.MustCompile(r.Statement), vendor: r.LLDPOUI})
	}
	return out
}()

// lldpStated says whether os, an OS a passive frame read from a device's LLDP description, is a statement the device's card
// vouches for: it matches a row of network-os.json whose lldp_oui is the IEEE vendor of mac. No MAC, a private MAC or another
// vendor's card: false.
func lldpStated(os, mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	vendor, ok := oui.Lookup([6]byte(hw))
	if !ok {
		return false
	}
	for _, st := range lldpStatements {
		if st.vendor == vendor && st.re.MatchString(os) {
			return true
		}
	}
	return false
}

// The basis of a value, beside its source and confidence (contract.ts Observed.basis): how Vedette knows it.
const (
	basisStated = "stated" // the device announced it about itself (its LLDP statement, lldpStated, and the model of the same frame)
	basisGuess  = "guess"  // nmap's OS fingerprint: a guess, shown as one and never as a confidence level
)

// osBasis is the basis of an OS observation: a fingerprint guess of nmap (never the device's own NTLM answer), the device's
// LLDP statement, or "" (the source and confidence say it all).
func osBasis(value, source, mac string) string {
	switch {
	case source == "nmap" && observe.SelfStatedBasis(value) != "":
		return observe.SelfStatedBasis(value) // the device's own statement without a login (observe.SelfStatedBasis)
	case source == "nmap" && !ntlmAnswer(value):
		return basisGuess
	case source == "passive" && lldpStated(value, mac):
		return basisStated
	}
	return ""
}

// markStated sets stated on each OS observation of list that is the device's LLDP statement (lldpStated), read against the MAC
// that wins in list (the newest one, INV-1), or the device's own statement without a login (observe.SelfStatedBasis, written by a scan
// as source nmap). A list without a MAC states no LLDP OS.
func markStated(list []obs) {
	var mac obs
	for _, o := range list {
		if o.field == "mac" && (mac.id == "" || better(o, mac)) {
			mac = o
		}
	}
	for i, o := range list {
		list[i].stated = o.field == "os" && (o.source == "passive" && mac.id != "" && lldpStated(o.value, mac.value) ||
			o.source == "nmap" && observe.SelfStatedBasis(o.value) != "")
	}
}

// modelBasis is the basis of a model observation: "stated" when it is passive and came with an OS statement of the same LLDP frame
// (frameOS: the device's passive OS seen at the same moment, "" when none) that its card vouches for (lldpStated), so the model
// and the OS of one frame read alike; "" otherwise (an mDNS or SSDP model, a frame on another vendor's card).
func modelBasis(source, frameOS, mac string) string {
	if source == "passive" && frameOS != "" && lldpStated(frameOS, mac) {
		return basisStated
	}
	return ""
}
