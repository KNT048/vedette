package surface

import "github.com/knt048/vedette/modules/scan/commonports"

// kind is what the scan does with an open port besides listing it.
type kind int

// The kinds follow commonports.Use, value for value (TestPortKindsFollowTheList).
const (
	plain   kind = iota // listed only
	web                 // one GET of / over plain HTTP
	webTLS              // one GET of / over HTTPS, and its certificate
	tlsOnly             // a TLS handshake for the certificate (mail, LDAP, MQTT…)
)

type portSpec struct {
	port    int
	service string
	kind    kind
}

// commonPorts is the fixed list of TCP ports the scan connects to (D-229): commonports.List, the one list sensor-active's external
// nmap shape names too (D-514). Its uses are this package's kinds, in the same order.
var commonPorts = func() []portSpec {
	out := make([]portSpec, len(commonports.List))
	for i, p := range commonports.List {
		out[i] = portSpec{port: p.Number, service: p.Service, kind: kind(p.Use)}
	}
	return out
}()

var portByNumber = func() map[int]portSpec {
	m := make(map[int]portSpec, len(commonPorts))
	for _, p := range commonPorts {
		m[p.port] = p
	}
	return m
}()
