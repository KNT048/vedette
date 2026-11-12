package logs

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	logsdata "github.com/knt048/vedette/content/logs"
	"github.com/knt048/vedette/core/apierr"
)

// kind is one entry of content/logs/kinds.json.
type kind struct {
	ID     string   `json:"id"`
	Protos []string `json:"protos"` // the protocols the device can really send with; the first is the default
	Reads  string   `json:"reads"`  // "parsed" or "stored"
}

var kinds = func() map[string]kind {
	var list []kind
	if err := json.Unmarshal(logsdata.Kinds, &list); err != nil {
		panic("logs: content/logs/kinds.json: " + err.Error()) // embedded data: a programming error
	}
	out := make(map[string]kind, len(list))
	for _, k := range list {
		out[k.ID] = k
	}
	return out
}()

// KindIDs returns the ids of the source kinds, in the order of the file.
func KindIDs() []string {
	var list []kind
	_ = json.Unmarshal(logsdata.Kinds, &list)
	ids := make([]string, len(list))
	for i, k := range list {
		ids[i] = k.ID
	}
	return ids
}

var certPinRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// normalize checks a source input in the order the mock does (kind, name, IP, protocol, port) and returns it with the name
// trimmed. The messages are the mock's: the GUI shows them as they are. Limits that contract.ts states (the enums, the
// name pattern, the port range) are refused first by the generated validator as 400 invalid (D-73); these codes remain
// for what the schema cannot say (the protocol a kind can send, an IP that is not a dotted quad) and for the service
// used directly.
func (in Input) normalize(tlsOK bool) (Input, error) {
	k, ok := kinds[in.Kind]
	if !ok {
		return in, apierr.New(400, "bad_kind", "Choose a device type from the list.")
	}
	in.Name = strings.TrimSpace(in.Name)
	if !nameRE.MatchString(in.Name) {
		return in, apierr.New(400, "bad_name", "The name may only contain letters without accents, digits, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: FW-HQ.")
	}
	if a, err := netip.ParseAddr(in.SenderIP); err != nil || !a.Is4() || a.String() != in.SenderIP {
		return in, apierr.New(400, "bad_ip", "The IP address of the sending device is not valid. Enter it like 192.168.10.1.")
	}
	if !slices.Contains(k.Protos, in.Proto) {
		return in, apierr.New(400, "bad_proto", "This device type cannot send logs with the chosen protocol. Pick another protocol from the list.")
	}
	if in.Proto == "tls" && !tlsOK { // D-203, D-214: the box has no certificate to serve (loopback or dev, plain HTTP); a source that would silently never receive is refused
		return in, apierr.New(400, "tls_unavailable", "Syslog over TLS needs the box's HTTPS certificate; this box serves plain HTTP. Choose UDP or TCP.")
	}
	if in.Port < 1 || in.Port > 65535 {
		return in, apierr.New(400, "bad_port", "The port must be a number from 1 to 65535. Usually 514 (UDP or TCP) or 6514 (TLS).")
	}
	if in.ClientCertSHA256 != "" {
		if in.Proto != "tls" {
			return in, apierr.New(400, "bad_client_cert", "Only a TLS source can have a client certificate, given as its SHA-256 fingerprint: 64 hexadecimal characters.")
		}
		if !certPinRE.MatchString(in.ClientCertSHA256) {
			return in, apierr.New(400, "bad_client_cert", "Only a TLS source can have a client certificate, given as its SHA-256 fingerprint: 64 hexadecimal characters.")
		}
	}
	return in, nil
}
