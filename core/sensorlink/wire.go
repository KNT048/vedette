package sensorlink

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// The bodies of the protocol (sensor-protocol.md section 6). Decoding is strict (internal/jsonstrict: unknown field, repeated
// key, nesting over 32 and trailing data are errors) and the decoders check what is structural about the whole body: sizes,
// counts, types, ranges. What is about one observation (a MAC that does not match, a value that is dirty, a time outside the
// window) is not checked here: core answers those item by item in rejected[] (D-112 (3)).

// Config is the answer to GET /config (passive): what the capture process may do right now.
type Config struct {
	Interface string   `json:"interface"` // "" = do not capture
	Span      bool     `json:"span"`
	Extract   Extract  `json:"extract"`
	Filters   []Filter `json:"filters"`
}

// Extract holds the four metadata switches of D-43.
type Extract struct {
	DNS   bool `json:"dns"`
	SNI   bool `json:"sni"`
	HTTP  bool `json:"http"`
	Flows bool `json:"flows"`
}

// Filter is one exclusion rule: Type is cidr, host or port.
type Filter struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ConfigReply is what a Backend returns for GET /config. NotModified answers 304 (the sensor's ETag is current).
type ConfigReply struct {
	NotModified bool
	ETag        string
	Config      Config
}

// ObservationsRequest is the body of POST /observations.
type ObservationsRequest struct {
	Epoch string            `json:"epoch"`
	Seq   int64             `json:"seq"`
	Items []ObservationItem `json:"items"`
}

// ObservationItem is one thing a sensor saw. There is deliberately no source: core sets it from the role (D-111 (2)).
type ObservationItem struct {
	MAC        string    `json:"mac,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Field      string    `json:"field"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	SeenAt     time.Time `json:"seen_at"`
}

// ObservationsReply is the 200 of POST /observations: partial success, never retried (D-112 (3)).
type ObservationsReply struct {
	AckSeq   int64      `json:"ack_seq"`
	Rejected []Rejected `json:"rejected"`
}

// Rejected is one refused item: its index in the request and why (invalid_item, out_of_window, budget_exhausted, refused).
type Rejected struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

// PassiveHeartbeat is the heartbeat body of the passive role.
type PassiveHeartbeat struct {
	Version     string           `json:"version"`
	Interfaces  []HeartbeatIface `json:"interfaces"`
	Span        HeartbeatSpan    `json:"span"`
	Drops       map[string]int64 `json:"drops"`
	DevicesSeen int64            `json:"devices_seen"`
}

// HeartbeatIface is one network card the sensor sees.
type HeartbeatIface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	Link bool     `json:"link"`
	IPv4 []string `json:"ipv4"`
}

// HeartbeatSpan is what the sensor measured on the SPAN port.
type HeartbeatSpan struct {
	PPS          int64      `json:"pps"`
	OtherMACs    int64      `json:"other_macs"`
	LastPacketAt *time.Time `json:"last_packet_at"`
}

// ActiveHeartbeat is the heartbeat body of the active role.
type ActiveHeartbeat struct {
	Version string        `json:"version"`
	Nmap    HeartbeatNmap `json:"nmap"`
}

// HeartbeatNmap says whether the worker can run nmap.
type HeartbeatNmap struct {
	Present bool   `json:"present"`
	Version string `json:"version"`
}

// JobsReply is the answer to GET /jobs (active).
type JobsReply struct {
	Instance string   `json:"instance"`
	Jobs     []Job    `json:"jobs"`
	Cancel   []string `json:"cancel"`
}

// Job is one nmap job. There is no argv, flag, path or URL on the wire (D-111 (3)): the worker builds the command itself.
type Job struct {
	ID       string   `json:"id"`
	Shape    string   `json:"shape"`
	Rate     int      `json:"rate"`
	Targets  []string `json:"targets"`
	TimeoutS int      `json:"timeout_s"`
}

// JobResult is the body of POST /jobs/{id}/result.
type JobResult struct {
	Status    string `json:"status"` // done, failed, stopped, refused
	Reason    string `json:"reason"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
	XMLB64    string `json:"xml_b64"`

	xml []byte // the decoded XMLB64, set by the server's decoder
}

type instanceReply struct {
	Instance string `json:"instance"`
}

var (
	errInvalid  = errors.New("invalid body")
	errTooLarge = errors.New("payload too large")

	epochRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	jobIDRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	versionRE  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	ifaceRE    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	macRE      = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	nmapVerRE  = regexp.MustCompile(`^[0-9A-Za-z._+-]{0,32}$`)
	etagRE     = regexp.MustCompile(`^"[A-Za-z0-9._:-]{1,64}"$`)
	resultCode = map[string]bool{"": true, "invalid_job": true, "busy": true, "nmap_missing": true, "exec_failed": true, "deadline": true, "cancelled": true}
	resultStat = map[string]bool{"done": true, "failed": true, "stopped": true, "refused": true}
)

const maxSeq = 1<<53 - 1

// The limits of the passive heartbeat (sensor-protocol.md section 9).
const (
	MaxHeartbeatIfaces   = 32
	MaxHeartbeatPrefixes = 8
	MaxDropKeys          = 64
)

// DropKeys is the closed set of the counters a passive heartbeat may carry in drops (sensor-protocol.md 6.3): what the capture
// process counts instead of passing on. A key outside it is a 400, like any field this protocol does not know. The capture
// package's tests check that every counter the capture can produce is here.
var DropKeys = []string{
	"arp_mac_mismatch", "batch_dropped", "capture_failed", "dhcp_mac_mismatch", "dns_name_rejected", "excluded", "filters_invalid",
	"flows_dropped", "fragment_skipped", "malformed_arp", "malformed_dhcp", "malformed_dns", "malformed_ethernet", "malformed_http",
	"malformed_ipv4", "malformed_lldp", "malformed_mdns", "malformed_ssdp", "malformed_tcp", "malformed_tls", "malformed_udp", "metadata_dropped",
	"metadata_failed", "new_macs_dropped", "new_macs_unconfirmed", "non_unicast_ip", "observation_failed", "observation_rejected",
	"observations_dropped", "unusable_record", "value_empty", "value_truncated", "values_dropped", "vendor_rejected",
}

// ValidDropKey reports whether k is in DropKeys.
func ValidDropKey(k string) bool { return slices.Contains(DropKeys, k) }

// ValidIfaceName reports whether s is a card name of the protocol (sensor-protocol.md section 5).
func ValidIfaceName(s string) bool { return ifaceRE.MatchString(s) }

// ValidMAC reports whether s is a MAC of the protocol: six lower-case hex pairs separated by colons.
func ValidMAC(s string) bool { return macRE.MatchString(s) }

func invalid(what string) error {
	return fmt.Errorf("%w: %s", errInvalid, what)
}

func decodeObservations(raw []byte) (*ObservationsRequest, error) {
	var r ObservationsRequest
	if err := jsonstrict.Decode(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	switch {
	case !epochRE.MatchString(r.Epoch):
		return nil, invalid("epoch")
	case r.Seq < 1 || r.Seq > maxSeq:
		return nil, invalid("seq")
	case len(r.Items) < 1 || len(r.Items) > MaxItems:
		return nil, invalid("items")
	}
	return &r, nil
}

func decodePassiveHeartbeat(raw []byte) (*PassiveHeartbeat, error) {
	var h PassiveHeartbeat
	if err := jsonstrict.Decode(raw, &h); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if !versionRE.MatchString(h.Version) || len(h.Version) > 64 {
		return nil, invalid("version")
	}
	if len(h.Interfaces) > 32 {
		return nil, invalid("interfaces")
	}
	for _, i := range h.Interfaces {
		if !ifaceRE.MatchString(i.Name) || !macRE.MatchString(i.MAC) || len(i.IPv4) > 8 {
			return nil, invalid("interface")
		}
		for _, p := range i.IPv4 {
			if pf, err := netip.ParsePrefix(p); err != nil || !pf.Addr().Is4() {
				return nil, invalid("ipv4")
			}
		}
	}
	if h.Span.PPS < 0 || h.Span.OtherMACs < 0 || h.DevicesSeen < 0 {
		return nil, invalid("counter")
	}
	if len(h.Drops) > MaxDropKeys {
		return nil, invalid("drops")
	}
	for k, v := range h.Drops {
		if !ValidDropKey(k) || v < 0 {
			return nil, invalid("drops")
		}
	}
	return &h, nil
}

func decodeActiveHeartbeat(raw []byte) (*ActiveHeartbeat, error) {
	var h ActiveHeartbeat
	if err := jsonstrict.Decode(raw, &h); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if !versionRE.MatchString(h.Version) || len(h.Version) > 64 || !nmapVerRE.MatchString(h.Nmap.Version) {
		return nil, invalid("version")
	}
	return &h, nil
}

// decodeJobResult checks the body of a job result. A decoded XML over 8 MiB is errTooLarge (413), not a syntax error.
func decodeJobResult(raw []byte) (*JobResult, error) {
	var r JobResult
	if err := jsonstrict.Decode(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if !resultStat[r.Status] || !resultCode[r.Reason] || r.ExitCode < -1 || r.ExitCode > 255 {
		return nil, invalid("result")
	}
	if base64.StdEncoding.DecodedLen(len(r.XMLB64)) > MaxResultXML+3 {
		return nil, errTooLarge
	}
	if r.XMLB64 != "" {
		if r.Status != "done" {
			return nil, invalid("xml_b64 on a result that is not done")
		}
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(r.XMLB64)))
		n, err := base64.StdEncoding.Decode(buf, []byte(r.XMLB64))
		if err != nil {
			return nil, invalid("xml_b64")
		}
		if n > MaxResultXML {
			return nil, errTooLarge
		}
		r.xml = buf[:n]
	}
	return &r, nil
}

// XML is the nmap output the server's decoder found in a result (nil when there is none). It is not set on a JobResult a
// sensor builds; the sensor puts the bytes in XMLB64 with SetXML.
func (r *JobResult) XML() []byte { return r.xml }

// SetXML fills XMLB64 from the raw nmap output.
func (r *JobResult) SetXML(b []byte) { r.XMLB64 = base64.StdEncoding.EncodeToString(b) }
