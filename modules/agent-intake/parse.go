package agentintake

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/observe"
)

// The parsers of the four public operations (INV-7, D-169 (8)). The ogen server has already decoded the JSON envelope; what is parsed
// here is the content: it is hostile (SYS-6), so every parser is fail-closed (anything that does not fit is dropped or refused, never
// guessed), bounded, and reads only the allow-listed columns of the allow-listed queries. Unknown outer keys (decorations, epoch,
// counter, numerics, action, ...) are ignored and never stored.

const (
	maxValue     = 256  // runes of any one column value; a longer one drops its row
	maxVersion   = 100  // inventory's limit for a version
	maxName      = 200  // inventory's limit for a name
	maxHostID    = 200  // host_identifier and hostname, runes
	maxRows      = 5000 // package rows kept per snapshot (inventory.maxItems)
	maxIfaceRows = 8    // interface rows kept
	maxEvents    = 64   // result events read per log request; the schedule has six queries
)

var (
	enrollSecretRE = regexp.MustCompile(`^vdt_osquery_[a-z0-9]{32}$`)
	nodeKeyRE      = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// row is one snapshot row: only allow-listed columns, every value a clean string.
type row map[string]string

// columns is the allow-list: the queries of the schedule and the columns of each that are read. Anything else in a result is never
// looked at (D-169 (8)).
var columns = map[string][]string{
	"os_version":   {"name", "version", "major", "minor", "patch", "build", "platform", "arch"},
	"system_info":  {"hostname", "hardware_vendor", "hardware_model"},
	"interfaces":   {"mac", "address"},
	"deb_packages": {"name", "version", "arch", "source"},
	"kernel_info":  {"version"}, // the running kernel release (D-516)
	"rpm_packages": {"name", "version", "release", "arch", "epoch"},
	"programs":     {"name", "version", "publisher", "install_date"},
	"os_revision":  {"name", "version", "revision", "arch"}, // Windows's update revision (D-524)
}

// cleanValue trims a text from a node and reports whether it can be kept: valid UTF-8, at most max runes, no control or invisible
// character (the same rule as the inventory's cleanText, with core/observe.Ignorable for the invisible ones). Empty is clean.
func cleanValue(s string, limit int) (string, bool) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit {
		return "", false
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || observe.Ignorable(r) }) {
		return "", false
	}
	return s, true
}

// ---- enroll ----

// enrollIn is a parsed enrol request.
type enrollIn struct {
	secret         string
	hostIdentifier string
	hostname       string // from host_details.system_info, "" when absent or not clean
	platform       string // host_details.os_version.platform
	osqueryVersion string // host_details.osquery_info.version
}

// parseEnroll reads an enrol request. ok is false for a missing or malformed secret or a host_identifier that is empty or not clean:
// the handler answers node_invalid for those, the same as for an unknown token (no oracle).
func parseEnroll(req *oas.InventoryPostIntakeOsqueryEnrollReq) (enrollIn, bool) {
	var in enrollIn
	if req == nil || !req.EnrollSecret.Set || !enrollSecretRE.MatchString(req.EnrollSecret.Value) {
		return in, false
	}
	in.secret = req.EnrollSecret.Value
	id, ok := cleanValue(req.HostIdentifier, maxHostID)
	if !ok || id == "" {
		return in, false
	}
	in.hostIdentifier = id
	if req.HostDetails.Set {
		in.hostname = detail(req.HostDetails.Value, "system_info", "hostname", maxHostID)
		in.platform = detail(req.HostDetails.Value, "os_version", "platform", 32)
		in.osqueryVersion = detail(req.HostDetails.Value, "osquery_info", "version", 32)
	}
	return in, true
}

// detail reads details[group][key] as a clean string; anything else (a missing group, another type, dirty text) is "".
func detail(details oas.InventoryPostIntakeOsqueryEnrollReqHostDetails, group, key string, limit int) string {
	raw, ok := details[group]
	if !ok {
		return ""
	}
	var g map[string]json.RawMessage
	if json.Unmarshal(raw, &g) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(g[key], &s) != nil {
		return ""
	}
	s, _ = cleanValue(s, limit)
	return s
}

// ---- config ----

// parseConfig reads the node key of a config request; ok is false when it cannot be a key we issued.
func parseConfig(req *oas.InventoryPostIntakeOsqueryConfigReq) (nodeKey string, ok bool) {
	if req == nil || !nodeKeyRE.MatchString(req.NodeKey) {
		return "", false
	}
	return req.NodeKey, true
}

// ---- status ----

// parseStatus reads the enrolment token from the Authorization header value ("Bearer <token>"); ok is false when it is not one.
func parseStatus(authorization string) (secret string, ok bool) {
	t, found := strings.CutPrefix(authorization, "Bearer ")
	if !found || !enrollSecretRE.MatchString(t) {
		return "", false
	}
	return t, true
}

// parseStatusHost reads the optional host_identifier of a status request. named is false when none was sent or it is not clean (empty, too
// long, control characters): the answer then carries no host field at all, the same for every such input (no oracle on what was wrong).
func parseStatusHost(req oas.OptInventoryPostIntakeOsqueryStatusReq) (host string, named bool) {
	if !req.Set || !req.Value.HostIdentifier.Set {
		return "", false
	}
	id, ok := cleanValue(req.Value.HostIdentifier.Value, maxHostID)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// ---- log ----

// logIn is a parsed log request.
type logIn struct {
	nodeKey   string
	result    bool             // log_type = result; status lines are read for their size only and dropped
	snaps     map[string][]row // by query name, from the allow-list; the last event of a name wins
	dropped   int              // rows and events that did not fit (not clean, wrong type, unknown query)
	truncated map[string]bool  // lists cut at their cap
	events    int              // events in the request
}

type event struct {
	Name     string                       `json:"name"`
	Action   string                       `json:"action"`
	Snapshot []map[string]json.RawMessage `json:"snapshot"`
}

// parseLog reads a log request. ok is false only when the node key cannot be one of ours. A result event of an unknown query, an event
// that is not a snapshot, a row with a column of the wrong type or with unclean text is dropped on its own and counted; the rest of
// the request is kept. Differential results (action added/removed) are ignored: the schedule is snapshot-only.
func parseLog(req *oas.InventoryPostIntakeOsqueryLogReq) (logIn, bool) {
	in := logIn{snaps: map[string][]row{}, truncated: map[string]bool{}}
	if req == nil || !nodeKeyRE.MatchString(req.NodeKey) {
		return in, false
	}
	in.nodeKey = req.NodeKey
	in.events = len(req.Data)
	if req.LogType != oas.InventoryPostIntakeOsqueryLogReqLogTypeResult {
		return in, true // status lines: read for size (the body cap) and discarded
	}
	in.result = true
	for i, item := range req.Data {
		if i >= maxEvents {
			in.dropped += len(req.Data) - i
			break
		}
		in.readEvent(item)
	}
	return in, true
}

func (in *logIn) readEvent(item oas.InventoryPostIntakeOsqueryLogReqDataItem) {
	var ev event
	if !readEvent(item, &ev) {
		in.dropped++
		return
	}
	cols, known := columns[ev.Name]
	if !known || ev.Action != "snapshot" {
		in.dropped++
		return
	}
	limit := maxRows
	if ev.Name == "interfaces" {
		limit = maxIfaceRows
	}
	rows := make([]row, 0, min(len(ev.Snapshot), limit))
	for _, raw := range ev.Snapshot {
		r, ok := readRow(raw, cols)
		if !ok {
			in.dropped++
			continue
		}
		if len(rows) >= limit {
			in.truncated[ev.Name] = true
			break
		}
		rows = append(rows, r)
	}
	in.snaps[ev.Name] = rows
}

// readEvent decodes the three keys of an event that matter; everything else in the map is left undecoded.
func readEvent(item oas.InventoryPostIntakeOsqueryLogReqDataItem, ev *event) bool {
	for _, k := range []string{"name", "action"} {
		raw, ok := item[k]
		if !ok {
			return false
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return false
		}
		if k == "name" {
			ev.Name = s
		} else {
			ev.Action = s
		}
	}
	raw, ok := item["snapshot"]
	if !ok || json.Unmarshal(raw, &ev.Snapshot) != nil {
		return false
	}
	return true
}

// readRow keeps the allow-listed columns of one row; false when one of them is not a string or not clean.
func readRow(raw map[string]json.RawMessage, cols []string) (row, bool) {
	r := make(row, len(cols))
	for _, c := range cols {
		v, ok := raw[c]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			return nil, false
		}
		s, ok = cleanValue(s, maxValue)
		if !ok {
			return nil, false
		}
		r[c] = s
	}
	return r, true
}

// ---- interfaces ----

// iface is one declared IPv4 address and the MAC of its card.
type iface struct {
	ip  netip.Addr
	mac string
}

// parseInterfaces turns the rows of the interfaces query into addresses: IPv4 only, never loopback, link-local, unspecified or
// multicast, the MAC in the form aa:bb:cc:dd:ee:ff and never all-zero. A row that does not fit is dropped.
func parseInterfaces(rows []row) []iface {
	var out []iface
	for _, r := range rows {
		ip, err := netip.ParseAddr(r["address"])
		if err != nil || !ip.Is4() || ip.Zone() != "" || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		mac, ok := normMAC(r["mac"])
		if !ok {
			continue
		}
		out = append(out, iface{ip: ip, mac: mac})
	}
	return out
}

// normMAC returns the colon-separated lower-case form of a MAC and reports whether it is one unicast, non-zero address.
func normMAC(s string) (string, bool) {
	if len(s) != 17 {
		return "", false
	}
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		switch {
		case i%3 == 2:
			if c != ':' && c != '-' {
				return "", false
			}
			b[i] = ':'
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
		default:
			return "", false
		}
	}
	m := string(b)
	if m == "00:00:00:00:00:00" || hexVal(b[1])&1 == 1 { // all-zero, or the group bit of the first octet (multicast, broadcast)
		return "", false
	}
	return m, true
}

func hexVal(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}
