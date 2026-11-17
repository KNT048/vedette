package api

// GET /v1/state/ports (docs/specs/host-api.md section 5): the ports the box itself listens on from outside, for its own device's
// Open services (inventory INV-3, kien 2026-11-17: the box is never scanned, so without this its device said "No open port seen
// yet" while it serves 8443). Read from the kernel's socket tables (/proc/net/{tcp,tcp6,udp,udp6}) and /proc/<pid>, no program
// runs. Read-only, no lock, no audit line, like the other state reads. A host older than it answers 404 unknown_command; core
// then keeps what the box's device lists.

// ListenPort is one port the box listens on at an address other than loopback (every address, 0.0.0.0 or ::, counts). Proto is
// "tcp" (a socket in LISTEN) or "udp" (a bound socket with no peer). Process names what holds it: the Vedette service
// ("vedette-core") when the process runs in a vedette-*.service unit or is a container monitor (conmon) of a unit, else the
// process name of /proc/<pid>/comm reduced to printable ASCII ("sshd"); "" when no process could be found. Proto is ProtoTCP or
// ProtoUDP (decoy.go): the same protocol names, a word of the answer, never a network the host listens on or dials.
type ListenPort struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process"`
}

// PortsState is the body of GET /v1/state/ports, sorted by protocol then port, one entry per port and protocol.
type PortsState struct {
	Ports []ListenPort `json:"ports"`
}

// MaxPorts bounds the list (the inventory keeps at most 1000 services of one source): the lowest ports are kept.
const MaxPorts = 1000
