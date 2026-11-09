package honeypot

import (
	"context"
	"net/netip"
	"strings"
	"time"
)

// ServiceName is one of the five trap services of INV-2.
type ServiceName string

// The five services, with the fixed ports of INV-2.
const (
	SMB   ServiceName = "smb"
	RDP   ServiceName = "rdp"
	SSH   ServiceName = "ssh"
	MSSQL ServiceName = "mssql"
	HTTP  ServiceName = "http"
)

// Services lists the traps in the order the API shows them.
var Services = []ServiceName{SMB, RDP, SSH, MSSQL, HTTP}

// Port is the fixed port of a service (INV-2); 0 for an unknown name.
func (s ServiceName) Port() int {
	switch s {
	case SMB:
		return 445
	case RDP:
		return 3389
	case SSH:
		return 22
	case MSSQL:
		return 1433
	case HTTP:
		return 80
	}
	return 0
}

// Label is the name shown for the service ("SMB").
func (s ServiceName) Label() string {
	switch s {
	case SMB, RDP, SSH, MSSQL, HTTP:
		return strings.ToUpper(string(s))
	}
	return string(s)
}

// Valid reports whether s is one of the five services.
func (s ServiceName) Valid() bool { return s.Port() != 0 }

// HitKind says what a hit is (contract.ts HitKind).
type HitKind string

// The hit kinds.
const (
	KindService HitKind = "service"
	KindToken   HitKind = "token"
	KindScan    HitKind = "scan"
)

// Trap states (INV-7).
const (
	StateOff       = "off"
	StateListening = "listening"
	StateConflict  = "conflict"
)

// Trap is one service trap (contract.ts Trap).
type Trap struct {
	Service   ServiceName `json:"service"`
	Port      int         `json:"port"`
	Enabled   bool        `json:"enabled"`
	State     string      `json:"state"`
	Since     *string     `json:"since"`
	Hits7d    int         `json:"hits_7d"`
	LastHitAt *string     `json:"last_hit_at"`
}

// BoxRef is the box as the overview names it.
type BoxRef struct {
	IP   *string `json:"ip"`
	Name string  `json:"name"`
}

// AssetRef is a device named by id.
type AssetRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Summary counts the real hits (INV-4: never test hits).
type Summary struct {
	Today     int     `json:"today"`
	Week      int     `json:"week"`
	LastHitAt *string `json:"last_hit_at"`
	LastSrc   *string `json:"last_src"`
}

// Overview is GET /honeypot (contract.ts HpOverview).
type Overview struct {
	SecondaryIP   *string   `json:"secondary_ip"`
	Hostname      string    `json:"hostname"`
	LAN           *string   `json:"lan"`
	Box           BoxRef    `json:"box"`
	Ignored7d     int       `json:"ignored_7d"`
	ConflictAsset *AssetRef `json:"conflict_asset"`
	Traps         []Trap    `json:"traps"`
	Summary       Summary   `json:"summary"`
	UpdatedAt     string    `json:"updated_at"`
}

// Hit is a row of the hit list (contract.ts Hit). SourceIP repeats SrcIP for the response module (INV-8) and is not
// part of the API.
type Hit struct {
	ID         string       `json:"id"`
	TS         string       `json:"ts"`
	Kind       HitKind      `json:"kind"`
	Service    *ServiceName `json:"service"`
	Label      string       `json:"label"`
	Port       *int         `json:"port"`
	SrcIP      string       `json:"src_ip"`
	SrcAssetID *string      `json:"src_asset_id"`
	SrcName    *string      `json:"src_name"`
	IsTest     bool         `json:"is_test"`
	Excerpt    string       `json:"excerpt"`
}

// SourceIP is the address the hit came from, for the response module.
func (h Hit) SourceIP() string { return h.SrcIP }

// HitEvent is one line around a hit (contract.ts HitEvent).
type HitEvent struct {
	TS     string `json:"ts"`
	Source string `json:"source"`
	Text   string `json:"text"`
	Mark   bool   `json:"mark"`
}

// DetailAsset is the source device of a hit detail.
type DetailAsset struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	IP       string `json:"ip"`
	Approved bool   `json:"approved"`
}

// HitDetail is GET /honeypot/hits/{id} (contract.ts HitDetail).
type HitDetail struct {
	Hit
	TrapIP        string       `json:"trap_ip"`
	TrapHostname  string       `json:"trap_hostname"`
	Asset         *DetailAsset `json:"asset"`
	Events        []HitEvent   `json:"events"`
	WindowMinutes int          `json:"window_minutes"`
}

// WindowMinutes is the hour of log lines around a hit (INV-9).
const WindowMinutes = 60

// Personality is what a decoy looks like (contract.ts Personality).
type Personality string

// The personalities of INV-11.
const (
	WindowsFS Personality = "windows_fs"
	NAS       Personality = "nas"
	Printer   Personality = "printer"
	Camera    Personality = "camera"
	Linux     Personality = "linux"
)

// DecoyService is a service a personality shows.
type DecoyService struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

// Decoy is a decoy device (contract.ts Decoy).
type Decoy struct {
	ID          string         `json:"id"`
	Personality Personality    `json:"personality"`
	Name        string         `json:"name"`
	IP          string         `json:"ip"`
	Enabled     bool           `json:"enabled"`
	CreatedAt   string         `json:"created_at"`
	Services    []DecoyService `json:"services"`
}

// DecoySuggestion is a device type that exists in the inventory (INV-11).
type DecoySuggestion struct {
	Personality Personality `json:"personality"`
	Count       int         `json:"count"`
	Examples    []string    `json:"examples"`
}

// DecoysResponse is GET /honeypot/decoys.
type DecoysResponse struct {
	Items       []Decoy           `json:"items"`
	Suggestions []DecoySuggestion `json:"suggestions"`
	SpareIPs    []string          `json:"spare_ips"`
}

// DecoyInput is POST /honeypot/decoys.
type DecoyInput struct {
	Personality Personality `json:"personality"`
	Name        string      `json:"name"`
	IP          string      `json:"ip"`
}

// TokenType is the kind of a honey token.
type TokenType string

// The token types.
const (
	TokenFile       TokenType = "file"
	TokenCredential TokenType = "credential"
	TokenURL        TokenType = "url"
	TokenDNS        TokenType = "dns"
)

// Token is a honey token (contract.ts Token). Password is set only for a credential token (INV-10).
type Token struct {
	ID              string    `json:"id"`
	Type            TokenType `json:"type"`
	Name            string    `json:"name"`
	Value           string    `json:"value"`
	Password        *string   `json:"password"`
	PlantAt         string    `json:"plant_at"`
	CreatedAt       string    `json:"created_at"`
	LastTriggeredAt *string   `json:"last_triggered_at"`
	Triggers        int       `json:"triggers"`
}

// TokenInput is POST /honeypot/tokens.
type TokenInput struct {
	Type    TokenType `json:"type"`
	Name    string    `json:"name"`
	PlantAt string    `json:"plant_at"`
	Ext     string    `json:"ext,omitempty"`
}

// HitFilter selects hits. Asset is a device id (the sources whose IP the device has now).
type HitFilter struct{ Asset string }

// ---- ports ----

// Device is a device of the inventory as the module needs it. IP is the zero Addr when the device has none.
type Device struct {
	ID       string
	IP       netip.Addr
	Name     string // hostname, else the IP
	Hostname string // "" when none
	Kind     string
	OS       string
	Approved bool
	Ports    []int // ports seen listening
	IsBox    bool
}

// Box is the box itself; IP is the zero Addr when unknown.
type Box struct {
	IP   netip.Addr
	Name string
}

// Inventory is what the module reads of the inventory (cmd/vedette adapts inventory.Service; modules do not import each other).
type Inventory interface {
	Devices(ctx context.Context) ([]Device, error)
	LANRanges(ctx context.Context) ([]netip.Prefix, error)
	Box(ctx context.Context) (Box, error)
}

// HostStatus is what the host says about the decoy machinery. Available is false on a machine that is not an
// appliance (or while vedette-host cannot be reached); Reason then says why. Running means the container is up.
type HostStatus struct {
	Available bool
	Running   bool
	Reason    string
}

// Host is the module's only way to the OS (FORBID-3, SYS-1): decoy IPs (host-api 6.6) and the `honeypot` container
// (6.8, 6.9). Every call is idempotent.
type Host interface {
	Status(ctx context.Context) (HostStatus, error)
	AddDecoyIP(ctx context.Context, ip netip.Addr) error
	RemoveDecoyIP(ctx context.Context, ip netip.Addr) error
	StartContainer(ctx context.Context) error
	StopContainer(ctx context.Context) error // persist: the module is off or no trap is on
}

// LogEvent is a log line from another source around a hit.
type LogEvent struct {
	TS     time.Time
	Source string // honeypot | firewall | dhcp | ad | vedette
	Text   string
}

// Logs is the optional view of the logs module (S-LOG-1): the lines around a hit. nil means none.
type Logs interface {
	Around(ctx context.Context, at time.Time, window time.Duration, src netip.Addr) ([]LogEvent, error)
}

// Event is an event handed to the Publisher (name <module>.<object>.<verb>).
type Event struct {
	Name string
	Data any
}

// Publisher sends events on the bus, after the transaction committed.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// PublisherFunc adapts a function to Publisher.
type PublisherFunc func(ctx context.Context, e Event) error

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, e Event) error { return f(ctx, e) }

// ModuleGate says whether a module is on (modreg.Registry implements it).
type ModuleGate interface{ Enabled(id string) bool }

// EventHitCreated is the event of a real hit (POST-1). Test hits publish nothing (INV-4).
const EventHitCreated = "honeypot.hit.created"

// HitEventData is the data of EventHitCreated. Every text is cut to size and came from the network.
type HitEventData struct {
	ID      string  `json:"id"`
	TS      string  `json:"ts"`
	Kind    HitKind `json:"kind"`
	Service string  `json:"service"`
	Port    int     `json:"port"`
	SrcIP   string  `json:"src_ip"`
	Label   string  `json:"label"`
}
