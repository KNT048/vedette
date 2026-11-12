package logs

import (
	"context"
	"time"
)

// ModuleID is the id of the module in the registry and in core/jobs.
const ModuleID = "logs"

// Limits (CONTRACT, INV-1, INV-5; starting points to measure, ponytail).
const (
	// MaxLineBytes is the longest line kept: longer ones are cut on a character boundary (the listener, L2, already bounds
	// the wire at 8 KiB; this is the second bound on the consumer's side).
	MaxLineBytes = 2048
	// MaxBatch is the most lines one Ingest call takes (like the 500 items of the observation wire, D-112).
	MaxBatch = 500
	// MaxEventBytes is how many bytes of line text the module keeps at most, whatever the retention: the disk guard against a
	// flood. Ingest starts a purge when it is passed, and the purge goes down to 90% of it so a purge is not started by every
	// batch. The files are larger than this (row overhead and two indexes, about 1.6x).
	// ponytail: 4 GiB of line text, one constant; make it a setting only when a customer's disk asks for another number.
	MaxEventBytes = 4 << 30
	// maxIngestLineBytes is where a line is cut before it is sanitized: the sanitizer walks the whole string, and a line of
	// megabytes would be walked for 2,048 bytes of result.
	maxIngestLineBytes = 4 * MaxLineBytes
	// ExportMaxBytes caps what the device_logs export source writes: core caps the whole export at 128 MiB (D-132) and one
	// source must not use it all. A line is counted as 2 x its bytes + 128, which is an upper bound of what it writes: the JSON
	// object is {"id":"le-<up to 19 digits>","ts":<24>,"source_id":"ls-<26>"=29 characters,"line":"..."} plus a newline, a fixed
	// part of at most 118 bytes, and the line text, already sanitized (no control character but the tab), at most doubles when it
	// is written (a quote, a backslash and a tab become two bytes; the rest is written as it is: no HTML or \u escaping).
	ExportMaxBytes = 32 << 20
	// EventsPage is how many of the newest events GET /logs/events returns.
	EventsPage = 200
	// CountCap is where the "total" of a search stops counting (a count of millions would make every search slow).
	CountCap = 100_000
	// purgeChunk is how many rows one purge transaction deletes: the writer is free between two chunks.
	purgeChunk = 10_000
	// silentAfter is how long without a line before a source that has sent something shows as "silent".
	silentAfter = time.Hour
	// SearchTimeout bounds one search of the lines; MaxSearches is how many may run at once on a box. A search is a scan
	// (instr over the window), so a viewer typing in the box must not be able to occupy the database.
	SearchTimeout = 5 * time.Second
	MaxSearches   = 2
	// bucketSeconds is the width of a counter bucket.
	bucketSeconds = 300
)

// RetentionChoices are the allowed retention periods in days (INV-4); the default is 30.
var RetentionChoices = []int{7, 30, 90, 180}

// Input is what a source is created or edited with (SourceInput of contract.ts).
type Input struct {
	Kind     string
	Name     string
	SenderIP string
	Proto    string
	Port     int
}

// Source is a log source as the API shows it (LogSource of contract.ts).
type Source struct {
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	Name         string     `json:"name"`
	SenderIP     string     `json:"sender_ip"`
	AssetID      *string    `json:"asset_id"`
	AssetName    *string    `json:"asset_name"`
	Proto        string     `json:"proto"`
	Port         int        `json:"port"`
	LastReceived *time.Time `json:"last_received"`
	LinesPerHour int        `json:"lines_per_hour"`
	State        string     `json:"state"` // receiving | silent | never
	CreatedAt    time.Time  `json:"created_at"`
}

// BoxInfo says where the box listens (SourcesResponse.box).
type BoxInfo struct {
	IP       *string `json:"ip"` // nil when no LAN range is declared, or the box has no address in it (in a container it cannot see the host's)
	Hostname string  `json:"hostname"`
	LAN      *string `json:"lan"`
	Iface    string  `json:"iface"`
}

// SourcesView is the answer of GET /logs/sources.
type SourcesView struct {
	Box           BoxInfo  `json:"box"`
	Sources       []Source `json:"sources"`
	RetentionDays int      `json:"retention_days"`
}

// UnknownSender is a sender whose syslog was dropped because no source declares it with the protocol it used (UnknownSender of contract.ts).
type UnknownSender struct {
	IP       string    `json:"ip"`
	Proto    string    `json:"proto"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// UnknownSendersView is the answer of GET /logs/unknown-senders.
type UnknownSendersView struct {
	Items []UnknownSender `json:"items"`
}

// Event is one stored line as the API shows it (LogEvent).
type Event struct {
	ID         string    `json:"id"`
	TS         time.Time `json:"ts"`
	SourceID   string    `json:"source_id"`
	SourceName string    `json:"source_name"`
	Line       string    `json:"line"`
}

// EventQuery is GET /logs/events.
type EventQuery struct {
	Window string // 1h | 24h | 7d
	Source string // a source id, or empty
	Q      string // a keyword, matched in the line and in the source name
}

// EventsView is the answer of GET /logs/events.
type EventsView struct {
	Events []Event `json:"events"`
	Total  int     `json:"total"`
}

// NewItem is a kind of line a source had not sent before (NewItem of contract.ts).
type NewItem struct {
	ID         string    `json:"id"`
	Signature  string    `json:"signature"`
	SourceID   string    `json:"source_id"`
	SourceName string    `json:"source_name"`
	Count      int       `json:"count"`
	FirstSeen  time.Time `json:"first_seen"`
	Sample     string    `json:"sample"`
}

// SpikeItem is a kind of line that a source sent far more often than usual (SpikeItem of contract.ts).
type SpikeItem struct {
	ID             string  `json:"id"`
	Signature      string  `json:"signature"`
	SourceID       string  `json:"source_id"`
	SourceName     string  `json:"source_name"`
	Count          int     `json:"count"`
	BaselinePerDay float64 `json:"baseline_per_day"`
	Sample         string  `json:"sample"`
}

// Digest is the answer of GET /logs/digest. New and Spikes come from the signature counters (INV-6); BadConnections are the newest
// hits of the last 24 hours (iochits.go, INV-7), empty while the feeds module is off (PRE-3). IOCMatching is false when no connection can be
// matched at all: the feeds module is off, or no switched-on feed lists an indicator (every IOC feed off, or none loaded yet).
type Digest struct {
	GeneratedAt    time.Time   `json:"generated_at"`
	Lines24h       int         `json:"lines_24h"`
	BaselineDays   int         `json:"baseline_days"`
	HistoryDays    int         `json:"history_days"` // whole days of logs so far, at most BaselineDays (historyDays)
	New            []NewItem   `json:"new"`
	Spikes         []SpikeItem `json:"spikes"`
	BadConnections []IocHit    `json:"bad_connections"`
	IOCMatching    bool        `json:"ioc_matching"`
}

// Line is one received line handed to Ingest.
type Line struct {
	SourceID string    // a declared source (the listener resolves the sender address to it)
	At       time.Time // receive time; zero or in the future means now
	Text     string
}

// IngestResult says what Ingest did with a batch.
type IngestResult struct {
	Stored  int // lines stored
	Unknown int // lines of a source that is not declared (dropped)
}

// Device is an inventory device as the sources list names it.
type Device struct{ ID, Name string }

// Inventory is what logs reads from the inventory (Kien's): the device with a given IP, to name the sender of a source.
type Inventory interface {
	// DevicesByIP returns the devices with these IPv4 addresses; an address with no device is absent.
	DevicesByIP(ctx context.Context, ips []string) (map[string]Device, error)
}

// Box says where the box listens; nil Box in Config means "unknown" (the page then says no LAN range is declared).
type Box interface {
	Info(ctx context.Context) (BoxInfo, error)
}
