package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// DeviceFound is what one device check found, as stored with its job (sa_job.found, migration 0012): the words of its History row
// and of the device page's Last checks come from it. Only nmap's own result is kept (port numbers, nmap's service names, its OS
// guess), never a banner or a page title.
type DeviceFound struct {
	// Reach is how far the check looked: "top100" (the gentle scan), "top1000" (a normal or versions scan with the extra ports),
	// "extra" (only the extra ports answered), "all" (the weekly scan of every port). Ports are compared only within one reach.
	Reach    string      `json:"reach"`
	TimedOut bool        `json:"timed_out,omitempty"` // nmap reached its host timeout: no port table, what was known is kept
	Open     int         `json:"open"`                // open ports it found (Ports holds the first maxFoundPorts)
	Ports    []FoundPort `json:"ports,omitempty"`
	OS       string      `json:"os,omitempty"` // the OS it recorded (nmap's guess of 85 % or more, or the device's NTLM answer); "" when none
	// Compared: a previous check of the device with the same reach was there to compare the ports with (New, Gone).
	Compared bool  `json:"compared,omitempty"`
	New      []int `json:"new,omitempty"`  // TCP ports open now that the previous check of the same reach did not find
	Gone     []int `json:"gone,omitempty"` // TCP ports that check found and this one did not
	// OSWas is the previous OS guess when this check recorded another one; "" when it is the same, or when there is nothing to compare.
	OSWas string `json:"os_was,omitempty"`
}

// FoundPort is one open port of a check, with nmap's service name ("" when nmap named none).
type FoundPort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Name  string `json:"name,omitempty"`
}

const (
	maxFoundPorts = 64
	maxFoundDiff  = 32
)

// reachOf is the reach of a check that recorded as kind.
func reachOf(kind nmapargv.Kind) string {
	switch {
	case kind.IsGentle():
		return "top100"
	case kind == nmapargv.AllPorts:
		return "all"
	case kind == nmapargv.Extra:
		return "extra"
	default:
		return "top1000"
	}
}

// foundOf is what the check of h found, compared with the earlier checks of the device (newest first; prev): its ports with the
// newest one of the same reach, else, for a normal scan, with normalPorts (the TCP ports of the last normal scan, kept in sa_all_ports;
// nil when none); its OS guess with the newest one that recorded an OS.
func foundOf(h host, kind nmapargv.Kind, prev []DeviceFound, normalPorts []int) DeviceFound {
	f := DeviceFound{Reach: reachOf(kind), TimedOut: h.timedOut}
	for _, o := range deviceObservations(h, kind) {
		if o.Field == observe.OS {
			f.OS = o.Value
		}
	}
	if i := slices.IndexFunc(prev, func(p DeviceFound) bool { return p.OS != "" }); i >= 0 && f.OS != "" && prev[i].OS != f.OS {
		f.OSWas = prev[i].OS
	}
	if h.timedOut {
		return f
	}
	var tcp []int
	for _, s := range servicesOf(h) {
		f.Open++
		if len(f.Ports) < maxFoundPorts {
			f.Ports = append(f.Ports, FoundPort{Port: s.Port, Proto: s.Proto, Name: s.Name})
		}
		if s.Proto == "tcp" {
			tcp = append(tcp, s.Port)
		}
	}
	var before []int
	i := slices.IndexFunc(prev, func(p DeviceFound) bool { return p.Reach == f.Reach && !p.TimedOut })
	switch {
	case i >= 0 && prev[i].Open <= len(prev[i].Ports): // its whole list was kept
		f.Compared = true
		for _, p := range prev[i].Ports {
			if p.Proto == "tcp" {
				before = append(before, p.Port)
			}
		}
	case i < 0 && f.Reach == "top1000" && normalPorts != nil:
		f.Compared, before = true, normalPorts
	}
	if f.Compared {
		for _, p := range tcp {
			if !slices.Contains(before, p) && len(f.New) < maxFoundDiff {
				f.New = append(f.New, p)
			}
		}
		for _, p := range before {
			if !slices.Contains(tcp, p) && len(f.Gone) < maxFoundDiff {
				f.Gone = append(f.Gone, p)
			}
		}
		slices.Sort(f.New)
		slices.Sort(f.Gone)
	}
	return f
}

// startDeviceJob is startJob for the check of one device: the row names the device, so its runs stay its own when it changes
// address (the device page's Last checks), and its next check finds what this one found.
func (s *Service) startDeviceJob(ctx context.Context, reason, assetID string) (string, error) {
	return s.startJobOf(ctx, KindDevice, reason, 1, assetID)
}

// earlierFound is what the earlier checks of the device found (jobs other than jobID that stored it), newest first, at most
// earlierChecks of them.
func (s *Service) earlierFound(ctx context.Context, assetID, jobID string) ([]DeviceFound, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT found FROM sa_job WHERE asset_id = ? AND kind = ? AND id <> ? AND found IS NOT NULL
ORDER BY started_at DESC, rowid DESC LIMIT ?`, assetID, KindDevice, jobID, earlierChecks)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: reading the earlier checks of a device: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DeviceFound
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("sensoractive: reading the earlier checks of a device: %w", err)
		}
		var f DeviceFound
		if json.Unmarshal([]byte(raw), &f) == nil { // an unreadable row compares with nothing
			out = append(out, f)
		}
	}
	return out, rows.Err()
}

// earlierChecks is how many earlier checks of a device a new one is compared with (the newest of its reach, the newest with an OS).
const earlierChecks = 20

// normalPorts is the TCP ports of the device's last normal scan (sa_all_ports.normal_ports); nil when it has none.
func (s *Service) normalPorts(ctx context.Context, assetID string) []int {
	var raw string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT normal_ports FROM sa_all_ports WHERE asset_id = ?`, assetID).Scan(&raw); err != nil {
		return nil
	}
	var out []int
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	if out == nil {
		out = []int{}
	}
	return out
}

// saveFound stores what the check found with its job. A failure is logged: the result itself is recorded, only its words are lost.
func (s *Service) saveFound(ctx context.Context, jobID string, f DeviceFound) {
	b, err := json.Marshal(f)
	if err == nil && len(b) > 8000 {
		f.Ports = f.Ports[:min(len(f.Ports), 8)]
		b, err = json.Marshal(f)
	}
	if err == nil {
		err = s.db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE sa_job SET found = ? WHERE id = ?`, string(b), jobID)
			return err
		})
	}
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: keeping what a device check found failed", "job", jobID, "error", err)
	}
}

// beforeRecord is what recordDevice compares a check with, read before it records anything (the normal ports are replaced then).
func (s *Service) beforeRecord(ctx context.Context, assetID, jobID string, ip netip.Addr) ([]DeviceFound, []int) {
	prev, err := s.earlierFound(ctx, assetID, jobID)
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: the earlier checks of a device could not be read", "ip", ip.String(), "error", err)
	}
	return prev, s.normalPorts(ctx, assetID)
}
