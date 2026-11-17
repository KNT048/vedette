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
	Reach    string `json:"reach"`
	TimedOut bool   `json:"timed_out,omitempty"` // nmap reached its host timeout: no port table, what was known is kept
	// ExtraFailed: a top1000 check whose run over the extra ports (nmapargv.ExtraPorts) did not finish, so it covered nmap's top
	// 1000 only. Its ports are compared, and compared with, only outside the extra ports, and its OS guess (an NTLM answer may come
	// from that run) is never compared.
	ExtraFailed bool        `json:"extra_failed,omitempty"`
	Open        int         `json:"open"` // open ports it found (Ports holds the first maxFoundPorts)
	Ports       []FoundPort `json:"ports,omitempty"`
	OS          string      `json:"os,omitempty"` // the OS it recorded (nmap's guess of 85 % or more, or the device's NTLM answer); "" when none
	// Compared: a previous check of the device with the same reach was there to compare the ports with (New, Gone).
	Compared bool `json:"compared,omitempty"`
	// ComparedPart: one of the two checks had ExtraFailed, so the extra ports were left out of the comparison.
	ComparedPart bool  `json:"compared_part,omitempty"`
	New          []int `json:"new,omitempty"`  // TCP ports open now that the previous check of the same reach did not find
	Gone         []int `json:"gone,omitempty"` // TCP ports that check found and this one did not
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

// foundOf is what the check of h found (extraFailed: its run over the extra ports did not finish), compared with the earlier checks
// of the device (newest first; prev): its ports with the newest one of the same reach that kept its whole list, only over the ports
// both covered; its OS guess with the newest one that recorded an OS, when both are complete top1000 checks. With no earlier check
// to compare with, it says what it found and nothing about a change.
func foundOf(h host, kind nmapargv.Kind, extraFailed bool, prev []DeviceFound) DeviceFound {
	f := DeviceFound{Reach: reachOf(kind), TimedOut: h.timedOut, ExtraFailed: extraFailed && reachOf(kind) == "top1000"}
	for _, o := range deviceObservations(h, kind) {
		if o.Field == observe.OS {
			f.OS = o.Value
		}
	}
	full := func(p DeviceFound) bool { return p.Reach == "top1000" && !p.ExtraFailed }
	if i := slices.IndexFunc(prev, func(p DeviceFound) bool { return p.OS != "" }); i >= 0 && f.OS != "" && prev[i].OS != f.OS && full(f) && full(prev[i]) {
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
	i := slices.IndexFunc(prev, func(p DeviceFound) bool { return p.Reach == f.Reach && !p.TimedOut })
	if i < 0 || prev[i].Open > len(prev[i].Ports) { // no earlier check of this reach, or its list was not kept whole
		return f
	}
	// A check whose extra ports did not finish covered nmap's top 1000 only: a port of the extra list says nothing either way.
	// nmap's top 1000 is not known here, so every extra port is left out, the ones inside the top 1000 too.
	covered := func(p int) bool {
		part := f.ExtraFailed || prev[i].ExtraFailed
		return !part || !slices.Contains(nmapargv.ExtraPortNumbers, p)
	}
	var before []int
	for _, p := range prev[i].Ports {
		if p.Proto == "tcp" {
			before = append(before, p.Port)
		}
	}
	f.Compared, f.ComparedPart = true, f.ExtraFailed || prev[i].ExtraFailed
	for _, p := range tcp {
		if covered(p) && !slices.Contains(before, p) && len(f.New) < maxFoundDiff {
			f.New = append(f.New, p)
		}
	}
	for _, p := range before {
		if covered(p) && !slices.Contains(tcp, p) && len(f.Gone) < maxFoundDiff {
			f.Gone = append(f.Gone, p)
		}
	}
	slices.Sort(f.New)
	slices.Sort(f.Gone)
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

// beforeRecord is what recordDevice compares a check with: the device's earlier checks, read before it records anything.
func (s *Service) beforeRecord(ctx context.Context, assetID, jobID string, ip netip.Addr) []DeviceFound {
	prev, err := s.earlierFound(ctx, assetID, jobID)
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: the earlier checks of a device could not be read", "ip", ip.String(), "error", err)
	}
	return prev
}
