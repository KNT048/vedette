package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/run"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// DeviceFound is what one device check found, as stored with its run (items: foundItems): the words of its History row
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
	New          []int `json:"new,omitempty"` // TCP ports open now that the previous check of the same reach did not find
	// Gone are the TCP ports that check found open and that refused the connection this time (host.answer): closed.
	Gone []int `json:"gone,omitempty"`
	// NoAnswer are the TCP ports that check found open and that sent nothing back this time: a firewall that drops probes and a device
	// or link that rate-limits them look the same, so the check is incomplete for them and what was known about them is kept.
	NoAnswer []int `json:"no_answer,omitempty"`
	// Dropped are the TCP ports the previous check already kept as NoAnswer and that sent nothing back again: two misses in a row
	// take a port off the device's list (the public scan's rule too).
	Dropped []int `json:"dropped,omitempty"`
	// NoPortAnswered: the device was up but no port it was asked about answered (host.noPortAnswered): the check is incomplete.
	NoPortAnswered bool `json:"no_port_answered,omitempty"`
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
	f := DeviceFound{Reach: reachOf(kind), TimedOut: h.timedOut, ExtraFailed: extraFailed && reachOf(kind) == "top1000", NoPortAnswered: h.noPortAnswered()}
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
	// before: the ports open at that check, and the ones it kept after they gave no answer (still on the device's list)
	var before []int
	for _, p := range prev[i].Ports {
		if p.Proto == "tcp" {
			before = append(before, p.Port)
		}
	}
	before = unionPorts(before, prev[i].NoAnswer)
	f.Compared, f.ComparedPart = true, f.ExtraFailed || prev[i].ExtraFailed
	for _, p := range tcp {
		if covered(p) && !slices.Contains(before, p) && len(f.New) < maxFoundDiff {
			f.New = append(f.New, p)
		}
	}
	for _, p := range before {
		if !covered(p) || slices.Contains(tcp, p) {
			continue
		}
		// host.answer is the one rule: closed only when the device refused the connection; nothing back is not a closed port
		switch h.answer(p) {
		case answeredClosed:
			f.Gone = appendCapped(f.Gone, p)
		case noAnswer:
			if slices.Contains(prev[i].NoAnswer, p) {
				f.Dropped = appendCapped(f.Dropped, p)
			} else {
				// not capped: recordHost keeps these out of the replace scope, and a port left off would be removed as if closed. The
				// list stays bounded: a port kept once is dropped or open at the next check, so it holds ports open at the previous one
				f.NoAnswer = append(f.NoAnswer, p)
			}
		}
	}
	for _, l := range [][]int{f.New, f.Gone, f.NoAnswer, f.Dropped} {
		slices.Sort(l)
	}
	return f
}

func appendCapped(l []int, p int) []int {
	if len(l) < maxFoundDiff {
		return append(l, p)
	}
	return l
}

// What a check found is kept as items of its run (core_run_item), not as a blob: one item for the check (its reach and how complete
// it was, as a code of checkCodes), one per open port (the first maxFoundPorts; "more" when there were others), one per port open before
// that closed, gave no answer or gave no answer twice, one for the OS it recorded, and one saying it was compared with an earlier check. The run page lists them as they
// are; loadFound reads them back for the words of the history and for the next check's comparison.

const (
	itemCheck   = "check"   // label: the device's address; outcome: a checkCodes code
	itemPort    = "port"    // label: "22/tcp ssh"; outcome: open | new (open, and not before) | gone | no_answer | dropped | more
	itemOS      = "os"      // label: the OS; outcome: recorded | changed (and then an item "before": the OS of the previous check)
	itemCompare = "compare" // label: "the previous check"; outcome: compared | compared_part
)

// checkCodes maps a check's reach and flags to the outcome of its check item, and back.
var checkCodes = func() map[string]DeviceFound {
	m := map[string]DeviceFound{}
	for _, reach := range []string{"top100", "top1000", "extra", "all"} {
		for _, part := range []bool{false, true} {
			for _, to := range []bool{false, true} {
				for _, quiet := range []bool{false, true} {
					f := DeviceFound{Reach: reach, ExtraFailed: part, TimedOut: to, NoPortAnswered: quiet && !to}
					m[checkCode(f)] = f
				}
			}
		}
	}
	return m
}()

func checkCode(f DeviceFound) string {
	c := f.Reach
	if f.ExtraFailed {
		c += "_part"
	}
	if f.TimedOut {
		c += "_timeout"
	}
	if f.NoPortAnswered {
		c += "_no_answer"
	}
	return c
}

// foundItems is f as the items of its run.
func foundItems(assetID string, ip netip.Addr, f DeviceFound) []run.Item {
	its := []run.Item{{SubjectKind: itemCheck, SubjectID: assetID, Label: ip.String(), Outcome: checkCode(f)}}
	for _, p := range f.Ports {
		out := "open"
		if p.Proto == "tcp" && slices.Contains(f.New, p.Port) {
			out = "new"
		}
		its = append(its, run.Item{SubjectKind: itemPort, Label: portLabel(p), Outcome: out})
	}
	if f.Open > len(f.Ports) {
		its = append(its, run.Item{SubjectKind: itemPort, Label: fmt.Sprintf("%d more open ports", f.Open-len(f.Ports)), Outcome: "more"})
	}
	for _, l := range []struct {
		ports []int
		out   string
	}{{f.Gone, "gone"}, {f.NoAnswer, "no_answer"}, {f.Dropped, "dropped"}} {
		for _, p := range l.ports {
			its = append(its, run.Item{SubjectKind: itemPort, Label: strconv.Itoa(p) + "/tcp", Outcome: l.out})
		}
	}
	if f.OS != "" {
		if f.OSWas == "" {
			its = append(its, run.Item{SubjectKind: itemOS, Label: f.OS, Outcome: "recorded"})
		} else {
			its = append(its, run.Item{SubjectKind: itemOS, Label: f.OS, Outcome: "changed"}, run.Item{SubjectKind: itemOS, Label: f.OSWas, Outcome: "before"})
		}
	}
	if f.Compared {
		c := run.Item{SubjectKind: itemCompare, Label: "the previous check", Outcome: "compared"}
		if f.ComparedPart {
			c.Outcome = "compared_part"
		}
		its = append(its, c)
	}
	return its
}

func portLabel(p FoundPort) string {
	l := strconv.Itoa(p.Port) + "/" + p.Proto
	if p.Name != "" {
		l += " " + p.Name
	}
	return l
}

// loadFound reads back what the check of run id found; false when it stored nothing (it did not finish, or the device did not answer).
func (s *Service) loadFound(ctx context.Context, id string) (DeviceFound, bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT subject_kind, label, outcome FROM core_run_item WHERE run_id = ? ORDER BY seq`, id)
	if err != nil {
		return DeviceFound{}, false, fmt.Errorf("sensoractive: reading what a check found: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var f DeviceFound
	ok := false
	for rows.Next() {
		var kind, lbl, out string
		if err := rows.Scan(&kind, &lbl, &out); err != nil {
			return DeviceFound{}, false, fmt.Errorf("sensoractive: reading what a check found: %w", err)
		}
		switch kind {
		case itemCheck:
			c, known := checkCodes[out]
			if !known {
				continue
			}
			f.Reach, f.ExtraFailed, f.TimedOut, f.NoPortAnswered, ok = c.Reach, c.ExtraFailed, c.TimedOut, c.NoPortAnswered, true
		case itemPort:
			switch out {
			case "open", "new":
				if p, good := parsePortLabel(lbl); good {
					f.Ports = append(f.Ports, p)
					f.Open++
					if out == "new" {
						f.New = append(f.New, p.Port)
					}
				}
			case "more":
				f.Open++ // its list was not kept whole: a later check is not compared with it
			case "gone", "no_answer", "dropped":
				if p, good := parsePortLabel(lbl); good {
					switch out {
					case "gone":
						f.Gone = append(f.Gone, p.Port)
					case "no_answer":
						f.NoAnswer = append(f.NoAnswer, p.Port)
					default:
						f.Dropped = append(f.Dropped, p.Port)
					}
				}
			}
		case itemOS:
			if out == "before" {
				f.OSWas = lbl
			} else {
				f.OS = lbl
			}
		case itemCompare:
			f.Compared, f.ComparedPart = true, out == "compared_part"
		}
	}
	return f, ok, rows.Err()
}

// parsePortLabel reads a label foundItems wrote: "22/tcp" and the service name after a space.
func parsePortLabel(l string) (FoundPort, bool) {
	head, name, _ := strings.Cut(l, " ")
	num, proto, ok := strings.Cut(head, "/")
	n, err := strconv.Atoi(num)
	if !ok || err != nil || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") {
		return FoundPort{}, false
	}
	return FoundPort{Port: n, Proto: proto, Name: name}, true
}

// earlierFound is what the earlier checks of the device found (runs other than runID), newest first, at most earlierChecks of them.
func (s *Service) earlierFound(ctx context.Context, assetID, runID string) ([]DeviceFound, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM core_run WHERE module = ? AND kind IN (?, ?) AND subject_kind = 'device' AND subject_id = ?
		AND id <> ? ORDER BY queued_at DESC, rowid DESC LIMIT ?`, ModuleID, RunCheck, RunAllPorts, assetID, runID, earlierChecks)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: reading the earlier checks of a device: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("sensoractive: reading the earlier checks of a device: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var out []DeviceFound
	for _, id := range ids {
		if f, ok, err := s.loadFound(ctx, id); err != nil {
			return nil, err
		} else if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// earlierChecks is how many earlier checks of a device a new one is compared with (the newest of its reach, the newest with an OS).
const earlierChecks = 20

// saveFound records what the check found as items of its run. A failure is logged: the result itself is recorded, only its words
// are lost.
func (s *Service) saveFound(ctx context.Context, assetID string, ip netip.Addr, f DeviceFound) {
	x := execOf(ctx)
	if x == nil {
		return
	}
	if err := x.AddItems(context.WithoutCancel(ctx), foundItems(assetID, ip, f)...); err != nil && !errors.Is(err, run.ErrNotLive) {
		s.log.WarnContext(ctx, "sensoractive: keeping what a device check found failed", "run", x.ID(), "error", err)
	}
}

// beforeRecord is what recordDevice compares a check with: the device's earlier checks, read before it records anything.
func (s *Service) beforeRecord(ctx context.Context, assetID, runID string, ip netip.Addr) []DeviceFound {
	prev, err := s.earlierFound(ctx, assetID, runID)
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: the earlier checks of a device could not be read", "ip", ip.String(), "error", err)
	}
	return prev
}
