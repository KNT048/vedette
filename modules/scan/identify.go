package scan

import (
	"context"
	"errors"
)

// Identifier identifies a device before a Scan now run checks it (D-501): sensor-active's nmap device scan records what it finds
// (type, operating system, software with its CPE) in the inventory, and the findings module matches that before plan reads the
// device's findings. Without it a device known only by its address has no software, so nothing to check. cmd/vedette wires
// sensor-active; nil: no identification, and each device of a Scan now run says so (reason unavailable).
type Identifier interface {
	// Identify returns what was recorded about the device, or why nothing was. ErrIdentifyStopped (wrapped or not) says the run
	// stopped it; any other error is a failure of the scanner or of storage.
	Identify(ctx context.Context, assetID string) (Identification, error)
}

// Identification is what Identify found: Found in words, Why the reason no software was recorded ("" when some was): one of the
// IdentReason values, or an inventory refusal reason that identReason folds.
type Identification struct {
	Found []string
	Why   string
}

// ErrIdentifyStopped is the error of an identification the run's Stop now (or its end) cut short.
var ErrIdentifyStopped = errors.New("scan: the identification was stopped")

// ErrIdentifyInterrupted is the error of an identification sensor-active stopped by itself while the run goes on: the device, the
// discovery settings (rate, scope) or the module changed. That device is not checked in this run; the next one is (review M2).
var ErrIdentifyInterrupted = errors.New("scan: the identification was interrupted by a change")

// IdentRow is contract.ts RunIdentRow: per device of a Scan now run, what the identification recorded, or exactly why nothing
// was (D-501). The note is the backend's words; the GUI shows it as is.
type IdentRow struct {
	TargetID string   `json:"target_id"`
	Label    string   `json:"label"`
	IP       string   `json:"ip"`
	Found    []string `json:"found"`
	Reason   *string  `json:"reason"` // nil: software was recorded
	Note     string   `json:"note"`
}

// maxFoundLines bounds IdentRow.Found (contract.ts: at most 20).
const maxFoundLines = 20

// identNote is the note of each reason (contract.ts IdentReason), and of a device that was identified ("").
var identNote = map[string]string{
	"":                    "Recorded on the device page. Software with a version is compared with the CISA list of exploited flaws; an operating system nmap only guessed is not, until you add it with its version there.",
	"os_unconfirmed":      "nmap only guessed the operating system and no service gave a version, so nothing is compared with the CISA list yet: a guess would flag every flaw of that system. Add the operating system and its version on the device page to check it.",
	"host_down":           "Did not answer: it may be switched off, asleep (phones often are) or off the network. Scan it again while it is in use.",
	"no_open_ports":       "Answered, but every port tried was closed, so no service could be identified. Add its software on the device page, or install the osquery agent on it.",
	"filtered":            "Answered, but a firewall dropped the probes (every port tried was filtered), so nothing could be identified. Add its software on the device page, or install the osquery agent on it.",
	"no_version":          "Has open ports, but no service gave its product or version and the operating system could not be told, so there is nothing to compare. Add its software and version on the device page.",
	"os_low_confidence":   "No service gave its product or version, and the operating system guess was less than 85% sure, so it was not recorded. Add the operating system and its version on the device page.",
	"gentle_only":         "Fragile device: only a gentle port scan ran, without version or operating system detection, so no software was recorded. Add its software on the device page, or allow regular scans for it there.",
	"timed_out":           "The identification scan ran out of time before it finished, so nothing new was recorded. Scan it again later.",
	"busy":                "Device discovery was scanning at that moment, so this device was not identified in this scan. Scan it again in a few minutes.",
	"unavailable":         "The network scanner (nmap in the scan container, Active discovery) is not available, so this device was not identified. Check the box's services and that Active discovery is on, then scan again.",
	"declared_by_hand":    "Added by hand: Vedette does not port-scan it. The software you entered is what was checked.",
	"scanning_off":        "Active scanning is off under Devices, Scope and sensors, so this device was not identified. Only what was already known was checked.",
	"not_approved":        "Not approved in the inventory: not scanned, so not identified.",
	"out_of_scope":        "Outside the confirmed scope now: not scanned, so not identified.",
	"scope_not_confirmed": "The scan scope commitment is not ticked under Devices, Scope and sensors: not scanned, so not identified.",
	"box":                 "This address is the Vedette box itself or one of its decoys: it is never scanned.",
	"regular_scan_never":  "Set to never be scanned on its device page: not identified. Change that setting to identify it.",
	"no_ip":               "No IP address is known for this device, so it could not be scanned or identified.",
	"not_scanned":         "Not scanned in this run, so not identified.",
}

// identReason folds a reason of sensor-active or of the scan's own checks (consent, skipNote) into contract.ts IdentReason.
func identReason(why string) string {
	switch why {
	case "unapproved":
		return "not_approved"
	case reasonOutOfScope, "excluded", "moved":
		return "out_of_scope"
	}
	if _, ok := identNote[why]; ok {
		return why
	}
	return "not_scanned"
}

// noteIdentStopped is the note of a device whose identification Stop now cut short; noteIdentInterrupted of one sensor-active
// stopped by itself (ErrIdentifyInterrupted).
const (
	noteIdentStopped     = "Stopped while this device was being identified: nothing new was recorded."
	noteIdentInterrupted = "The device, the discovery settings or Active discovery changed while it was being identified, so it was stopped and this device was not checked in this scan. Scan it again."
)

// identRow is the row of d for a reason ("" when software was recorded).
func identRow(d Device, found []string, why string) IdentRow {
	r := IdentRow{TargetID: d.ID, Label: orDash(d.Label), IP: orDash(d.IP), Found: []string{}}
	for _, f := range found {
		if len(r.Found) < maxFoundLines {
			r.Found = append(r.Found, clip(f, 300))
		}
	}
	if why == "" {
		r.Note = identNote[""]
		return r
	}
	reason := identReason(why)
	r.Reason, r.Note = &reason, identNote[reason]
	return r
}

// skippedRow is the row of a device the run did not scan: it keeps the note of its result row (skipNote), so the two say the same.
func skippedRow(d Device, why string) IdentRow {
	r := identRow(d, nil, why)
	if n := skipNote[why]; n != "" {
		r.Note = n
	}
	return r
}

// identify runs the identification of d for a Scan now run (D-501). end is "" to check the device, "stopped" when the run's Stop now
// cut it short (the run then stops as during a nuclei job), "skip" when sensor-active stopped it by itself (the device is not checked,
// the run goes on, review M2). A failure is logged and said as unavailable: the check of what is known goes on. busy is the run's:
// once discovery was busy, the rest of the run says busy at once instead of waiting for it device by device (review M3).
func (s *Service) identify(ctx context.Context, d Device, busy *bool) (row IdentRow, end string) {
	if s.cfg.Identify == nil {
		return identRow(d, nil, "unavailable"), ""
	}
	if busy != nil && *busy {
		return identRow(d, nil, "busy"), ""
	}
	got, err := s.cfg.Identify.Identify(ctx, d.ID)
	switch {
	case ctx.Err() != nil || errors.Is(err, ErrIdentifyStopped):
		r := identRow(d, nil, "not_scanned")
		r.Note = noteIdentStopped
		return r, "stopped"
	case errors.Is(err, ErrIdentifyInterrupted):
		r := identRow(d, nil, "not_scanned")
		r.Note = noteIdentInterrupted
		return r, "skip"
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "scan: identifying a device failed", "asset", d.ID, "error", err)
		return identRow(d, nil, "unavailable"), ""
	}
	if got.Why == "busy" && busy != nil {
		*busy = true
	}
	return identRow(d, got.Found, got.Why), ""
}
