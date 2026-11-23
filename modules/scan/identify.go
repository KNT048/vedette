package scan

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// Identifier identifies a device before a Scan now run checks it: sensor-active's nmap device scan records what it finds
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
// was. The note is the backend's words; the GUI shows it as is.
type IdentRow struct {
	TargetID string   `json:"target_id"`
	Label    string   `json:"label"`
	IP       string   `json:"ip"`
	Found    []string `json:"found"`
	Reason   *string  `json:"reason"` // nil: software was recorded
	Note     string   `json:"note"`
}

// OSPages is the OS each device page shows now (the inventory's ranking, through cmd/vedette). Absent from the map: no device page.
type OSPages interface {
	OSShown(ctx context.Context, ids []string) (map[string]string, error)
}

// osLine starts the identification line of the OS a device check recorded (sensor-active `identified`).
const osLine = "Operating system: "

// osNotUsed replaces an OS line whose OS is not the one the device page shows now (a better source, or a newer scan's guess).
const osNotUsed = osLine + "scan guess not used now"

// withShownOS keeps each identification row's OS line only when it names the OS its device page shows now: otherwise it says the
// scan guess is not used, never a second OS value beside the page's. A failed read is logged and drops the OS lines (the list still
// answers). Without OSPages the rows stay as recorded.
func (s *Service) withShownOS(ctx context.Context, runs []RunView) {
	if s.cfg.OSPages == nil {
		return
	}
	var ids []string
	for _, v := range runs {
		for _, r := range v.Identification {
			if slices.ContainsFunc(r.Found, func(l string) bool { return strings.HasPrefix(l, osLine) }) && !slices.Contains(ids, r.TargetID) {
				ids = append(ids, r.TargetID)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	shown, err := s.cfg.OSPages.OSShown(ctx, ids)
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "scan: the OS the device pages show could not be read; identification rows are listed without their OS", "error", err)
	}
	for _, v := range runs {
		for i := range v.Identification {
			r := &v.Identification[i]
			out := r.Found[:0:0]
			for _, l := range r.Found {
				recorded, isOS := strings.CutPrefix(l, osLine)
				page, known := shown[r.TargetID]
				switch {
				case !isOS:
				case err != nil:
					continue
				case known && page != recorded:
					l = osNotUsed
				}
				out = append(out, l)
			}
			r.Found = out
		}
	}
}

// maxFoundLines bounds IdentRow.Found (contract.ts: at most 20).
const maxFoundLines = 20

// identNote is the note of each reason (contract.ts IdentReason), and of a device that was identified ("").
var identNote = map[string]string{
	"":                    "Recorded on the device page. Software with a version is compared with the CISA list of exploited flaws; an operating system nmap only guessed is not, until you add it with its version there.",
	"os_unconfirmed":      "nmap only guessed the operating system and no service gave a version, so nothing is compared with the CISA list yet: a guess would flag every flaw of that system. Add the operating system and its version on the device page to check it.",
	"os_no_patch_level":   "The device named its Windows release and build (shown above) but not its monthly update level, so nothing is compared with the CISA list yet: that would flag every flaw fixed since that release. On the device page, add the system it runs, Windows or Windows Server (winver on the device shows which), with its full version, for example 10.0.17763.6532; or install the osquery agent on it.",
	"host_down":           "Did not answer: it may be switched off, asleep (phones often are) or off the network. Scan it again while it is in use.",
	"no_open_ports":       "Answered, but every port tried was closed, so no service could be identified. Add its software on the device page, or install the osquery agent on it.",
	"filtered":            "Answered, but no port it was asked about answered back: the device or a firewall dropped or slowed the probes, so the scan is incomplete and nothing could be identified. Scan it again later; if it stays like this, add its software on the device page or install the osquery agent on it.",
	"no_version":          "Has open ports, but no service gave its product or version and the operating system could not be told, so there is nothing to compare. Add its software and version on the device page.",
	"os_low_confidence":   "No service gave its product or version, and the operating system guess was less than 85% sure, so it was not recorded. Add the operating system and its version on the device page.",
	"gentle_only":         "Fragile device: only a gentle port scan ran, without version or operating system detection, so no software was recorded. Add its software on the device page, or allow regular scans for it there.",
	"timed_out":           "Scan incomplete: nmap gave up before it finished (the device or a firewall slowed the probes), so nothing new was recorded. Scan it again later.",
	"busy":                "Another network scan was running at that moment (device discovery, or a scan of your public IP under Exposure; a deep one takes up to an hour), so this device was not identified in this scan. Scan it again once it has finished.",
	"unavailable":         "The network scanner (nmap in the scan container, Active discovery) is not available, so this device was not identified. Check the box's services and that Active discovery is on, then scan again.",
	"declared_by_hand":    "Added by hand, with its network scan off: not scanned. The software you entered is what is checked; turn its network scan on on its page (Sources) to scan it.",
	"scanning_off":        "Active scanning is off under Settings › Scanning › Engines, so this device was not identified. Only what was already known was checked.",
	"not_approved":        "Not approved in the inventory: not scanned, so not identified.",
	"out_of_scope":        "Outside the confirmed scope now: not scanned, so not identified.",
	"scope_not_confirmed": "The scan scope commitment is not ticked under Settings › Scanning › Safety: not scanned, so not identified.",
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

// identify runs the identification of d for a Scan now run. end is "" to check the device, "stopped" when the run's Stop now
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
