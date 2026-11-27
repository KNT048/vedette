package findings

import (
	"fmt"
	"strings"
)

// The status model: one status per finding, computed here and nowhere else. An open finding's status is its urgency layer (the first
// five codes), a handled finding's is its resolution. A device's status (its badge) is the most urgent status of its open findings with
// the count of distinct CVEs at that status, else "needs your input" when only questions wait for a person, else none.

// CodePossible is the device status of a device whose only open items are possible findings (CVEs Vedette cannot decide).
const CodePossible = "possible"

// OpenCodes are the open statuses, the status of layer n at index n-1.
var OpenCodes = []string{CodeUnderAttack, CodeExploited, CodePublicExploit, CodeCriticalEdge, CodeUpdateRecommended}

// StatusOf is the one status of a finding: its urgency layer while open, its resolution once handled.
func StatusOf(f Finding) string {
	if f.State == StateOpen {
		return LayerCode(f.Urgency)
	}
	return string(f.Resolution)
}

// Status is the status of a view: the status every place shows for the finding.
func (v View) Status() string { return StatusOf(v.Finding) }

// layerOf is the urgency layer of an open status; false for any other word.
func layerOf(code string) (int, bool) {
	for i, c := range OpenCodes {
		if c == code {
			return i + 1, true
		}
	}
	return 0, false
}

// ErrBadFilter is a list filter with a word the list does not know.
var ErrBadFilter = &APIError{"bad_filter", 400, "The filter has a value the list does not know."}

// parseLayers reads a comma-separated list of open statuses into their layers; "" is no filter.
func parseLayers(s string) ([]int, error) {
	var out []int
	for _, w := range strings.Split(s, ",") {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		l, ok := layerOf(w)
		if !ok {
			return nil, fmt.Errorf("findings: status %q: %w", w, ErrBadFilter)
		}
		out = append(out, l)
	}
	return out, nil
}

// parseResolutions reads a comma-separated list of resolutions; "" is no filter.
func parseResolutions(s string) ([]Resolution, error) {
	var out []Resolution
	for _, w := range strings.Split(s, ",") {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		if r := Resolution(w); r.Valid() {
			out = append(out, r)
			continue
		}
		return nil, fmt.Errorf("findings: resolution %q: %w", w, ErrBadFilter)
	}
	return out, nil
}

// DeviceStatus is the badge of a device: a status code and its count (distinct CVEs at an open status; the possible CVEs for possible).
type DeviceStatus struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// DeviceCounts is what the status of one device is computed from: the distinct CVEs of its open findings at each layer (index 1..5)
// and its possible CVEs.
type DeviceCounts struct {
	CVEs     [UrgencyUpdate + 1]int
	Possible int
}

// DeviceStatusOf is the one rule of a device's badge: the most urgent layer of its open findings with the distinct CVEs at it, else
// possible with its possible CVEs when only those wait, else nil. The Devices list, the device page and Home read it.
func DeviceStatusOf(c DeviceCounts) *DeviceStatus {
	for l := UrgencyUnderAttack; l <= UrgencyUpdate; l++ {
		if c.CVEs[l] > 0 {
			return &DeviceStatus{Code: LayerCode(l), Count: c.CVEs[l]}
		}
	}
	if c.Possible > 0 {
		return &DeviceStatus{Code: CodePossible, Count: c.Possible}
	}
	return nil
}

// statusRank orders device statuses most urgent first (an unknown code, and none, last).
func statusRank(s *DeviceStatus) int {
	if s == nil {
		return 9
	}
	if l, ok := layerOf(s.Code); ok {
		return l
	}
	return UrgencyUpdate + 1
}

// SeverityBand is the band of a CVSS base score: FIRST's table for 3.x and 4.0 (critical from 9.0), NVD's table for 2.0 (no critical);
// "none" for a score of 0.
func SeverityBand(c CVSS) string {
	switch {
	case c.Score >= 9 && c.Version != "2.0":
		return "critical"
	case c.Score >= 7:
		return "high"
	case c.Score >= 4:
		return "medium"
	case c.Score > 0:
		return "low"
	}
	return "none"
}

// bandRank orders bands most severe first, no score last.
func bandRank(c *CVSS) int {
	if c == nil {
		return 6
	}
	switch SeverityBand(*c) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	}
	return 5
}
