package notify

import (
	"fmt"
	"testing"
)

// Home's headline of a first look told in several summaries reads back how many findings on how many devices each summary's title
// counts (summaryCounts). The titles are what summaryNotice writes: a change of their words that the reader does not follow fails here,
// not on a customer's Home (the findings a summary counts without listing them would silently drop out of the headline).
func TestSummaryCountsReadsBackEveryTitleSummaryNoticeWrites(t *testing.T) {
	s := &Service{}
	for _, prior := range []string{"", "the previous summary"} {
		for _, c := range []struct{ listed, unlisted, devices int }{{1, 0, 1}, {1, 2, 2}, {3, 0, 2}, {2, 148, 37}} {
			keep := make([]string, c.listed)
			infos := map[string]FindingInfo{}
			for i := range keep {
				keep[i] = fmt.Sprintf("f-%d", i)
				infos[keep[i]] = FindingInfo{CVE: fmt.Sprintf("CVE-2026-%04d", i), Layer: 2, Open: true, Devices: []string{"web-01"}}
			}
			n := s.summaryNotice("install", keep, infos, c.unlisted, c.devices, 2, prior)
			found, devices, ok := summaryCounts(n.Title)
			wantDevices := c.devices
			if c.unlisted == 0 {
				wantDevices = 1 // every listed finding is on web-01
			}
			if !ok || found != c.listed+c.unlisted || devices != wantDevices {
				t.Errorf("summaryCounts(%q) = %d, %d, %v; want %d, %d, true", n.Title, found, devices, ok, c.listed+c.unlisted, wantDevices)
			}
		}
	}
}
