package orgtime

import (
	"maps"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestCanonicalZoneWritesAnAliasUnderItsCurrentName(t *testing.T) {
	for in, want := range map[string]string{
		"Asia/Saigon": "Asia/Ho_Chi_Minh", "Asia/Calcutta": "Asia/Kolkata", "Europe/Kiev": "Europe/Kyiv", "US/Eastern": "America/New_York",
		"America/Buenos_Aires": "America/Argentina/Buenos_Aires", "Asia/Ho_Chi_Minh": "Asia/Ho_Chi_Minh", "UTC": "UTC", "Europe/Berlin": "Europe/Berlin",
		"": "", "Mars/Olympus": "Mars/Olympus",
	} {
		if got := CanonicalZone(in); got != want {
			t.Errorf("CanonicalZone(%q) = %q, want %q", in, got, want)
		}
	}
	// Every alias and every target is a zone Go knows, the target is no alias itself, and both read the same offsets.
	at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	for alias, target := range backwardZones {
		a, errA := time.LoadLocation(alias)
		z, errZ := time.LoadLocation(target)
		if errA != nil || errZ != nil {
			t.Errorf("%s -> %s: %v %v", alias, target, errA, errZ)
			continue
		}
		if _, again := backwardZones[target]; again {
			t.Errorf("%s -> %s, itself an alias", alias, target)
		}
		_, oa := at.In(a).Zone()
		_, oz := at.In(z).Zone()
		if oa != oz {
			t.Errorf("%s and %s differ now: %d vs %d", alias, target, oa, oz)
		}
	}
}

// The web writes a browser's alias under the same current name before it shows or sends it (web/src/lib/zoneNames.ts): the two lists
// are the same.
func TestTheWebKnowsTheSameAliases(t *testing.T) {
	raw, err := os.ReadFile("../../web/src/lib/zoneNames.ts")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`^  '([^']+)': '([^']+)',$`)
	web := map[string]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		if m := line.FindStringSubmatch(l); m != nil {
			web[m[1]] = m[2]
		}
	}
	if !maps.Equal(web, backwardZones) {
		t.Fatalf("web/src/lib/zoneNames.ts has %d aliases, core/orgtime %d: keep them equal", len(web), len(backwardZones))
	}
}
