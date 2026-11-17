package scan

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"testing"
)

type fakeOSPages struct {
	shown map[string]string
	err   error
}

func (f fakeOSPages) OSShown(context.Context, []string) (map[string]string, error) {
	return f.shown, f.err
}

// A Scan now identification row names the OS it recorded only when it is the one its device page shows now: a better source, or a
// newer scan's guess, makes the line "scan guess not used now" (never a second OS value); a device with no page keeps its line; a
// failed read drops the OS lines and the list still answers; the other lines never change.
func TestIdentificationRowsNameOnlyTheOSThePageShows(t *testing.T) {
	t.Parallel()
	runs := func() []RunView {
		return []RunView{{Identification: []IdentRow{
			{TargetID: "a-same", Found: []string{"Type: switch", "Operating system: NetOS (12)"}},
			{TargetID: "a-better", Found: []string{"Type: switch", "Operating system: NetOS (8.5 - 11.2)", "Software: OpenSSH 6.9"}},
			{TargetID: "a-gone", Found: []string{"Operating system: Linux 5.4 - 5.15"}},
		}}}
	}
	pages := map[string]string{"a-same": "NetOS (12)", "a-better": "NetOS 15.1R7.9"}
	s := &Service{cfg: Config{OSPages: fakeOSPages{shown: pages}, Log: slog.New(slog.DiscardHandler)}}
	got := runs()
	s.withShownOS(t.Context(), got)
	want := [][]string{
		{"Type: switch", "Operating system: NetOS (12)"},
		{"Type: switch", "Operating system: scan guess not used now", "Software: OpenSSH 6.9"},
		{"Operating system: Linux 5.4 - 5.15"},
	}
	for i, r := range got[0].Identification {
		if !slices.Equal(r.Found, want[i]) {
			t.Errorf("%s: %q, want %q", r.TargetID, r.Found, want[i])
		}
	}
	s.cfg.OSPages = fakeOSPages{err: errors.New("read failed")}
	got = runs()
	s.withShownOS(t.Context(), got)
	if f := got[0].Identification[1].Found; !slices.Equal(f, []string{"Type: switch", "Software: OpenSSH 6.9"}) {
		t.Errorf("a failed read: %q, want the OS line dropped", f)
	}
	s.cfg.OSPages = nil
	got = runs()
	s.withShownOS(t.Context(), got)
	if f := got[0].Identification[1].Found; f[1] != "Operating system: NetOS (8.5 - 11.2)" {
		t.Errorf("no OSPages: %q, want the rows as recorded", f)
	}
}
