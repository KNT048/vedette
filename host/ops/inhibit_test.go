package ops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What busctl --json=short printed on Ubuntu 26.04 (systemd 259) with apt installing, plus the delay locks of
// ModemManager and unattended-upgrades that never refuse a reboot.
const inhibitorsAPT = `{"type":"a(ssssuu)","data":[[["sleep","ModemManager","ModemManager needs to reset devices","delay",0,5445],` +
	`["shutdown","Unattended Upgrades Shutdown","Stop ongoing upgrades or perform upgrades before shutdown","delay",0,5402],` +
	`["shutdown:sleep","APT","APT is installing or removing packages","block",0,7781]]]}` + "\n"

// The answer of an idle Ubuntu 26.04 box (systemd 259), saved by the lead: delay locks only, none blocks.
func TestParseInhibitorsSystemd259Fixture(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("testdata", "inhibitors_systemd259.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := parseInhibitors(raw); err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseInhibitors(t *testing.T) {
	t.Parallel()
	got, err := parseInhibitors([]byte(inhibitorsAPT))
	if err != nil || len(got) != 1 || got[0] != (inhibitor{Who: "APT", Why: "APT is installing or removing packages"}) {
		t.Fatalf("%+v %v", got, err)
	}
	none := []string{
		`{"type":"a(ssssuu)","data":[[]]}`,
		`{"type":"a(ssssuu)","data":[[["sleep","x","y","block",0,1]]]}`,         // sleep only
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","block-weak",0,1]]]}`, // logind ignores it for root
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","delay",0,1]]]}`,
		`{"type":"a(ssssuu)","data":[[["idle:handle-power-key","x","y","block",1000,1]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdownx","x","y","block",0,1]]]}`, // a word, not a prefix
	}
	for _, in := range none {
		if got, err := parseInhibitors([]byte(in)); err != nil || len(got) != 0 {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	unknown := []string{
		``, `null`, `{}`, `[]`, `garbage`, `{"type":"a(ssssuu)"}`, `{"type":"a(ssssuu)","data":null}`,
		`{"type":"a(ssssuu)","data":[null]}`, `{"type":"a(ssssuu)","data":[]}`, `{"type":"a(ssssuu)","data":[[],[]]}`,
		`{"type":"a(sssuu)","data":[[]]}`, `{"type":"a(ssssuu)","data":[[]],"x":1}`,
		`{"type":"a(ssssuu)","data":[[]]} {}`, `{"type":"a(ssssuu)","data":[[]]}]`,
		`{"type":"a(ssssuu)","data":[[null]]}`, `{"type":"a(ssssuu)","data":[[["shutdown","x","y","block",0]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","block",0,1,2]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdown",null,"y","block",0,1]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","block",null,1]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","block",-1,1]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","block",0,4294967296]]]}`,
		`{"type":"a(ssssuu)","data":[[["shutdown","x","y","block",0,1.5]]]}`,
		`{"type":"a(ssssuu)","data":[[[1,"x","y","block",0,1]]]}`,
		`{"type":"a(ssssuu)","data":[{"a":1}]}`,
	}
	for _, in := range unknown {
		if got, err := parseInhibitors([]byte(in)); err == nil {
			t.Errorf("%q was believed: %+v", in, got)
		}
	}
	big := `{"type":"a(ssssuu)","data":[[` + strings.Repeat(`["sleep","x","y","delay",0,1],`, maxInhibitors) + `["sleep","x","y","delay",0,1]]]}`
	if _, err := parseInhibitors([]byte(big)); err == nil {
		t.Error("more than maxInhibitors locks were believed")
	}
}

func TestCleanInhibitText(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"APT":                     "APT",
		"  two\t\nwords  ":        "two words",
		"":                        "unknown",
		" \t ":                    "unknown",
		`<script>"x"&'y'` + "`\\": "?script??x???y???",
		"caf" + string(rune(0xe9)) + " \x1b[31mred" + string(rune(0x202e)) + "!": "caf? ?[31mred?!", // e acute, ESC, RIGHT-TO-LEFT OVERRIDE
		strings.Repeat("a", 200):       strings.Repeat("a", 64),
		strings.Repeat("a", 63) + " b": strings.Repeat("a", 63), // the cut falls right after a space
	} {
		if got := cleanInhibitText(in, inhibitWhoMax); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInhibitedMessageNamesWhoAndWhy(t *testing.T) {
	t.Parallel()
	got := inhibitedMessage([]inhibitor{{Who: "APT", Why: "APT is installing or removing packages"}, {Who: "x", Why: "y"}})
	want := "The box cannot reboot now: APT holds a shutdown lock (and 1 more) (APT is installing or removing packages). Reboot after it finishes."
	if got != want {
		t.Fatalf("%q", got)
	}
}

// The host runner runs busctl with exactly the one ListInhibitors argv (security.md: argv only, allowlist).
func TestBusctlOnlyListsInhibitors(t *testing.T) {
	t.Parallel()
	if err := ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binBusctl, argsListInhibitors); err != nil {
		t.Fatal(err)
	}
	for _, a := range [][]string{
		nil, {"--version"},
		{"--system", "--json=short", "call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "Reboot", "b", "true"},
		{"--system", "--json=short", "call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListInhibitors", "x"},
		{"--system", "call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListInhibitors"},
	} {
		if ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binBusctl, a) == nil {
			t.Errorf("busctl %q accepted", a)
		}
	}
	if ValidateApplierArgv("/var/lib/vedette-host", binBusctl, argsListInhibitors) == nil {
		t.Error("the applier runner has busctl")
	}
	// systemctl never gets a way past an inhibitor (D-453).
	for _, a := range [][]string{{"reboot", "--check-inhibitors=no"}, {"reboot", "--force"}, {"reboot", "-i"}, {"--check-inhibitors=no", "reboot"}, {"reboot", "-ff"}} {
		if ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binSystemctl, a) == nil {
			t.Errorf("systemctl %q accepted", a)
		}
	}
}

func FuzzParseInhibitors(f *testing.F) {
	f.Add([]byte(inhibitorsAPT))
	f.Add([]byte(`{"type":"a(ssssuu)","data":[[]]}`))
	f.Add([]byte(`{"type":"a(ssssuu)","data":[[["shutdown","\u0000<x>","\ud800","block",0,1]]]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := parseInhibitors(in)
		if err != nil {
			if got != nil {
				t.Fatal("a partial list with an error")
			}
			return
		}
		for _, b := range got {
			for _, s := range []string{b.Who, b.Why} {
				if s == "" || len(s) > inhibitWhyMax || strings.ContainsAny(s, "\"'<>&`\\") || strings.TrimSpace(s) != s {
					t.Fatalf("unclean text %q", s)
				}
				for _, r := range s {
					if r < 0x20 || r > 0x7e {
						t.Fatalf("unclean rune %q in %q", r, s)
					}
				}
			}
			if len(b.Who) > inhibitWhoMax {
				t.Fatalf("who too long %q", b.Who)
			}
		}
	})
}
