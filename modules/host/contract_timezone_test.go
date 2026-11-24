package host_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/host/api"
)

// os.timezone.set sets the operating system's zone with the one fixed timedatectl argv, reads the effect back from /etc/localtime,
// and GET /v1/state/time reads the same link.
func TestContract_Timezone_SetsTheZoneReadsItBackAndIsIdempotent(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	ctx := context.Background()
	if st, err := e.h.Client.StateTime(ctx); err != nil || st.Timezone != "Etc/UTC" {
		t.Fatalf("state/time before = %+v, %v", st, err)
	}
	r := e.ok(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Asia/Ho_Chi_Minh"})
	if res := result[api.OSTimezoneResult](t, r); res.Zone != "Asia/Ho_Chi_Minh" || !res.Changed {
		t.Fatalf("result = %+v", res)
	}
	if got := e.m.Calls("timedatectl"); !slices.EqualFunc(got, [][]string{{"set-timezone", "Asia/Ho_Chi_Minh"}}, slices.Equal) {
		t.Fatalf("timedatectl argv = %q", got)
	}
	assertEnvClean(t, e.m.Envs("timedatectl"))
	if st, err := e.h.Client.StateTime(ctx); err != nil || st.Timezone != "Asia/Ho_Chi_Minh" {
		t.Fatalf("state/time after = %+v, %v", st, err)
	}
	// The same zone again changes nothing and runs no program.
	r = e.ok(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Asia/Ho_Chi_Minh"})
	if res := result[api.OSTimezoneResult](t, r); res.Changed {
		t.Fatalf("the second run says it changed the zone: %+v", res)
	}
	if n := len(e.m.Calls("timedatectl")); n != 1 {
		t.Fatalf("timedatectl ran %d times", n)
	}
	// A three-part name and a name that is a link inside the database (UTC -> Etc/UTC) are zones too.
	e.ok(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "America/Argentina/Buenos_Aires"})
	e.ok(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "UTC"})
	if st, _ := e.h.Client.StateTime(ctx); st.Timezone != "UTC" {
		t.Fatalf("state/time = %+v", st)
	}
}

// A name that is not a zone name never reaches the system: path tricks, the posix/ and right/ trees, the database's own files and
// anything not shaped like an IANA name are 400 invalid_args; a well-formed name the machine has no zone file for (an alias its
// tzdata package left out) is 412 zone_unknown, and so is a database entry that is a link leading out of it or not a TZif file.
func TestContract_Timezone_BadNamesNeverReachTheSystem(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	for _, z := range []string{
		"", "../../etc/passwd", "/etc/passwd", "Asia/../../../etc/shadow", "Asia/./Ho_Chi_Minh", "Asia//Ho_Chi_Minh", "Asia/Ho_Chi_Minh/",
		"right/UTC", "posix/Asia/Ho_Chi_Minh", "posixrules", "localtime", "Factory", "zone.tab", "tzdata.zi", "-UTC", "--help",
		"Asia/Ho Chi Minh", "Asia/Ho_Chi_Minh\n", "UTC;reboot", "$(reboot)", "A/B/C/D", "Ásia/Hà_Nội", strings.Repeat("A", 65),
	} {
		e.refused(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: z}, http.StatusBadRequest, api.CodeInvalidArgs)
	}
	// A link inside the database that leads outside it, a file that is not a zone, a directory.
	e.m.WriteRoot("secret", "TZif not a zone, outside the database\n")
	if err := os.Symlink("../../../secret", filepath.Join(e.m.Root, "usr/share/zoneinfo/Asia/Escape")); err != nil {
		t.Fatal(err)
	}
	e.m.WriteRoot("usr/share/zoneinfo/Asia/Plain", "not a zone file\n")
	for _, z := range []string{"Asia/Saigon", "Mars/Olympus", "Asia/Escape", "Asia/Plain", "Asia"} {
		e.refused(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: z}, http.StatusPreconditionFailed, api.CodeZoneUnknown)
	}
	if n := len(e.m.Calls("timedatectl")); n != 0 {
		t.Fatalf("timedatectl ran %d times for refused names", n)
	}
	if st, _ := e.h.Client.StateTime(context.Background()); st.Timezone != "Etc/UTC" {
		t.Fatalf("the zone changed: %+v", st)
	}
}

// An exit code of 0 is not enough: the link must name the zone afterwards. A timedatectl that fails is reported with its reason.
func TestContract_Timezone_TheEffectIsReadBack(t *testing.T) {
	t.Parallel()
	t.Run("timedatectl exits 0 but the link is unchanged", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.RuleText("timedatectl", "set-timezone", "", 0, "", "")
		e.final(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Europe/Berlin"}, api.StatusFailed, api.CodeEffectNotVerified)
	})
	t.Run("timedatectl fails", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.RuleText("timedatectl", "set-timezone", "", 1, "", "")
		r := e.final(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Europe/Berlin"}, api.StatusFailed, api.CodeTimezoneNotSet)
		if r.Error == nil || !strings.Contains(r.Error.Message, "timedatectl") {
			t.Fatalf("error = %+v", r.Error)
		}
	})
	t.Run("a copied /etc/localtime reads as no known zone", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.RemoveRoot("etc/localtime")
		e.m.WriteRoot("etc/localtime", "TZif copied file\n")
		if st, err := e.h.Client.StateTime(context.Background()); err != nil || st.Timezone != "" {
			t.Fatalf("state/time = %+v, %v", st, err)
		}
		e.ok(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Europe/Berlin"}) // timedated replaces the copy by a link
		if st, _ := e.h.Client.StateTime(context.Background()); st.Timezone != "Europe/Berlin" {
			t.Fatalf("state/time = %+v", st)
		}
	})
}

// os.timezone.set takes no shared write lock: while another write command runs (here an os.check whose apt-get waits), core can
// still align the zone, and nothing a person starts at that moment is refused busy because of it. While apt installs (tzdata may
// rewrite /etc/localtime) it is refused and core tries again.
func TestContract_Timezone_NeverHoldsOrWaitsForTheWriteLock(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	release := filepath.Join(e.m.Rec, "release-apt")
	exectest.WriteScript(t, filepath.Join(e.m.Bin, "apt-get"), "#!/bin/sh\nwhile [ ! -e '"+release+"' ]; do sleep 0.02; done\nexit 0\n")
	check, err := e.h.Client.Run(context.Background(), api.CmdOSCheck, nil, e.id(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	r := e.ok(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Europe/Berlin"})
	if res := result[api.OSTimezoneResult](t, r); !res.Changed {
		t.Fatalf("result = %+v", res)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitDone(t, e.h.Client, check.RunID)
	for _, c := range e.o.Commands() {
		if c.Name() == api.CmdOSTimezoneSet && c.Write() {
			t.Fatal("os.timezone.set is a write command: it would take the shared lock")
		}
	}
	e.installing.Store(true)
	e.refused(t, api.CmdOSTimezoneSet, api.OSTimezoneArgs{Zone: "Asia/Ho_Chi_Minh"}, http.StatusConflict, api.CodeInstallInProgress)
	e.installing.Store(false)
	if st, _ := e.h.Client.StateTime(context.Background()); st.Timezone != "Europe/Berlin" {
		t.Fatalf("state/time = %+v", st)
	}
}
