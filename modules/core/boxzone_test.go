package core_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/core"
)

// osZoneOf is the zone the fake machine's /etc/localtime names.
func (e *osEnv) osZoneOf() string {
	e.t.Helper()
	target, err := os.Readlink(filepath.Join(e.m.Root, "etc/localtime"))
	if err != nil {
		e.t.Fatal(err)
	}
	return api.ZoneOfLink(target)
}

func (e *osEnv) timedatectlCalls() int { return len(e.m.Calls("timedatectl")) }

func (e *osEnv) auditCount(action string) int {
	e.t.Helper()
	return e.env.Count(e.t, "SELECT count(*) FROM core_audit WHERE action = '"+action+"'")
}

// At start, once setup is done, core sets the operating system's zone when it differs from the box's, once, and audits that one
// change; a start that finds them equal runs nothing and writes nothing.
func TestBoxZone_TheStartAlignsTheOperatingSystemOnceAndOnlyWhenItDiffers(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	// Before setup nobody chose a zone: the default is not pushed onto the operating system.
	if e.handler.ZoneAlignedForTest() || e.timedatectlCalls() != 0 {
		t.Fatal("aligned before setup was done")
	}
	e.setZone("Asia/Saigon") // an older version stored the alias; the operating system has only the current name
	h := e.newHandlers(t, e.gate, 0)
	eventuallyOS(t, "the start aligns the zone", func() bool { return h.ZoneAlignedForTest() })
	if got := e.osZoneOf(); got != "Asia/Ho_Chi_Minh" {
		t.Fatalf("the operating system uses %q", got)
	}
	if n := e.timedatectlCalls(); n != 1 {
		t.Fatalf("timedatectl ran %d times", n)
	}
	if n := e.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'core.os_time_zone' AND user = 'system' AND target = 'Asia/Ho_Chi_Minh' AND detail = 'from Etc/UTC to Asia/Ho_Chi_Minh'"); n != 1 {
		t.Fatalf("%d audit rows of the change", n)
	}
	g := e.admin.get("/core/general")
	wantOK(t, g, 200)
	if g.str("timezone") != "Asia/Ho_Chi_Minh" || g.str("os_time_zone", "state") != "in_sync" || g.str("os_time_zone", "zone") != "Asia/Ho_Chi_Minh" {
		t.Fatalf("general = %s", g.Raw)
	}
	// A restart with the two equal: nothing runs, nothing is audited.
	h2 := e.newHandlers(t, e.gate, 0)
	eventuallyOS(t, "the second start looks", func() bool { return h2.ZoneAlignedForTest() })
	if n := e.timedatectlCalls(); n != 1 {
		t.Fatalf("timedatectl ran again: %d", n)
	}
	if n := e.auditCount("core.os_time_zone"); n != 1 {
		t.Fatalf("%d audit rows after a start that changed nothing", n)
	}
}

// A person saves another zone in Settings › General: the schedules move, the operating system follows at once, the answer says so;
// an alias is kept under its current name; a zone the operating system lacks is saved for Vedette and reported as not set.
func TestBoxZone_SavingTheZoneSetsTheOperatingSystemAndSaysHowItWent(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.setZone("Asia/Ho_Chi_Minh")
	e.handler = e.newHandlers(t, e.gate, 0)
	eventuallyOS(t, "the start aligns the zone", func() bool { return e.handler.ZoneAlignedForTest() })

	p := e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": "Europe/Berlin"})
	wantOK(t, p, 200)
	if p.str("timezone") != "Europe/Berlin" || p.str("os_time_zone", "state") != "in_sync" || p.str("os_time_zone", "zone") != "Europe/Berlin" || e.osZoneOf() != "Europe/Berlin" {
		t.Fatalf("put = %s, os %s", p.Raw, e.osZoneOf())
	}
	if n := e.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'core.os_time_zone' AND user = 'admin@acme.example' AND detail = 'from Asia/Ho_Chi_Minh to Europe/Berlin'"); n != 1 {
		t.Fatalf("%d audit rows by the person", n)
	}
	// The browser's alias: stored, shown and set under the current name.
	p = e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": "Asia/Saigon"})
	wantOK(t, p, 200)
	if p.str("timezone") != "Asia/Ho_Chi_Minh" || e.osZoneOf() != "Asia/Ho_Chi_Minh" {
		t.Fatalf("alias: %s, os %s", p.Raw, e.osZoneOf())
	}
	if n := e.env.Count(t, "SELECT count(*) FROM core_org WHERE timezone = 'Asia/Ho_Chi_Minh'"); n != 1 {
		t.Fatal("the alias was stored as typed")
	}
	// Europe/Paris is a zone Vedette knows and this operating system does not: the save stands, the answer says why the system
	// keeps its zone.
	p = e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": "Europe/Paris"})
	wantOK(t, p, 200)
	if p.str("timezone") != "Europe/Paris" || p.str("os_time_zone", "state") != "failed" || p.str("os_time_zone", "zone") != "Asia/Ho_Chi_Minh" ||
		!strings.Contains(p.str("os_time_zone", "message"), "does not know") || e.osZoneOf() != "Asia/Ho_Chi_Minh" {
		t.Fatalf("unknown to the system: %s", p.Raw)
	}
	if g := e.admin.get("/core/general"); g.str("os_time_zone", "state") != "failed" {
		t.Fatalf("general after a failed set = %s", g.Raw)
	}
	// Names that are no zone never reach the helper.
	calls := e.timedatectlCalls()
	for _, tz := range []string{"../../etc/passwd", "right/UTC", "posix/Asia/Ho_Chi_Minh", "Local", "Asia/Ho_Chi_Minh\n"} {
		wantStatus(t, e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": tz}), 400, "invalid_timezone")
	}
	if e.timedatectlCalls() != calls {
		t.Fatal("a refused name reached the helper")
	}
}

// zoneHost is a host whose time zone side answers what a test says, the rest the in-process host.
type zoneHost struct {
	core.Host
	stateErr atomic.Pointer[error]
	setErr   atomic.Pointer[error]
}

func (z *zoneHost) StateTime(ctx context.Context) (api.TimeState, error) {
	if p := z.stateErr.Load(); p != nil {
		return api.TimeState{}, *p
	}
	return z.Host.StateTime(ctx)
}

func (z *zoneHost) OSTimezoneSet(ctx context.Context, zone, rid, actor string) (api.Run, error) {
	if p := z.setErr.Load(); p != nil {
		return api.Run{}, *p
	}
	return z.Host.OSTimezoneSet(ctx, zone, rid, actor)
}

// No helper, a helper older than the command, and a busy helper: General says which, a save still goes through, and a busy helper
// is asked again.
func TestBoxZone_WithoutAHelperThatCanSetItGeneralSaysSo(t *testing.T) {
	t.Parallel()
	t.Run("container-only install", func(t *testing.T) {
		t.Parallel()
		e := newOSEnv(t, osOpts{noHost: true})
		e.setZone("Europe/Berlin")
		g := e.admin.get("/core/general")
		if g.str("os_time_zone", "state") != "not_managed" || g.str("os_time_zone", "message") == "" {
			t.Fatalf("general = %s", g.Raw)
		}
		wantOK(t, e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": "UTC"}), 200)
	})
	t.Run("older helper and busy helper", func(t *testing.T) {
		t.Parallel()
		e := newOSEnv(t, osOpts{})
		e.setZone("Asia/Ho_Chi_Minh")
		zh := &zoneHost{Host: e.hh.Client}
		older := error(&hostclient.Error{Status: http.StatusNotFound, Code: api.CodeUnknownCommand, Message: "unknown"})
		zh.stateErr.Store(&older)
		e.handler = e.newHandlers(t, zh, 0)
		eventuallyOS(t, "the start looks", func() bool { return e.handler.ZoneAlignedForTest() })
		p := e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": "Europe/Berlin"})
		wantOK(t, p, 200)
		if p.str("os_time_zone", "state") != "not_managed" || !strings.Contains(p.str("os_time_zone", "message"), "older") {
			t.Fatalf("older helper: %s", p.Raw)
		}
		zh.stateErr.Store(nil)
		busy := error(&hostclient.Error{Status: http.StatusConflict, Code: api.CodeBusy, Message: "busy"})
		zh.setErr.Store(&busy)
		p = e.admin.putGeneral(map[string]any{"name": "Acme", "timezone": "Europe/Berlin"})
		if p.str("os_time_zone", "state") != "pending" || e.osZoneOf() != "Etc/UTC" {
			t.Fatalf("busy helper: %s", p.Raw)
		}
		// The helper is free again: the box sets it by itself.
		zh.setErr.Store(nil)
		e.handler.WakeZoneAlignment()
		eventuallyOS(t, "the retry sets the zone", func() bool { return e.osZoneOf() == "Europe/Berlin" })
		eventuallyOS(t, "general says in sync", func() bool { return e.admin.get("/core/general").str("os_time_zone", "state") == "in_sync" })
	})
}

// The first-run setup takes the zone the wizard offers, stored under its current name; a name that is no zone is refused on its
// field before anything is created.
func TestBoxZone_FirstRunSetupTakesTheZone(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	body := setupBody(w.openSetup())
	body["timezone"] = "Mars/Olympus"
	r := w.client().post("/core/setup", body)
	wantStatus(t, r, 400, "invalid_timezone")
	if n := w.env.Count(t, "SELECT count(*) FROM core_org"); n != 0 {
		t.Fatal("setup went ahead")
	}
	body["timezone"] = "Asia/Calcutta"
	wantOK(t, w.client().post("/core/setup", body), 200)
	if n := w.env.Count(t, "SELECT count(*) FROM core_org WHERE timezone = 'Asia/Kolkata'"); n != 1 {
		t.Fatal("the zone was not stored under its current name")
	}
	if got := orgtime.CanonicalZone("Asia/Calcutta"); got != "Asia/Kolkata" {
		t.Fatal(got)
	}
	// Without a zone the default stays.
	w2 := newWorld(t)
	wantOK(t, w2.client().post("/core/setup", setupBody(w2.openSetup())), 200)
	if n := w2.env.Count(t, "SELECT count(*) FROM core_org WHERE timezone = '"+core.DefaultTimezone+"'"); n != 1 {
		t.Fatal("the default zone is not stored")
	}
}
