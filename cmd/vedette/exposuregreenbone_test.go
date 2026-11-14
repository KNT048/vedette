package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// OpenVAS (D-529, FULL-2): exposure's GreenboneHost over the host's greenbone.* commands, against a fake host client.

const gbTestLogin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeGBHost struct {
	mu    sync.Mutex
	calls []string
	args  []string
	run   func(command string) (api.Run, error)
}

func (f *fakeGBHost) Greenbone(_ context.Context, command string, args any, _, actor string) (api.Run, error) {
	b, _ := json.Marshal(args)
	f.mu.Lock()
	f.calls, f.args = append(f.calls, command+" "+actor), append(f.args, string(b))
	f.mu.Unlock()
	if f.run != nil {
		return f.run(command)
	}
	return api.Run{Status: api.StatusSucceeded}, nil
}

func (f *fakeGBHost) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func gbHostFor(f *fakeGBHost, socket string) exposureGreenbone {
	return exposureGreenbone{host: f, socket: socket, login: func(context.Context) (string, error) { return gbTestLogin, nil }}
}

func TestExposureGreenbone_UpGivesTheLoginDownAndSyncFeedNone(t *testing.T) {
	t.Parallel()
	f := &fakeGBHost{}
	g := gbHostFor(f, "/nonexistent")
	for _, step := range []func(context.Context) error{g.Up, g.Down, g.SyncFeed} {
		if err := step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"greenbone.up exposure:openvas", "greenbone.down exposure:openvas", "greenbone.sync_feed exposure:openvas"}
	if got := f.Calls(); strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("calls %q, want %q", got, want)
	}
	if f.args[0] != `{"password":"`+gbTestLogin+`"}` || f.args[1] != "null" || f.args[2] != "null" {
		t.Fatalf("args %q", f.args)
	}
}

// The host's sentences reach the page as *exposure.Unavailable, a cancelled run is "turned off meanwhile", an old host says to
// update, and nothing of it carries the password.
func TestExposureGreenbone_HostOutcomes(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		run  func(string) (api.Run, error)
		want func(error) bool
	}{
		"a failed step": {func(string) (api.Run, error) {
			return api.Run{Status: api.StatusFailed, Error: &api.RunError{Code: api.CodeGreenboneFailed, Message: "OpenVAS: podman compose up failed. The box log has the details."}}, nil
		}, func(err error) bool {
			var un *exposure.Unavailable
			return errors.As(err, &un) && strings.HasPrefix(un.Reason, "OpenVAS: podman compose up failed")
		}},
		"turned off meanwhile": {func(string) (api.Run, error) {
			return api.Run{Status: api.StatusFailed, Error: &api.RunError{Code: api.CodeGreenboneCancelled, Message: "x"}}, nil
		}, func(err error) bool { return errors.Is(err, context.Canceled) }},
		"an old host": {func(string) (api.Run, error) {
			return api.Run{}, &hostclient.Error{Status: 404, Code: api.CodeUnknownCommand}
		}, func(err error) bool {
			var un *exposure.Unavailable
			return errors.As(err, &un) && strings.Contains(un.Reason, "older than this version")
		}},
	} {
		g := gbHostFor(&fakeGBHost{run: tc.run}, "/nonexistent")
		err := g.Up(t.Context())
		if !tc.want(err) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), gbTestLogin) {
			t.Errorf("%s: the error carries the password", name)
		}
	}
}

// review r1 M2: a feed update that outlasts exposure's bound, or is cut short, returns at once and never stops OpenVAS: only turning
// it off or switching the module off does (they send their own Down).
func TestExposureGreenbone_ASlowFeedUpdateLeavesOpenVASUp(t *testing.T) {
	t.Parallel()
	for name, end := range map[string]error{"deadline": context.DeadlineExceeded, "cancelled": context.Canceled} {
		ctx, cancel := context.WithCancelCause(t.Context())
		f := &fakeGBHost{}
		f.run = func(string) (api.Run, error) {
			cancel(end) // exposure's 60 minutes end (or a stop) while the host still pulls
			return api.Run{Status: api.StatusRunning}, end
		}
		if err := gbHostFor(f, "/nonexistent").SyncFeed(ctx); err == nil {
			t.Errorf("%s: no error", name)
		}
		if got := f.Calls(); len(got) != 1 || got[0] != "greenbone.sync_feed exposure:openvas" {
			t.Errorf("%s: calls %q, want the feed update only (no down)", name, got)
		}
	}
}

// Dial: no socket yet is "starting" (exposure then reads its state as starting within the grace); a socket gives the login.
func TestExposureGreenbone_DialWithTheSocketMissingSaysStarting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g := gbHostFor(&fakeGBHost{}, filepath.Join(dir, "gvmd.sock"))
	_, _, err := g.Dial(t.Context())
	var un *exposure.Unavailable
	if !errors.As(err, &un) || !strings.Contains(un.Reason, "still starting") {
		t.Fatalf("%v, want an Unavailable that says starting", err)
	}
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "unix", g.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	conn, login, err := g.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if login.User != "admin" || login.Password != gbTestLogin {
		t.Fatalf("login %q", login.User)
	}
}

// Review r2: cfg.Greenbone and privacy flow 16 are wired together. Without vedette-host nothing is wired and flow 16 is off even with
// the setting on; with it, the setting decides. The GMP password is made in core/secrets once, 48 hex characters.
func TestExposureGreenbone_WiredWithPrivacyFlow16(t *testing.T) {
	t.Parallel()
	enable := func(s *stack) {
		s.t.Helper()
		if err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(s.t.Context(), `UPDATE exp_setting SET greenbone = 1, greenbone_by = 'admin', greenbone_at = '2026-11-14T10:00:00Z' WHERE id = 1`)
			return err
		}); err != nil {
			s.t.Fatal(err)
		}
	}
	plain := newStack(t)
	if exposureGreenboneFor(*plain.d) != nil {
		t.Fatal("OpenVAS is wired on an install without vedette-host")
	}
	enable(plain)
	if (privacyFacts{d: plain.d}).GreenboneEnabled(t.Context()) {
		t.Fatal("flow 16 is on without vedette-host")
	}
	sock, data := filepath.Join(t.TempDir(), "host.sock"), t.TempDir()
	box := newStackWith(t, func(d *deps) { d.HostSocket, d.DataDir, d.KeyPath = sock, data, filepath.Join(data, "vedette.key") })
	g, ok := exposureGreenboneFor(*box.d).(exposureGreenbone)
	if !ok {
		t.Fatal("OpenVAS is not wired on an appliance")
	}
	if g.socket != api.GreenboneSocket {
		t.Fatalf("socket %s", g.socket)
	}
	p := privacyFacts{d: box.d}
	if p.GreenboneEnabled(t.Context()) {
		t.Fatal("flow 16 is on by default")
	}
	enable(box)
	if !p.GreenboneEnabled(t.Context()) {
		t.Fatal("flow 16 is off with OpenVAS enabled")
	}
	pw1, err := g.login(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	pw2, _ := g.login(t.Context())
	if pw1 != pw2 || !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(pw1) {
		t.Fatal("the GMP password is not one stable 48-hex secret")
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("the test made the host socket")
	}
	// LEGAL §3: the probe log has the scan's row before the task starts (the scan module's table, Scans -> Probe log).
	if err := (exposureProbeLog{d: *box.d}).RecordGreenboneProbe(t.Context(), exposure.GreenboneProbe{ID: "pb_gb1", IP: "93.184.216.34", PortList: "All IANA assigned TCP", Config: "full", Note: "many probes"}); err != nil {
		t.Fatal(err)
	}
	if n := box.count(`SELECT COUNT(*) FROM scan_probe WHERE id = 'pb_gb1' AND ip = '93.184.216.34' AND template LIKE 'exposure: OpenVAS%' AND request LIKE '%All IANA assigned TCP%'`); n != 1 {
		t.Fatalf("probe rows %d", n)
	}
}
