package logs

import (
	"database/sql"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// events_around of ai (D-223): the kinds of line that named one address, with counts and the source's name, never a line; and the
// connections to listed destinations of that address.
func TestContract_EventsAroundCountsKindsOfOneAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	accepted := "<38>Nov  9 10:00:00 gw sshd[812]: Accepted password for bob from 203.0.113.9 port 51234 ssh2"
	e.feedAll(src, append(append(repeat(sshFail("203.0.113.9"), 5), repeat(sshFail("198.51.100.7"), 2)...), accepted))
	if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_ioc_hits (id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence, source_id)
			VALUES ('h1', ?, '192.168.10.9', '203.0.113.9', 'ip', 'syslog:FW-HQ', '["Tor exits"]', 0.9, ?)`, store.FormatTS(e.svc.now()), src.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := e.svc.now()
	got, err := e.svc.EventsAround(t.Context(), netip.MustParseAddr("::ffff:203.0.113.9"), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lines != 6 || len(got.Kinds) != 2 || got.Kinds[0] != (AroundKind{SourceName: "FW-HQ", Signature: e.sshSig(), Count: 5}) || got.Kinds[1] != (AroundKind{SourceName: "FW-HQ", Signature: e.svc.sigs.Of("linux-rsyslog", accepted).Signature, Count: 1}) {
		t.Fatalf("%+v", got)
	}
	if len(got.Connections) != 1 || got.Connections[0].ID != "h1" {
		t.Fatalf("connections %+v", got.Connections)
	}
	if old, _ := e.svc.EventsAround(t.Context(), netip.MustParseAddr("203.0.113.9"), now.Add(-30*time.Hour), now.Add(-26*time.Hour)); old.Lines != 0 || len(old.Connections) != 0 {
		t.Fatalf("a range before the lines: %+v", old)
	}
	if _, err := e.svc.EventsAround(t.Context(), netip.MustParseAddr("203.0.113.9"), now.Add(-25*time.Hour), now); !errors.Is(err, ErrBadRange) {
		t.Fatalf("25 hours: %v", err)
	}
}
