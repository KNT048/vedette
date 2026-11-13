package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
)

// fakeHits answers the connection counts of the honeypot hits (D-496).
type fakeHits struct {
	conns map[string]int
	err   error
}

func (f fakeHits) HitConnections(_ context.Context, hits []notify.HitRef) (map[string]int, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]int{}
	for _, h := range hits {
		if n, ok := f.conns[h.ID]; ok {
			out[h.ID] = n
		}
	}
	return out, nil
}

// M5-190: a trap hit that got more connections folded into it shows that many times, not once; without the answer the count is notify's own.
func TestTrapIncidentTimesAreTheConnectionsOfItsHit(t *testing.T) {
	for _, tc := range []struct {
		name string
		hits fakeHits
		want int
	}{
		{"folded", fakeHits{conns: map[string]int{"hit-1": 3}}, 3},
		{"port error", fakeHits{err: errors.New("honeypot busy")}, 1},
		{"unknown hit", fakeHits{conns: map[string]int{}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(c *notify.Config) { c.Hits = tc.hits })
			unsub := e.svc.Subscribe(e.bus)
			defer unsub()
			if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventHoneypotHit, Data: map[string]any{"id": "hit-1", "ts": "2026-11-09T09:59:00Z", "kind": "service", "service": "smb", "src_ip": "192.168.10.107", "label": "FILESRV-OLD"}}); err != nil {
				t.Fatal(err)
			}
			l, err := e.svc.Incidents(e.ctx())
			if err != nil || len(l) != 1 || l[0].Count != tc.want {
				t.Fatalf("list = %+v, %v; want count %d", l, err, tc.want)
			}
			d, err := e.svc.IncidentDetail(e.ctx(), l[0].ID)
			if err != nil || d.Incident.Count != tc.want {
				t.Fatalf("detail count = %d, %v; want %d", d.Incident.Count, err, tc.want)
			}
		})
	}
}
