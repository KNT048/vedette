package sensorpassive_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	sp "github.com/knt048/vedette/modules/sensor-passive"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// flakySource delivers a few frames, then fails like a card that lost its link.
type flakySource struct{ n int }

func (f *flakySource) Next(ctx context.Context) (sp.Packet, error) {
	if err := ctx.Err(); err != nil {
		return sp.Packet{}, err
	}
	if f.n < 3 {
		f.n++
		return sp.Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)}, nil
	}
	return sp.Packet{}, errors.New("receive: network is down")
}
func (f *flakySource) Close() error { return nil }

// Low: a live capture never ends cleanly, so the back-off was reset only by a settings change and every failure over the
// life of the process doubled the pause until it stuck at ten minutes. A session that received frames starts it over.
func TestBackoffStartsOverAfterASessionThatReceivedFrames(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	opens := 0
	e := newEnv(t, nil, true, func(c *sp.Config, _ *env) {
		c.Open = func(string) (sp.Source, error) {
			mu.Lock()
			opens++
			mu.Unlock()
			return &flakySource{}, nil
		}
	})
	e.setInterface("eth0", false)
	e.run()
	pause(t, 1500*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	// base 20 ms: without the reset the pauses are 20, 40, 80 ... 640 ms and fewer than 8 opens fit in 1.5 s
	if opens < 15 {
		t.Errorf("only %d opens in 1.5 s: the pause kept growing after sessions that worked", opens)
	}
}
