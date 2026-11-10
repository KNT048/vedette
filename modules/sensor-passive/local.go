package sensorpassive

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// localLink is the capture's Link for the capture job that still runs inside core (until SP-5): the same three calls as over the
// wire, answered by this Service directly. Everything a remote sensor says goes through the same checks, budgets and clamps.
type localLink struct{ s *Service }

func (l localLink) Config(ctx context.Context, etag string, wait time.Duration) (sensorlink.ConfigReply, error) {
	return l.s.Config(ctx, wait, etag)
}

func (l localLink) PostObservations(ctx context.Context, req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	return l.s.Observations(ctx, req)
}

func (l localLink) PassiveHeartbeat(ctx context.Context, hb *sensorlink.PassiveHeartbeat) (string, error) {
	return l.s.PassiveHeartbeat(ctx, hb)
}

// Run is the capture job that runs inside core until SP-5 moves it to the sensor container: a capture.Runner whose link is this
// Service. It returns only when ctx is cancelled (the module was turned off, SYS-5, or the process stops); wire it as a core/jobs
// job so that it runs only while the module is on. The Runner is built once and lives across switches of the module, so the
// book of devices already reported and the epoch survive a module off and on, like a sensor process that is not restarted.
func (s *Service) Run(ctx context.Context) error {
	s.runnerMu.Lock()
	if s.runner == nil {
		r, err := capture.New(capture.Config{Link: localLink{s}, Interfaces: s.host.Interfaces, Open: s.open, Meta: s.meta, Clock: s.clock, Log: s.log,
			Version: s.version, FlushEvery: s.flushEvery, HeartbeatEvery: s.beatEvery, RetryEvery: s.retryEvery, SummaryEvery: s.summaryEvery,
			RetryAfterCap: s.retryAfterCap})
		if err != nil {
			s.runnerMu.Unlock()
			return err
		}
		s.runner = r
	}
	r := s.runner
	s.runnerMu.Unlock()
	return r.Run(ctx)
}
