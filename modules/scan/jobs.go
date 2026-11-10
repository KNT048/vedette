package scan

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// RecoverEvery is how often the recover job looks for a run a restart left live. core/jobs runs a job as soon as its
// module is on, so after a restart the run is closed at once; later passes are cheap.
const RecoverEvery = 10 * time.Minute

// Jobs are the module's background work; core/jobs runs them only while the module is on (SYS-5).
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: ModuleID, Name: "recover", Every: RecoverEvery, Run: svc.RunRecover}}
}

// RunRecover closes a run the database says is live while this process runs none (review M4): it shows stopped and
// its open probe rows are closed (INV-7).
func (s *Service) RunRecover(ctx context.Context) error { return s.reapOrphan(ctx) }

// Close stops the live run and waits for it to end, at most the time a stopped run needs (review M4). Called when
// Vedette shuts down; the run ends as stopped with the reason.
func (s *Service) Close() {
	s.closing.Store(true)
	s.mu.Lock()
	l := s.live
	s.mu.Unlock()
	if l == nil {
		return
	}
	l.cancel()
	select {
	case <-l.done:
	case <-time.After(stopGrace + finishTimeout):
		s.cfg.Log.Error("scan: the live run did not stop at shutdown", "run", l.id)
	}
}

// stopReason is why a run ended before its last device: Vedette shut down, or a person pressed Stop now.
func (s *Service) stopReason() string {
	if s.closing.Load() {
		return stopShutdown
	}
	return stopNow
}
