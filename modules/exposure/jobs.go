package exposure

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// JobTick is how often the auto-detect job wakes up to see whether a check is due. The shortest interval a customer
// can choose is one minute, so it wakes every minute; the check itself runs every interval_min minutes, and a run
// can start up to half a tick early. Most wake-ups do nothing.
const JobTick = time.Minute

// Jobs returns the jobs of the module (core runs one only while the module is on). auto-detect wakes up every
// JobTick and checks the box's public IPs when one is due (INV-11): the first time right after the module starts,
// then every interval_min minutes while the customer has auto-detect on.
//
// greenbone-feed wakes up every GreenboneSyncTick and updates Greenbone's feed once a week while Greenbone is enabled (D-564 G6,
// RunGreenboneSync); most wake-ups do nothing.
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "auto-detect", Every: JobTick, Run: svc.RunAutoDetect},
		{Module: ModuleID, Name: "greenbone-feed", Every: GreenboneSyncTick, Run: svc.RunGreenboneSync},
	}
}

// GreenboneSyncTick is how often the greenbone-feed job wakes up to see whether the weekly update is due (or was put off by a scan).
const GreenboneSyncTick = time.Hour

// autoDue says whether the job should check now: auto-detect is on and the last check is older than the interval
// (or there was none, which is the first start of the box).
func autoDue(b BoxIP, now time.Time) bool {
	if !b.Auto {
		return false
	}
	if b.LastRun == nil {
		return true
	}
	at, err := parseTS(b.LastRun.At)
	if err != nil || at.After(now.Add(clockSlack)) { // written while the clock was ahead (L1): do not wait for it
		return true
	}
	return !now.Before(at.Add(time.Duration(b.IntervalMin) * time.Minute).Add(-JobTick / 2))
}

// RunAutoDetect is the body of the auto-detect job (INV-11): the first check right after the box starts or the
// module is turned on, then one every interval_min minutes while auto-detect is on. The check is a full one
// (DeepRounds rounds, which finds every IP behind a load balancer) the first time and then at most once an hour;
// the checks in between are light (one round, three requests). Expected outcomes (not public, services down or
// disagreeing, list full) are in last_run; the job fails only on a failure of the box itself.
func (s *Service) RunAutoDetect(ctx context.Context) error {
	b, err := s.Settings(ctx)
	if err != nil {
		return err
	}
	if !autoDue(b, s.clock()) {
		return nil
	}
	deep, err := s.deepDue(ctx)
	if err != nil {
		return err
	}
	if _, err := s.Detect(ctx, SystemUser, deep); err != nil && !isOutcome(err) {
		return err
	}
	return nil
}
