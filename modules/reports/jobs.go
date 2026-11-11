package reports

import (
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// JobTick is how often the weekly-send job looks at the schedule. A slot is an hour, so a minute is fine; nearly every wake-up
// reads one row and does nothing.
const JobTick = time.Minute

// Jobs returns the jobs of the module; core runs them only while the module is on (SYS-5).
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: ModuleID, Name: "weekly-send", Every: JobTick, Run: svc.RunSchedule}}
}
