package reports

import (
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// JobTick is how often the send job looks for a send the schedule asked for; nearly every wake-up reads one row and does nothing.
const JobTick = 20 * time.Second

// Jobs returns the jobs of the module; core runs them only while the module is on (SYS-5).
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: ModuleID, Name: "report-send", Every: JobTick, Run: svc.RunPending}}
}
