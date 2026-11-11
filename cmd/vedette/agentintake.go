package main

import "github.com/knt048/vedette/core/jobs"

// agentIntakeJobs is the node-prune job of agent-intake: a normal job (not Housekeeping), so it never runs while the module is off (D-265 (8)).
func agentIntakeJobs(d deps) []jobs.Job {
	if d.AgentIntake == nil {
		return nil
	}
	return d.AgentIntake.Jobs()
}
