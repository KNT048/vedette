package main

import "github.com/knt048/vedette/core/jobs"

// agentIntakeJobs is the node-prune job of agent-intake, a Housekeeping job (D-160): it deletes nodes silent for 90 days and tokens
// expired for 30 days that no node uses, whether or not the module is on.
func agentIntakeJobs(d deps) []jobs.Job {
	if d.AgentIntake == nil {
		return nil
	}
	return d.AgentIntake.Jobs()
}
