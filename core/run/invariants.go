package run

import "strings"

// Invariant is a read-only query over the database that counts the rows breaking one rule of runs; 0 is healthy. The box's
// self-check runs them after every deploy, and the tests run them on every state they make.
type Invariant struct {
	Name  string
	Rule  string
	Query string
}

func quoted(ss ...Status) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = "'" + string(s) + "'"
	}
	return strings.Join(q, ", ")
}

// Invariants are the rules of the runs tables. That no run is running or stopping right after a start is a rule of Recover,
// proved by its tests: a database read while the box runs has live runs by design.
var Invariants = []Invariant{
	{
		Name:  "runs.one_live_per_lane",
		Rule:  "at most one run is running or stopping in each lane",
		Query: `SELECT count(*) FROM (SELECT lane FROM core_run WHERE status IN (` + quoted(Running, Stopping) + `) GROUP BY lane HAVING count(*) > 1)`,
	},
	{
		Name:  "runs.ended_have_ended_at",
		Rule:  "a run has an end time exactly when it has ended",
		Query: `SELECT count(*) FROM core_run WHERE (status IN (` + quoted(Done, Partial, Failed, Stopped) + `)) <> (ended_at IS NOT NULL)`,
	},
	{
		Name:  "runs.waiting_for_only_while_waiting",
		Rule:  "a run says what it waits for exactly while it waits",
		Query: `SELECT count(*) FROM core_run WHERE (status = '` + string(Waiting) + `') <> (waiting_for IS NOT NULL)`,
	},
	{
		Name: "runs.known_status",
		Rule: "every run is in one of the eight run states, and every step in one of them or skipped",
		Query: `SELECT (SELECT count(*) FROM core_run WHERE status NOT IN (` + quoted(Statuses...) + `))
			+ (SELECT count(*) FROM core_run_step WHERE status NOT IN (` + quoted(StepStatuses...) + `))`,
	},
	{
		Name: "runs.progress_is_the_sum_of_steps",
		Rule: "a run with steps counts the work of its steps",
		Query: `SELECT count(*) FROM core_run r JOIN (SELECT run_id, sum(total) AS total, sum(done) AS done FROM core_run_step GROUP BY run_id) s
			ON s.run_id = r.id WHERE r.total <> s.total OR r.done <> s.done`,
	},
}
