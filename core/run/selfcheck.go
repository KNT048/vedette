package run

import "github.com/knt048/vedette/core/selfcheck"

// The rules of the runs tables are part of the box's self-check, so a deploy that leaves them broken is caught at once.
func init() {
	for _, inv := range Invariants {
		selfcheck.Register(selfcheck.Invariant{Name: inv.Name, Query: inv.Query})
	}
}
