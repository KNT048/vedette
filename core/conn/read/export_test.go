package read

import "time"

// SetBudgetForTest shortens the time of a call.
func (r *Reader) SetBudgetForTest(d time.Duration) { r.budget = d }
