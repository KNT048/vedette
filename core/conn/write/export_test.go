package write

import "time"

// SetAfterCredentialForTest runs f between opening the credential and dialling.
func (w *Writer) SetAfterCredentialForTest(f func()) { w.afterCredential = f }

// SetLeaveBudgetForTest shortens the leave line's budget after a refused SSH line.
func (w *Writer) SetLeaveBudgetForTest(d time.Duration) { w.leaveBudget = d }

// LeaveLineForTest is leaveLine.
func LeaveLineForTest(sent []string) string { return leaveLine(sent) }

// LeaveRulesForTest loads leave.json and returns every leave line, in order.
func LeaveRulesForTest() ([]string, error) {
	rules, err := leaveRules()
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.leave)
	}
	return out, err
}
