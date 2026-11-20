package exposure

// The scan schedule of a target is the shared schedule exposure.target:<id> (core/schedule). Until a target's page reads that
// schedule, the old target view says the target is scanned only when a person asks.

// Every is how often a target is scanned by its schedule (contract.ts ScheduleEvery).
type Every string

// The schedule words of the old target view.
const (
	EveryOff Every = "off"
)

// ScheduleView is the schedule of a target as the old target view shows it (contract.ts ScanSchedule).
type ScheduleView struct {
	Every  Every   `json:"every"`
	NextAt *string `json:"next_at"`
	Note   *string `json:"note"`
}

// noSchedule is the schedule of every target in the old target view: scanned when a person asks.
func noSchedule() *ScheduleView { return &ScheduleView{Every: EveryOff} }
