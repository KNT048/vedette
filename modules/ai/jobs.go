// Package ai is the library behind the AI assistant module: provider profiles, per-job routing with
// fallback, the token meter, the hook runner, the read-only tool filter, prompt assembly and the
// hash-chained activity log. It has no HTTP, no database and no scheduler; WP-25 wires it to core.
package ai

// Job is one of the ten AI jobs (INV-2).
type Job string

// The ten AI jobs, as in contract.ts.
const (
	JobExplainFinding    Job = "explain-finding"
	JobMitigationConfig  Job = "mitigation-config"
	JobCVENews           Job = "cve-news"
	JobLogDigest         Job = "log-digest"
	JobLogInvestigate    Job = "log-investigate"
	JobAskMyData         Job = "ask-my-data"
	JobWeeklyReport      Job = "weekly-report"
	JobPDPLAssessment    Job = "pdpl-assessment"
	JobTranslateAdvisory Job = "translate-advisory"
	JobResponsePlan      Job = "response-plan"
)

// Jobs lists every job in contract order.
func Jobs() []Job {
	return []Job{JobExplainFinding, JobMitigationConfig, JobCVENews, JobLogDigest, JobLogInvestigate,
		JobAskMyData, JobWeeklyReport, JobPDPLAssessment, JobTranslateAdvisory, JobResponsePlan}
}

// Valid reports whether j is one of the ten jobs.
func (j Job) Valid() bool {
	for _, k := range Jobs() {
		if j == k {
			return true
		}
	}
	return false
}

// CarriesInternalData reports whether the job sends the customer's logs or device data to the model.
// Only the two jobs that work on public text (CVE advisories) do not (INV-3, `AI_JOBS` in the mock).
func (j Job) CarriesInternalData() bool {
	return j != JobCVENews && j != JobTranslateAdvisory
}

// Name is the phrase used in error messages ("... for log summaries").
func (j Job) Name() string {
	switch j {
	case JobExplainFinding:
		return "explaining findings"
	case JobMitigationConfig:
		return "writing mitigation configs"
	case JobCVENews:
		return "CVE news"
	case JobLogDigest:
		return "log summaries"
	case JobLogInvestigate:
		return "log investigation"
	case JobAskMyData:
		return "asking your data"
	case JobWeeklyReport:
		return "the weekly report"
	case JobPDPLAssessment:
		return "the data protection assessment"
	case JobTranslateAdvisory:
		return "translating advisories"
	case JobResponsePlan:
		return "response plans"
	}
	return string(j)
}

// Tier is the token level (INV-4): min, med or max.
type Tier string

// The three token levels.
const (
	TierMin Tier = "min"
	TierMed Tier = "med"
	TierMax Tier = "max"
)

// Valid reports whether t is a known level.
func (t Tier) Valid() bool { return t == TierMin || t == TierMed || t == TierMax }

// Lower returns the next level down: max -> med -> min. min stays min. There is no way up.
func (t Tier) Lower() Tier {
	switch t {
	case TierMax:
		return TierMed
	case TierMed:
		return TierMin
	}
	return t
}

// EstimatePerDay is the rough token use per day shown in the UI (no money, D-6). ok is false for max,
// which depends on the number of alerts.
func (t Tier) EstimatePerDay() (tokens int, ok bool) {
	switch t {
	case TierMin:
		return 10_000, true
	case TierMed:
		return 60_000, true
	}
	return 0, false
}

// Daily cap limits (INV-4, PRE-3).
const (
	MinDailyCap = 1_000
	MaxDailyCap = 5_000_000
)

// ValidDailyCap reports whether n is allowed as a shared or per-profile daily token cap.
func ValidDailyCap(n int) bool { return n >= MinDailyCap && n <= MaxDailyCap }
