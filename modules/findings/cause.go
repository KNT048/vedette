package findings

import "slices"

// The cause of a possible CVE: why it is still undecided now and what would decide it, one of a closed list. Where Undecided says
// what in the data blocked the match (the rows, the advisory text), the cause says which step of deciding is missing: data that has
// not come yet, an input only the device or a person has, a page nobody can read, the AI's reading (not set up, out of budget, unsure),
// or a person's word. Every possible CVE has exactly one (PossibleCause); TestPossibleCause_EveryPossibleRowHasOne checks it.
const (
	CauseVendorSilent     = "vendor_silent"     // no vendor page states more than the record (a third party's word, or no page at all)
	CausePageUnreadable   = "page_unreadable"   // the vendor's page could not be read (a script-rendered portal, a refusal)
	CauseNeedsReading     = "needs_reading"     // the vendor's advisory must be read: no AI is set up, or the AI's reading is still to come
	CauseAIUnsure         = "ai_unsure"         // the AI read the pages and could not tell, or its quote was not in the page
	CauseAIBudget         = "ai_budget"         // the AI's reading waits for the budget (today's reads or this month's tokens)
	CauseIdentityUnproven = "identity_unproven" // the software is not tied to a product the CVE records name in a way the box can check
	CauseVersionNeeded    = "version_needed"    // the version, build, edition, system or package release only the device or a person states
	CausePendingNVD       = "pending_nvd"       // NVD has not listed the affected versions yet
	CauseNeedsPerson      = "needs_person"      // a person decides: an exploited CVE read not affected, or a reading a person rejected
)

// PossibleCauses is the closed list of causes.
var PossibleCauses = []string{CauseVendorSilent, CausePageUnreadable, CauseNeedsReading, CauseAIUnsure, CauseAIBudget, CauseIdentityUnproven,
	CauseVersionNeeded, CausePendingNVD, CauseNeedsPerson}

// ReadState is how the AI's reading of advisories stands on this box, as a cause reads it.
type ReadState struct {
	Ready         bool // a reading can run (the AI module on, a profile for explaining findings)
	Auto          bool // it runs by itself after a match pass
	BudgetReached bool // today's automatic reads or this month's tokens for background jobs are used up
}

// PossibleCause is the cause of one possible CVE (one of PossibleCauses), "" for an item that is not possible (settled from the
// vendor's word). The one function every reader of causes calls: the lists, the audit and the coverage of a match pass.
func PossibleCause(it PossibleItem, rs ReadState) string {
	q := it.Question
	reason := ""
	if q.Detail.Undecided != nil {
		reason = q.Detail.Undecided.Reason
	}
	switch {
	case it.State == PossibleSettled:
		return ""
	case it.State == PossibleProposal:
		return CauseNeedsPerson
	case q.Detail.NVDPending || reason == UndecidedNVDPending:
		return CausePendingNVD
	case q.Kind == QuestionVersionNeeded || q.Kind == QuestionPlatform || q.Kind == QuestionPackageRelease,
		slices.Contains([]string{UndecidedNoVersion, UndecidedPlatform, UndecidedPackage}, reason),
		reason == UndecidedAttribute && q.CheckKey == "": // an unlisted release line the reading can decide is the reading's (checkable)
		return CauseVersionNeeded
	case reason == UndecidedPlatformOnly:
		// NVD names the operating system only as the environment of the affected software: not affected as a product, and only an
		// exploited CVE makes a row of it at all, which a person closes
		return CauseNeedsPerson
	}
	if c := it.Check; c != nil {
		if c.RejectedBy != "" {
			return CauseNeedsPerson
		}
		if st := c.Reading; st != nil {
			switch {
			case st.Status == StatementUnsure || !st.QuoteFound:
				return CauseAIUnsure
			case st.verdictFor(*c.idOr(q)) == VerdictNotAffected && st.VendorPage && it.Exploited:
				return CauseNeedsPerson
			}
			return CauseVendorSilent // the page the AI read states nothing that decides this version, or is not the vendor's
		}
		if c.Undecided != nil {
			switch c.Undecided.Reason {
			case UndecidedNoReference:
				return CauseVendorSilent
			case UndecidedFetchFailed:
				return CausePageUnreadable
			case UndecidedAIUnsure:
				return CauseAIUnsure
			}
		}
		if c.DecidedBy == DecidedAI && !c.Stale {
			return CauseAIUnsure
		}
	}
	if q.CheckKey == "" {
		if q.SoftwareID == "" || q.Detail.Version != "" && q.Detail.Check == nil {
			return CauseIdentityUnproven // a name-only match, or a line with no product the box can key a reading by
		}
		if q.Detail.Version == "" {
			return CauseVersionNeeded
		}
	}
	switch {
	case it.Unread:
		return CausePageUnreadable
	case !rs.Ready:
		return CauseNeedsReading
	case rs.BudgetReached:
		return CauseAIBudget
	}
	return CauseNeedsReading
}

// idOr is the check's identity, else the question's.
func (c Check) idOr(q Question) *CheckID {
	if c.ID.Product != "" {
		return &c.ID
	}
	if q.Detail.Check != nil {
		return q.Detail.Check
	}
	return &CheckID{}
}
