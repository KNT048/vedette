package mitigation

import (
	"context"
	"errors"

	"github.com/knt048/vedette/modules/findings"
)

// Skill is what the customer's AI is asked to do for a finding (POST /findings/{id}/ai).
type Skill string

// The two skills. The AI jobs behind them are "explain-finding" and "mitigation-config".
const (
	SkillExplain Skill = "explain"
	SkillConfig  Skill = "mitigation-config"
)

// ErrAIUnavailable is what AI.Run returns when no profile is assigned to the job or the ai module is
// off; the handler answers 409 ai_unavailable.
var ErrAIUnavailable = errors.New("ai unavailable")

// AIRequest is what the AI gets: the finding as the page shows it, which is device and KEV data of
// the customer's own box, and whether a confirmed pack exists (the config skill is for when it does not).
type AIRequest struct {
	Skill   Skill
	Finding findings.Row
	HasPack bool
	User    string // email of the person who asked
}

// AIOutput is the answer of the AI module, already metered and logged by it.
type AIOutput struct {
	Model      string
	Profile    string // name of the profile that answered
	InputTok   int
	OutputTok  int
	Paragraphs []string
	Steps      []string
	Citations  []findings.Citation
	ActivityID string // id of the ai_activity row, "" when none
}

// AI is the small door to the ai module (its RunJob, WP-25, not wired yet). The AI never gets a write
// tool here (SYS-8): it returns text and this module stores it as an AI result.
type AI interface {
	// Available reports whether a profile is assigned and allowed for the skill and the ai module is on.
	Available(ctx context.Context, s Skill) bool
	// Run asks the AI. ErrAIUnavailable (wrapped) when it cannot be used.
	Run(ctx context.Context, req AIRequest) (AIOutput, error)
}

// Vendors is what mitigation reads from the inventory (Kien's) to mark the firewall guides (INV-5).
type Vendors interface {
	// HasFirewallVendor reports whether the inventory has a firewall or router whose vendor is the
	// given lower-case inventory vendor name ("fortinet", "mikrotik").
	HasFirewallVendor(ctx context.Context, vendor string) (bool, error)
}

// Verifier checks the signature of an update (core/updates, Kien's; not built yet).
type Verifier interface {
	// Verify returns nil only when the signature of the whole update is valid.
	Verify(ctx context.Context, u Update) error
}
