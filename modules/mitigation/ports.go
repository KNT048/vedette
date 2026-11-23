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

// AIRequest is what the AI is asked about: one finding, by id. The AI door reads the finding's view and the brief of its CVE itself, the
// same sources the page reads, and whether a confirmed pack exists (the config skill is for when it does not).
type AIRequest struct {
	Skill     Skill
	FindingID string
	HasPack   bool
	User      string // email of the person who asked
}

// AIOutput is the answer of the AI module, already metered and logged by it.
type AIOutput struct {
	Model      string
	Profile    string // name of the profile that answered
	InputTok   int
	OutputTok  int
	Paragraphs []string
	Steps      []string
	// Answers are the four answers in order (findings.AIResult.Answers).
	Answers []findings.AIAnswer
	// Configs are the ready config blocks of the mitigation-config skill (Code is the lines to paste, Note what the change is based
	// on, SideEffect what it can break); none for explain.
	Configs []findings.CodeStep
	// NoConfigReason says why no config (or no firewall rule) helps for this finding, when the AI gave none (#897 r1 H1).
	NoConfigReason string
	// Shortened: a part of the answer was longer than the AI module keeps (cut at a sentence end, or a config block left out whole).
	Shortened  bool
	Citations  []findings.Citation
	ActivityID string // id of the ai_activity row, "" when none
}

// AI is the small door to the ai module (its RunJob, WP-25, not wired yet). The AI never gets a write
// tool here (SYS-8): it returns text and this module stores it as an AI result.
type AI interface {
	// Available reports whether a profile is assigned and allowed for the skill and the ai module is on.
	Available(ctx context.Context, s Skill) bool
	// Run asks the AI. ErrAIUnavailable (wrapped) when it cannot be used; an *apierr.Error of the ai module (ai_unavailable,
	// budget_reached, ai_cut_off, ai_bad_format, blocked_by_hook, provider_error, unreachable, ai_timeout) is answered as it is.
	Run(ctx context.Context, req AIRequest) (AIOutput, error)
}

// Vendors is what mitigation reads from the inventory to mark the firewall guides of a confirmed pack (INV-5).
type Vendors interface {
	// HasFirewallVendor reports whether the inventory has a firewall or router whose vendor is the
	// given lower-case inventory vendor name ("fortinet", "mikrotik").
	HasFirewallVendor(ctx context.Context, vendor string) (bool, error)
}

// Verifier checks the signature of an update (core/updates; not built yet).
type Verifier interface {
	// Verify returns nil only when the signature of the whole update is valid. The signature must bind
	// Update.Version and the bytes of every Docs[].Data (and their set), or the replay protection and
	// the confirmed-pack rule can be bypassed by swapping what the signature does not cover.
	Verify(ctx context.Context, u Update) error
}
