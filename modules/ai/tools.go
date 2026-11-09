package ai

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/knt048/vedette/modules/ai/provider"
)

// Access says whether a tool only reads or can change something.
type Access string

// Tool access levels. Anything that is not exactly "read" is treated as write.
const (
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

// Tool is a tool known to the box: a product tool such as search_assets, or one of a connection (`ConnectorTool`).
type Tool struct {
	Name        string
	Description string
	Access      Access
	Enabled     bool
	// Public marks a tool whose results hold no customer data (for example a public CVE lookup). Only Public
	// tools may be offered to jobs that do not carry internal data (cve-news, translate-advisory): those jobs
	// may run on a cloud profile under the privacy rule, so a tool that reads logs or assets must never reach them.
	Public bool
	// Jobs lists the jobs that may use the tool. For a job that carries internal data an empty list means every
	// job; for a job that does not, the job must be listed (empty never means "every job" there).
	Jobs []Job
	// ConnectorID names the connection a tool belongs to ("" for product tools), so a call is dispatched to
	// exactly the tool that was offered.
	ConnectorID string
	Schema      json.RawMessage
}

var toolNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// nameKey is how tool names are compared: case and surrounding spaces do not make a different tool.
func nameKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func (t Tool) offeredTo(job Job) bool {
	if t.Access != AccessRead || !t.Enabled || !toolNameRE.MatchString(t.Name) {
		return false
	}
	listed := false
	for _, j := range t.Jobs {
		listed = listed || j == job
	}
	if !job.CarriesInternalData() {
		return t.Public && listed
	}
	return len(t.Jobs) == 0 || listed
}

// offered picks, for each name, the tool the model is offered: the first enabled read tool for the job, unless
// any tool of that name (any case) is a write tool, in which case the name is withheld altogether.
func offered(job Job, tools []Tool) []Tool {
	writeNames := map[string]bool{}
	for _, t := range tools {
		if t.Access != AccessRead {
			writeNames[nameKey(t.Name)] = true
		}
	}
	seen := map[string]bool{}
	var out []Tool
	for _, t := range tools {
		k := nameKey(t.Name)
		if writeNames[k] || seen[k] || !t.offeredTo(job) {
			continue
		}
		seen[k] = true
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ForModel returns the tool list sent to the model for job: only tools with access "read" that are enabled
// and allowed for the job (INV-14, SYS-8). A write tool never appears, whatever its other fields say and
// whatever hooks are configured; there is no parameter that can add one. If two tools share a name (case and
// spaces ignored) and either is a write tool, the name is withheld altogether, so a read tool cannot stand in
// for a write tool of the same name. A job that carries no internal data gets only Public tools. The result is
// sorted by name so the prompt is stable.
func ForModel(job Job, tools []Tool) []provider.ToolDef {
	var defs []provider.ToolDef
	for _, t := range offered(job, tools) {
		defs = append(defs, provider.ToolDef{Name: t.Name, Description: t.Description, InputSchema: t.Schema})
	}
	return defs
}

// Offered returns exactly the tool ForModel offered under that name, with its ConnectorID. A call to any
// other name (a write tool, a disabled tool, a tool of another job, an invented one) gets ok=false and must
// not run.
func Offered(job Job, tools []Tool, name string) (Tool, bool) {
	for _, t := range offered(job, tools) {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}
