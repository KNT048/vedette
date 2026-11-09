package ai

import (
	"encoding/json"
	"regexp"
	"sort"

	"github.com/kiennt048/vedette/modules/ai/provider"
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
	// Jobs lists the jobs that may use the tool; empty = every job.
	Jobs   []Job
	Schema json.RawMessage
}

var toolNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (t Tool) offeredTo(job Job) bool {
	if t.Access != AccessRead || !t.Enabled || !toolNameRE.MatchString(t.Name) {
		return false
	}
	if len(t.Jobs) == 0 {
		return true
	}
	for _, j := range t.Jobs {
		if j == job {
			return true
		}
	}
	return false
}

// ForModel returns the tool list sent to the model for job: only tools with access "read" that are enabled
// and allowed for the job (INV-14, SYS-8). A write tool never appears, whatever its other fields say and
// whatever hooks are configured; there is no parameter that can add one. If two tools share a name and
// either is a write tool, the name is withheld altogether, so a read tool cannot stand in for a write tool
// of the same name. The result is sorted by name so the prompt is stable.
func ForModel(job Job, tools []Tool) []provider.ToolDef {
	writeNames := map[string]bool{}
	for _, t := range tools {
		if t.Access != AccessRead {
			writeNames[t.Name] = true
		}
	}
	seen := map[string]bool{}
	var defs []provider.ToolDef
	for _, t := range tools {
		if writeNames[t.Name] || seen[t.Name] || !t.offeredTo(job) {
			continue
		}
		seen[t.Name] = true
		defs = append(defs, provider.ToolDef{Name: t.Name, Description: t.Description, InputSchema: t.Schema})
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs
}

// Offered returns the tool a model's call refers to, only if ForModel offered it for this job. A call to
// any other name (a write tool, a disabled tool, an invented one) gets ok=false and must not run.
func Offered(job Job, tools []Tool, name string) (Tool, bool) {
	for _, d := range ForModel(job, tools) {
		if d.Name != name {
			continue
		}
		for _, t := range tools {
			if t.Name == name {
				return t, true
			}
		}
	}
	return Tool{}, false
}
