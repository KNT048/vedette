package modules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/modreg"
)

// Walk-1 W1-25: Settings → Modules shows a name and a summary for every module the box lists. The names live in the GUI's
// common.json (modules.<id>.name, .summary); every module manifest (not the host component) must have both, so a new module
// without a display name fails here, not on a customer's screen.
func TestEveryModuleHasADisplayName(t *testing.T) {
	t.Parallel()
	ms, err := modreg.Load(Manifests)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "web", "src", "locales", "en", "common.json"))
	if err != nil {
		t.Fatal(err)
	}
	var common struct {
		Modules map[string]struct{ Name, Summary string } `json:"modules"`
	}
	if err := json.Unmarshal(b, &common); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range ms {
		if m.Component {
			continue
		}
		n++
		if d := common.Modules[m.ID]; strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Summary) == "" {
			t.Errorf("module %s has no display name or summary in web/src/locales/en/common.json (modules.%s)", m.ID, m.ID)
		}
	}
	if n < 10 {
		t.Fatalf("only %d modules loaded", n)
	}
}
