package opstest

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
)

// Envs reads what `export -p` of the fake's shell wrote: dash (Ubuntu, CI) and bash in POSIX mode (macOS /bin/sh)
// quote differently, and both must give back the exact values, sorted, without the shell's own variables.
func TestEnvsParsesExportOfDashAndBash(t *testing.T) {
	t.Parallel()
	const script = `export Q='it'"'"'s "x" $y \z' EMPTY=; { echo "=== env"; export -p; echo "=== env"; export -p; } > "$1"`
	want := []string{"EMPTY=", `Q=it's "x" $y \z`}
	ran := 0
	for _, sh := range [][]string{{"/bin/dash"}, {"/bin/bash", "--posix"}, {"/bin/sh"}} {
		if _, err := os.Stat(sh[0]); err != nil {
			continue
		}
		ran++
		m := &Machine{Rec: t.TempDir()}
		r, err := vexec.NewRunner(slog.New(slog.DiscardHandler), vexec.Binary{Name: "sh", Path: sh[0], Validate: func([]string) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		res, err := r.Run(ctx, "sh", append(sh[1:], "-c", script, "sh", filepath.Join(m.Rec, "x.env")), nil)
		cancel()
		if err != nil {
			t.Fatalf("%v: %v %s", sh, err, res.Stderr)
		}
		got := m.Envs("x")
		if len(got) != 2 {
			b, _ := os.ReadFile(filepath.Join(m.Rec, "x.env"))
			t.Fatalf("%v: %d calls, want 2:\n%s", sh, len(got), b)
		}
		for _, env := range got {
			if !slices.IsSorted(env) {
				t.Errorf("%v: not sorted: %q", sh, env)
			}
			mine := slices.DeleteFunc(slices.Clone(env), func(s string) bool {
				return strings.HasPrefix(s, "PATH=") || strings.HasPrefix(s, "LANG=")
			})
			if !slices.Equal(mine, want) {
				t.Errorf("%v: %q, want %q (and only PATH and LANG besides)", sh, env, want)
			}
		}
	}
	if ran == 0 {
		t.Skip("no /bin/sh, /bin/dash or /bin/bash")
	}
}
