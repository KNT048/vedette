package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -self-update-apply (D-316): root only, a well-formed run id, no other flag, and only as the copy
// <state>/selfupdate/applier, whose folder gives the state directory (never /usr/lib/vedette/vedette-host).
func TestSelfUpdateApplyRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(state, "selfupdate"), 0o700); err != nil {
		t.Fatal(err)
	}
	applier := filepath.Join(state, "selfupdate", "applier")
	env, _ := testEnv(t)
	env.executable = func() (string, error) { return applier, nil }
	for name, c := range map[string]struct {
		args []string
		euid int
		exe  string
		want string
	}{
		"not root":        {[]string{"-self-update-apply", "rn_0123456789abcdef"}, 1000, applier, "root"},
		"bad run id":      {[]string{"-self-update-apply", "rn_x"}, 0, applier, "not a run id"},
		"another flag":    {[]string{"-self-update-apply", "rn_0123456789abcdef", "-state-dir", dir}, 0, applier, "no other flag"},
		"the installed":   {[]string{"-self-update-apply", "rn_0123456789abcdef"}, 0, "/usr/lib/vedette/vedette-host", "only as"},
		"no journal here": {[]string{"-self-update-apply", "rn_0123456789abcdef"}, 0, applier, "journal"},
	} {
		e := env
		e.euid = c.euid
		exe := c.exe
		e.executable = func() (string, error) { return exe, nil }
		err := run(context.Background(), c.args, new(bytes.Buffer), e)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if s, err := applierStateDir(applier); err != nil || s != state {
		t.Fatalf("%q %v", s, err)
	}
}
