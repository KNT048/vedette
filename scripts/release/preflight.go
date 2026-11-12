package main

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

// The release preflight (WP-08j). Nothing here signs or publishes: it refuses a build that must never be published.

// testKeysTag is the build tag of keys_testonly.go (internal/release): the throwaway release keys.
const testKeysTag = "releasetestkeys"

// maxBinary bounds what CheckBinary reads into memory (vedette-host is a few tens of MB).
const maxBinary = 512 << 20

// BinaryRules say how strict CheckBinary is. A zero value only refuses -tags releasetestkeys.
type BinaryRules struct {
	// Release is the check of a binary about to be published: it must come from a clean checkout (vcs.modified=false, a revision),
	// and it must contain the bytes of every key in Keys. A build with the throwaway keys swapped in through `go build -overlay`
	// records neither -overlay nor -tags, so the only proof that the production keys are inside is the keys themselves.
	Release bool
	Keys    []string // key lines that must appear verbatim in the binary (Release only)
}

// CheckBinary refuses the Go binary at path when it was built with -tags releasetestkeys or carries no build information
// (a binary without it cannot be shown clean); with rules.Release also the dirty tree and a missing production key.
// It reads the build info the way `go version -m` does, without running anything.
func CheckBinary(path string, rules BinaryRules) error {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: no Go build information (is it a Go binary?): %w", path, err)
	}
	set := map[string]string{}
	for _, s := range bi.Settings {
		set[s.Key] = s.Value
	}
	if slices.Contains(strings.Split(set["-tags"], ","), testKeysTag) {
		return fmt.Errorf("%s was built with -tags %s: it embeds the throwaway release keys, never publish it", path, testKeysTag)
	}
	if !rules.Release {
		return nil
	}
	if set["vcs.revision"] == "" {
		return fmt.Errorf("%s has no vcs.revision: build the release from a git checkout", path)
	}
	if set["vcs.modified"] != "false" {
		return fmt.Errorf("%s was built from a tree with uncommitted changes (vcs.modified=%q): commit first, a release is its commit", path, set["vcs.modified"])
	}
	return checkKeys(path, rules.Keys)
}

// checkKeys refuses a binary that does not contain every key line verbatim (Go keeps string constants as they are).
func checkKeys(path string, keys []string) error {
	if len(keys) == 0 {
		return errors.New("no production keys to look for")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() > maxBinary {
		return fmt.Errorf("%s: cannot read it (or it is over %d MB)", path, maxBinary>>20)
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path is the binary the maintainer asked to check
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !bytes.Contains(data, []byte(k)) {
			return fmt.Errorf("%s does not contain the production release key %.12s…: it was built with other keys (-overlay?), never publish it", path, k)
		}
	}
	return nil
}

func cmdCheckBinaries(args []string, stdout io.Writer) error {
	fs := newFlags("check-binaries")
	rel := fs.Bool("release", false, "the checks of a binary about to be published: clean tree, and the production key bytes inside (use for vedette-host only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("check-binaries needs at least one binary")
	}
	rules := BinaryRules{Release: *rel}
	if *rel {
		active, backup, testOnly := release.EmbeddedMinisignKeys()
		if testOnly || active == "" || backup == "" {
			return errors.New("this checker was built with the throwaway keys or none: run it with GOFLAGS= and without -tags")
		}
		rules.Keys = []string{active, backup}
	}
	var errs []error
	for _, p := range fs.Args() {
		if err := CheckBinary(p, rules); err != nil {
			errs = append(errs, err)
			continue
		}
		say(stdout, "ok: %s (no -tags %s%s)", p, testKeysTag, map[bool]string{true: ", clean tree, production keys inside"}[*rel])
	}
	return errors.Join(errs...)
}

// cmdMinSequence prints the sequence of the published index, verified like every previous index: the MIN_SEQUENCE the release's
// vedette-host is built with (a box that holds the index of that sequence accepts nothing lower).
func cmdMinSequence(args []string, stdout io.Writer) error {
	fs := newFlags("min-sequence")
	prev := fs.String("prev-index", "", "directory of the published index (index.json and index.json.minisig)")
	keys := fs.String("keys-dir", "", "directory with the public keys (default: the keys compiled in)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prev == "" {
		return errors.New("-prev-index is required")
	}
	trust, err := LoadTrust(*keys)
	if err != nil {
		return err
	}
	idx, err := LoadPrevIndex(*prev, trust)
	if err != nil {
		return err
	}
	say(stdout, "%d", idx.Sequence)
	return nil
}
