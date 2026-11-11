package main

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// The release preflight (WP-08j). Nothing here signs or publishes: it refuses a build that must never be published.

// testKeysTag is the build tag of keys_testonly.go (internal/release): the throwaway release keys. A binary that carries them
// would trust a key whose private half is in the repository.
const testKeysTag = "releasetestkeys"

// CheckBinary refuses the Go binary at path when it was built with -tags releasetestkeys or carries no build information
// (a binary without it cannot be shown clean). It reads the build info the way `go version -m` does, without running anything.
func CheckBinary(path string) error {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: no Go build information (is it a Go binary?): %w", path, err)
	}
	for _, s := range bi.Settings {
		if s.Key == "-tags" && slices.Contains(strings.Split(s.Value, ","), testKeysTag) {
			return fmt.Errorf("%s was built with -tags %s: it embeds the throwaway release keys, never publish it", path, testKeysTag)
		}
	}
	return nil
}

func cmdCheckBinaries(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("check-binaries needs at least one binary (core, vedette-host)")
	}
	var errs []error
	for _, p := range args {
		if err := CheckBinary(p); err != nil {
			errs = append(errs, err)
			continue
		}
		say(stdout, "ok: %s is built without -tags %s", p, testKeysTag)
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
