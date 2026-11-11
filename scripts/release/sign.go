package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // release helper outside the product: fixed argv (the pinned minisign), no shell
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Signer signs a file the way a release is signed: a detached minisign signature (prehashed "ED") at sigPath, with a trusted
// comment that the signature covers. The private key never enters this program: MinisignCLI hands a path to the pinned minisign
// tool, and the passphrase reaches it on its stdin.
type Signer interface {
	SignFile(ctx context.Context, path, sigPath, trustedComment string) error
}

// MinisignCLI signs with the minisign command line tool (version and checksum pinned in deploy/tools.env).
type MinisignCLI struct {
	Bin     string // absolute path of the minisign binary
	KeyPath string // the secret key file: mode 0600 or stricter, outside the repository
	// Passphrase is sent to minisign on stdin. With a nil Passphrase minisign prompts on the terminal (Interactive), which is how
	// the maintainer normally signs; an unencrypted test key needs neither.
	Passphrase  []byte
	Interactive bool
	// RepoRoot is the root of the repository the key must stay out of (main sets it from git); empty means the working directory.
	RepoRoot string
}

var commentRE = regexp.MustCompile(`^[ -~]{1,200}$`)

// SignFile runs `minisign -S -s <key> -m <path> -x <sigPath> -t <comment>`.
func (s MinisignCLI) SignFile(ctx context.Context, path, sigPath, trustedComment string) error {
	if !commentRE.MatchString(trustedComment) {
		return errors.New("the trusted comment must be one line of printable ASCII")
	}
	if !filepath.IsAbs(s.Bin) {
		return errors.New("the minisign binary must be an absolute path (see scripts/release/minisign.sh)")
	}
	if fi, err := os.Stat(s.Bin); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("minisign binary %s is not an executable file", s.Bin)
	}
	// The path handed to minisign is the resolved one that was checked: a symlink swapped after the check cannot redirect it.
	key, err := checkKeyFile(s.KeyPath, s.RepoRoot)
	if err != nil {
		return err
	}
	if err := os.Remove(sigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	timeout := time.Minute
	if s.Interactive {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Bin, "-S", "-s", key, "-m", path, "-x", sigPath, "-t", trustedComment) //nolint:gosec // fixed argv; paths are the maintainer's, checked above
	cmd.Env = []string{"LC_ALL=C"}
	var out bytes.Buffer
	switch {
	case s.Interactive && s.Passphrase == nil:
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	default:
		if s.Passphrase != nil {
			line := append(append([]byte{}, s.Passphrase...), '\n')
			defer clear(line) // the copy handed to the pipe; the caller clears Passphrase itself
			cmd.Stdin = bytes.NewReader(line)
		}
		cmd.Stdout, cmd.Stderr = &out, &out
	}
	if err := cmd.Run(); err != nil {
		_ = os.Remove(sigPath)
		return fmt.Errorf("minisign did not sign %s: %w%s", filepath.Base(path), err, tail(out.String()))
	}
	if fi, err := os.Stat(sigPath); err != nil || fi.Size() == 0 {
		return fmt.Errorf("minisign reported success but wrote no signature to %s", sigPath)
	}
	return nil
}

// tail is the last of minisign's output for an error message (it prints the key id and progress, never the passphrase).
func tail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 300 {
		s = "..." + s[len(s)-300:]
	}
	return ": " + strings.Join(strings.Fields(s), " ")
}

// checkKeyFile refuses a secret key that other users can read, or that sits inside the repository (a private key never
// touches the repo: a stray `git add -A` would publish it).
// It returns the resolved path (symlinks followed) to hand to the tool. root is the repository root; empty means the working directory.
func checkKeyFile(p, root string) (string, error) {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("secret key: %w", err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("secret key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("secret key %s is not a regular file", p)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret key %s is readable by other users (mode %04o): chmod 600", p, fi.Mode().Perm())
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	if root != "" {
		if r, err := filepath.EvalSymlinks(root); err == nil {
			if rel, err := filepath.Rel(r, resolved); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("secret key %s is inside the repository %s: keep keys outside it", p, r)
			}
		}
	}
	return resolved, nil
}
