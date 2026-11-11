// Command release is the release builder (WP-08f, D-164): it turns a release description, the built image digests, the cosign
// signatures and the previous release into the documents the box verifies (release-manifest.json, index.json), signs them
// with the pinned minisign tool, and verifies the result with the box-side verifier (internal/release) before anything is
// published. It runs on the maintainer's machine, offline; it pushes nothing, creates no tag and holds no key.
//
//	go run ./scripts/release cosign-plan -in release.in.json -key ~/keys/cosign.key -out dist/release/cosign
//	go run ./scripts/release manifest    -in release.in.json -cosign-dir dist/release/cosign -out dist/release [-prev DIR -prev-ref v0.1.0 -keys-dir DIR]
//	go run ./scripts/release index       -out dist/release -manifest dist/release/release-manifest.json [-prev DIR -keys-dir DIR]
//	go run ./scripts/release sign        -dir dist/release -key ~/keys/minisign.key -minisign /abs/minisign [-slot backup] [-passphrase-stdin]
//	go run ./scripts/release verify      -dir dist/release [-prev DIR] [-keys-dir DIR]
//
// See `make help` (release-*) for the make targets and docs/specs/update-manifest.md for the documents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knt048/vedette/internal/release"
)

const maxPassphrase = 1024

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "usage: release cosign-plan|manifest|index|sign|verify [flags]")
		return 2
	}
	var err error
	ctx := context.Background()
	switch args[0] {
	case "cosign-plan":
		err = cmdCosignPlan(args[1:], stdout)
	case "manifest":
		err = cmdManifest(ctx, args[1:], stdout, stderr)
	case "index":
		err = cmdIndex(args[1:], stdout)
	case "sign":
		err = cmdSign(ctx, args[1:], stdin, stdout)
	case "verify":
		err = cmdVerify(args[1:], stdout)
	default:
		say(stderr, "release: unknown command %q", args[0])
		return 2
	}
	if err != nil {
		say(stderr, "release: %v", err)
		var ge *GuardError
		if errors.As(err, &ge) {
			return 3
		}
		return 1
	}
	return 0
}

// say prints one line; a failed write to a terminal or a buffer is not something this tool can act on.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// shellQuote quotes for a POSIX shell: the plan is printed for a person to read and run, never executed here.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func readInputs(p string) (Inputs, error) {
	raw, err := readSmall(p, 1<<20)
	if err != nil {
		return Inputs{}, err
	}
	return ParseInputs(raw)
}

func cmdCosignPlan(args []string, stdout io.Writer) error {
	fs := newFlags("cosign-plan")
	in := fs.String("in", "release.in.json", "release description")
	key := fs.String("key", "", "cosign private key file (COSIGN_PASSWORD names its password in the environment of the shell that runs the plan)")
	out := fs.String("out", "dist/release/cosign", "directory the payloads and signatures are written to")
	bin := fs.String("cosign", "cosign", "cosign command (the pinned binary, WP-08k)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return errors.New("-key is required")
	}
	inputs, err := readInputs(*in)
	if err != nil {
		return err
	}
	say(stdout, "mkdir -p %s", shellQuote(*out))
	for _, im := range inputs.Images {
		argv, err := CosignArgv(*bin, *key, *out, im.Service, im.Digest)
		if err != nil {
			return err
		}
		q := make([]string, len(argv))
		for i, a := range argv {
			q[i] = shellQuote(a)
		}
		say(stdout, "%s", strings.Join(q, " "))
	}
	return nil
}

func cmdManifest(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("manifest")
	in := fs.String("in", "release.in.json", "release description")
	out := fs.String("out", "dist/release", "output directory")
	cosignDir := fs.String("cosign-dir", "", "directory with <service>.payload.json and <service>.sig from cosign")
	prev := fs.String("prev", "", "directory of the previous release (index.json, release-manifest.json and their .minisig)")
	prevRef := fs.String("prev-ref", "", "git ref of the previous release (default v<its version>)")
	prevMig := fs.String("prev-migrations", "", "directory holding the previous release's modules/*/migrations (instead of -prev-ref)")
	repo := fs.String("repo", ".", "repository root")
	keys := fs.String("keys-dir", "", "directory with minisign.pub, minisign-backup.pub, cosign.pub (default: the keys compiled in)")
	now := fs.String("now", "", "RFC 3339 time to use as released_at when the description has none (default now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs, err := readInputs(*in)
	if err != nil {
		return err
	}
	env := Env{Now: time.Now(), CosignDir: *cosignDir}
	if *now != "" {
		if env.Now, err = time.Parse(time.RFC3339, *now); err != nil {
			return fmt.Errorf("-now: %w", err)
		}
	}
	if env.CurTree, err = DirTree(os.DirFS(*repo)); err != nil {
		return fmt.Errorf("migrations of the working tree: %w", err)
	}
	if *prev != "" {
		trust, err := LoadTrust(*keys)
		if err != nil {
			return err
		}
		if env.Prev, err = LoadPrev(*prev, trust); err != nil {
			return err
		}
		switch {
		case *prevMig != "":
			env.PrevTree, err = DirTree(os.DirFS(*prevMig))
		default:
			ref := *prevRef
			if ref == "" {
				ref = "v" + env.Prev.Manifest.Version
			}
			env.PrevTree, err = GitTree(ctx, *repo, ref)
		}
		if err != nil {
			return fmt.Errorf("migrations of the previous release: %w", err)
		}
	}
	res, err := BuildManifest(inputs, env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // build output, not secret
		return err
	}
	p := filepath.Join(*out, manifestFile)
	if err := os.WriteFile(p, res.Manifest, 0o644); err != nil { //nolint:gosec // build output, not secret
		return err
	}
	say(stdout, "wrote %s (version %s, db_schema %d, rollback.safe=%t)", p, inputs.Version, res.DBSchema, inputs.Rollback.Safe)
	if !inputs.Rollback.Safe && len(res.Findings) > 0 {
		say(stderr, "rollback.safe=false is right: the migrations since the previous release are not add-only:")
		for _, f := range res.Findings {
			say(stderr, "  - %s", f)
		}
	}
	return nil
}

func cmdIndex(args []string, stdout io.Writer) error {
	fs := newFlags("index")
	out := fs.String("out", "dist/release", "output directory")
	manifest := fs.String("manifest", "", "release-manifest.json of the release to announce (empty: only refresh the index)")
	prev := fs.String("prev", "", "directory of the previous release (its index carries revocations and the other channel)")
	keys := fs.String("keys-dir", "", "directory with the public keys (default: the keys compiled in)")
	seq := fs.Uint64("sequence", 0, "index sequence (default previous + 1)")
	rollout := fs.Int("rollout", -1, "rollout percent of the channel (default 100)")
	days := fs.Int("valid-days", 14, "days until expires_at (at most 14)")
	now := fs.String("now", "", "RFC 3339 generated_at (default now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := IndexParams{Now: time.Now(), Sequence: *seq, Rollout: *rollout, ValidFor: time.Duration(*days) * 24 * time.Hour}
	if *days <= 0 {
		return errors.New("-valid-days must be positive")
	}
	if *now != "" {
		t, err := time.Parse(time.RFC3339, *now)
		if err != nil {
			return fmt.Errorf("-now: %w", err)
		}
		p.Now = t
	}
	var prevIndex *release.Index
	if *prev != "" {
		trust, err := LoadTrust(*keys)
		if err != nil {
			return err
		}
		if prevIndex, err = verifyIndexFile(*prev, trust, nil); err != nil {
			return fmt.Errorf("previous index: %w", err)
		}
	}
	if *manifest != "" {
		raw, err := readDoc(*manifest)
		if err != nil {
			return err
		}
		var d struct {
			Version string `json:"version"`
			Channel string `json:"channel"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("manifest: %w", err)
		}
		p.ManifestVersion, p.Channel, p.ManifestRaw = d.Version, d.Channel, raw
	}
	files, err := BuildIndex(prevIndex, p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // build output, not secret
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*out, f.Name), f.Data, 0o644); err != nil { //nolint:gosec // build output, not secret
			return err
		}
		say(stdout, "wrote %s", filepath.Join(*out, f.Name))
	}
	return nil
}

func cmdSign(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlags("sign")
	dir := fs.String("dir", "dist/release", "directory with the documents")
	key := fs.String("key", "", "minisign secret key file (mode 600, outside the repository)")
	bin := fs.String("minisign", "", "absolute path of the pinned minisign (scripts/release/minisign.sh prints it)")
	slot := fs.String("slot", "active", "active: index and manifest; backup: indexes only, into .backup.minisig (offline key, D-103)")
	pass := fs.Bool("passphrase-stdin", false, "read the key's passphrase from the first line of stdin (default: minisign asks on the terminal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *bin == "" {
		return errors.New("-key and -minisign are required")
	}
	if *slot != "active" && *slot != "backup" {
		return errors.New("-slot is active or backup")
	}
	s := MinisignCLI{Bin: *bin, KeyPath: *key, Interactive: true}
	if *pass {
		line, err := readLine(stdin)
		if err != nil {
			return fmt.Errorf("passphrase: %w", err)
		}
		s.Passphrase, s.Interactive = []byte(line), false
	}
	written, err := SignRelease(ctx, s, *dir, *slot == "backup")
	for _, w := range written {
		say(stdout, "signed %s", w)
	}
	return err
}

// readLine reads one line of at most maxPassphrase bytes, a byte at a time so nothing after the line is consumed.
func readLine(r io.Reader) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for len(b) <= maxPassphrase {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return strings.TrimSuffix(string(b), "\r"), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(b) > 0 {
				return string(b), nil
			}
			return "", err
		}
	}
	return "", errors.New("line too long")
}

func cmdVerify(args []string, stdout io.Writer) error {
	fs := newFlags("verify")
	dir := fs.String("dir", "dist/release", "directory with the signed documents")
	prev := fs.String("prev", "", "directory of the previous release (sequence must not go back)")
	keys := fs.String("keys-dir", "", "directory with the public keys (default: the keys compiled in, which must be the real release keys)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	trust, err := LoadTrust(*keys)
	if err != nil {
		return err
	}
	s, err := VerifyDir(*dir, *prev, trust)
	if err != nil {
		return err
	}
	say(stdout, "verified: index sequence %d signed by %s, release %s (%s), backup signature %t", s.Sequence, s.IndexKeyID, s.Version, s.Channel, s.BackupSig)
	for _, im := range s.Images {
		say(stdout, "  image %s (cosign verified)", im)
	}
	return nil
}
