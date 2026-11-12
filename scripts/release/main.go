// Command release is the release builder (WP-08f, D-164): it turns a release description, the built image digests, the cosign
// signatures and the previous release into the documents the box verifies (release-manifest.json, index.json), signs them
// with the pinned minisign tool, and verifies the result with the box-side verifier (internal/release) before anything is
// published. It runs on the maintainer's machine, offline except push and publish (D-457); it creates no tag and holds no key.
//
//	go run ./scripts/release cosign-plan -in release.in.json -images dist/release/images.json -sbom dist/sbom -key ~/keys/cosign.key -out dist/release/cosign   (prints the sign lines, then a cosign attest --type cyclonedx line per platform SBOM)
//	go run ./scripts/release manifest    -in release.in.json -cosign-dir dist/release/cosign -out dist/release [-prev-index DIR -ref v0.2.0 -baseline-ref v0.1.0 -keys-dir DIR]
//	go run ./scripts/release container-assets -in release.in.json -out dist/release [-ref v0.2.0 -compose-dir deploy/compose/container-only]   (D-451: the compose files and the filled vedette.env, read from git at the tag; sign signs them, verify checks them)
//	go run ./scripts/release index       -out dist/release -manifest dist/release/release-manifest.json [-prev-index DIR -keys-dir DIR]
//	go run ./scripts/release index       -out dist/refresh -prev-index DIR        (the weekly refresh: no manifest; then sign and verify the same directory)
//	go run ./scripts/release index       ... -revoke-key <key id> -revoke-reason TEXT   (a key revocation; it counts only in an index the backup key signs)
//	go run ./scripts/release min-sequence -prev-index DIR [-keys-dir DIR]   (prints the sequence of the published index: the MIN_SEQUENCE of vedette-host; index -min-sequence N refuses a sequence not above it)
//	go run ./scripts/release check-binaries BINARY...   (preflight: refuses a binary built with -tags releasetestkeys, the throwaway release keys)
//	go run ./scripts/release sign        -dir dist/release -key ~/keys/minisign.key -minisign /abs/minisign [-slot backup | -slot rescue -prev-index DIR -keys-dir DIR] [-passphrase-stdin]
//	go run ./scripts/release verify      -dir dist/release [-prev-index DIR] [-keys-dir DIR]
//	go run ./scripts/release packs       -dir content/mitigation/packs -version 2026.12.2.1 -key ~/keys/minisign.key -minisign /abs/minisign [-keys-dir DIR] [-passphrase-stdin]
//	go run ./scripts/release push        -version 0.2.0 [-registry ghcr.io/knt048] [-platforms linux/amd64,linux/arm64] -out dist/release   (D-457: the lists of make images, by digest; writes images.json)
//	go run ./scripts/release in          -images dist/release/images.json -channel stable -rollback-safe false [-rollback-min-version V] [-min-upgrade-from V] [-deb-dir dist] -out release.in.json
//	go run ./scripts/release publish     -dir dist/release -in release.in.json [-prev-index DIR | -first-release] [-keys-dir DIR] [-run]   (prints, or runs, the gh release commands; the index last)
//
// push and publish talk to the registry and GitHub (podman's login, gh's token); every other command is offline.
//
// See `make help` (release-*) for the make targets and docs/specs/update-manifest.md for the documents.
package main

import (
	"bytes"
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
		say(stderr, "usage: release cosign-plan|manifest|container-assets|index|min-sequence|check-binaries|sign|verify|packs|push|in|publish [flags]")
		return 2
	}
	var err error
	ctx := context.Background()
	switch args[0] {
	case "cosign-plan":
		err = cmdCosignPlan(ctx, args[1:], stdout)
	case "manifest":
		err = cmdManifest(ctx, args[1:], stdout, stderr)
	case "container-assets":
		err = cmdContainerAssets(ctx, args[1:], stdout)
	case "index":
		err = cmdIndex(args[1:], stdout)
	case "min-sequence":
		err = cmdMinSequence(args[1:], stdout)
	case "check-binaries":
		err = cmdCheckBinaries(args[1:], stdout)
	case "sign":
		err = cmdSign(ctx, args[1:], stdin, stdout)
	case "verify":
		err = cmdVerify(args[1:], stdout)
	case "packs":
		err = cmdPacks(ctx, args[1:], stdin, stdout)
	case "push":
		err = cmdPush(ctx, args[1:], stdout)
	case "in":
		err = cmdInputs(ctx, args[1:], stdout)
	case "publish":
		err = cmdPublish(ctx, args[1:], stdout)
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

func cmdCosignPlan(ctx context.Context, args []string, stdout io.Writer) error {
	return cosignPlanCmd(ctx, execRun, args, stdout)
}

// cosignPlanCmd is cosign-plan with the podman runner given (the tests fake it).
func cosignPlanCmd(ctx context.Context, run runFunc, args []string, stdout io.Writer) error {
	fs := newFlags("cosign-plan")
	in := fs.String("in", "release.in.json", "release description")
	images := fs.String("images", "dist/release/images.json", "what release push pushed, by digest (the platform digests the SBOMs attach to)")
	key := fs.String("key", "", "cosign private key file (COSIGN_PASSWORD names its password in the environment of the shell that runs the plan)")
	out := fs.String("out", "dist/release/cosign", "directory the payloads and signatures are written to (inside dist/)")
	sbom := fs.String("sbom", "dist/sbom", "directory of make sbom RELEASE=1 IMAGE_TAG=<version>: <image>-<arch>.cdx.json (inside dist/; each checked against the local image podman reports)")
	bin := fs.String("cosign", "cosign", "cosign command (the pinned binary: scripts/release/cosign.sh)")
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
	doc, err := readImages(*images)
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	plan, err := CosignPlan(ctx, run, inputs, doc, CosignPlanOpts{Bin: *bin, Key: *key, Dir: dir, Out: *out, SBOMDir: *sbom})
	if err != nil {
		return err
	}
	for _, argv := range plan {
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
	prevIndex := fs.String("prev-index", "", "directory of the published index (index.json and index.json.minisig); omit before the first release")
	ref := fs.String("ref", "", "git ref of the release being built (default v<version>); its migrations are read from git, never from the working tree")
	baseRef := fs.String("baseline-ref", "", "git ref of release rollback.min_version, the rollback baseline (default v<min_version>)")
	repo := fs.String("repo", ".", "repository root")
	keys := fs.String("keys-dir", "", "directory with minisign.pub, minisign-backup.pub, cosign.pub (default: the keys compiled in)")
	now := fs.String("now", "", "RFC 3339 time to use as released_at when the description has none (default now; at most 10 minutes from the clock)")
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
	if err := checkClock(env.Now, "-now"); err != nil {
		return err
	}
	if inputs.ReleasedAt != "" {
		t, err := time.Parse(time.RFC3339, inputs.ReleasedAt)
		if err != nil {
			return fmt.Errorf("released_at: %w", err)
		}
		if err := checkClock(t, "released_at"); err != nil {
			return err
		}
	}
	if *prevIndex != "" {
		trust, err := LoadTrust(*keys)
		if err != nil {
			return err
		}
		if env.PrevIndex, err = LoadPrevIndex(*prevIndex, trust); err != nil {
			return err
		}
	}
	// Both trees come from git objects at refs, and the migration files on disk must match git: what is checked is what is built.
	if err := CheckClean(ctx, *repo); err != nil {
		return err
	}
	if *ref == "" {
		*ref = "v" + inputs.Version
	}
	if env.CurTree, err = GitTree(ctx, *repo, *ref); err != nil {
		return fmt.Errorf("migrations of %s: %w", *ref, err)
	}
	if mv := inputs.Rollback.MinVersion; mv != "" {
		if *baseRef == "" {
			*baseRef = "v" + mv
		}
		if env.Baseline, err = GitTree(ctx, *repo, *baseRef); err != nil {
			if inputs.Rollback.Safe {
				return fmt.Errorf("migrations of rollback baseline %s: %w", *baseRef, err)
			}
			say(stderr, "note: no migrations at %s (%v): the guard did not run, which is fine for rollback.safe=false", *baseRef, err)
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
		say(stderr, "rollback.safe=false is right: the migrations since rollback.min_version are not add-only:")
		for _, f := range res.Findings {
			say(stderr, "  - %s", f)
		}
	}
	return nil
}

// checkClock refuses a time that is not close to the clock: a wrong released_at or generated_at in a signed document is
// permanent, and an index dated ahead pins its expiry in the future.
func checkClock(t time.Time, what string) error {
	if d := time.Since(t); d > 10*time.Minute || d < -10*time.Minute {
		return fmt.Errorf("%s %s is more than 10 minutes from the clock (%s)", what, t.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	}
	return nil
}

func cmdIndex(args []string, stdout io.Writer) error {
	fs := newFlags("index")
	out := fs.String("out", "dist/release", "output directory")
	manifest := fs.String("manifest", "", "release-manifest.json of the release to announce (empty: only refresh the index)")
	prev := fs.String("prev-index", "", "directory of the published index (it carries revocations, advisories and the other channel; required for a refresh)")
	keys := fs.String("keys-dir", "", "directory with the public keys (default: the keys compiled in)")
	seq := fs.Uint64("sequence", 0, "index sequence (default previous + 1; at most 10 above it)")
	minSeq := fs.Uint64("min-sequence", 0, "MIN_SEQUENCE the release's vedette-host was built with (see min-sequence): the new sequence must be above it")
	rollout := fs.Int("rollout", -1, "rollout percent of the channel (default 100)")
	days := fs.Int("valid-days", 14, "days until expires_at (at most 14)")
	now := fs.String("now", "", "RFC 3339 generated_at (default now)")
	var revoke []string
	fs.Func("revoke-key", "revoke this key id (repeatable; counts only once the backup key signs the index, D-108, D-259)", func(v string) error {
		revoke = append(revoke, v)
		return nil
	})
	reason := fs.String("revoke-reason", "", "why the keys of -revoke-key are revoked (one line)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := IndexParams{Now: time.Now(), Sequence: *seq, MinSequence: *minSeq, Rollout: *rollout, ValidFor: time.Duration(*days) * 24 * time.Hour,
		RevokeKeys: revoke, RevokeReason: *reason}
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
	if err := checkClock(p.Now, "generated_at"); err != nil {
		return err
	}
	if *manifest == "" {
		// A refresh (D-150) announces nothing, so it must start from the published index and must not sit next to a manifest of
		// an earlier run (sign would sign it and verify would then look for it in the index).
		if *prev == "" {
			return errors.New("refreshing the index needs -prev-index: the published index to carry on from")
		}
		if _, err := os.Stat(filepath.Join(*out, manifestFile)); err == nil {
			return fmt.Errorf("%s holds a %s of an earlier run: use a directory of its own for a refresh", *out, manifestFile)
		}
	}
	var prevIndex *release.Index
	if len(revoke) > 0 && *prev == "" {
		return errors.New("-revoke-key needs -prev-index: a rescue index carries on from the last published index (D-259)")
	}
	if *prev != "" {
		trust, err := LoadTrust(*keys)
		if err != nil {
			return err
		}
		p.BackupKeyID = trust.Backup.KeyID()
		if *prev != "" {
			if prevIndex, err = LoadPrevIndex(*prev, trust); err != nil {
				return err
			}
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
	slot := fs.String("slot", slotActive, "active: index and manifest; backup: indexes only, into .backup.minisig (offline key, D-103); rescue: the backup key signs index and manifest into .minisig after the active key leaked (D-259)")
	pass := fs.Bool("passphrase-stdin", false, "read the key's passphrase from the first line of stdin (default: minisign asks on the terminal)")
	prev := fs.String("prev-index", "", "-slot rescue: directory of the last index published before the rescue")
	keys := fs.String("keys-dir", "", "-slot rescue: the public keys the installed boxes trust (the ones before the leak)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *bin == "" {
		return errors.New("-key and -minisign are required")
	}
	if *slot != slotActive && *slot != slotBackup && *slot != slotRescue {
		return errors.New("-slot is active, backup or rescue")
	}
	rescue := *slot == slotRescue
	if rescue != (*prev != "" && *keys != "") || (!rescue && (*prev != "" || *keys != "")) {
		return errors.New("-slot rescue takes -prev-index and -keys-dir, and only it does (D-259)")
	}
	var trust release.Trust
	if rescue {
		var err error
		if trust, err = LoadTrust(*keys); err != nil {
			return err
		}
	}
	s := MinisignCLI{Bin: *bin, KeyPath: *key, Interactive: true}
	if root, err := RepoRoot(ctx, "."); err == nil {
		s.RepoRoot = root
	}
	if *pass {
		line, err := readLine(stdin)
		if err != nil {
			return fmt.Errorf("passphrase: %w", err)
		}
		defer clear(line)
		s.Passphrase, s.Interactive = line, false
	}
	var written []string
	var err error
	if rescue {
		written, err = SignRescue(ctx, s, *dir, *prev, trust)
	} else {
		written, err = SignRelease(ctx, s, *dir, *slot)
	}
	for _, w := range written {
		say(stdout, "signed %s", w)
	}
	return err
}

// readLine reads one line of at most maxPassphrase bytes, a byte at a time so nothing after the line is consumed.
// It returns bytes, not a string, so the caller can wipe them.
func readLine(r io.Reader) ([]byte, error) {
	var b []byte
	one := make([]byte, 1)
	for len(b) <= maxPassphrase {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return bytes.TrimSuffix(b, []byte("\r")), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(b) > 0 {
				return b, nil
			}
			clear(b)
			return nil, err
		}
	}
	clear(b)
	return nil, errors.New("line too long")
}

func cmdVerify(args []string, stdout io.Writer) error {
	fs := newFlags("verify")
	dir := fs.String("dir", "dist/release", "directory with the signed documents")
	prev := fs.String("prev-index", "", "directory of the published index (the sequence must not go back; required for an index-only directory)")
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
	if s.IndexOnly {
		say(stdout, "verified: index-only refresh, sequence %d signed by %s, channels unchanged, backup signature %t", s.Sequence, s.IndexKeyID, s.BackupSig)
		return nil
	}
	if s.Rescue {
		say(stdout, "verified: RESCUE release: index and manifest signed by the backup key %s, which revokes the active key of these keys", s.IndexKeyID)
	}
	say(stdout, "verified: index sequence %d signed by %s, release %s (%s), backup signature %t", s.Sequence, s.IndexKeyID, s.Version, s.Channel, s.BackupSig)
	for _, im := range s.Images {
		say(stdout, "  image %s (cosign verified)", im)
	}
	if s.ContainerAssets {
		say(stdout, "  container assets %s: signed, vedette.env names the images above", strings.Join(containerAssets, ", "))
	}
	return nil
}
