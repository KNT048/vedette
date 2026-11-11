package mitigation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The confirmed packs ship inside the signed core image (D-36, D-345): a directory of pack files (*.json), a VERSION file and
// packs.minisig, the release minisign signature of the statement below. This file holds the two pure halves of that: the statement
// the signature covers, and the bounded reader of the directory. The signature itself is checked by the Verifier that cmd/vedette
// builds over internal/release (D-346); this module does not link the release keys.

// StatementHeader is the first line of the signed statement. It separates the statement from every other document the release key
// signs (index.json and release-manifest.json are JSON, so they cannot be read as one, nor one as them).
const StatementHeader = "vedette mitigation packs v1"

// Files of a pack directory besides the packs.
const (
	PackVersionFile   = "VERSION"
	PackSignatureFile = "packs.minisig"
	PackStatementFile = "packs.list" // a copy of the statement, for people who check it with minisign; never read by the box
)

// Limits of a pack directory: the statement must fit internal/release's 256 KiB document cap.
const (
	maxPackFiles = 1000
	maxPackTotal = 32 << 20
	maxSigBytes  = 2 << 10
)

var docNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$`)

// ErrBadPackSet means the update cannot be put into a statement: a document name is not a plain file name, appears twice, or the
// version is not one line. The Verifier refuses such an update before any signature check.
var ErrBadPackSet = errors.New("pack set is not well formed")

// Statement is the text the release key signs for one update (D-346): the header, the version, then one line per document with the
// SHA-256 of its bytes and its name, sorted by name. It binds Update.Version, every byte of every Docs[].Data and the set of
// documents (adding, removing, renaming or swapping one changes it).
func Statement(version string, docs []Doc) ([]byte, error) {
	if version == "" || len(version) > 64 || strings.ContainsAny(version, "\r\n\x00") || strings.TrimSpace(version) != version {
		return nil, fmt.Errorf("%w: the version must be one line of 1 to 64 characters", ErrBadPackSet)
	}
	if len(docs) > maxPackFiles {
		return nil, fmt.Errorf("%w: more than %d documents", ErrBadPackSet, maxPackFiles)
	}
	lines := make([]string, 0, len(docs))
	seen := map[string]bool{}
	for _, d := range docs {
		if !docNameRE.MatchString(d.Name) {
			return nil, fmt.Errorf("%w: %q is not a pack file name", ErrBadPackSet, clipName(d.Name))
		}
		if seen[d.Name] {
			return nil, fmt.Errorf("%w: %s appears twice", ErrBadPackSet, d.Name)
		}
		seen[d.Name] = true
		sum := sha256.Sum256(d.Data)
		lines = append(lines, hex.EncodeToString(sum[:])+" "+d.Name)
	}
	slices.SortFunc(lines, func(a, b string) int { return strings.Compare(a[65:], b[65:]) })
	var b bytes.Buffer
	b.WriteString(StatementHeader + "\nversion " + version + "\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.Bytes(), nil
}

func clipName(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.ToValidUTF8(s, "?")
}

// ErrNoPackDir means the directory does not exist: this build ships no packs.
var ErrNoPackDir = errors.New("no pack directory")

// ReadPackDir reads a pack directory into an Update (fail closed): only regular files are read, never a link or anything below a
// sub-directory; VERSION and packs.minisig are required; every other *.json file is a document; packs.list and README files are
// skipped and any other file refuses the directory. Sizes are capped per file, in number and in total.
func ReadPackDir(dir string) (Update, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return Update{}, ErrNoPackDir
	}
	if err != nil {
		return Update{}, fmt.Errorf("mitigation: reading the pack directory: %w", err)
	}
	var u Update
	var haveVersion, haveSig bool
	total := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if !e.Type().IsRegular() {
			return Update{}, fmt.Errorf("mitigation: %q in the pack directory is not a regular file", clipName(name))
		}
		limit := maxDocBytes
		switch {
		case name == PackVersionFile:
			limit = 64 + 1
		case name == PackSignatureFile:
			limit = maxSigBytes
		case name == PackStatementFile || strings.HasPrefix(name, "README"):
			continue
		case docNameRE.MatchString(name):
			if len(u.Docs) >= maxPackFiles {
				return Update{}, fmt.Errorf("mitigation: more than %d pack files", maxPackFiles)
			}
		default:
			return Update{}, fmt.Errorf("mitigation: unexpected file %q in the pack directory", clipName(name))
		}
		data, err := readCapped(filepath.Join(dir, name), limit)
		if err != nil {
			return Update{}, err
		}
		if total += len(data); total > maxPackTotal {
			return Update{}, fmt.Errorf("mitigation: the pack directory is larger than %d bytes", maxPackTotal)
		}
		switch name {
		case PackVersionFile:
			u.Version, haveVersion = strings.TrimSuffix(string(data), "\n"), true
		case PackSignatureFile:
			u.Signature, haveSig = data, true
		default:
			u.Docs = append(u.Docs, Doc{Name: name, Data: data})
		}
	}
	if !haveVersion || !haveSig {
		return Update{}, fmt.Errorf("mitigation: the pack directory has no %s or no %s", PackVersionFile, PackSignatureFile)
	}
	return u, nil
}

// readCapped reads a regular file of at most limit bytes; a link is refused at open (O_NOFOLLOW is not portable, so the mode is
// checked again on the open file).
func readCapped(path string, limit int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the path is a directory entry of the box's own content directory
	if err != nil {
		return nil, fmt.Errorf("mitigation: opening %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("mitigation: %s is not a regular file", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("mitigation: reading %s: %w", filepath.Base(path), err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("mitigation: %s is larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}
