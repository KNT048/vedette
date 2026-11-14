// Package archive is the format of a Vedette backup (docs/specs/host-api.md 6.11): one tar.gz (Go standard library) with
// fixed member names. The host writes and restores it; core reads it back when a person uploads a backup they downloaded
// (S-CORE-1, D-518). Both read it as untrusted bytes with the same rules, so they live here once.
//
//	manifest.json   small JSON, see Manifest
//	vedette.db      core's SQLite database, the snapshot core wrote (the host copies bytes, D-87)
//	vedette.key     core's secrets master key, only when include_secrets
package archive

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Member names, the manifest version and the size cap of each member.
const (
	MemberManifest = "manifest.json"
	MemberDB       = "vedette.db"
	MemberKey      = "vedette.key"

	ManifestVersion = 1

	MaxManifestBytes = 64 << 10
	MaxKeyBytes      = 4 << 10
	MaxDBBytes       = 64 << 30 // 64 GiB of database inside an archive; the appliance is far below it
)

// Manifest is the small description inside every backup.
type Manifest struct {
	Version         int    `json:"version"`
	DBSchema        string `json:"db_schema"`
	CreatedAt       string `json:"created_at"`
	IncludesSecrets bool   `json:"includes_secrets"`
}

var schemaPairRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}=[0-9]{1,9}$`)

// ValidSchema accepts "" or up to 64 comma-separated module=version pairs.
func ValidSchema(s string) bool {
	if s == "" {
		return true
	}
	pairs := strings.Split(s, ",")
	if len(pairs) > 64 {
		return false
	}
	for _, p := range pairs {
		if !schemaPairRE.MatchString(p) {
			return false
		}
	}
	return true
}

// ParseManifest validates the manifest text. It is a pure function over untrusted bytes.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifestBytes {
		return m, errors.New("manifest is too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, errors.New("manifest is not valid")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return m, errors.New("manifest has trailing data")
	}
	if m.Version != ManifestVersion {
		return m, fmt.Errorf("manifest version %d is not supported", m.Version)
	}
	if !ValidSchema(m.DBSchema) {
		return m, errors.New("manifest db_schema is not valid")
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return m, errors.New("manifest created_at is not valid")
	}
	return m, nil
}

// ErrArchive means the archive is not a valid Vedette backup. The text never carries archive content.
var ErrArchive = errors.New("ops: not a valid backup archive")

// Sink receives the content of one accepted member (at most size bytes).
type Sink func(name string, r io.Reader, size int64) error

// memberLimit is the size cap of a member, 0 for a name that is not allowed.
func memberLimit(name string) int64 {
	switch name {
	case MemberManifest:
		return MaxManifestBytes
	case MemberKey:
		return MaxKeyBytes
	case MemberDB:
		return MaxDBBytes
	}
	return 0
}

// Read walks the archive and hands each accepted member to sink. It accepts only the three
// member names, once each, as regular files, in the order manifest, db, key (the key is
// optional), with the declared size within the cap, and stops at the declared size however much
// the compressed stream would expand to (no zip bombs). Absolute paths, "..", links, devices,
// directories, PAX records and anything else are rejected before any byte of that member is read.
// It never writes anywhere itself: the sink decides, and the names it sees are constants.
func Read(r io.Reader, sink Sink) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: not gzip", ErrArchive)
	}
	defer func() { _ = zr.Close() }()
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	want := []string{MemberManifest, MemberDB, MemberKey}
	next := 0
	first := true
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: unreadable tar", ErrArchive)
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: a member is not a regular file", ErrArchive)
		}
		limit := memberLimit(hdr.Name)
		if limit == 0 {
			return fmt.Errorf("%w: unexpected member", ErrArchive)
		}
		if first && hdr.Name != MemberManifest {
			return fmt.Errorf("%w: the manifest must come first", ErrArchive)
		}
		first = false
		for next < len(want) && want[next] != hdr.Name {
			next++ // the key may be absent
		}
		if next == len(want) {
			return fmt.Errorf("%w: members out of order or repeated", ErrArchive)
		}
		next++
		if hdr.Size < 0 || hdr.Size > limit {
			return fmt.Errorf("%w: a member is too large", ErrArchive)
		}
		if len(hdr.PAXRecords) > 0 {
			return fmt.Errorf("%w: extended records are not allowed", ErrArchive)
		}
		if err := sink(hdr.Name, io.LimitReader(tr, hdr.Size), hdr.Size); err != nil {
			return err
		}
	}
	if next == 0 {
		return fmt.Errorf("%w: empty", ErrArchive)
	}
	return nil
}
