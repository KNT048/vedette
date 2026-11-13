package ops

import (
	"context"
	"io"
	"time"

	"github.com/knt048/vedette/host/server"
)

// Internals that the external tests (package ops_test) need.

// Bundle readers (D-452): fuzzed and fed hand-built sparse entries from package ops_test (opstest builds them).
var (
	WalkBundle       = walkBundle
	ExtractLayout    = extractLayout
	CheckLayout      = checkLayout
	BundleMemberCap  = bundleMemberCap
	ErrBundle        = errBundle
	ErrArchiveDigest = errArchiveDigest
)

// The names of Vedette's things in podman, for the test that ties install.sh --uninstall to them (D-508 review).
const (
	IntNetwork    = intNetwork
	LocalPrefix   = localPrefix
	NmapTagPrefix = nmapTagPrefix
)

var (
	FilterJournal        = filterJournal
	SchemaNewer          = schemaNewer
	ParseRebootPkgs      = parseRebootPkgs
	FcntlLockHeld        = fcntlLockHeld
	AutoSecurityTemplate = autoSecurityTemplate
	FreeBytes            = freeBytes
	PkgNameRE            = pkgNameRE
	RedactLine           = redactLine
)

// WriteArchive writes members (name, data) as a backup archive.
func WriteArchive(w io.Writer, members map[string][]byte, order []string) (string, int64, error) {
	var files []archiveFile
	for _, n := range order {
		files = append(files, archiveFile{Name: n, Data: members[n]})
	}
	return writeArchive(w, files, time.Unix(1_700_000_000, 0))
}

// Retain applies the retention rule to records (kind, created offset in minutes) and returns the kept indexes.
func Retain(kinds []string, minutes []int) (kept []int) {
	ix := backupIndex{}
	for i, k := range kinds {
		ix.Backups = append(ix.Backups, backupRecord{ID: string(rune('a' + i)), Kind: k, CreatedAt: time.Unix(1_700_000_000, 0).Add(time.Duration(minutes[i]) * time.Minute)})
	}
	retain(&ix, nil, "")
	for _, r := range ix.Backups {
		kept = append(kept, int(r.ID[0]-'a'))
	}
	return kept
}

// RetainExports applies the export retention rule to exports (sizes in bytes, oldest first, one
// minute apart) and returns the kept indexes, oldest first.
func RetainExports(sizes []int64) (kept []int) {
	ix := exportIndex{}
	for i, sz := range sizes {
		ix.Exports = append(ix.Exports, exportRecord{ID: string(rune('a' + i)), CreatedAt: time.Unix(1_700_000_000, 0).Add(time.Duration(i) * time.Minute), Size: sz})
	}
	retainExports(&ix)
	for _, r := range ix.Exports {
		kept = append(kept, int(r.ID[0]-'a'))
	}
	return kept
}

// NetPending exposes the network-change-pending check of os.reboot.
func (o *Ops) NetPending() bool { return o.netPending() }

// WriteUnit writes a service's unit through the root write path (units.go).
func (o *Ops) WriteUnit(service string, text []byte, keepPrev bool) error {
	return o.writeUnit(service, text, keepPrev)
}

// ErrUnitUnsafe is what the root write path answers for a link, a bad owner or an open directory.
var ErrUnitUnsafe = errUnitUnsafe

// ErrWriteBusy is what a Locker answers while a command holds the write lock.
var ErrWriteBusy = server.ErrWriteBusy

// DockerFwdTick runs one look at the Docker forward rules (D-267).
func (o *Ops) DockerFwdTick(ctx context.Context) { o.dockerFwdTick(ctx) }

// HangBound is how long a test waits for something that must happen before it calls the code hung (D-373): long enough
// that a loaded machine never trips it, so a red run means a real hang.
const HangBound = 30 * time.Second
