package ops

import (
	"io"
	"time"
)

// Internals that the external tests (package ops_test) need.

var (
	FilterJournal        = filterJournal
	SchemaNewer          = schemaNewer
	ParseRebootPkgs      = parseRebootPkgs
	FcntlLockHeld        = fcntlLockHeld
	AutoSecurityTemplate = autoSecurityTemplate
	FreeBytes            = freeBytes
	PkgNameRE            = pkgNameRE
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
	retain(&ix)
	for _, r := range ix.Backups {
		kept = append(kept, int(r.ID[0]-'a'))
	}
	return kept
}
