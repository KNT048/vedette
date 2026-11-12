package ops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// The files of host.self_update under <state>/selfupdate (spec 6.14 "Tệp của host"): versions.json (the
// running package and the one before it), journal.json (one self-update under way), started.json (the
// witness a host writes after READY), packages/ (the kept .deb of current and previous), staged/ (the copy
// about to be installed) and applier (the copy of the old binary the transient unit runs). Every file is
// 0600 root (applier 0700), written to a temp file, fsynced, renamed and the directory fsynced; every reader
// is strict (no unknown field, no trailing data, a size cap, every value checked) and refuses a symlink or
// anything but a regular file. A file that does not read is treated as missing by its caller: the host never
// guesses a version or a phase.
//
// State formats (review M6, spec 6.14): while a journal exists that has not ended installed, nothing here is
// rewritten into a form the previous release could not read. Today every format is the first one; a real
// change must run after SettleParked(succeeded) and keep a testdata folder of the release before it.

const (
	suVersionsName = "versions.json"
	suJournalName  = "journal.json"
	suStartedName  = "started.json"
	// maxSUFile caps each of the three JSON files: a journal holds at most 50 lines of 512 bytes.
	maxSUFile = 64 << 10
	// maxHostPackage is the largest host .deb (spec 6.14 Check 3) and the cap of the applier copy.
	maxHostPackage = 256 << 20
	// maxSULogLines and maxSULogLine bound the applier's log lines in the journal.
	maxSULogLines = 50
	maxSULogLine  = 512
)

// validHostVersion says whether v can name a host package (the one rule, release.ParseHostPackageName).
func validHostVersion(v string) bool {
	_, _, ok := parseHostPkgName(hostPkgName(v, "amd64"))
	return ok
}

// hostPkgName is vedette-host_<version>_<arch>.deb.
func hostPkgName(version, arch string) string { return release.HostPackageName(version, arch) }

// parseHostPkgName is the one file-name rule of a kept or released host package (spec 6.14), shared with
// scripts/release in internal/release: version and architecture, or false.
func parseHostPkgName(name string) (version, arch string, ok bool) {
	return release.ParseHostPackageName(name)
}

// debVersion is the Debian form of a host version: the prerelease "-" becomes "~" (D-155 (1)).
func debVersion(v string) string { return strings.Replace(v, "-", "~", 1) }

// isTestVersion is the rule of scripts/release refuseTestVersion and install.sh: a -test. prerelease or a -test suffix.
func isTestVersion(v string) bool {
	l := strings.ToLower(v)
	return strings.Contains(l, "-test.") || strings.HasSuffix(l, "-test")
}

// refuseTestBuild: a test build of the system helper is installed only by a host that is itself a test build, either
// built with the test keys (releasetestkeys) or a test-channel build (make install-artifacts: a -test. version that trusts
// the throwaway keys through the key overlay, D-166, D-382). A release host never installs one: scripts/release refuses a
// -test. version, so no released host carries one, and the release documents are verified with its own keys anyway.
func refuseTestBuild(target, running string, testOnly bool) bool {
	return isTestVersion(target) && !testOnly && !isTestVersion(running)
}

var (
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// suRequestIDRE is the request id rule of the server (a UUID v4 in lowercase).
	suRequestIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// --- versions.json ------------------------------------------------------------------------------

// suPkg is one kept package.
type suPkg struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

func (p suPkg) valid() bool {
	return validHostVersion(p.Version) && hex64RE.MatchString(p.SHA256) && p.Size > 0 && p.Size <= maxHostPackage
}

// suVersions is versions.json.
type suVersions struct {
	Current  suPkg  `json:"current"`
	Previous *suPkg `json:"previous"`
}

// parseSUVersions reads versions.json strictly.
func parseSUVersions(b []byte) (suVersions, error) {
	var v suVersions
	if err := decodeSUStrict(b, &v); err != nil {
		return suVersions{}, err
	}
	if !v.Current.valid() || (v.Previous != nil && (!v.Previous.valid() || v.Previous.Version == v.Current.Version)) {
		return suVersions{}, errors.New("versions.json holds a value that is not valid")
	}
	return v, nil
}

// --- journal.json -------------------------------------------------------------------------------

// Phases of the journal (spec 6.14). staged is the only phase of attempt 0; the four last ones end it.
const (
	phStaged       = "staged"
	phDispatched   = "dispatched"
	phInstalling   = "installing"
	phChecking     = "checking"
	phInstalled    = "installed"
	phRollingBack  = "rolling_back"
	phRolledBack   = "rolled_back"
	phRollbackFail = "rollback_failed"
	phNotStarted   = "not_started"
)

var suPhases = []string{phStaged, phDispatched, phInstalling, phChecking, phInstalled, phRollingBack, phRolledBack, phRollbackFail, phNotStarted}

// suReasons are the values reason may take: why a rollback ran, or why the applier did not start.
var suReasons = []string{api.CodeSelfUpdateUnhealthy, api.CodeInstallFailed, api.CodeDpkgLocked, api.CodePackageChanged}

// suRef names a package by version and hash.
type suRef struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// suTo is the package being installed.
type suTo struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// suJournal is journal.json: written by the host at Run (staged, then dispatched with each attempt) and by
// the applier for its phases; read by both.
type suJournal struct {
	RunID         string    `json:"run_id"`
	RequestID     string    `json:"request_id"`
	From          suRef     `json:"from"`
	To            suTo      `json:"to"`
	ApplierSHA256 string    `json:"applier_sha256"`
	Phase         string    `json:"phase"`
	Attempt       int       `json:"attempt"`
	BootID        string    `json:"boot_id"`
	StartedAt     time.Time `json:"started_at"`
	Deadline      time.Time `json:"deadline"`
	Reason        *string   `json:"reason"`
	Log           []string  `json:"log"`
}

func (j suJournal) validate() error {
	c, err := release.CompareVersions(j.To.Version, j.From.Version)
	switch {
	case !runIDArgRE.MatchString(j.RunID) || !suRequestIDRE.MatchString(j.RequestID):
		return errors.New("run or request id")
	case !validHostVersion(j.From.Version) || !hex64RE.MatchString(j.From.SHA256):
		return errors.New("from")
	case !validHostVersion(j.To.Version) || !hex64RE.MatchString(j.To.SHA256) || j.To.Size <= 0 || j.To.Size > maxHostPackage:
		return errors.New("to")
	case err != nil || c <= 0:
		return errors.New("to is not above from")
	case !hex64RE.MatchString(j.ApplierSHA256):
		return errors.New("applier hash")
	case !slices.Contains(suPhases, j.Phase) || j.Attempt < 0 || j.Attempt > 2 || (j.Attempt == 0) != (j.Phase == phStaged):
		return errors.New("phase or attempt")
	case !bootIDRE.MatchString(j.BootID):
		return errors.New("boot id")
	case j.StartedAt.IsZero() || !j.Deadline.After(j.StartedAt) || j.Deadline.Sub(j.StartedAt) > suRunWindow:
		return errors.New("deadline")
	case j.Reason != nil && !slices.Contains(suReasons, *j.Reason):
		return errors.New("reason")
	case len(j.Log) > maxSULogLines:
		return errors.New("too many log lines")
	}
	for _, l := range j.Log {
		if !cleanLine(l) {
			return errors.New("log line")
		}
	}
	return nil
}

// cleanLine is a log line of the applier: valid UTF-8, at most maxSULogLine bytes, no control character.
func cleanLine(l string) bool {
	return len(l) <= maxSULogLine && utf8.ValidString(l) && !strings.ContainsFunc(l, unicode.IsControl)
}

// parseSUJournal reads journal.json strictly.
func parseSUJournal(b []byte) (suJournal, error) {
	var j suJournal
	if err := decodeSUStrict(b, &j); err != nil {
		return suJournal{}, err
	}
	if j.Log == nil {
		return suJournal{}, errors.New("journal.json has no log")
	}
	if err := j.validate(); err != nil {
		return suJournal{}, fmt.Errorf("journal.json: %w", err)
	}
	return j, nil
}

// --- started.json -------------------------------------------------------------------------------

// suStarted is started.json: the witness a host writes after READY (spec 6.14, D-316 (4)).
type suStarted struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	BootID  string    `json:"boot_id"`
	At      time.Time `json:"at"`
}

// parseSUStarted reads started.json strictly. A dev version (not SemVer) is allowed: such a host never
// takes part in a self-update, but it still writes its witness.
func parseSUStarted(b []byte) (suStarted, error) {
	var s suStarted
	if err := decodeSUStrict(b, &s); err != nil {
		return suStarted{}, err
	}
	if !tokenRE.MatchString(s.Version) || s.PID <= 1 || s.PID > 1<<22 || !bootIDRE.MatchString(s.BootID) || s.At.IsZero() {
		return suStarted{}, errors.New("started.json holds a value that is not valid")
	}
	return s, nil
}

// decodeSUStrict decodes exactly one JSON object of at most maxSUFile bytes: no unknown field, no trailing data.
// encoding/json matches keys case-insensitively and the last of two equal keys wins; that is accepted here
// because only root writes these files (a root-only 0700 folder), unlike the request bodies, which the server
// checks for such keys (jsonstrict).
func decodeSUStrict(b []byte, v any) error {
	if len(b) > maxSUFile {
		return errors.New("too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// --- reading and writing --------------------------------------------------------------------------

// readSU reads one file of <state>/selfupdate through an os.Root: a regular file (not a link), at most
// maxSUFile bytes. jAbsent when it is not there, jInvalid when it is not a plain small file, jUnreadable
// on an I/O error or when the file was replaced while it was opened (the writer renames: read it again).
func (o *Ops) readSU(name string) ([]byte, jstate) { return readSUIn(o.cfg.StateDir, name) }

// readSUIn is readSU for a state directory (the applier has no Ops). The host and the applier both write the
// journal by rename, so a read that met a rename is tried again (three times in all).
func readSUIn(stateDir, name string) ([]byte, jstate) {
	for range 2 {
		if b, st := readSUOnce(stateDir, name); st != jUnreadable {
			return b, st
		}
	}
	return readSUOnce(stateDir, name)
}

func readSUOnce(stateDir, name string) ([]byte, jstate) {
	r, err := openRootOf(suDir(stateDir))
	if err != nil {
		return nil, jUnreadable
	}
	defer func() { _ = r.Close() }()
	lst, err := r.Lstat(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, jAbsent
	case err != nil:
		return nil, jUnreadable
	case !lst.Mode().IsRegular() || lst.Size() > maxSUFile:
		return nil, jInvalid
	}
	f, err := r.OpenFile(name, os.O_RDONLY|nonBlockNoFollow, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, jInvalid
		}
		return nil, jUnreadable
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, jUnreadable
	case !os.SameFile(fi, lst):
		return nil, jUnreadable // replaced (an atomic rename) between the look and the open: look again
	case !fi.Mode().IsRegular():
		return nil, jInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSUFile+1))
	if err != nil {
		return nil, jUnreadable
	}
	if len(b) > maxSUFile {
		return nil, jInvalid
	}
	return b, jOK
}

func (o *Ops) loadSUVersions() (suVersions, jstate) {
	b, st := o.readSU(suVersionsName)
	if st != jOK {
		return suVersions{}, st
	}
	v, err := parseSUVersions(b)
	if err != nil {
		return suVersions{}, jInvalid
	}
	return v, jOK
}

func (o *Ops) loadSUJournal() (suJournal, jstate) {
	b, st := o.readSU(suJournalName)
	if st != jOK {
		return suJournal{}, st
	}
	j, err := parseSUJournal(b)
	if err != nil {
		return suJournal{}, jInvalid
	}
	return j, jOK
}

// saveSU writes one file of <state>/selfupdate atomically (0600). It encodes without HTML escaping, so a log
// line full of "<" or ">=" (dpkg's dependency output) keeps its size, and it refuses what readSU would refuse:
// more than maxSUFile bytes. One limit for the writer and the reader, so a written journal always reads.
func (o *Ops) saveSU(name string, v any) error { return saveSUIn(o.cfg.StateDir, name, v) }

// saveSUIn is saveSU for a state directory (the applier has no Ops).
func saveSUIn(stateDir, name string, v any) error {
	b, err := encodeSU(v)
	if err != nil {
		return fmt.Errorf("ops: %s: %w", name, err)
	}
	return writeFileAtomic(filepath.Join(suDir(stateDir), name), b, 0o600)
}

// encodeSU is the JSON of a self-update file: no HTML escaping, at most maxSUFile bytes.
func encodeSU(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if buf.Len() > maxSUFile {
		return nil, errors.New("larger than the readers accept")
	}
	return buf.Bytes(), nil
}

// keptFile hashes packages/<name>: a regular file (not a link) owned by the host's owner, mode 0600, at
// most maxHostPackage bytes. It returns the SHA-256 and the size.
func (o *Ops) keptFile(name string) (string, int64, error) {
	if _, _, ok := parseHostPkgName(name); !ok {
		return "", 0, errors.New("not a host package name")
	}
	f, st, err := openRegularNoFollow(filepath.Join(keptDir(o.cfg.StateDir), name))
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != o.cfg.OwnerUID || st.Mode().Perm() != 0o600 || st.Size() <= 0 || st.Size() > maxHostPackage {
		return "", 0, fmt.Errorf("ops: %s is not a 0600 file of the host's owner within the size limit", name)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxHostPackage+1))
	if err != nil {
		return "", 0, err
	}
	if n != st.Size() {
		return "", 0, fmt.Errorf("ops: %s changed while it was read", name)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// sha256Reader is the lowercase hex SHA-256 of what r holds, read up to maxHostPackage bytes.
func sha256Reader(r io.Reader) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxHostPackage+1))
	if err != nil {
		return "", err
	}
	if n > maxHostPackage {
		return "", errors.New("too large")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// keptVersions lists the versions in packages/ for this machine's architecture, sorted by SemVer. Names
// that are not host packages are left alone.
func (o *Ops) keptVersions() []string {
	es, err := os.ReadDir(keptDir(o.cfg.StateDir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		if v, arch, ok := parseHostPkgName(e.Name()); ok && arch == o.arch() && e.Type().IsRegular() {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b string) int { c, _ := release.CompareVersions(a, b); return c })
	return out
}

// retainKept keeps the .deb of v.Current and v.Previous in packages/ and removes every other host package
// (spec 6.14: two files, no more), with one audit line each.
func (o *Ops) retainKept(v suVersions) {
	for _, ver := range o.keptVersions() {
		if ver == v.Current.Version || (v.Previous != nil && ver == v.Previous.Version) {
			continue
		}
		if err := removeIfThere(filepath.Join(keptDir(o.cfg.StateDir), hostPkgName(ver, o.arch()))); err != nil {
			o.log.Warn("could not remove an old host package", "version", ver)
			continue
		}
		o.note(api.CmdHostSelfUpdate, "host_package_removed", map[string]any{"version": ver})
	}
}

// adoptHostPackage records the running version's .deb as current when versions.json does not name it
// (spec 6.14 "Nhận bản đầu"): install.sh puts the file in packages/ after it checked its SHA-256 and just
// before apt installs it (postinst restarts this host inside that apt run), and the folder is root's, so
// trust on first use is enough. The current it replaces becomes
// previous when its file is still there with the recorded hash. dpkg-deb confirms the package, version and
// architecture of the file before it is recorded. A dev build adopts nothing, and neither does
// a host that finds a journal (the end of that self-update writes versions.json). It runs at Start.
func (o *Ops) adoptHostPackage(ctx context.Context) {
	if !validHostVersion(o.cfg.Version) {
		return
	}
	if _, st := o.readSU(suJournalName); st != jAbsent {
		return
	}
	old, st := o.loadSUVersions()
	if st == jOK && old.Current.Version == o.cfg.Version {
		return
	}
	name := hostPkgName(o.cfg.Version, o.arch())
	sha, size, err := o.keptFile(name)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			o.log.WarnContext(ctx, "the kept package of the running version is not usable; not adopted", "error", err.Error())
		}
		return
	}
	// The name is not proof: dpkg-deb must say it is vedette-host of this version and architecture (review L2).
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second) // a part of Start's own time: dpkg-deb reads one header
	err = o.checkDebFields(dctx, filepath.Join(keptDir(o.cfg.StateDir), name), o.cfg.Version)
	cancel()
	if err != nil {
		o.log.WarnContext(ctx, "the kept package of the running version is not that package; not adopted", "error", err.Error())
		return
	}
	nv := suVersions{Current: suPkg{Version: o.cfg.Version, SHA256: sha, Size: size}}
	if st == jOK {
		if psha, _, err := o.keptFile(hostPkgName(old.Current.Version, o.arch())); err == nil && psha == old.Current.SHA256 {
			prev := old.Current
			nv.Previous = &prev
		}
	}
	if err := o.saveSU(suVersionsName, nv); err != nil {
		o.log.ErrorContext(ctx, "could not record the adopted host package", "error", err.Error())
		return
	}
	o.note(api.CmdHostSelfUpdate, "host_package_adopted", map[string]any{"version": nv.Current.Version, "sha256": sha})
	o.retainKept(nv)
}

// readHost is GET /v1/state/host: the running version, the previous one, the kept packages and the
// self-update under way. A damaged versions.json or journal.json gives null for its field and a log line.
func (o *Ops) readHost(context.Context) (any, error) {
	st := api.HostState{Version: o.cfg.Version, PackagesKept: []string{}}
	if v, s := o.loadSUVersions(); s == jOK && v.Previous != nil {
		st.Previous = &api.HostVersionRef{Version: v.Previous.Version}
	} else if s != jOK && s != jAbsent {
		o.log.Warn("versions.json of the self-update does not read")
	}
	if kept := o.keptVersions(); kept != nil {
		st.PackagesKept = kept
	}
	if j, s := o.loadSUJournal(); s == jOK {
		st.Update = &api.HostUpdate{RunID: j.RunID, Phase: j.Phase, To: j.To.Version}
	} else if s != jAbsent {
		o.log.Warn("journal.json of the self-update does not read")
	}
	return st, nil
}
