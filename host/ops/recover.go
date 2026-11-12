package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
)

// vedette-host -recover-core-data: the way out of core_data_unrecoverable that needs no running core (D-317,
// RUNBOOK 5.5). The host gave up putting core's data back (the journal of core says so); this command shows what
// is in core_data, and with an explicit choice and the operator's go-ahead it puts the aside copies back (or keeps
// what is there), clears the journal and leaves core stopped, ready for systemctl start. It is one shot, as root,
// never beside the daemon (the state lock), never while core runs, and all of core's tree goes through the same
// checked root handle as every other command (openCore: checkChain, no symlinks, descriptor checks).

// Codes of the recovery that are not in spec section 11 (the command is not on the socket).
const (
	RecoverNotUnrecoverable = "not_unrecoverable"    // core's journal is not marked unrecoverable: the host finishes it by itself
	RecoverJournalInvalid   = "journal_invalid"      // core's journal does not parse or cannot be read
	RecoverCoreRunning      = "core_running"         // core's unit is not stopped
	RecoverNoCopy           = "no_copy"              // -use rollback, but there is no aside copy to put back
	RecoverVersions         = "versions_mismatch"    // the unit of core pins a release the recorded versions do not explain
	RecoverUnitMismatch     = "unit_mismatch"        // the copies are of another release than the unit pins
	RecoverDBCopyMissing    = "db_copy_missing"      // copies of the database's WAL/SHM without the database copy
	RecoverInProgress       = "recovery_in_progress" // an earlier -use rollback stopped half way: only it can finish
	RecoverCoreRan          = "core_ran_since"       // a live file where a copy goes back: core ran after a stopped recovery
	RecoverAuditDown        = "audit_unavailable"    // the start line could not be written, so nothing was changed
)

// The two choices of -use.
const (
	RecoverUseRollback = "rollback" // put the <name>.rollback copies back
	RecoverUseCurrent  = "current"  // keep the files that are in core_data now
)

// replacedInfix names a file the recovery moved out of the way: <name>.replaced-<unix nano>, kept in core_data.
const replacedInfix = ".replaced-"

// Phases of recoverState.
const (
	recMoving  = "moving"  // the files in the way are being set aside; no copy has been put back yet
	recPutting = "putting" // everything in the way is aside; the copies are being put back (database last)
)

var (
	coreFileRE        = `(vedette\.db(-wal|-shm|-journal)?|vedette\.key)`
	rollbackFileRE    = regexp.MustCompile(`^` + coreFileRE + `\.rollback$`)
	replacedFileRE    = regexp.MustCompile(`^` + coreFileRE + `\.replaced-[0-9]+$`)
	quarantineEntryRE = regexp.MustCompile(`^` + coreFileRE + `(\.rollback)?\.quarantine-[0-9]+$`)
)

// recoverState is the progress of -use rollback, kept in the (root-owned) journal of core before the first rename.
type recoverState struct {
	At    int64    `json:"at"`    // the unix nano of the .replaced-<at> names, so a rerun uses the same ones
	Phase string   `json:"phase"` // recMoving | recPutting
	Names []string `json:"names"` // the copies being put back
}

// valid is true for no progress at all and for a well-formed one.
func (r *recoverState) valid() bool {
	if r == nil {
		return true
	}
	return r.At > 0 && (r.Phase == recMoving || r.Phase == recPutting) && len(r.Names) > 0 && len(r.Names) <= 8 &&
		!slices.ContainsFunc(r.Names, func(n string) bool { return !isAsideName(n) })
}

// RecoverArgs says what to do. Use empty only reports; Apply false only reports what Use would do.
type RecoverArgs struct {
	Use   string // "", RecoverUseRollback or RecoverUseCurrent
	Apply bool   // the operator said yes
	Where string // core_data as host.conf names it, for the report only (the command line has it; only openCore reads Config.CoreData, INV-14)
}

// RecoverUseValid says whether s is a value of -use.
func RecoverUseValid(s string) bool {
	return s == "" || s == RecoverUseRollback || s == RecoverUseCurrent
}

// recoverEntry is one thing in core_data that the recovery reports.
type recoverEntry struct {
	name    string
	kind    string // "file", "directory", "link", "other"
	size    int64
	modTime time.Time
}

func kindOf(m os.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m.IsDir():
		return "directory"
	case m.Type()&os.ModeSymlink != 0:
		return "link"
	}
	return "other"
}

type noter interface {
	Note(command, code string, detail map[string]any) error
}

// auditSink is the writer of the command's own lines: the one given with AuditTo (the command line), else the
// daemon's chain. Nil when there is none.
func (o *Ops) auditSink() noter {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.noteOnly != nil {
		return o.noteOnly
	}
	if o.notifier != nil {
		return o.notifier
	}
	return nil
}

// coreUnitDigest is the digest the installed unit of core pins, empty when it is not a unit the host wrote.
func (o *Ops) coreUnitDigest() string {
	text, st := o.readUnit(api.ServiceCore)
	if st != fileOK {
		return ""
	}
	d, _, err := o.ourUnit(api.ServiceCore, text)
	if err != nil {
		return ""
	}
	return d
}

// RecoverCoreData is the command. The caller holds LockState and has opened the audit chain (AuditTo) when
// a.Apply. logf gets one line per fact; every name that came from core_data is quoted (core chooses those).
func (o *Ops) RecoverCoreData(ctx context.Context, a RecoverArgs, logf func(string)) error {
	if !RecoverUseValid(a.Use) || (a.Apply && a.Use == "") {
		return bsErr(BootstrapBadArgs, "-use is rollback or current, and -yes needs one of them")
	}
	t, st, _ := o.loadJournal(api.ServiceCore)
	switch st {
	case jAbsent:
		logf("nothing to recover: core has no unfinished change on record")
		return nil
	case jInvalid, jUnreadable:
		return bsErr(RecoverJournalInvalid, "the journal of core (containers/transition-core.json) cannot be read or is not valid; look at it by hand (RUNBOOK 5.5)")
	}
	if !t.Unrecoverable {
		return bsErr(RecoverNotUnrecoverable, "the journal of core is not marked unrecoverable: the host puts core's data back by itself when it runs; start it")
	}
	tree, err := o.openCore()
	if err != nil {
		return bsErr(api.CodeCoreDataInvalid, "core_data is not safe to use: it must be a real directory under root-owned directories that nobody else can write")
	}
	defer tree.close()

	logf(fmt.Sprintf("the host gave up putting core's data back (change %q, run %q, database revert %q)", t.Op, t.RunID, t.DBRevert))
	logf("core_data: " + a.Where)
	unit := o.coreUnitDigest()
	logf(fmt.Sprintf("the unit of core pins %q; the interrupted change was a move to release %q (digest %q) from digest %q; the aside copies are the data of the release it moved from",
		unit, t.Version, t.Digest, t.FromDigest))

	have, missing, err := tree.copies(t.Aside)
	if err != nil {
		return bsErr(api.CodeCoreDataInvalid, err.Error())
	}
	others, listNote := tree.listing(t.Aside)
	resuming := t.Recover != nil
	names := namesOf(have)
	if resuming {
		names = t.Recover.Names
		logf(fmt.Sprintf("an earlier -use rollback stopped half way (phase %q); only -use rollback finishes it", t.Recover.Phase))
	}
	say := func(title string, es []recoverEntry) {
		if len(es) == 0 {
			return
		}
		logf(title)
		for _, e := range es {
			logf(fmt.Sprintf("  %-36q %-9s %9d bytes  %s", e.name, e.kind, e.size, e.modTime.UTC().Format(time.RFC3339)))
		}
	}
	say("aside copies of the interrupted change (<name>.rollback):", have)
	for _, n := range missing {
		logf(fmt.Sprintf("  %q: gone (put back before, or lost); the journal named it", n+asideSuffix))
	}
	if t.DBRevert == dbBackup {
		logf(fmt.Sprintf("the change would have restored backup %q (RUNBOOK 5.3 restores a backup)", t.BackupID))
	}
	say("set aside by the host or by an earlier recovery (never touched by this command):", others)
	if listNote != "" {
		logf(listNote)
	}
	dbOnlyWAL := !resuming && slices.Contains(t.Aside, coreDBFile) && !slices.Contains(names, coreDBFile) &&
		slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, coreDBFile+"-") })
	if dbOnlyWAL {
		logf("the copy of vedette.db is gone but copies of its WAL/SHM are not: they cannot be put back without it")
	}

	if a.Use == "" {
		logf("choose what core starts on:")
		logf("  -use rollback   put the aside copies back; the files they replace are kept as <name>" + replacedInfix + "<time>")
		logf("  -use current    keep what is in core_data now")
		logf("nothing was changed; add -yes to apply a choice")
		return nil
	}
	if a.Use == RecoverUseCurrent && resuming {
		return bsErr(RecoverInProgress, "an earlier -use rollback stopped half way; finish it with -use rollback (RUNBOOK 5.5)")
	}
	if a.Use == RecoverUseRollback {
		switch {
		case !resuming && len(names) == 0:
			return bsErr(RecoverNoCopy, "there is no usable aside copy to put back; keep what is there (-use current) or restore a backup (RUNBOOK 5.3)")
		case dbOnlyWAL:
			return bsErr(RecoverDBCopyMissing, "the copy of the database is gone, so its WAL/SHM copies must not be put back; keep what is there (-use current) or restore a backup (RUNBOOK 5.3)")
		case t.FromDigest != "" && unit != t.FromDigest:
			return bsErr(RecoverUnitMismatch, "the aside copies are the data of another release than the unit of core pins; put that unit back first (containers/units/core.prev, RUNBOOK 5.5) or keep what is there (-use current)")
		}
	}
	if _, ok := o.coreVersionPlan(); !ok { // reconcileCoreVersion writes the record below, after the files
		return bsErr(RecoverVersions, "the unit of core pins a release that the recorded versions do not explain; nothing was changed (RUNBOOK 5.5)")
	}
	var keep []string
	if a.Use == RecoverUseRollback {
		for _, n := range names {
			logf(fmt.Sprintf("will put back %q as %q", n+asideSuffix, n))
		}
		if !resuming || t.Recover.Phase == recMoving {
			keep = tree.liveAmong(candidatesToReplace(names))
		}
		for _, n := range keep {
			logf(fmt.Sprintf("will keep the file now at %q as %q", n, n+replacedInfix+"<time>"))
		}
	} else {
		logf("will keep every file now in core_data; the aside copies stay where they are")
	}
	logf("will remove the journal of core (containers/transition-core.json); core is not started")
	if !a.Apply {
		logf("nothing was changed; add -yes to do this")
		return nil
	}

	if !isStopped(o.unitActive(ctx, api.ServiceCore)) {
		return bsErr(RecoverCoreRunning, "core is not stopped; stop it first (systemctl stop "+unitOf(api.ServiceCore)+")")
	}
	sink := o.auditSink()
	if sink == nil {
		return bsErr(RecoverAuditDown, "the audit log is not open; nothing was changed")
	}
	// The start line first, and fail closed: a change that cannot be recorded is not made.
	if err := sink.Note("recover-core-data", "core_data_recover_start", map[string]any{"run_id": t.RunID, "use": a.Use, "put_back": names, "kept_replaced": keep, "resuming": resuming}); err != nil {
		return bsErr(RecoverAuditDown, "the audit log could not be written; nothing was changed")
	}
	if a.Use == RecoverUseRollback {
		if err := o.putRecovered(tree, &t, names); err != nil {
			return err
		}
	}
	if !o.reconcileCoreVersion() {
		return bsErr(RecoverVersions, "the files are in place but the recorded versions could not be brought in line with the unit; the journal was kept: fix that, then run -use "+a.Use+" again, which finishes the versions and the journal")
	}
	o.removeJournal(api.ServiceCore)
	o.forgetRecoveryNotes(api.ServiceCore)
	if err := sink.Note("recover-core-data", "core_data_recovered", map[string]any{"run_id": t.RunID, "use": a.Use, "put_back": names, "kept_replaced": keep}); err != nil {
		return bsErr(BootstrapFailed, "core_data is as chosen and the journal is removed, but the audit line of the end could not be written; the start line is in the log")
	}
	logf("done: core_data is as chosen and the journal is removed; start core with: systemctl start " + unitOf(api.ServiceCore))
	return nil
}

func namesOf(es []recoverEntry) []string {
	var n []string
	for _, e := range es {
		n = append(n, strings.TrimSuffix(e.name, asideSuffix))
	}
	return n
}

// putRecovered does -use rollback in the order that is safe to stop anywhere (the journal says how far it got):
//  1. every live file in the way (the copies' names, and the database's WAL/SHM when the database goes back) is
//     renamed to <name>.replaced-<at>; nothing is put back yet, so a crash leaves no database beside a foreign WAL;
//  2. the copies go back with the database LAST: a crash then leaves no database (core would start on an empty
//     one, which is loud) instead of an old database without its WAL (which would silently lose transactions).
//
// The progress (the stamp, the names, the phase) is saved in the journal before the first rename and between the
// phases; a rerun uses it and finishes.
func (o *Ops) putRecovered(tree *coreTree, t *transition, names []string) error {
	if t.Recover == nil {
		stamp := time.Now
		if tree.now != nil {
			stamp = tree.now
		}
		t.Recover = &recoverState{At: stamp().UnixNano(), Phase: recMoving, Names: slices.Clone(names)}
		if err := o.saveJournal(*t); err != nil {
			return bsErr(BootstrapFailed, "the progress could not be saved in the journal; nothing was changed")
		}
	}
	if t.Recover.Phase == recMoving {
		if err := tree.setAside(candidatesToReplace(t.Recover.Names), t.Recover.At); err != nil {
			return bsErr(BootstrapFailed, "core_data could not be set aside: "+oneLine(err))
		}
		t.Recover.Phase = recPutting
		if err := o.saveJournal(*t); err != nil {
			return bsErr(BootstrapFailed, "the progress could not be saved in the journal; run -use rollback again")
		}
	}
	if err := tree.putCopies(t.Recover.Names); err != nil {
		if errors.Is(err, errCoreRan) {
			return bsErr(RecoverCoreRan, "core ran after an earlier -use rollback stopped half way: a live "+oneLine(err)+" that this command did not put back is core's own, and the old WAL that was put back may be gone. Nothing was changed. Look at the files in core_data (vedette.db*, and *.replaced-* which keep what the first run set aside); the safe ways out are restoring a backup (RUNBOOK 5.3) or -use current if core's data is the one to keep")
		}
		return bsErr(BootstrapFailed, "core_data could not be put back: "+oneLine(err)+"; run -use rollback again")
	}
	return nil
}

func oneLine(err error) string { return strings.Join(strings.Fields(err.Error()), " ") }

// copies looks (Lstat, the names of the journal only) at each <name>.rollback: the usable ones and the names whose
// copy is not there. A copy that is not a regular file is an error (what would be renamed over the live file is
// unknown).
func (t *coreTree) copies(aside []string) (have []recoverEntry, missing []string, err error) {
	for _, n := range aside {
		st, err := t.root.Lstat(n + asideSuffix)
		switch {
		case errors.Is(err, os.ErrNotExist):
			missing = append(missing, n)
		case err != nil:
			return nil, nil, errors.New("core_data cannot be read")
		case !st.Mode().IsRegular():
			return nil, nil, fmt.Errorf("an aside copy (%q) is not a regular file; move it away by hand (RUNBOOK 5.5)", n+asideSuffix)
		default:
			have = append(have, recoverEntry{name: n + asideSuffix, kind: "file", size: st.Size(), modTime: st.ModTime()})
		}
	}
	sort.Slice(have, func(i, j int) bool { return have[i].name < have[j].name })
	return have, missing, nil
}

// listing reads core_data (at most maxSweepEntries names) only to tell what else the host or an earlier recovery set
// aside: for the report, nothing is decided from it. The note says when the listing is not complete.
func (t *coreTree) listing(aside []string) (others []recoverEntry, note string) {
	d, err := t.root.Open(".")
	if err != nil {
		return nil, "core_data could not be listed; the entries set aside are not shown"
	}
	defer func() { _ = d.Close() }()
	ents, err := d.ReadDir(maxSweepEntries)
	for _, e := range ents {
		n := e.Name()
		isRB := rollbackFileRE.MatchString(n) && !slices.Contains(aside, strings.TrimSuffix(n, asideSuffix))
		if !isRB && !quarantineEntryRE.MatchString(n) && !replacedFileRE.MatchString(n) {
			continue
		}
		st, lerr := t.root.Lstat(n)
		if lerr != nil {
			continue
		}
		others = append(others, recoverEntry{name: n, kind: kindOf(st.Mode()), size: st.Size(), modTime: st.ModTime()})
	}
	sort.Slice(others, func(i, j int) bool { return others[i].name < others[j].name })
	if (err != nil && !errors.Is(err, io.EOF)) || len(ents) >= maxSweepEntries {
		note = "the listing of core_data is not complete (too many names, or a read error); other entries set aside may exist"
	}
	return others, note
}

// liveAmong says which of names exist now (Lstat).
func (t *coreTree) liveAmong(names []string) []string {
	var out []string
	for _, n := range names {
		if _, err := t.root.Lstat(n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// candidatesToReplace: every name that gets a copy back, and, when the database does, its sidecars (a WAL of
// another database must not meet the old one, the rule of putAsideBack).
func candidatesToReplace(names []string) []string {
	out := slices.Clone(names)
	if slices.Contains(names, coreDBFile) {
		for _, sfx := range sidecars {
			if !slices.Contains(out, coreDBFile+sfx) {
				out = append(out, coreDBFile+sfx)
			}
		}
	}
	return out
}

// setAside renames each live name in names to <name>.replaced-<at> (a thing that is not a regular file is
// quarantined, as everywhere else) and makes it durable.
func (t *coreTree) setAside(names []string, at int64) error {
	for _, n := range names {
		if err := t.moveAway(n, at); err != nil {
			return err
		}
	}
	t.syncDir()
	return nil
}

func (t *coreTree) moveAway(n string, at int64) error {
	st, err := t.root.Lstat(n)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look at %q: %w", n, err)
	}
	if !st.Mode().IsRegular() {
		return t.quarantineIfNotRegular(n)
	}
	return t.root.Rename(n, fmt.Sprintf("%s%s%d", n, replacedInfix, at))
}

// errCoreRan says putCopies found a live file where a copy was to go.
var errCoreRan = errors.New("ops: a live file is in the place of an aside copy")

// putCopies renames each copy that is still there back to its name: the key and anything else first, the
// database's sidecars next, the database last. A copy that is gone was put back by an earlier run.
func (t *coreTree) putCopies(names []string) error {
	order := slices.Clone(names)
	rank := func(n string) int {
		switch {
		case n == coreDBFile:
			return 2
		case strings.HasPrefix(n, coreDBFile+"-"):
			return 1
		}
		return 0
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(order[i]) < rank(order[j]) })
	for _, n := range order {
		if !isAsideName(n) {
			return fmt.Errorf("%q is not a file a rollback moves", n)
		}
		st, err := t.root.Lstat(n + asideSuffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("the aside copy of %q is not usable", n)
		}
		// Phase 1 left nothing at these names, so a live file here is not ours: core ran since (it is the only thing that
		// makes a database or a WAL). Never rename onto it (RENAME_NOREPLACE by hand: Lstat in the root, refuse).
		if _, err := t.root.Lstat(n); err == nil {
			return fmt.Errorf("%w: %q", errCoreRan, n)
		}
		if n == coreDBFile { // a WAL or journal that is not one this run put back would be replayed on the old database
			for _, sfx := range sidecars {
				if _, err := t.root.Lstat(coreDBFile + sfx); err == nil && !slices.Contains(names, coreDBFile+sfx) {
					return fmt.Errorf("%w: %q", errCoreRan, coreDBFile+sfx)
				}
			}
		}
		if err := t.root.Rename(n+asideSuffix, n); err != nil {
			return fmt.Errorf("put %q back: %w", n, err)
		}
	}
	t.syncDir()
	return nil
}
