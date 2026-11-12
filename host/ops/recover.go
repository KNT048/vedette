package ops

import (
	"context"
	"errors"
	"fmt"
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
	RecoverNotUnrecoverable = "not_unrecoverable" // core's journal is not marked unrecoverable: the host finishes it by itself
	RecoverJournalInvalid   = "journal_invalid"   // core's journal does not parse or cannot be read
	RecoverCoreRunning      = "core_running"      // core's unit is not stopped
	RecoverNoCopy           = "no_copy"           // -use rollback, but there is no aside copy to put back
	RecoverVersions         = "versions_mismatch" // the unit of core pins a release the recorded versions do not explain
)

// The two choices of -use.
const (
	RecoverUseRollback = "rollback" // put the <name>.rollback copies back
	RecoverUseCurrent  = "current"  // keep the files that are in core_data now
)

// replacedInfix names a file the recovery moved out of the way: <name>.replaced-<unix nano>, kept in core_data.
const replacedInfix = ".replaced-"

var (
	coreFileRE        = `(vedette\.db(-wal|-shm|-journal)?|vedette\.key)`
	rollbackFileRE    = regexp.MustCompile(`^` + coreFileRE + `\.rollback$`)
	replacedFileRE    = regexp.MustCompile(`^` + coreFileRE + `\.replaced-[0-9]+$`)
	quarantineEntryRE = regexp.MustCompile(`\.quarantine-[0-9]+$`)
)

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

// RecoverCoreData is the command. The caller holds LockState and has opened the audit chain (AuditTo) when
// a.Apply. logf gets one line per fact, names only.
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
	rb, others, err := tree.inventory(t.Aside)
	if err != nil {
		return bsErr(api.CodeCoreDataInvalid, err.Error())
	}
	say := func(title string, es []recoverEntry) {
		if len(es) == 0 {
			return
		}
		logf(title)
		for _, e := range es {
			logf(fmt.Sprintf("  %-34s %-9s %9d bytes  %s", e.name, e.kind, e.size, e.modTime.UTC().Format(time.RFC3339)))
		}
	}
	say("aside copies of the interrupted change (<name>.rollback):", rb.entries)
	for _, n := range rb.missing {
		logf("  " + n + asideSuffix + ": gone (put back before, or lost); the journal named it")
	}
	if t.DBRevert == dbBackup {
		logf("the change would have restored backup " + t.BackupID + " (RUNBOOK 5.3 restores a backup)")
	}
	say("set aside by the host or by an earlier recovery (never touched by this command):", others)

	if a.Use == "" {
		logf("choose what core starts on:")
		logf("  -use rollback   put the aside copies back; the files they replace are kept as <name>" + replacedInfix + "<time>")
		logf("  -use current    keep what is in core_data now")
		logf("nothing was changed; add -yes to apply a choice")
		return nil
	}
	if a.Use == RecoverUseRollback && len(rb.entries) == 0 {
		return bsErr(RecoverNoCopy, "there is no usable aside copy to put back; keep what is there (-use current) or restore a backup (RUNBOOK 5.3)")
	}
	if _, ok := o.coreVersionPlan(); !ok { // reconcileCoreVersion writes the record below, after the files
		return bsErr(RecoverVersions, "the unit of core pins a release that the recorded versions do not explain; nothing was changed (RUNBOOK 5.5)")
	}
	var move, keep []string
	if a.Use == RecoverUseRollback {
		move, keep = tree.recoverPlan(rb.names())
		for _, n := range move {
			logf("will put back " + n + asideSuffix + " as " + n)
		}
		for _, n := range keep {
			logf("will keep the file now at " + n + " as " + n + replacedInfix + "<time>")
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
	if a.Use == RecoverUseRollback {
		if err := tree.putRecovered(rb.names()); err != nil {
			return bsErr(BootstrapFailed, "core_data could not be put back: "+strings.Join(strings.Fields(err.Error()), " "))
		}
	}
	if !o.reconcileCoreVersion() {
		return bsErr(RecoverVersions, "the files are in place but the recorded versions could not be brought in line with the unit; the journal was kept")
	}
	o.removeJournal(api.ServiceCore)
	o.forgetRecoveryNotes(api.ServiceCore)
	o.note("recover-core-data", "core_data_recovered", map[string]any{"run_id": t.RunID, "use": a.Use, "put_back": move, "kept_replaced": keep})
	logf("done: core_data is as chosen and the journal is removed; start core with: systemctl start " + unitOf(api.ServiceCore))
	return nil
}

// rbSet is what inventory found of the aside copies.
type rbSet struct {
	entries []recoverEntry // the <name>.rollback files that are regular files, for the names of core's tree
	missing []string       // names the journal says were moved aside whose copy is not there
}

func (r rbSet) names() []string {
	var n []string
	for _, e := range r.entries {
		n = append(n, strings.TrimSuffix(e.name, asideSuffix))
	}
	return n
}

// inventory reads core_data (at most maxSweepEntries names) with Lstat only: the usable aside copies, those
// named by the journal's aside that are gone, and everything else the host or an earlier recovery set aside.
// An aside copy that is not a regular file is a refusal (what would be renamed over the live file is unknown).
func (t *coreTree) inventory(aside []string) (rbSet, []recoverEntry, error) {
	d, err := t.root.Open(".")
	if err != nil {
		return rbSet{}, nil, errors.New("core_data cannot be read")
	}
	defer func() { _ = d.Close() }()
	ents, _ := d.ReadDir(maxSweepEntries)
	var rb rbSet
	var others []recoverEntry
	have := map[string]bool{}
	for _, e := range ents {
		n := e.Name()
		isRB, isQ, isRep := rollbackFileRE.MatchString(n), quarantineEntryRE.MatchString(n), replacedFileRE.MatchString(n)
		if !isRB && !isQ && !isRep {
			continue
		}
		st, err := t.root.Lstat(n)
		if err != nil {
			return rbSet{}, nil, errors.New("core_data changed while it was read")
		}
		re := recoverEntry{name: n, kind: kindOf(st.Mode()), size: st.Size(), modTime: st.ModTime()}
		// Only the names the journal moved are put back; a copy it does not name is left, and only listed.
		named := isRB && slices.Contains(aside, strings.TrimSuffix(n, asideSuffix))
		switch {
		case named && !st.Mode().IsRegular():
			return rbSet{}, nil, errors.New("an aside copy (" + n + ") is not a regular file; move it away by hand (RUNBOOK 5.5)")
		case named:
			rb.entries = append(rb.entries, re)
			have[strings.TrimSuffix(n, asideSuffix)] = true
		default:
			others = append(others, re)
		}
	}
	sort.Slice(rb.entries, func(i, j int) bool { return rb.entries[i].name < rb.entries[j].name })
	sort.Slice(others, func(i, j int) bool { return others[i].name < others[j].name })
	for _, n := range aside {
		if !have[n] {
			rb.missing = append(rb.missing, n)
		}
	}
	return rb, others, nil
}

// recoverPlan says which files of names (those with an aside copy) are put back and which live files, now at
// those names or at the database's sidecars, are kept aside as <name>.replaced-<time>.
func (t *coreTree) recoverPlan(names []string) (put, replaced []string) {
	put = names
	exists := func(n string) bool { _, err := t.root.Lstat(n); return err == nil }
	for _, n := range candidatesToReplace(names) {
		if exists(n) {
			replaced = append(replaced, n)
		}
	}
	return put, replaced
}

// candidatesToReplace: every name that gets a copy back, and, when the database does, its sidecars (a WAL of
// another database must not meet the old one, the same rule as putAsideBack).
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

// putRecovered does the plan: each live file in the way is renamed to <name>.replaced-<time> (a thing that is
// not a regular file is quarantined, as everywhere else), then each aside copy takes its name. Renames only,
// inside the root handle; a crash half way leaves a state the same command finishes (the copies still there are
// the ones still to put back, and the sidecars of the database were moved first).
func (t *coreTree) putRecovered(names []string) error {
	for _, n := range names {
		if !isAsideName(n) {
			return fmt.Errorf("%q is not a file a rollback moves", n)
		}
	}
	stamp := time.Now
	if t.now != nil {
		stamp = t.now
	}
	at := stamp().UnixNano()
	move := func(n string) error {
		st, err := t.root.Lstat(n)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("look at %s: %w", n, err)
		}
		if !st.Mode().IsRegular() {
			return t.quarantineIfNotRegular(n)
		}
		return t.root.Rename(n, fmt.Sprintf("%s%s%d", n, replacedInfix, at))
	}
	// Sidecars first, so that a rerun after a crash still removes them.
	for _, n := range candidatesToReplace(names) {
		if !slices.Contains(names, n) {
			if err := move(n); err != nil {
				return err
			}
		}
	}
	for _, n := range names {
		if err := move(n); err != nil {
			return err
		}
		if err := t.root.Rename(n+asideSuffix, n); err != nil {
			return fmt.Errorf("put %s back: %w", n, err)
		}
	}
	t.syncDir()
	return nil
}
