package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// The honeypot namespace vedette-hp (D-102 (1), (3), (4), D-121). The host creates it in Ops.Start,
// before it says READY, and again whenever it finds it missing (/run/netns is a tmpfs). It sets the
// sysctls, brings lo up and loads the egress ruleset whenever it creates the namespace and at every
// start, and it checks the effect: the sysctls read back, and the ruleset listed from inside the
// namespace has the drop rule. A namespace whose egress drop cannot be proven is not usable: nothing
// is added to it and the decoy links already in it are deleted (they would answer with no egress
// control), to be rebuilt by the next reconcile that proves it.

const hpNSDir = "run/netns"

var errNotOurNS = errors.New("ops: /run/netns/vedette-hp is not a namespace the host can trust")

// checkNSFile looks at /run/netns/vedette-hp. It is absent (false, nil), a good namespace
// (true, nil), or something the host refuses to use: errNotOurNS, and nothing is changed.
//
// How: lstat of the directory and of the name (no symlink at either, owner and mode), then the file
// is opened with O_NOFOLLOW|O_NONBLOCK and the descriptor is asked (Deps.IsNetNS): a regular file on
// nsfs whose NS_GET_NSTYPE is CLONE_NEWNET and that is not this process's own network namespace.
// One thing that is not a namespace is removed instead of refused: the empty regular file that a
// crashed "ip netns add" leaves before it mounts (size 0, the host's owner, and on the same device
// as the directory, so it is not a mount point); it is unlinked with unlinkat on the directory's
// descriptor (os.Root) and the namespace is made again.
func (o *Ops) checkNSFile() (present bool, err error) {
	dir := o.path(hpNSDir)
	dst, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !dst.IsDir() || dst.Mode()&os.ModeSymlink != 0 || !o.ownedByHost(dst) || dst.Mode().Perm()&0o022 != 0 {
		return false, errNotOurNS
	}
	path := dir + "/" + hpNS
	lst, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !lst.Mode().IsRegular() || !o.ownedByHost(lst) {
		return false, errNotOurNS
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the fixed namespace name under /run/netns
	if err != nil {
		return false, errNotOurNS
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || !os.SameFile(st, lst) {
		return false, errNotOurNS
	}
	if ok, err := o.d.IsNetNS(f); err == nil && ok {
		return true, nil
	}
	if lst.Size() == 0 && sameDevice(lst, dst) {
		return false, o.removeStaleNS(dir, lst)
	}
	return false, errNotOurNS
}

func sameDevice(a, b os.FileInfo) bool {
	x, ok1 := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && x.Dev == y.Dev
}

// removeStaleNS unlinks the leftover file through the directory's descriptor, once it is seen to be
// still the same file that was inspected.
func (o *Ops) removeStaleNS(dir string, was os.FileInfo) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if now, err := r.Lstat(hpNS); err != nil || !os.SameFile(now, was) {
		return errNotOurNS
	}
	o.log.Warn("removing the empty leftover /run/netns/vedette-hp of an interrupted namespace creation")
	return r.Remove(hpNS)
}

func (o *Ops) ownedByHost(fi os.FileInfo) bool {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == o.cfg.OwnerUID
}

// ensureHP makes the namespace usable: it exists and is ours, its sysctls are set and read back, lo is up
// and its ruleset drops new outgoing connections. configure forces the settings (Start); they are
// also made whenever the namespace had to be created. Otherwise one "nft list ruleset" proves the
// ruleset is still there, and a missing one is loaded again. On any failure the decoy links in a
// namespace that is ours are deleted (failClosed) and hpOK is false until a later call succeeds.
func (o *Ops) ensureHP(ctx context.Context, configure bool) (err error) {
	defer func() {
		o.hpOK.Store(err == nil)
		if err != nil {
			o.failClosed(ctx)
		}
	}()
	present, err := o.checkNSFile()
	if err != nil {
		return err
	}
	if !o.hpConfigured.Load() {
		configure = true // never proven since this host started: set and read back
	}
	if !present {
		o.hpConfigured.Store(false)
		if _, code, err := o.exec(ctx, binIP, argvNetnsAdd()...); err != nil || code != 0 {
			return fmt.Errorf("ops: ip netns add failed (exit %d)", code)
		}
		if present, err = o.checkNSFile(); err != nil || !present {
			return errors.Join(errNotOurNS, err)
		}
		configure = true
	}
	want := o.wantedDecoys()
	if configure {
		if err := o.configureHP(ctx, want); err != nil {
			return err
		}
	}
	ok, err := o.rulesetLoaded(ctx, want)
	if err != nil {
		return err
	}
	if !ok && !configure {
		if err := o.loadRuleset(ctx, want); err != nil {
			return err
		}
		ok, err = o.rulesetLoaded(ctx, want)
		if err != nil {
			return err
		}
	}
	if !ok {
		return errors.New("ops: the ruleset of vedette-hp (egress drop, per-address ports) is not loaded")
	}
	return nil
}

// failClosed deletes every decoy link of the namespace when the namespace is the host's own and its
// egress control is not proven. hp/decoys.json is kept, so the next proven reconcile rebuilds them.
// A namespace that is absent or not trusted is not touched. It runs with a context of its own: the
// caller's may be the reason for the failure.
func (o *Ops) failClosed(ctx context.Context) {
	if present, err := o.checkNSFile(); err != nil || !present {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	links, err := o.listNS(cctx)
	if err != nil {
		o.log.ErrorContext(ctx, "the egress control of vedette-hp is not proven and its links could not be listed")
		return
	}
	n := 0
	for _, l := range links {
		if linkNameRE.MatchString(l.Name) {
			n++
		}
	}
	o.dropOrphans(cctx, links, nil)
	if n > 0 {
		o.log.ErrorContext(ctx, "the egress control of vedette-hp is not proven: its decoy links were deleted", "links", n)
		o.note("decoy_ip", "decoys_closed", map[string]any{"links": n})
	}
}

func (o *Ops) configureHP(ctx context.Context, want []decoyEntry) error {
	o.hpConfigured.Store(false)
	if _, code, err := o.exec(ctx, binIP, argvSysctl()...); err != nil || code != 0 {
		return fmt.Errorf("ops: setting the sysctls of vedette-hp failed (exit %d)", code)
	}
	if err := o.verifySysctls(ctx); err != nil {
		return err
	}
	if err := o.ipRun(ctx, argvLoUp()); err != nil {
		return err
	}
	if err := o.loadRuleset(ctx, want); err != nil {
		return err
	}
	o.hpConfigured.Store(true)
	return nil
}

// verifySysctls reads the settings back from inside the namespace and compares the values.
func (o *Ops) verifySysctls(ctx context.Context) error {
	res, code, err := o.exec(ctx, binIP, argvSysctlRead()...)
	if err != nil || code != 0 {
		return fmt.Errorf("ops: reading the sysctls of vedette-hp failed (exit %d)", code)
	}
	got := strings.Fields(string(res.Stdout))
	if len(got) != len(hpSysctls) {
		return errors.New("ops: the sysctls of vedette-hp read back in an unexpected form")
	}
	for i, kv := range hpSysctls {
		if _, want, _ := strings.Cut(kv, "="); got[i] != want {
			return fmt.Errorf("ops: a sysctl of vedette-hp is %s, not %s", got[i], want)
		}
	}
	return nil
}

// loadRuleset loads the ruleset rendered for list (renderRuleset, decoyports.go) in one nft
// transaction: "flush ruleset" and the new table replace what was there at once.
func (o *Ops) loadRuleset(ctx context.Context, list []decoyEntry) error {
	_, code, err := o.execIn(ctx, binIP, strings.NewReader(renderRuleset(list)), argvNftLoad()...)
	if err != nil || code != 0 {
		return fmt.Errorf("ops: loading the ruleset of vedette-hp failed (exit %d)", code)
	}
	return nil
}
