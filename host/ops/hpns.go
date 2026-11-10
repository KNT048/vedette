package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// The honeypot namespace vedette-hp (D-102 (1), (3), (4)). The host creates it in Ops.Start, before
// it says READY, and again whenever it finds it missing (/run/netns is a tmpfs). It sets the
// sysctls and loads the egress ruleset whenever it creates the namespace and at every start, and it
// checks the effect: the ruleset listed from inside the namespace must contain the drop rule,
// otherwise the namespace is not usable and nothing is added to it.

const hpNSDir = "run/netns"

var errNotOurNS = errors.New("ops: /run/netns/vedette-hp is not a namespace the host can trust")

// checkNSFile looks at /run/netns/vedette-hp. It is absent (false, nil), a good namespace
// (true, nil), or something the host refuses to use (a symlink, a directory, a FIFO, a file that
// is not an nsfs mount, another owner, a writable /run/netns): errNotOurNS, and nothing is changed.
//
// How: lstat of the directory and of the name (no symlink at either, owner and mode), then the file
// is opened with O_NOFOLLOW|O_NONBLOCK and the descriptor is asked: a regular file whose
// filesystem is nsfs (statfs magic 0x6e736673). A bind-mounted namespace shows up as a regular
// file on nsfs; an empty file, a copy or a link planted at the name is none of that.
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
	ok, err := o.d.IsNsfs(f)
	if err != nil || !ok {
		return false, errNotOurNS
	}
	return true, nil
}

func (o *Ops) ownedByHost(fi os.FileInfo) bool {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == o.cfg.OwnerUID
}

// ensureHP makes the namespace usable: it exists and is ours, its sysctls are set and its ruleset
// drops new outgoing connections. configure forces the sysctls and the ruleset (Start); they are
// also set whenever the namespace had to be created. Otherwise one "nft list ruleset" proves the
// ruleset is still there, and a missing one is loaded again.
func (o *Ops) ensureHP(ctx context.Context, configure bool) error {
	present, err := o.checkNSFile()
	if err != nil {
		return err
	}
	if !present {
		if _, code, err := o.exec(ctx, binIP, argvNetnsAdd()...); err != nil || code != 0 {
			return fmt.Errorf("ops: ip netns add failed (exit %d)", code)
		}
		if present, err = o.checkNSFile(); err != nil || !present {
			return errors.Join(errNotOurNS, err)
		}
		configure = true
	}
	if configure {
		if err := o.configureHP(ctx); err != nil {
			return err
		}
	}
	ok, err := o.egressDropLoaded(ctx)
	if err != nil {
		return err
	}
	if !ok && !configure {
		if err := o.loadRuleset(ctx); err != nil {
			return err
		}
		ok, err = o.egressDropLoaded(ctx)
		if err != nil {
			return err
		}
	}
	if !ok {
		return errors.New("ops: the egress drop rule is not loaded in vedette-hp")
	}
	return nil
}

func (o *Ops) configureHP(ctx context.Context) error {
	if _, code, err := o.exec(ctx, binIP, argvSysctl()...); err != nil || code != 0 {
		return fmt.Errorf("ops: setting the sysctls of vedette-hp failed (exit %d)", code)
	}
	return o.loadRuleset(ctx)
}

func (o *Ops) loadRuleset(ctx context.Context) error {
	_, code, err := o.execIn(ctx, binIP, strings.NewReader(hpRulesetText), argvNftLoad()...)
	if err != nil || code != 0 {
		return fmt.Errorf("ops: loading the egress ruleset of vedette-hp failed (exit %d)", code)
	}
	return nil
}

// egressDropLoaded lists the ruleset from inside the namespace and looks for the drop rule.
func (o *Ops) egressDropLoaded(ctx context.Context) (bool, error) {
	res, code, err := o.exec(ctx, binIP, argvNftList()...)
	if err != nil || code != 0 {
		return false, fmt.Errorf("ops: listing the ruleset of vedette-hp failed (exit %d)", code)
	}
	return hasEgressDrop(res.Stdout), nil
}

// hasEgressDrop reads the text of "nft list ruleset": inside table inet vedette_hp, a chain of
// the output hook holds "ct state established,related accept" and then "ct state new drop". The
// text is compared without spaces and braces, so "ct state { established, related }" counts too.
func hasEgressDrop(out []byte) bool {
	norm := func(s string) string {
		return strings.NewReplacer(" ", "", "\t", "", "{", "", "}", "").Replace(s)
	}
	inTable, inChain, hook, accept := false, false, false, false
	for _, raw := range bytes.Split(out, []byte("\n")) {
		line := norm(string(raw))
		switch {
		case strings.HasPrefix(line, "table"):
			inTable, inChain, hook, accept = line == "tableinetvedette_hp", false, false, false
		case !inTable:
		case strings.HasPrefix(line, "chain"):
			inChain, hook, accept = true, false, false
		case !inChain:
		case strings.HasPrefix(line, "typefilterhookoutput"):
			hook = true
		case line == "ctstateestablished,relatedaccept":
			accept = hook
		case line == "ctstatenewdrop":
			if hook && accept {
				return true
			}
		}
	}
	return false
}
