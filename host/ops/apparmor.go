package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/knt048/vedette/host/api"
)

// The AppArmor profile of the containers at host start (D-458). Every unit selects the profile vedette-container
// (AppArmorConfModule), and Podman refuses to start a container whose named profile is not loaded ("AppArmor profile
// vedette-container specified but not loaded"), core's included. apparmor.service loads it at boot from /etc/apparmor.d and the
// package's postinst at install; this is the repair when neither did (the service failed, the file came back after a boot, an
// administrator unloaded it): at Start, where AppArmor is on, the host reads the kernel's list and loads the profile when it is
// missing, unless an administrator disabled it with the standard link in /etc/apparmor.d/disable. It never blocks the start: the
// outcome is one audit line (apparmor_profile_loaded, or apparmor_profile_missing with a reason) and a log line.
//
// ponytail: once per host start, no watch; a profile unloaded while the host runs is found at its next start (RUNBOOK has the command).

const (
	binAppArmorParser = "apparmor_parser"
	appArmorFileRel   = "etc/apparmor.d/" + AppArmorProfile
	// appArmorDisableRel is the link `aa-disable` makes (and apparmor.service honours at boot).
	appArmorDisableRel  = "etc/apparmor.d/disable/" + AppArmorProfile
	appArmorEnabledRel  = "sys/module/apparmor/parameters/enabled"
	appArmorProfilesRel = "sys/kernel/security/apparmor/profiles"
	// appArmorLoadLimit bounds one compile and load (a second or two on the target machines).
	appArmorLoadLimit = 60 * time.Second
	// maxProfilesList bounds the read of the kernel's list (a few hundred profiles on a desktop, a few dozen on a server).
	maxProfilesList = 4 << 20
)

// argsAppArmorLoad is the one apparmor_parser command line: replace (or add) the profile from the packaged file, compile it
// afresh and refresh the cache that the boot-time load uses (the package's postrm removes that cache file on purge).
var argsAppArmorLoad = []string{"--replace", "--skip-read-cache", "--write-cache", "/" + appArmorFileRel}

// validateAppArmorParser accepts exactly argsAppArmorLoad.
var validateAppArmorParser = exactly(argsAppArmorLoad...)

// appArmorOn says whether the kernel has AppArmor enabled (the module parameter Podman's check reads too).
func (o *Ops) appArmorOn() bool {
	b, err := readBounded(o.path(appArmorEnabledRel), 16)
	return err == nil && bytes.HasPrefix(b, []byte("Y"))
}

// appArmorLoaded says whether the kernel lists the profile, in any mode ("vedette-container (enforce)", "(complain)"). A list
// longer than the bound is read cut: a profile past the cut is taken as missing and loaded again (--replace, harmless).
func (o *Ops) appArmorLoaded() (bool, error) {
	b, err := readBounded(o.path(appArmorProfilesRel), maxProfilesList)
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), 1<<16)
	for sc.Scan() {
		if bytes.HasPrefix(sc.Bytes(), []byte(AppArmorProfile+" (")) {
			return true, nil
		}
	}
	return false, sc.Err()
}

// ensureAppArmor runs once at Start (see the comment at the top of this file).
func (o *Ops) ensureAppArmor(ctx context.Context) {
	if !o.appArmorOn() {
		return
	}
	missing := func(reason string, attrs ...any) {
		o.log.ErrorContext(ctx, "the AppArmor profile of the Vedette containers is not loaded: they cannot start (docs/RUNBOOK.md)", append([]any{"profile", AppArmorProfile, "reason", reason}, attrs...)...)
		o.note(api.CmdContainerStart, "apparmor_profile_missing", map[string]any{"profile": AppArmorProfile, "reason": reason})
	}
	loaded, err := o.appArmorLoaded()
	switch {
	case err != nil:
		missing("profiles_unreadable", "error", err.Error())
		return
	case loaded:
		return
	}
	if _, err := os.Lstat(o.path(appArmorDisableRel)); err == nil {
		missing("disabled")
		return
	}
	if st, err := os.Lstat(o.path(appArmorFileRel)); err != nil || !st.Mode().IsRegular() {
		missing("file_missing")
		return
	}
	lctx, cancel := context.WithTimeout(ctx, appArmorLoadLimit)
	defer cancel()
	_, code, err := o.exec(lctx, binAppArmorParser, argsAppArmorLoad...)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		missing("parser_missing")
		return
	case err != nil || code != 0:
		missing("load_failed", "exit_code", code)
		return
	}
	if loaded, err := o.appArmorLoaded(); err != nil || !loaded {
		missing("not_listed_after_load")
		return
	}
	o.log.InfoContext(ctx, "loaded the AppArmor profile of the Vedette containers", "profile", AppArmorProfile)
	o.note(api.CmdContainerStart, "apparmor_profile_loaded", map[string]any{"profile": AppArmorProfile})
}
