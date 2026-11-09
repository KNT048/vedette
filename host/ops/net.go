package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// net.apply, net.confirm and net.revert (spec 6.5, D-99, D-100, D-101, D-106).
//
// Every net.apply carries the whole desired state of what Vedette manages. A change of the
// management part (card, mode, address with prefix, gateway) goes through the confirm window: the
// new file is only an overlay in /run until net.confirm. DNS, SPAN and NTP changes apply at once;
// the same state is a no-op. NTP is applied before the network and is not part of a revert: it is
// not what the admin reaches the box by.

var errEffect = errors.New("the network configuration does not do what it should")

// desiredNet parses and validates the args of net.apply. Two rules are left to Check because they
// are refusals with their own codes, not argument errors: the SPAN card equal to the management
// card (same_iface) and a gateway outside the subnet (gateway_outside_subnet); the returned
// configuration then still holds them.
func desiredNet(a api.NetApplyArgs) (NetplanConfig, time.Duration, error) {
	m := NetplanMgmt{Iface: a.Mgmt.Iface, Mode: a.Mgmt.Mode}
	if a.Mgmt.Address != "" {
		p, err := netip.ParsePrefix(a.Mgmt.Address)
		if err != nil {
			return NetplanConfig{}, 0, bad("mgmt.address", "must be an address in CIDR form, for example 192.168.1.10/24")
		}
		m.Address = p
	}
	if a.Mgmt.Gateway != "" {
		g, err := netip.ParseAddr(a.Mgmt.Gateway)
		if err != nil {
			return NetplanConfig{}, 0, bad("mgmt.gateway", "must be an IP address")
		}
		m.Gateway = g
	}
	for _, s := range a.Mgmt.DNS {
		d, err := netip.ParseAddr(s)
		if err != nil {
			return NetplanConfig{}, 0, bad("mgmt.dns", "must be IP addresses")
		}
		m.DNS = append(m.DNS, d)
	}
	cfg := NetplanConfig{Mgmt: m}
	if a.SPAN.Iface != nil {
		if *a.SPAN.Iface == "" {
			return NetplanConfig{}, 0, bad("span.iface", "must be an interface name or null")
		}
		cfg.SPAN = *a.SPAN.Iface
	}
	vc := cfg
	if vc.SPAN == vc.Mgmt.Iface {
		vc.SPAN = ""
	}
	if gatewayOutside(vc.Mgmt) {
		vc.Mgmt.Gateway = netip.Addr{}
	}
	if err := vc.validate(); err != nil {
		return NetplanConfig{}, 0, err
	}
	if err := checkNTPList(a.NTP); err != nil {
		return NetplanConfig{}, 0, err
	}
	window := time.Duration(a.ConfirmTimeoutS) * time.Second
	switch {
	case a.ConfirmTimeoutS == 0:
		window = api.DefaultConfirmTimeoutS * time.Second
	case a.ConfirmTimeoutS < api.MinConfirmTimeoutS || a.ConfirmTimeoutS > api.MaxConfirmTimeoutS:
		return NetplanConfig{}, 0, bad("confirm_timeout_s", "must be between 30 and 600")
	}
	return cfg, window, nil
}

// gatewayOutside: a unicast gateway that is not a host address of the static address's subnet.
func gatewayOutside(m NetplanMgmt) bool {
	return m.Mode == api.NetModeStatic && m.Address.IsValid() && m.Address.Addr().Is4() && m.Gateway.IsValid() &&
		unicast4(m.Gateway) && !hostInSubnet(m.Address.Masked(), m.Gateway)
}

func invalidFromField(err error) error {
	var fe *fieldError
	if errors.As(err, &fe) {
		return server.Invalid(fe.Field, fe.Reason)
	}
	return err
}

func (o *Ops) cmdNetApply() server.Command {
	return server.Define(server.Spec[api.NetApplyArgs]{
		Name: api.CmdNetApply, Write: true, Awaits: true, Timeout: 60 * time.Second,
		Validate: func(a *api.NetApplyArgs) error {
			_, _, err := desiredNet(*a)
			return invalidFromField(err)
		},
		Check: o.checkNetApply,
		Run:   o.runNetApply,
	})
}

func (o *Ops) cmdNetConfirm() server.Command {
	return server.Define(server.Spec[api.NetRunArgs]{
		Name: api.CmdNetConfirm, Write: true, WhileAwaiting: true, Timeout: 60 * time.Second,
		Validate: validNetRunArgs, Run: o.runNetConfirm,
	})
}

func (o *Ops) cmdNetRevert() server.Command {
	return server.Define(server.Spec[api.NetRunArgs]{
		Name: api.CmdNetRevert, Write: true, WhileAwaiting: true, Timeout: 60 * time.Second,
		Validate: validNetRunArgs, Run: o.runNetRevert,
	})
}

func validNetRunArgs(a *api.NetRunArgs) error {
	if !runIDRE.MatchString(a.RunID) {
		return server.Invalid("run_id", "must be a run id")
	}
	return nil
}

// checkNetApply is the read-only Check of net.apply (spec 6.5 step 1). A run that already waits is
// answered by the framework (409 pending_confirm) before this runs.
func (o *Ops) checkNetApply(_ context.Context, a api.NetApplyArgs) error {
	cfg, _, err := desiredNet(a)
	if err != nil {
		return invalidFromField(err)
	}
	switch {
	case cfg.SPAN != "" && cfg.SPAN == cfg.Mgmt.Iface:
		return refuse412(api.CodeSameIface, "The SPAN card must be a different card from the management card.")
	case gatewayOutside(cfg.Mgmt):
		return refuse412(api.CodeGatewayOutsideSubnet, "The gateway must be an address inside the subnet of the box's address.")
	}
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return errors.New("ops: list the interfaces: " + err.Error())
	}
	known := func(name string) bool {
		return slices.ContainsFunc(ifaces, func(h HostIface) bool { return h.Name == name && !h.Loopback })
	}
	if !known(cfg.Mgmt.Iface) || (cfg.SPAN != "" && !known(cfg.SPAN)) {
		return refuse412(api.CodeIfaceUnknown, "That network card does not exist on this machine.")
	}
	if r := o.CheckBackend(); r != nil {
		return r
	}
	return nil
}

func sameMgmt(a, b NetplanMgmt) bool {
	return a.Iface == b.Iface && a.Mode == b.Mode && a.Address == b.Address && a.Gateway == b.Gateway
}

func (o *Ops) runNetApply(ctx context.Context, rc *server.RunContext, a api.NetApplyArgs) (any, error) {
	want, window, err := desiredNet(a)
	if err != nil {
		return nil, invalidFromField(err)
	}
	text, err := renderNetplan(want)
	if err != nil {
		return nil, err
	}
	cur, curOK := o.readNetplanConfig()
	curText := []byte(nil)
	if curOK {
		if curText, err = renderNetplan(cur); err != nil {
			return nil, err
		}
	}
	cfgChanged := !curOK || !bytes.Equal(curText, text)
	mgmtChanged := !curOK || !sameMgmt(cur.Mgmt, want.Mgmt)
	ntpChanged := !o.ntpUnchanged(a.NTP)
	if !cfgChanged && !ntpChanged {
		rc.Log("The box already has this configuration; nothing to change.")
		return api.NetApplyResult{}, nil
	}
	if !mgmtChanged {
		return o.applyWithoutConfirm(ctx, rc, want, text, a.NTP, cfgChanged, ntpChanged)
	}
	return o.applyWithConfirm(ctx, rc, want, text, a.NTP, ntpChanged, window)
}

// applyNTPStep runs the NTP part of a net.apply, turning its failure into the run's failure.
func (o *Ops) applyNTPStep(ctx context.Context, rc *server.RunContext, servers []string) error {
	rc.Log("Applying the NTP servers.")
	if err := o.applyNTP(ctx, servers); err != nil {
		o.log.WarnContext(ctx, "the NTP sources were not applied", "error", err.Error())
		return &server.Failure{Code: api.CodeNTPNotApplied, Message: "chrony does not list the NTP servers that were set. The previous NTP servers were put back."}
	}
	return nil
}

// applyWithoutConfirm is the DNS, SPAN or NTP change: written to /etc and applied at once. The
// management address is unchanged, so no confirm window; a check that fails still puts the old
// file back.
func (o *Ops) applyWithoutConfirm(ctx context.Context, rc *server.RunContext, want NetplanConfig, text []byte, ntp []string, cfgChanged, ntpChanged bool) (any, error) {
	if ntpChanged {
		if err := o.applyNTPStep(ctx, rc, ntp); err != nil {
			return nil, err
		}
	}
	if !cfgChanged {
		return api.NetApplyResult{Changed: true}, nil
	}
	old, st := o.readNoFollowIn(netplanEtcDir, netplanName, maxNetplan)
	rc.Log("Writing the network configuration.")
	if err := o.writeIn(netplanEtcDir, netplanName, text, 0o600); err != nil {
		o.log.ErrorContext(ctx, "could not write the netplan file", "error", err.Error())
		return nil, fail(api.CodeNetplanApplyFailed, "The network configuration could not be written.")
	}
	restore := func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), netRevertTimeout)
		defer cancel()
		if st == fileOK {
			_ = o.writeIn(netplanEtcDir, netplanName, old, 0o600)
		} else {
			_ = o.removeIn(netplanEtcDir, netplanName)
		}
		_ = o.netplanApply(rctx, nil)
		_ = o.reapplyDecoys(rctx)
	}
	if err := o.netplanApply(ctx, rc); err != nil {
		restore()
		return nil, &server.Reverted{Code: api.CodeNetplanApplyFailed, Message: "netplan could not apply the new configuration; the previous one was restored."}
	}
	if err := o.reapplyDecoys(ctx); err != nil {
		restore()
		return nil, &server.Reverted{Code: api.CodeNetplanApplyFailed, Message: "The decoy addresses could not be restored; the previous configuration was restored."}
	}
	if err := o.effectCheck(ctx, rc, want); err != nil {
		restore()
		return nil, &server.Reverted{Code: api.CodeConnectivityCheckFail, Message: "The box did not reach its network with the new configuration; the previous one was restored."}
	}
	return api.NetApplyResult{Changed: true}, nil
}

// applyWithConfirm is a change of the management part (spec 6.5 steps 2 to 5).
func (o *Ops) applyWithConfirm(ctx context.Context, rc *server.RunContext, want NetplanConfig, text []byte, ntp []string, ntpChanged bool, window time.Duration) (any, error) {
	m := want.Mgmt
	boot := o.bootID()
	if boot == "" {
		return nil, fail(api.CodeBootIDUnreadable, "The host cannot read the boot id, so it cannot tell a restart from a crash; the network was not changed.")
	}
	if m.Mode == api.NetModeStatic && !o.holdsAddress(m.Iface, m.Address.Addr()) {
		rc.Log("Checking that the new address is free (ARP probe).")
		res, err := o.d.Probe.Probe(ctx, m.Iface, m.Address.Addr())
		switch {
		case err != nil:
			o.log.WarnContext(ctx, "the ARP probe failed", "error", err.Error())
			return nil, fail(api.CodeARPProbeFailed, "The host could not check whether the address is free, so the network was not changed.")
		case res.Conflict:
			return nil, refuse412(api.CodeAddressConflict, "Another device on the network already uses "+m.Address.Addr().String()+" ("+res.MAC+").")
		}
	}
	if ntpChanged {
		if err := o.applyNTPStep(ctx, rc, ntp); err != nil {
			return nil, err
		}
	}
	old, oldSt := o.readNoFollowIn(netplanEtcDir, netplanName, maxNetplan)
	if oldSt == fileBroken {
		return nil, fail(api.CodeNetBackendUnsupported, "The host's netplan file is not a plain file.")
	}
	p := netPending{RunID: rc.RunID, RevertAt: o.d.Now().Add(window).UTC(), BootID: boot, NewSHA: shaHex(text)}
	if oldSt == fileOK {
		p.OldSHA = shaHex(old)
	}
	// The note first: an overlay never exists without one.
	if err := o.savePending(p); err != nil {
		o.log.ErrorContext(ctx, "could not write net/pending.json", "error", err.Error())
		return nil, fail(api.CodeNetplanApplyFailed, "The host could not record the pending change, so the network was not changed.")
	}
	rc.Log("Writing the new configuration to the temporary overlay (the saved one stays as it is).")
	if err := o.writeIn(netplanRunDir, netplanName, text, 0o600); err != nil {
		o.log.ErrorContext(ctx, "could not write the netplan overlay", "error", err.Error())
		_ = o.deletePending()
		return nil, fail(api.CodeNetplanApplyFailed, "The new network configuration could not be written.")
	}
	if err := o.netplanApply(ctx, rc); err != nil {
		return o.revertNow(ctx, rc, api.CodeNetplanApplyFailed, "netplan could not apply the new configuration; the previous one was restored.")
	}
	rc.Log("Checking the new address and the gateway.")
	if err := o.effectCheck(ctx, rc, want); err != nil {
		return o.revertNow(ctx, rc, api.CodeConnectivityCheckFail, "The box did not reach its network with the new configuration; the previous one was restored.")
	}
	if err := o.reapplyDecoys(ctx); err != nil {
		return o.revertNow(ctx, rc, api.CodeNetplanApplyFailed, "The decoy addresses could not be restored; the previous configuration was restored.")
	}
	p.RevertAt = o.d.Now().Add(window).UTC()
	if err := o.savePending(p); err != nil {
		o.log.ErrorContext(ctx, "could not update net/pending.json", "error", err.Error())
		return o.revertNow(ctx, rc, api.CodeNetplanApplyFailed, "The host could not record the pending change; the previous configuration was restored.")
	}
	rc.OnParked(func() { o.armNetTimer(p.RunID, p.RevertAt) }) //nolint:contextcheck // the timer outlives the run: its revert has a context of its own
	rc.Log("The new configuration is running. Confirm it, or it is reverted.")
	return server.Awaiting{RevertAt: p.RevertAt, Result: api.NetApplyResult{Changed: true, Confirm: true}}, nil
}

// revertNow undoes the overlay of a run that has not started waiting yet, and ends it reverted (or
// failed revert_failed when the undo itself failed). The run's own context may be gone, so the
// undo gets one of its own.
func (o *Ops) revertNow(ctx context.Context, rc *server.RunContext, code, msg string) (any, error) {
	rc.Log("Reverting to the previous network configuration.")
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), netRevertTimeout)
	defer cancel()
	if err := o.undoOverlay(rctx, rc); err != nil {
		o.log.ErrorContext(ctx, "the immediate revert failed", "error", err.Error())
		return nil, &server.Failure{Code: api.CodeRevertFailed, Message: "Restoring the previous network configuration failed. The saved configuration is the old one: restarting the box restores it."}
	}
	return nil, &server.Reverted{Code: code, Message: msg}
}

// undoOverlay is the revert (D-100 (3)): remove the overlay, netplan apply, drop the note, apply
// the decoys again, check that the old configuration works. The note is dropped only once the
// overlay is gone and netplan has run, so a failure in between is retried at the next start.
// rc may be nil (the timer and Start have no run to log to).
func (o *Ops) undoOverlay(ctx context.Context, rc *server.RunContext) error {
	if err := o.removeIn(netplanRunDir, netplanName); err != nil {
		return err
	}
	if err := o.netplanApply(ctx, rc); err != nil {
		return err
	}
	if err := o.deletePending(); err != nil {
		o.log.ErrorContext(ctx, "could not remove net/pending.json", "error", err.Error())
	}
	if err := o.reapplyDecoys(ctx); err != nil {
		return err
	}
	if cfg, ok := o.readNetplanConfig(); ok {
		return o.effectCheck(ctx, rc, cfg)
	}
	return nil
}

// reapplyDecoys puts the decoy addresses back after the network changed (spec 6.6). The decoy
// commands arrive with slice 3-5; this is where they hook in.
func (o *Ops) reapplyDecoys(context.Context) error { return nil }

// netplanApply runs "netplan apply".
func (o *Ops) netplanApply(ctx context.Context, rc *server.RunContext) error {
	res, code, err := o.exec(ctx, binNetplan, "apply")
	if rc != nil {
		logOutput(rc, res.Stderr)
	}
	if err != nil || code != 0 {
		return fmt.Errorf("ops: netplan apply failed (exit %d)", code)
	}
	return nil
}

// --- the effect check -----------------------------------------------------------------------------

// waitFor polls cond every Deps.NetPoll for up to Deps.NetWait.
func (o *Ops) waitFor(ctx context.Context, cond func() bool, failed error) error {
	tries := int(o.d.NetWait / o.d.NetPoll)
	for i := 0; ; i++ {
		if cond() {
			return nil
		}
		if i >= tries {
			return failed
		}
		if !sleepCtx(ctx, o.d.NetPoll) {
			return ctx.Err()
		}
	}
}

// holdsAddress reports whether iface already has ip.
func (o *Ops) holdsAddress(iface string, ip netip.Addr) bool {
	return o.sourceAddr(iface, func(p netip.Prefix) bool { return p.Addr() == ip }).IsValid()
}

// sourceAddr returns the first address of iface that match accepts.
func (o *Ops) sourceAddr(iface string, match func(netip.Prefix) bool) netip.Addr {
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return netip.Addr{}
	}
	for _, h := range ifaces {
		if h.Name != iface {
			continue
		}
		for _, p := range h.Addrs {
			if match(p) {
				return p.Addr()
			}
		}
	}
	return netip.Addr{}
}

// effectCheck verifies what the configuration should have done (D-100 (1), D-101): the address is
// on the card (DHCP: some IPv4 address within the wait) and the gateway answers ARP from it. It
// looks at the system, not at an exit code.
func (o *Ops) effectCheck(ctx context.Context, rc *server.RunContext, cfg NetplanConfig) error {
	m := cfg.Mgmt
	var src netip.Addr
	want := func(p netip.Prefix) bool {
		if m.Mode == api.NetModeStatic {
			return p.Addr() == m.Address.Addr()
		}
		return p.Addr().Is4() && unicast4(p.Addr())
	}
	if err := o.waitFor(ctx, func() bool { src = o.sourceAddr(m.Iface, want); return src.IsValid() }, errEffect); err != nil {
		return err
	}
	gw := m.Gateway
	if m.Mode == api.NetModeDHCP {
		gw = netip.Addr{}
		if r := o.defaultRoute(); r != nil && r.Iface == m.Iface {
			gw, _ = netip.ParseAddr(r.Gateway)
		}
	}
	if !gw.IsValid() {
		return nil
	}
	if err := o.d.Probe.GatewayCheck(ctx, m.Iface, src, gw); err != nil {
		if rc != nil {
			rc.Log("The gateway did not answer.")
		}
		return errors.Join(errEffect, err)
	}
	return nil
}

// --- confirm and revert ---------------------------------------------------------------------------

// claimOrRefuse is the Claim of net.confirm and net.revert. The loser of a race with the timer (or
// with the other command) is refused 412 not_awaiting_confirm and has changed nothing.
func (o *Ops) claimOrRefuse(runID string) (*server.Claimed, error) {
	c, err := o.claim(runID)
	switch {
	case errors.Is(err, server.ErrNotAwaiting):
		return nil, refuse412(api.CodeNotAwaitingConfirm, "No run is waiting for confirmation with that run id (it may have finished or expired).")
	case err != nil:
		return nil, &server.Failure{Code: api.CodeShuttingDown, Message: "The host is shutting down; the change stays pending."}
	}
	return c, nil
}

func (o *Ops) runNetRevert(ctx context.Context, rc *server.RunContext, a api.NetRunArgs) (any, error) {
	c, err := o.claimOrRefuse(a.RunID)
	if err != nil {
		return nil, err
	}
	o.stopNetTimer()
	rc.Log("Reverting to the previous network configuration.")
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), netRevertTimeout)
	defer cancel()
	if !o.finishReverted(rctx, c, api.CodeCancelled, "The change was cancelled and the previous network configuration was restored.") {
		return nil, &server.Failure{Code: api.CodeRevertFailed, Message: "Restoring the previous network configuration failed. The saved configuration is the old one: restarting the box restores it."}
	}
	return api.NetRunArgs{RunID: a.RunID}, nil
}

// runNetConfirm keeps the change (spec 6.5 step 6): the overlay becomes the file in /etc. It
// writes /etc only for a note and an overlay that are exactly what the host wrote; anything else
// is reverted instead, and the caller is told.
func (o *Ops) runNetConfirm(ctx context.Context, rc *server.RunContext, a api.NetRunArgs) (any, error) {
	c, err := o.claimOrRefuse(a.RunID)
	if err != nil {
		return nil, err
	}
	o.stopNetTimer()
	done := false
	defer func() { //nolint:contextcheck // Finish takes no context: it must finish even when the caller's is cancelled
		if !done {
			_ = c.Finish(api.StatusFailed, &api.RunError{Code: api.CodeConfirmFailed, Message: "The confirmation stopped unexpectedly."})
		}
	}()
	revert := func(code, why string) (any, error) {
		done = true
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), netRevertTimeout)
		defer cancel()
		o.finishReverted(rctx, c, code, why)
		return nil, &server.Failure{Code: code, Message: why}
	}
	p, st := o.loadPending()
	if st != pendOK || p.RunID != a.RunID {
		return revert(api.CodePendingInvalid, "The note about the pending change could not be trusted, so the previous network configuration was restored instead.")
	}
	text, fs := o.readNoFollowIn(netplanRunDir, netplanName, maxNetplan)
	if cfg, perr := parseNetplan(text); fs != fileOK || perr != nil || shaHex(text) != p.NewSHA || cfg.Mgmt.Iface == "" {
		return revert(api.CodePendingInvalid, "The running configuration is not the one that was recorded, so the previous network configuration was restored instead.")
	}
	rc.Log("Saving the configuration.")
	if err := o.writeIn(netplanEtcDir, netplanName, text, 0o600); err != nil {
		o.log.ErrorContext(ctx, "confirm: could not write the netplan file", "error", err.Error())
		return revert(api.CodeConfirmFailed, "The configuration could not be saved, so the previous network configuration was restored instead.")
	}
	done = true
	if err := o.removeIn(netplanRunDir, netplanName); err != nil {
		// /etc now holds the new file and the overlay is the same bytes: the box runs the right
		// configuration. The note stays so the next start finishes the clean-up.
		o.log.ErrorContext(ctx, "confirm: could not remove the overlay", "error", err.Error())
		_ = c.Finish(api.StatusFailed, &api.RunError{Code: api.CodeConfirmFailed, Message: "The configuration was saved but the temporary copy could not be removed; the host finishes the clean-up when it restarts."}) //nolint:contextcheck // Finish takes no context: it must finish even when the caller's is cancelled
		return nil, &server.Failure{Code: api.CodeConfirmFailed, Message: "The configuration was saved but the temporary copy could not be removed."}
	}
	if err := o.deletePending(); err != nil {
		o.log.ErrorContext(ctx, "confirm: could not remove net/pending.json", "error", err.Error())
	}
	_ = c.Finish(api.StatusSucceeded, nil) //nolint:contextcheck // Finish takes no context: it must finish even when the caller's is cancelled
	return api.NetRunArgs{RunID: a.RunID}, nil
}
