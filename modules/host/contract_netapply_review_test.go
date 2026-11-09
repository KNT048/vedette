package host_test

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/server/servertest"
)

// The independent security review of slice 3-4 (H-1, M-1, M-2, M-3, L-1, L-3, L-4, L-5 and the
// info items). The first tests are the review's proofs, kept as permanent tests.

// stepProber is the fake prober with a hook in the gateway check (where the run spends its time).
type stepProber struct {
	*fakeProber
	onGW atomic.Pointer[func(src netip.Addr)]
}

func (p *stepProber) GatewayCheck(ctx context.Context, iface string, src, gw netip.Addr) error {
	if f := p.onGW.Load(); f != nil {
		(*f)(src)
	}
	return p.fakeProber.GatewayCheck(ctx, iface, src, gw)
}

// startNetWith is startNet with another Interfaces function and prober.
func startNetWith(t *testing.T, box *netBox, ifaces func() ([]ops.HostIface, error), probe ops.Prober, fp *fakeProber, muts ...mut) *netEnv {
	t.Helper()
	e := startSys(t, append([]mut{func(_ *ops.Config, d *ops.Deps) {
		d.Interfaces, d.Probe = ifaces, probe
		d.NetPoll, d.NetWait, d.NetRetryGap = time.Millisecond, 30*time.Millisecond, time.Millisecond
	}}, muts...)...)
	box.m = e.m
	physicalCards(e.m)
	e.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n^,+,ntp1.example.com,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	e.o.Start(context.Background(), e.h.Server)
	t.Cleanup(e.o.Close)
	return &netEnv{sysEnv: e, box: box, probe: fp}
}

func waitParkedOrDone(t *testing.T, h *servertest.Harness, id string) api.Run {
	t.Helper()
	var last api.Run
	eventually(t, "the run to wait or end", func() bool {
		r, err := h.Client.GetRun(context.Background(), id)
		last = r
		return err == nil && (r.Status == api.StatusAwaitingConfirm || r.Status.Terminal())
	})
	return last
}

// auditCodes lists the codes of the audit lines the host wrote on its own (Actor system).
func auditCodes(t *testing.T, h *servertest.Harness) []string {
	t.Helper()
	var out []string
	for _, r := range audit(t, h) {
		if r.Actor == "system" && r.Code != nil {
			out = append(out, r.Command+":"+*r.Code)
		}
	}
	return out
}

func hasCode(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

// --- H-1: a refused park never leaves an unwatched overlay ---------------------------------------------

// The wall clock steps forward while net.apply runs (chrony stepping a wrong clock right after this
// very run handed it its first NTP sources). The framework refuses the park (its 660 s bound), and
// the command learns of it through its AfterFinish callback: the overlay and the note are taken
// away, netplan is applied again, and the host audits why. Nothing of the unconfirmed address may
// reach /etc afterwards.
func TestContract_NetApply_AClockStepDuringApplyNeverLeavesAnUnwatchedOverlay(t *testing.T) {
	t.Parallel()
	box, fp := &netBox{}, &fakeProber{}
	sp := &stepProber{fakeProber: fp}
	n := startNetWith(t, box, box.interfaces, sp, fp)
	n.establish(t)
	var stepped atomic.Bool
	step := func(src netip.Addr) {
		if src.String() == "10.0.0.9" && stepped.CompareAndSwap(false, true) {
			n.clock.Advance(15 * time.Minute) // chrony steps a clock that was 15 minutes slow
		}
	}
	sp.onGW.Store(&step)
	applies := n.applies()

	r := n.start(t, staticArgs("10.0.0.9/24", "10.0.0.1"), "net.apply")
	run := waitParkedOrDone(t, n.h, r.RunID)
	if run.Status == api.StatusAwaitingConfirm {
		t.Fatal("setup: the park was meant to be refused by the 660 s bound")
	}
	if run.Status != api.StatusFailed || run.Error == nil || run.Error.Code != api.CodeCommandFailed {
		t.Fatalf("run %+v", run)
	}
	eventually(t, "the unwatched overlay and its note to be undone", func() bool {
		_, ok := n.file(runNetplan)
		_, err := os.Lstat(n.pendingPath())
		return !ok && os.IsNotExist(err)
	})
	eventually(t, "the audit line", func() bool { return hasCode(auditCodes(t, n.h), "net.apply:unwatched_overlay_undone") })
	if _, err := os.Lstat(n.pendingPath()); !os.IsNotExist(err) {
		t.Fatalf("the note is still there: %v", err)
	}
	if n.applies() != applies+2 {
		t.Fatalf("netplan apply ran %d times for the apply and the undo, want 2", n.applies()-applies)
	}
	if len(n.timers.active()) != 0 {
		t.Fatalf("%d timers armed for a run that never parked", len(n.timers.active()))
	}
	// A later DNS-only change to the same address is a management change again (the box's
	// configuration is the confirmed 10.0.0.5), so it waits for confirmation and writes nothing to /etc.
	n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }))
	if etc, _ := n.file(etcNetplan); strings.Contains(etc, "10.0.0.9/24") {
		t.Fatalf("the never-confirmed 10.0.0.9/24 reached /etc/netplan:\n%s", etc)
	}
}

// An overlay that no awaiting run owns never becomes "the current configuration" (H-1 (c)): a
// DNS-only apply of the very configuration the overlay holds is still a management change and
// waits for confirmation, so an unconfirmed address cannot be saved to /etc by a side door.
func TestContract_NetApply_AnOverlayNoRunOwnsIsNeverTheCurrentConfiguration(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	other := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	ov, _ := n.file(runNetplan)
	n.ok(t, "net.revert", api.NetRunArgs{RunID: other.RunID})
	waitStatus(t, n.h, other.RunID, api.StatusReverted)
	n.m.WriteRoot(runNetplan, ov) // a leftover: the overlay of a run that is gone
	if st := n.state(t); st.Config.Mgmt != nil {
		t.Fatalf("state/net reports an unowned overlay as the configuration: %+v", st.Config.Mgmt)
	}
	n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }))
	if etc, _ := n.file(etcNetplan); strings.Contains(etc, "10.0.0.9/24") {
		t.Fatalf("an unconfirmed address reached /etc/netplan:\n%s", etc)
	}
}

// --- M-1: an overlay at start means a full revert -------------------------------------------------------

// At start, "the note's boot_id differs from this boot" is not read as a reboot while the overlay is
// still in /run (tmpfs: no reboot happened) or when the boot id cannot be read: the box may still run
// the unconfirmed configuration, so the host runs netplan apply and says the box did not
// demonstrably restart (never reverted_by_reboot).
func TestContract_NetApply_AnOverlayStillInRunAtStartIsFullyRevertedNotSilentlyCleaned(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		tamper func(t *testing.T, n *netEnv)
		code   string
	}{
		"boot id unreadable at start": {func(_ *testing.T, n *netEnv) { n.m.WriteRoot("proc/sys/kernel/random/boot_id", "unreadable\n") }, api.CodeNotConfirmed},
		"note carries another boot id": {func(t *testing.T, n *netEnv) {
			b, err := os.ReadFile(n.pendingPath())
			if err != nil {
				t.Fatal(err)
			}
			s := regexp.MustCompile(`"boot_id":"[^"]+"`).ReplaceAllString(string(b), `"boot_id":"`+boot2+`"`)
			if err := os.WriteFile(n.pendingPath(), []byte(s), 0o600); err != nil { //nolint:gosec // a path of the test's own temp area
				t.Fatal(err)
			}
		}, api.CodePendingInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			n := startNet(t)
			n.establish(t)
			run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
			c.tamper(t, n)
			applies := n.applies()
			h2, _ := n.restart(t)
			done := waitStatus2(t, h2, run.RunID)
			if n.applies() != applies+1 {
				t.Errorf("the overlay was in /run at start but netplan apply ran %d times", n.applies()-applies)
			}
			if done.Status != api.StatusReverted || done.Error == nil || done.Error.Code != c.code {
				t.Errorf("run %s/%+v, want reverted %s (not reverted_by_reboot)", done.Status, done.Error, c.code)
			}
			n.gone(t, runNetplan)
			if _, err := os.Lstat(n.pendingPath()); !os.IsNotExist(err) {
				t.Errorf("the note is still there: %v", err)
			}
		})
	}
}

// A note and an overlay with no run (a crash while the change was starting) on an unreadable boot id
// are reverted, not dropped: the same rule as for a resumed run.
func TestContract_NetApply_AnOrphanOverlayWithAnUnreadableBootIDIsRevertedAtStart(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	// The run itself is lost (its file is gone); the note and the overlay remain.
	n.m.WriteRoot("proc/sys/kernel/random/boot_id", "unreadable\n")
	n.o.Close()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.h.Server.Shutdown(sctx); err != nil { // stop the writer of the run files before they are removed
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(n.m.State, "runs")); err != nil {
		t.Fatal(err)
	}
	applies := n.applies()
	n.restart(t)
	if n.applies() != applies+1 {
		t.Fatalf("netplan apply ran %d times at start", n.applies()-applies)
	}
	n.gone(t, runNetplan)
}

// --- L-1: a confirm that reached /etc is a confirm -----------------------------------------------------------

// A crash (or power loss) inside net.confirm after /etc was written but before the overlay and the
// note were removed: the resumed run is settled succeeded, as the orphan case already did.
func TestContract_NetApply_ACrashInsideConfirmAfterEtcWasWrittenIsReportedSucceeded(t *testing.T) {
	t.Parallel()
	for name, reboot := range map[string]bool{"same boot": false, "power loss": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			n := startNet(t)
			n.establish(t)
			run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
			ov, _ := n.file(runNetplan)
			n.m.WriteRoot(etcNetplan, ov) // confirm's rename reached the disk, then the host died
			if reboot {
				n.m.RemoveRoot(runNetplan)
				n.m.SetBootID(boot2)
			}
			applies := n.applies()
			h2, timers2 := n.restart(t)
			final := waitStatus2(t, h2, run.RunID)
			if final.Status != api.StatusSucceeded || final.Error != nil {
				t.Errorf("the run ended %s/%+v but /etc is the confirmed 10.0.0.9/24", final.Status, final.Error)
			}
			n.gone(t, runNetplan)
			if _, err := os.Lstat(n.pendingPath()); !os.IsNotExist(err) {
				t.Errorf("the note is still there: %v", err)
			}
			if n.applies() != applies || len(timers2.active()) != 0 {
				t.Errorf("applies +%d, timers %d: a finished confirm needs neither", n.applies()-applies, len(timers2.active()))
			}
		})
	}
}

// --- M-2: the SPAN card ----------------------------------------------------------------------------------------

// A SPAN change applies at once with no confirm window and strips the card of every address. Check
// refuses a card that holds an address now (the admin's session may come in by it), whatever else
// it is, and a card that is not a physical one.
func TestContract_NetApply_ASPANCardThatHoldsAnAddressOrIsNotPhysicalIsRefused(t *testing.T) {
	t.Parallel()
	box, fp := &netBox{}, &fakeProber{}
	var eth1Addr, br0Up atomic.Bool
	ifaces := func() ([]ops.HostIface, error) {
		l, err := box.interfaces()
		for i := range l {
			if l[i].Name == "eth1" && eth1Addr.Load() {
				l[i].Addrs = []netip.Prefix{netip.MustParsePrefix("172.16.9.4/24")}
			}
		}
		if br0Up.Load() {
			l = append(l, ops.HostIface{Name: "br0", MAC: "02:00:00:00:00:09"})
		}
		return l, err
	}
	n := startNetWith(t, box, ifaces, fp, fp)
	n.establish(t)
	applies := len(n.m.AllCalls())

	eth1Addr.Store(true)
	n.refused(t, "net.apply", staticArgs("10.0.0.5/24", "10.0.0.1", span("eth1")), 412, api.CodeSPANHasAddress)
	eth1Addr.Store(false)
	br0Up.Store(true)
	n.refused(t, "net.apply", staticArgs("10.0.0.5/24", "10.0.0.1", span("br0")), 412, api.CodeSPANNotPhysical)
	if got := len(n.m.AllCalls()); got != applies {
		t.Fatalf("a program ran for a refused SPAN card: %v", n.m.AllCalls()[applies:])
	}
	n.gone(t, runNetplan)
	// A physical card with no address is still accepted.
	n.final(t, "net.apply", staticArgs("10.0.0.5/24", "10.0.0.1", span("eth1")), api.StatusSucceeded, "")
}

func TestContract_NetApply_ASPANCardWithOnlyALinkLocalAddressIsAccepted(t *testing.T) {
	t.Parallel()
	box, fp := &netBox{}, &fakeProber{}
	ifaces := func() ([]ops.HostIface, error) {
		l, err := box.interfaces()
		for i := range l {
			if l[i].Name == "eth1" {
				l[i].Addrs = []netip.Prefix{netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("169.254.3.3/16")}
			}
		}
		return l, err
	}
	n := startNetWith(t, box, ifaces, fp, fp)
	n.establish(t)
	n.final(t, "net.apply", staticArgs("10.0.0.5/24", "10.0.0.1", span("eth1")), api.StatusSucceeded, "")
}

// --- M-3: a failed revert retries, then reboots ----------------------------------------------------------------

func (n *netEnv) failApply() { n.m.Rule("netplan", "apply", "", 1, "", "") }

func (n *netEnv) assertRebootScheduled(t *testing.T, h *servertest.Harness, timers *fakeTimers, at time.Time) {
	t.Helper()
	found := false
	for _, tm := range timers.active() {
		if tm.d == 60*time.Second {
			found = true
		}
	}
	if !found {
		t.Fatalf("no 60 s timer for the reboot: %+v", timers.active())
	}
	st, err := h.Client.StateNet(context.Background())
	if err != nil || st.Pending == nil || st.Pending.RebootAt == nil || !st.Pending.RebootAt.Equal(at) {
		t.Fatalf("state/net pending %+v (%v), want reboot_at %s", st.Pending, err, at)
	}
	if !hasCode(auditCodes(t, h), "os.reboot:reboot_scheduled_after_failed_revert") {
		t.Fatalf("the reboot was not audited: %v", auditCodes(t, h))
	}
}

// netplan apply fails during a revert: it is tried three times, and then the host schedules
// os.reboot in a minute (the file on disk is the old one). A confirm in that minute cannot help: the
// overlay is gone. The reboot shows in state/net as pending.reboot_at.
func TestContract_NetRevert_AFailedRevertRetriesThenSchedulesARebootInAMinute(t *testing.T) {
	t.Parallel()
	t.Run("net.revert", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
		n.failApply()
		applies := n.applies()
		r, err := n.call(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
		if err != nil || r.Status != api.StatusFailed || r.Error == nil || r.Error.Code != api.CodeRevertFailed {
			t.Fatalf("revert: %+v %v", r, err)
		}
		if n.applies()-applies != 3 {
			t.Fatalf("netplan apply was tried %d times, want 3", n.applies()-applies)
		}
		n.gone(t, runNetplan)
		n.assertRebootScheduled(t, n.h, n.timers, n.clock.Now().Add(60*time.Second))
		// The admin confirms in that minute: nothing waits any more.
		n.refused(t, "net.confirm", api.NetRunArgs{RunID: run.RunID}, 412, api.CodeNotAwaitingConfirm)
		if etc, _ := n.file(etcNetplan); strings.Contains(etc, "10.0.0.9") {
			t.Fatalf("a late confirm saved the change: %q", etc)
		}
		// The minute passes: the box reboots through the one reboot path.
		n.clock.Advance(60 * time.Second)
		for _, tm := range n.timers.active() {
			if tm.d == 60*time.Second {
				tm.fire()
			}
		}
		eventually(t, "the reboot", func() bool { return rebootCalls(n.sysEnv) == 1 })
	})
	t.Run("the timer", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
		tm := n.activeTimer(t)
		n.failApply()
		applies := n.applies()
		tm.fire()
		done := waitStatus(t, n.h, run.RunID, api.StatusFailed)
		if done.Error == nil || done.Error.Code != api.CodeRevertFailed {
			t.Fatalf("run %+v", done)
		}
		if n.applies()-applies != 3 {
			t.Fatalf("netplan apply was tried %d times, want 3", n.applies()-applies)
		}
		n.assertRebootScheduled(t, n.h, n.timers, n.clock.Now().Add(60*time.Second))
	})
	t.Run("start", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
		n.clock.Advance(61 * time.Second)
		n.failApply()
		applies := n.applies()
		h2, timers2 := n.restart(t)
		done := waitStatus(t, h2, run.RunID, api.StatusFailed)
		if done.Error == nil || done.Error.Code != api.CodeRevertFailed {
			t.Fatalf("run %+v", done)
		}
		if n.applies()-applies != 3 {
			t.Fatalf("netplan apply was tried %d times, want 3", n.applies()-applies)
		}
		n.assertRebootScheduled(t, h2, timers2, n.clock.Now().Add(60*time.Second))
	})
	t.Run("an immediate revert", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.failApply()
		n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusFailed, api.CodeRevertFailed)
		n.assertRebootScheduled(t, n.h, n.timers, n.clock.Now().Add(60*time.Second))
	})
	t.Run("a revert that works needs no reboot", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
		// the first try fails, the second works
		n.m.Rule("netplan", "apply", "", 1, "!tried", "tried")
		n.m.Rule("netplan", "apply", "", 0, "tried", "")
		n.ok(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
		waitStatus(t, n.h, run.RunID, api.StatusReverted)
		if st := n.state(t); st.Pending != nil {
			t.Fatalf("pending after a revert that worked: %+v", st.Pending)
		}
		for _, tm := range n.timers.active() {
			if tm.d == 60*time.Second {
				t.Fatal("a reboot was scheduled although the revert worked")
			}
		}
	})
}

// --- L-3, L-5: what a failure says ---------------------------------------------------------------------------------

func TestContract_NetApply_AFailureAfterNTPChangedSaysTheNTPServersWereUpdated(t *testing.T) {
	t.Parallel()
	ntp := func(a *api.NetApplyArgs) { a.NTP = []string{"ntp1.example.com"} }
	const sentence = "The NTP servers were updated; the network change was not kept."
	t.Run("a management change that does not connect", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		n.probe.set(func(p *fakeProber) { p.gwErrFor = map[string]error{"10.0.0.9": ops.ErrGatewaySilent} })
		r := n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1", ntp), api.StatusReverted, api.CodeConnectivityCheckFail)
		if !strings.Contains(r.Error.Message, sentence) {
			t.Fatalf("message %q does not say the NTP servers were updated", r.Error.Message)
		}
		if got := n.state(t).Config.NTP; len(got) != 1 {
			t.Fatalf("ntp %v: the NTP change is meant to stay", got)
		}
	})
	t.Run("a DNS change that does not connect", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		n.probe.set(func(p *fakeProber) { p.gwErr = ops.ErrGatewaySilent })
		r := n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", ntp, func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }), api.StatusReverted, api.CodeConnectivityCheckFail)
		if !strings.Contains(r.Error.Message, sentence) {
			t.Fatalf("message %q does not say the NTP servers were updated", r.Error.Message)
		}
	})
	t.Run("nothing to add when NTP did not change", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		n.probe.set(func(p *fakeProber) { p.gwErrFor = map[string]error{"10.0.0.9": ops.ErrGatewaySilent} })
		r := n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusReverted, api.CodeConnectivityCheckFail)
		if strings.Contains(r.Error.Message, "NTP") {
			t.Fatalf("message %q mentions NTP although it did not change", r.Error.Message)
		}
	})
}

// A DNS or SPAN change that fails and cannot be put back is a failure that says so, never
// "the previous one was restored".
func TestContract_NetApply_AFailedRestoreOfADNSChangeIsReportedAsFailed(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	n.probe.set(func(p *fakeProber) { p.gwErr = ops.ErrGatewaySilent })
	// the first netplan apply works, every later one fails
	n.m.Rule("netplan", "apply", "", 0, "!seen", "seen")
	n.m.Rule("netplan", "apply", "", 1, "seen", "")
	r := n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }), api.StatusFailed, api.CodeRevertFailed)
	if strings.Contains(r.Error.Message, "was restored") || !strings.Contains(r.Error.Message, "could not be restored") {
		t.Fatalf("message %q", r.Error.Message)
	}
}

// --- L-4: a revert notices a changed /etc --------------------------------------------------------------------------

func TestContract_NetRevert_ALteredEtcFileIsAuditedAndTheOverlayIsRevertedAnyway(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.m.WriteRoot(etcNetplan, "# edited by hand while the change waited\n")
	n.ok(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
	done := waitStatus(t, n.h, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodeCancelled {
		t.Fatalf("run %+v", done)
	}
	n.gone(t, runNetplan)
	if !hasCode(auditCodes(t, n.h), "net.apply:etc_differs_from_old_sha") {
		t.Fatalf("the mismatch was not audited: %v", auditCodes(t, n.h))
	}
	if _, err := os.Lstat(n.pendingPath()); !os.IsNotExist(err) {
		t.Fatalf("the note is still there: %v", err)
	}
}

func TestContract_NetRevert_AnUnchangedEtcFileIsNotReported(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.ok(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
	waitStatus(t, n.h, run.RunID, api.StatusReverted)
	if hasCode(auditCodes(t, n.h), "net.apply:etc_differs_from_old_sha") {
		t.Fatal("a mismatch was reported although /etc is what it was")
	}
}

// --- info: panic in confirm, re-arming at start ---------------------------------------------------------------------------

// panicOn is a log handler that panics on one message: the way to make code after /etc was written panic.
type panicOn struct{ msg string }

func (panicOn) Enabled(context.Context, slog.Level) bool { return true }
func (p panicOn) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, p.msg) {
		panic("injected: " + r.Message)
	}
	return nil
}
func (p panicOn) WithAttrs([]slog.Attr) slog.Handler { return p }
func (p panicOn) WithGroup(string) slog.Handler      { return p }

// net.confirm finishes the claimed run exactly once even when the code after the write of /etc
// panics: the run ends failed confirm_failed and the write lock is free.
func TestContract_NetConfirm_APanicAfterTheWriteStillFinishesTheRun(t *testing.T) {
	t.Parallel()
	box, fp := &netBox{}, &fakeProber{}
	n := startNetWith(t, box, box.interfaces, fp, fp, func(c *ops.Config, _ *ops.Deps) {
		c.Logger = slog.New(panicOn{msg: "confirm: could not remove net/pending.json"})
	})
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	netDir := filepath.Join(n.m.State, "net")
	if err := os.Chmod(netDir, 0o500); err != nil { //nolint:gosec // deleting the note now fails, and the host logs it; a path of the test's own temp area
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(netDir, 0o700) }) //nolint:gosec // a path of the test's own temp area
	r, err := n.call(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	if err != nil || r.Status != api.StatusFailed {
		t.Fatalf("confirm: %+v %v", r, err)
	}
	done := waitStatus(t, n.h, run.RunID, api.StatusFailed)
	if done.Error == nil || done.Error.Code != api.CodeConfirmFailed {
		t.Fatalf("run %+v", done)
	}
	if err := os.Chmod(netDir, 0o700); err != nil { //nolint:gosec // a path of the test's own temp area
		t.Fatal(err)
	}
	n.ok(t, "os.reboot.cancel", nil) // the lock is free
}

// After a restart the monotonic clock is gone: a re-armed timer waits at most until 660 s after the
// note's started_at, whatever revert_at says.
func TestContract_NetApply_TheTimerReArmedAtStartIsClampedTo660SecondsFromStartedAt(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.ConfirmTimeoutS = 600 }))
	b, err := os.ReadFile(n.pendingPath())
	if err != nil || !strings.Contains(string(b), `"started_at":"2026-11-09T12:00:00Z"`) {
		t.Fatalf("note %s %v", b, err)
	}
	far := regexp.MustCompile(`"revert_at":"[^"]+"`).ReplaceAllString(string(b), `"revert_at":"2026-11-09T15:00:00Z"`)
	if err := os.WriteFile(n.pendingPath(), []byte(far), 0o600); err != nil { //nolint:gosec // a path of the test's own temp area
		t.Fatal(err)
	}
	n.clock.Advance(10 * time.Second)
	h2, timers2 := n.restart(t)
	waitStatus(t, h2, run.RunID, api.StatusAwaitingConfirm)
	act := timers2.active()
	if len(act) != 1 || act[0].d != 650*time.Second {
		t.Fatalf("timers %+v, want one of 650 s (660 s from started_at, 10 s gone)", act)
	}
}
