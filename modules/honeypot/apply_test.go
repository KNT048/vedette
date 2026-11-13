package honeypot_test

// Apply and the addresses of the traps: the config folder belongs to core (the container mounts it read-only), the host is
// reconciled whatever happens to the files, and an address that cannot be a trap is never handed to the host.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/honeypot"
)

// Core never reads what is in its config folder: a FIFO at the name of the file, fed by a writer, would block a read or
// grow core's memory for ever (a symlink to /dev/zero is the same). The file is replaced by rename, the FIFO is not touched.
func TestApplyNeverReadsWhatIsInTheConfigFolder(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	mkfifo(t, e.confPath())
	keep, err := os.OpenFile(e.confPath(), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The writer opens the FIFO before Apply starts (keep is a reader, so the open returns at once): opened later, on a slow
	// machine, it could open the regular file Apply renamed into place and fill the disk. It writes at most 16 MiB and stops
	// with EPIPE once keep is closed.
	w, err := os.OpenFile(e.confPath(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	wdone := make(chan struct{})
	go func() {
		defer close(wdone)
		defer func() { _ = w.Close() }()
		chunk := make([]byte, 1<<20)
		for range 16 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- e.svc.Apply(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		_ = keep.Close()
		t.Fatal("Apply did not finish: it reads the file at opencanary.conf")
	}
	_ = keep.Close()
	<-wdone
	st, err := os.Lstat(e.confPath())
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 || st.Mode().Perm() != 0o644 {
		t.Fatalf("opencanary.conf after Apply: %v, %v", st, err)
	}
	if !e.host.isRunning() {
		t.Fatal("the traps do not start")
	}
}

// A symlink at the name is replaced, not followed: the file it points to is not touched.
func TestApplyReplacesASymlinkAtTheConfigNameWithoutFollowingIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	victim := filepath.Join(e.dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(e.confPath()), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, e.confPath()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" { //nolint:gosec // test file
		t.Fatalf("Apply wrote through the symlink: %q", b)
	}
	if st, err := os.Lstat(e.confPath()); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("%v %v", st, err)
	}
}

// The files are written once and again only when they change, with no temporary file left behind.
func TestApplyWritesTheFilesOnlyWhenTheyChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(e.confPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	second, _ := os.Stat(e.confPath())
	if !os.SameFile(first, second) {
		t.Fatal("an unchanged configuration was written again")
	}
	if err := e.setServices(e.main, honeypot.SSH, honeypot.SMB, honeypot.HTTP); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(e.confPath()); !strings.Contains(string(b), `"http.enabled": true`) {
		t.Fatalf("the change was not written: %s", b)
	}
	list, _ := os.ReadDir(filepath.Dir(e.confPath()))
	var names []string
	for _, f := range list {
		names = append(names, f.Name())
	}
	if len(names) != 2 {
		t.Fatalf("files in the config folder: %v (a temporary file was left)", names)
	}
}

// The container is asked to restart only when a configuration file was written since the last start the host
// acknowledged (D-161): the first start, and a start after a change; not the repeat of an unchanged Apply, and a start
// that failed keeps the restart due.
func TestApplyAsksForARestartOnlyAfterTheConfigurationChanged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	apply := func() {
		t.Helper()
		if err := e.svc.Apply(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	apply()
	if err := e.setServices(e.main, honeypot.SSH, honeypot.SMB, honeypot.HTTP); err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	e.host.failStart = errors.New("host busy")
	e.host.mu.Unlock()
	if err := e.svc.Apply(e.ctx()); err == nil {
		t.Fatal("a failed start was not reported")
	}
	e.host.mu.Lock()
	e.host.failStart = nil
	e.host.mu.Unlock()
	apply()
	apply()
	e.host.mu.Lock()
	got := append([]bool(nil), e.host.restarts...)
	e.host.mu.Unlock()
	if want := []bool{true, false, true, true, false}; !slices.Equal(got, want) {
		t.Fatalf("restart flags of the starts: %v, want %v", got, want)
	}
}

// breakConfigFolder makes ConfigDir unwritable (a file stands where the folder was): disk full, a changed mode, a broken
// mount all end in a write that fails.
func breakConfigFolder(t *testing.T, e *env) {
	t.Helper()
	dir := filepath.Dir(e.confPath())
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The host is reconciled even when the files cannot be written: a device that takes the Trap IP's address still makes the
// host drop it (FORBID-1) and turning every Trap IP off still stops the container (POST-5).
func TestApplyReconcilesTheHostWhenTheFilesCannotBeWritten(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.host.isRunning() || e.host.ipCount() != 1 {
		t.Fatalf("setup: running=%v ips=%d", e.host.isRunning(), e.host.ipCount())
	}
	breakConfigFolder(t, e)
	e.inv.add(dev("a-late", "192.168.10.240", "LATE", "pc"))
	if err := e.enable(e.main, false); err != nil {
		t.Fatal(err)
	}
	err := e.svc.Apply(ctx)
	if err == nil {
		t.Fatal("the failed write is reported")
	}
	if e.host.ipCount() != 0 || e.host.isRunning() {
		t.Fatalf("decoy IPs still on the host=%d, container running=%v; Apply: %v", e.host.ipCount(), e.host.isRunning(), err)
	}
}

// Without a written configuration nothing new is handed to the host: no address, no start of the container.
func TestApplyAddsNothingToTheHostWhenTheFilesCannotBeWritten(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	breakConfigFolder(t, e)
	if err := e.svc.Apply(e.ctx()); err == nil {
		t.Fatal("the failed write is reported")
	}
	for _, c := range e.host.log() {
		if strings.HasPrefix(c, "add ") || c == "start" {
			t.Fatalf("the host was asked to take an address or start without a configuration: %v", e.host.log())
		}
	}
}

// The box takes a Trap IP's address after it was accepted (a DHCP lease while it was off, a re-addressed box): it is never
// handed to the host as a decoy and the Trap IP cannot be turned on again (FORBID-1).
func TestTrapIPThatBecomesTheBoxIPIsAConflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	e.inv.mu.Lock()
	e.inv.box.IP = addr("192.168.10.240")
	e.inv.devices[0].IP = addr("192.168.10.240") // the box record of the inventory
	e.inv.mu.Unlock()
	if err := e.enable(e.main, false); err != nil {
		t.Fatal(err)
	}
	if enableErr := e.enable(e.main, true); apiCode(t, enableErr) != "ip_is_box" {
		t.Fatalf("enabling a Trap IP on the box's own IP: %v", enableErr)
	}
	e.exec(`UPDATE hp_trap_ips SET enabled = 1`) // switched on before the box took it
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := e.svc.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range o.Traps {
		if tr.Enabled && tr.State != honeypot.StateConflict {
			t.Errorf("%s is %s on the box's own address", tr.Service, tr.State)
		}
	}
	if e.host.ips[addr("192.168.10.240")] || e.host.isRunning() {
		t.Fatalf("the box address went to the host: ips=%v running=%v", e.host.ips, e.host.isRunning())
	}
	if why := e.svc.TrapConflicts()[addr("192.168.10.240")]; !strings.Contains(why, "box") {
		t.Fatalf("reason %q", why)
	}
}

// A Trap IP that is the box's own now stays out of the host and the other traps go on; when the LAN range changes so that
// every Trap IP is outside it, nothing is handed to the host at all.
func TestDecoyIPThatCannotBeATrapAnyMoreStaysOutOfTheHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	for i, ip := range []string{"192.168.10.241", "192.168.10.242"} {
		e.addTrapIP(fmt.Sprintf("LNX-%d", i), ip, honeypot.Linux, honeypot.SSH)
	}
	e.inv.mu.Lock()
	e.inv.box.IP = addr("192.168.10.241")
	e.inv.devices[0].IP = addr("192.168.10.241")
	e.inv.mu.Unlock()
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if e.host.ips[addr("192.168.10.241")] || !e.host.ips[addr("192.168.10.240")] || !e.host.ips[addr("192.168.10.242")] || !e.host.isRunning() {
		t.Fatalf("the box's own address went to the host or the others were dropped: %v", e.host.ips)
	}
	if c := e.svc.TrapConflicts(); len(c) != 1 || c[addr("192.168.10.241")] == "" {
		t.Fatalf("conflicts %v", c)
	}
	e.inv.mu.Lock()
	e.inv.ranges = []netip.Prefix{netip.MustParsePrefix("192.168.10.0/25")} // .240 to .242 are outside now
	e.inv.mu.Unlock()
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if e.host.ipCount() != 0 || e.host.isRunning() {
		t.Fatalf("addresses outside the LAN went to the host: %v", e.host.ips)
	}
	if o, _ := e.svc.Overview(ctx); o.Traps[2].State != honeypot.StateConflict {
		t.Fatalf("ssh trap %s with every Trap IP outside the LAN", o.Traps[2].State)
	}
}

// The host holds 32 addresses (host-api 6.6): the 33rd Trap IP is refused at creation.
func TestTrapIPsStayWithinTheHostLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	add := func(i int) error {
		_, err := e.tryAddTrapIP(fmt.Sprintf("LNX-%02d", i), fmt.Sprintf("192.168.10.%d", 150+i), honeypot.Linux, honeypot.SSH)
		return err
	}
	for i := range 31 {
		if err := add(i); err != nil {
			t.Fatalf("trap IP %d: %v", i, err)
		}
	}
	if err := add(31); apiCode(t, err) != "limit_reached" {
		t.Fatalf("a 33rd Trap IP: %v", err)
	}
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.host.ipCount(); n != 32 {
		t.Fatalf("%d addresses on the host, want 32", n)
	}
}

// Past the limit in the database (rows written by an older version or by hand) Apply hands the host 32 addresses, the
// oldest Trap IPs first, and says why it left the rest out.
func TestApplyCapsTheAddressesAtTheHostLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		for i := range 33 {
			_, err := tx.ExecContext(ctx, `INSERT INTO hp_trap_ips (id, name, ip, preset, services, enabled, created_at) VALUES (?, ?, ?, 'linux', '["ssh"]', 1, ?)`,
				fmt.Sprintf("dec-%02d", i), fmt.Sprintf("LNX-%02d", i), fmt.Sprintf("192.168.10.%d", 150+i), fmt.Sprintf("2026-11-09T10:00:%02d.000Z", i))
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.host.ipCount(); n != 32 || !e.host.ips[addr("192.168.10.240")] {
		t.Fatalf("%d addresses, the first Trap IP present %v", n, e.host.ips[addr("192.168.10.240")])
	}
	c := e.svc.TrapConflicts()
	if len(c) != 2 || !strings.Contains(c[addr("192.168.10.182")], "32") {
		t.Fatalf("conflicts %v", c)
	}
}

// Two requests at the limit cannot both pass: the check is in the transaction that writes.
func TestAddTrapIPLimitHoldsUnderConcurrency(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	for i := range 30 {
		e.addTrapIP(fmt.Sprintf("LNX-%02d", i), fmt.Sprintf("192.168.10.%d", 150+i), honeypot.Linux, honeypot.SSH)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.AddTrapIP(ctx, "a", honeypot.TrapIPInput{Name: fmt.Sprintf("NEW-%02d", i), IP: fmt.Sprintf("192.168.10.%d", 200+i), Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.SSH}})
			if err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d of 6 concurrent adds passed at one free slot", ok)
	}
	if n := e.count(`SELECT count(*) FROM hp_trap_ips`); n != 32 {
		t.Fatalf("%d trap IPs", n)
	}
}

type refuseOneIP struct {
	*fakeHost
	bad netip.Addr
}

func (h refuseOneIP) AddDecoyIP(ctx context.Context, ip netip.Addr, spec honeypot.DecoySpec) error {
	if ip == h.bad {
		return fmt.Errorf("ip_in_use: an ARP probe got an answer: %w", honeypot.ErrRefused)
	}
	return h.fakeHost.AddDecoyIP(ctx, ip, spec)
}

// One decoy IP the host refuses (an ARP probe answered by a device the inventory does not know yet) leaves the other
// traps up; the refused address is a conflict with the host's reason.
func TestOneRefusedDecoyIPDoesNotTakeTheOtherTrapsDown(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.cfg.Host = refuseOneIP{fakeHost: e.host, bad: addr("192.168.10.241")}
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	ctx := e.ctx()
	e.addTrapIP("PRN-FLOOR2", "192.168.10.241", honeypot.Printer, honeypot.HTTP)
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatalf("a refusal is not an Apply failure: %v", err)
	}
	if !e.host.isRunning() || !e.host.ips[addr("192.168.10.240")] || e.host.ips[addr("192.168.10.241")] {
		t.Fatalf("running=%v ips=%v", e.host.isRunning(), e.host.ips)
	}
	if why := e.svc.TrapConflicts()[addr("192.168.10.241")]; !strings.Contains(why, "ARP probe") {
		t.Fatalf("reason %q", why)
	}
	o, _ := e.svc.Overview(ctx)
	if o.Traps[2].State != honeypot.StateListening {
		t.Fatalf("ssh trap %s", o.Traps[2].State)
	}
	// The refused address is not owned by the box: a device there is a device.
	for _, ip := range e.svc.DecoyIPs(ctx) {
		if ip == addr("192.168.10.241") {
			t.Fatal("a refused address is listed as owned")
		}
	}
}

// When the host refuses one Trap IP that one is in conflict (INV-7) and the Trap IPs that were accepted keep running.
func TestRefusedTrapIPIsAConflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.cfg.Host = refuseOneIP{fakeHost: e.host, bad: addr("192.168.10.240")}
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	ctx := e.ctx()
	e.addTrapIP("PRN-FLOOR2", "192.168.10.241", honeypot.Printer, honeypot.HTTP)
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	o, _ := e.svc.Overview(ctx)
	if o.Traps[2].State != honeypot.StateConflict || o.Traps[4].State != honeypot.StateListening {
		t.Fatalf("ssh trap %s (refused address), http trap %s", o.Traps[2].State, o.Traps[4].State)
	}
	if st := e.trapIP(e.main).State; st != honeypot.StateConflict {
		t.Fatalf("refused Trap IP %s", st)
	}
	if !e.host.isRunning() || e.host.ipCount() != 1 {
		t.Fatalf("running=%v ips=%v", e.host.isRunning(), e.host.ips)
	}
}

// When the host refuses every address nothing runs and Apply says so.
func TestEveryAddressRefusedStopsTheContainer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.cfg.Host = refuseOneIP{fakeHost: e.host, bad: addr("192.168.10.240")}
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	if err := e.svc.Apply(e.ctx()); err == nil {
		t.Fatal("no address was placed: Apply reports it")
	}
	if e.host.isRunning() {
		t.Fatal("the container runs with no address")
	}
}

// DecoyIPs is the set the host holds after Apply: what inventory and the active sensor must leave alone (CONTRACT, open
// question 2). It is empty before the host has anything, follows decoys that are added or removed, and survives a restart.
func TestDecoyIPsAreTheAddressesTheHostHolds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	if got := e.svc.DecoyIPs(ctx); len(got) != 0 {
		t.Fatalf("before anything: %v", got)
	}
	e.setup()
	d := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if got := e.svc.DecoyIPs(ctx); len(got) != 0 {
		t.Fatalf("configured but not handed to the host yet: %v", got)
	}
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	set := func(s *honeypot.Service) map[netip.Addr]bool {
		m := map[netip.Addr]bool{}
		for _, ip := range s.DecoyIPs(ctx) {
			m[ip] = true
		}
		return m
	}
	if got := set(e.svc); len(got) != 2 || !got[addr("192.168.10.240")] || !got[addr("192.168.10.241")] {
		t.Fatalf("after Apply: %v", got)
	}
	again, err := honeypot.New(e.cfg) // a new process knows it from the database
	if err != nil {
		t.Fatal(err)
	}
	if got := set(again); len(got) != 2 {
		t.Fatalf("after a restart: %v", got)
	}
	if err := e.svc.DeleteTrapIP(ctx, "a", d.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if got := set(e.svc); len(got) != 1 || !got[addr("192.168.10.240")] {
		t.Fatalf("after the Trap IP was removed: %v", got)
	}
	if err := e.svc.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.DecoyIPs(ctx); len(got) != 0 {
		t.Fatalf("module off: %v", got)
	}
}

// A device really on the address (a conflict) is not box-owned: the inventory must see it.
func TestAddressWithADeviceIsNotOwnedByTheBox(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	e.inv.add(dev("a-late", "192.168.10.240", "LATE", "pc"))
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.DecoyIPs(ctx); len(got) != 0 {
		t.Fatalf("an address with a device on it is listed as owned: %v", got)
	}
}
