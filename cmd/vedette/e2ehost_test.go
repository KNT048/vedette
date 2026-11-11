package main

// The fakes of the real-backend run that stand for the machine around the box (WP-30 slice 4, D-163): an in-process vedette-host on a
// fake machine (the real host/ops commands on a temporary root, as modules/core/os_test.go and network_test.go build it), a small
// control endpoint to make that host fail, and a second box with no host at all (D-55). Test binary only: the product never imports them.
// Opt-in: VEDETTE_E2E_HOST=1 (make e2e-real sets it), so the plain harness test and the other slices are not slowed down.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	hostserver "github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// e2eHost is the fake machine and the host that runs on it.
type e2eHost struct {
	m        *opstest.Machine
	socket   string // -host-socket of the box
	dataDir  string // the box's data dir is the machine's core data (main.go checks that vedette.db and vedette.key sit there)
	lock     atomic.Bool
	fail     atomic.Bool // apt-get install fails
	ctlURL   string
	ctlToken string
	client   *hostclient.Client // the host's own answers, for GET /honeypot of the control endpoint (slice 8b)
}

var e2eAddrRE = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+/\d+`)

// e2eNIC makes a network card under the fake sysfs (physical ones have a device link).
func e2eNIC(t testing.TB, root, name string, physical bool) {
	t.Helper()
	dev := filepath.Join(root, "sys/devices/pci0000:00/net", name)
	for _, d := range []string{filepath.Join(dev, "statistics"), filepath.Join(root, "sys/class/net")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{"statistics/rx_packets": "0", "statistics/tx_packets": "0", "operstate": "up", "speed": "1000", "flags": "0x1003"} {
		if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if physical {
		if err := os.Symlink("../..", filepath.Join(dev, "device")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../../devices/pci0000:00/net/"+name, filepath.Join(root, "sys/class/net", name)); err != nil {
		t.Fatal(err)
	}
}

// e2eProber is an ARP prober that finds every address free and every gateway alive.
type e2eProber struct{}

func (e2eProber) Probe(context.Context, string, netip.Addr) (ops.ProbeResult, error) {
	return ops.ProbeResult{MAC: "aa:bb:cc:dd:ee:ff"}, nil
}
func (e2eProber) GatewayCheck(context.Context, string, netip.Addr, netip.Addr) error { return nil }

// interfaces are the cards of the fake machine; eth0's addresses follow whichever netplan file the host wrote last.
func (h *e2eHost) interfaces() ([]ops.HostIface, error) {
	text, err := h.m.ReadRoot("run/netplan/90-vedette.yaml")
	if err != nil {
		text, _ = h.m.ReadRoot("etc/netplan/90-vedette.yaml")
	}
	addrs := []netip.Prefix{netip.MustParsePrefix("192.168.1.50/24")}
	for _, a := range e2eAddrRE.FindAllString(text, -1) {
		addrs = append(addrs, netip.MustParsePrefix(a))
	}
	if strings.Contains(text, "dhcp4: true") {
		addrs = append(addrs, netip.MustParsePrefix("192.168.1.77/24"))
	}
	return []ops.HostIface{
		{Name: "lo", Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: addrs},
		{Name: "eth1", MAC: "02:00:00:00:00:02"},
		{Name: "eth2", MAC: "02:00:00:00:00:03", Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}},
		{Name: "veth1234", MAC: "02:00:00:00:00:04", Addrs: []netip.Prefix{netip.MustParsePrefix("10.88.0.1/16")}},
	}, nil
}

// aptRules is what the fake apt answers: updates pending until an install ran; the install fails while the knob is on.
func (h *e2eHost) aptRules() {
	h.m.ClearRules("apt-get")
	h.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	if h.fail.Load() {
		h.m.Rule("apt-get", "install", "", 100, "", "")
	} else {
		h.m.Rule("apt-get", "install", "", 0, "", "installed")
	}
	h.m.Rule("apt-get", "dist-upgrade", "sim_after.txt", 0, "installed", "")
	h.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
}

// autoSecurityFakes replaces opstest's fixed apt-config and systemctl by fakes that follow the switch: the host writes
// etc/apt/apt.conf.d/52vedette-unattended and reads the effect back, so the fakes answer "on" or "off" from that file.
// systemctl reboot is only recorded (reboots), never run.
func (h *e2eHost) autoSecurityFakes(t testing.TB) {
	t.Helper()
	conf := filepath.Join(h.m.Root, "etc/apt/apt.conf.d/52vedette-unattended")
	exectest.WriteScript(t, filepath.Join(h.m.Bin, "apt-config"), `#!/bin/sh
if grep -q 'Unattended-Upgrade "0"' '`+conf+`' 2>/dev/null; then cat '`+opstest.Fixture("aptconfig_off.txt")+`'; else cat '`+opstest.Fixture("aptconfig_on.txt")+`'; fi
`)
	exectest.WriteScript(t, filepath.Join(h.m.Bin, "systemctl"), `#!/bin/sh
case "$2" in vedette-honeypot*) exec '`+filepath.Join(h.m.Bin, "systemctl.ctr")+`' "$@" ;; esac
off() { grep -q 'Unattended-Upgrade "0"' '`+conf+`' 2>/dev/null; }
case "$1" in
  is-active) cat '`+opstest.Fixture("active.txt")+`' ;;
  is-enabled) if off; then cat '`+opstest.Fixture("disabled.txt")+`'; exit 1; else cat '`+opstest.Fixture("enabled.txt")+`'; fi ;;
  reboot) echo reboot >> '`+filepath.Join(h.m.Rec, "reboots")+`' ;;
esac
exit 0
`)
}

// honeypotFakes (slice 8b) gives the machine the honeypot unit and a systemctl and podman that remember what container.start and
// container.stop do (opstest's stateful ones). They answer for the honeypot unit only: every other call goes on to the fakes of the
// OS-update slice, which the stateful ones would change (is-active of any unit, podman of anything). The stateful systemctl is saved as
// systemctl.ctr, which autoSecurityFakes hands the honeypot calls to; podman gets a small wrapper here.
func (h *e2eHost) honeypotFakes(t testing.TB) {
	t.Helper()
	plain, ctr := filepath.Join(h.m.Bin, "podman.plain"), filepath.Join(h.m.Bin, "podman.ctr")
	if err := os.Rename(filepath.Join(h.m.Bin, "podman"), plain); err != nil {
		t.Fatal(err)
	}
	h.m.StatefulContainers()
	for from, to := range map[string]string{"podman": ctr, "systemctl": filepath.Join(h.m.Bin, "systemctl.ctr")} {
		if err := os.Rename(filepath.Join(h.m.Bin, from), to); err != nil {
			t.Fatal(err)
		}
	}
	exectest.WriteScript(t, filepath.Join(h.m.Bin, "podman"), `#!/bin/sh
case "$1 $2 $3" in "container inspect vedette-honeypot"*) exec '`+ctr+`' "$@" ;; esac
exec '`+plain+`' "$@"
`)
	h.m.InstallUnit(api.ServiceHoneypot, opstest.Digest('a'), true)
}

// startE2EHost starts the fake machine and its host on a unix socket, and the control endpoint. Everything stops with t.
func startE2EHost(t testing.TB) *e2eHost {
	t.Helper()
	h := &e2eHost{m: opstest.NewMachine(t)}
	// opstest's fake database and key are plain bytes: the box makes its own in this folder.
	_ = os.Remove(h.m.CoreDBPath())
	_ = os.Remove(filepath.Join(h.m.CoreData, "vedette.key"))
	h.dataDir = h.m.CoreData
	for _, c := range []struct {
		n string
		p bool
	}{{"eth0", true}, {"eth1", true}, {"eth2", false}} {
		e2eNIC(t, h.m.Root, c.n, c.p)
	}
	h.m.WriteRoot("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	h.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n^,+,ntp1.example.com,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	h.aptRules()
	h.honeypotFakes(t)
	h.autoSecurityFakes(t)

	o := h.m.Ops(time.Now, func(_ *ops.Config, d *ops.Deps) {
		d.LockHeld = func(string) (bool, error) { return h.lock.Load(), nil }
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
		// no timer fires during a run: a scheduled reboot never happens, and the 5-minute network revert is a Go test (D-118)
		d.AfterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } }
		d.Interfaces, d.Probe = h.interfaces, e2eProber{}
		d.NetPoll, d.NetWait, d.NetRetryGap = time.Millisecond, 30*time.Millisecond, time.Millisecond
	})
	hh := servertest.Start(t, o.Commands(), func(op *hostserver.Options) {
		op.StateDir, op.Readers, op.Now, op.WriteGate, op.Resume = h.m.State, o.Readers(), time.Now, o.WriteGate, o.Resume
	})
	o.Start(context.Background(), hh.Server)
	t.Cleanup(o.Close)
	h.socket, h.client = hh.Socket, hh.Client

	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		t.Fatal(err)
	}
	h.ctlToken = hex.EncodeToString(tok)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.ctlURL = "http://" + ln.Addr().String()
	srv := &http.Server{Handler: h.control(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return h
}

// control is the knobs of the fake host, behind a bearer token (the token is in ready.json, 0600): POST /host?lock=on|off makes
// the dpkg lock held (a run is refused 409 dpkg_locked), POST /host?install_fail=on|off makes apt-get install exit 100,
// reboot_required=on|off writes or removes /var/run/reboot-required, updates=reset makes the packages pending again, boot=<id> is a reboot done,
// hp_start=fail|ok makes `systemctl restart vedette-honeypot` exit 1 or work (slice 8b).
// GET /honeypot (slice 8b) is what the host itself says about the honeypot: the unit state and the decoy addresses with their MAC.
func (h *e2eHost) control() http.Handler {
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+h.ctlToken)) != 1 {
			http.Error(w, "no", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /honeypot", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		out := struct {
			UnitState string         `json:"unit_state"`
			Decoys    []api.NetDecoy `json:"decoys"`
			Restarts  int            `json:"restarts"` // `systemctl restart vedette-honeypot` calls so far, failed ones too
		}{Decoys: []api.NetDecoy{}}
		for _, c := range h.m.Calls("systemctl") {
			if len(c) > 1 && c[0] == "restart" && strings.HasPrefix(c[1], "vedette-honeypot") {
				out.Restarts++
			}
		}
		cs, err := h.client.StateContainers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for _, s := range cs.Services {
			if s.Service == api.ServiceHoneypot {
				out.UnitState = s.UnitState
			}
		}
		ns, err := h.client.StateNet(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		out.Decoys = append(out.Decoys, ns.Decoys...)
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /host", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		q := r.URL.Query()
		if v := q.Get("hp_start"); v != "" {
			h.m.Mark("restart-fails", v == "fail")
		}
		if v := q.Get("lock"); v != "" {
			h.lock.Store(v == "on")
		}
		if v := q.Get("install_fail"); v != "" {
			h.fail.Store(v == "on")
			h.aptRules()
		}
		if q.Get("reboot_required") != "" {
			if q.Get("reboot_required") == "on" {
				h.m.WriteRoot("var/run/reboot-required", "*** System restart required ***\n")
				h.m.WriteRoot("var/run/reboot-required.pkgs", "libc6\n")
			} else {
				h.m.RemoveRoot("var/run/reboot-required")
				h.m.RemoveRoot("var/run/reboot-required.pkgs")
			}
		}
		if q.Get("updates") == "reset" { // the packages are pending again
			h.m.Mark("installed", false)
		}
		if id := q.Get("boot"); id != "" { // the box came back from a reboot: the host takes writes again
			h.m.SetBootID(id)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"lock": h.lock.Load(), "install_fail": h.fail.Load()})
	})
	return mux
}

// startE2EBare runs a second box with no vedette-host (-host-socket "": a container-only install, D-55) in dir/bare and returns its
// ready.json. It stops with ctx; t waits for it.
func startE2EBare(ctx context.Context, t testing.TB, dir string) e2eReady {
	t.Helper()
	bare := filepath.Join(dir, "bare")
	if err := os.MkdirAll(bare, 0o700); err != nil { //nolint:gosec // test harness: dir is t.TempDir() or the folder the script made
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e2eBoxWith(ctx, bare, "", "", e2eReady{}) }()
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				t.Logf("bare box: %v", err)
			}
		case <-time.After(15 * time.Second):
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(bare, "ready.json")) //nolint:gosec // test harness: the folder is the one the script made
		var r e2eReady
		if err == nil && json.Unmarshal(b, &r) == nil {
			return r
		}
		select {
		case err := <-done:
			t.Fatalf("the bare box ended before it was ready: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the bare box was not ready in 30 s")
		}
	}
}

// TestE2EBoxHarnessHost runs in CI: the box with the fake host starts on the host's data folder, the bare box answers beside it, the
// control endpoint wants its token, and both stop on cancel.
func TestE2EBoxHarnessHost(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	host := startE2EHost(t)
	bare := startE2EBare(ctx, t, dir)
	done := make(chan error, 1)
	go func() {
		done <- e2eBoxWith(ctx, dir, host.dataDir, host.socket, e2eReady{HostControl: host.ctlURL, HostToken: host.ctlToken, BareURL: bare.BaseURL})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("box: %v", err)
			}
		case <-time.After(15 * time.Second):
		}
	})

	var ready e2eReady
	for deadline := time.Now().Add(20 * time.Second); ; {
		b, err := os.ReadFile(filepath.Join(dir, "ready.json")) //nolint:gosec // test harness: the folder is the one the script made
		if err == nil && json.Unmarshal(b, &ready) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ready.json did not appear within 20 s")
		}
		<-time.After(100 * time.Millisecond)
	}
	if ready.DataDir != host.dataDir || ready.HostControl == "" || ready.HostToken == "" || !strings.HasPrefix(ready.BareURL, "http://127.0.0.1:") || ready.BareURL == ready.BaseURL {
		t.Fatalf("ready.json = %+v", ready)
	}
	call := func(method, url, token string) int {
		req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := call(http.MethodPost, ready.HostControl+"/host?lock=on", ""); got != http.StatusUnauthorized {
		t.Errorf("control without a token = %d", got)
	}
	if got := call(http.MethodPost, ready.HostControl+"/host?lock=off", ready.HostToken); got != http.StatusOK {
		t.Errorf("control with the token = %d", got)
	}
	// slice 8b: the host has the honeypot unit (stopped) and no decoy; the control endpoint says so, and wants its token
	if got := call(http.MethodGet, ready.HostControl+"/honeypot", ""); got != http.StatusUnauthorized {
		t.Errorf("GET /honeypot without a token = %d", got)
	}
	hreq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ready.HostControl+"/honeypot", nil)
	if err != nil {
		t.Fatal(err)
	}
	hreq.Header.Set("Authorization", "Bearer "+ready.HostToken)
	hresp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}).Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	var hp struct {
		UnitState string         `json:"unit_state"`
		Decoys    []api.NetDecoy `json:"decoys"`
	}
	err = json.NewDecoder(hresp.Body).Decode(&hp)
	_ = hresp.Body.Close()
	if err != nil || hresp.StatusCode != http.StatusOK || hp.UnitState != api.UnitInactive || len(hp.Decoys) != 0 {
		t.Errorf("GET /honeypot = %d %+v %v", hresp.StatusCode, hp, err)
	}
	for _, u := range []string{ready.BaseURL, ready.BareURL} {
		if got := call(http.MethodGet, u+"/api/v1/setup", ""); got != http.StatusOK {
			t.Errorf("GET %s/api/v1/setup = %d", u, got)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the box returned %v on cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return within 15 s of cancel")
	}
}
