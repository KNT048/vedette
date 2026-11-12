// Contract tests of the host framework (modules/host/CONTRACT.md). WP-07a covers the invariants
// the framework itself owns: INV-1, INV-2, INV-3, INV-4, INV-12, POST-4, FORBID-1 and FORBID-2.
// The command-specific ones (INV-5..11, POST-1..3, FORBID-3..6) come with the commands in WP-07b.
package host_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

const (
	rid1 = "11111111-1111-4111-8111-111111111111"
	rid2 = "22222222-2222-4222-8222-222222222222"
)

// documentedCommands is the command list of docs/specs/host-api.md section 6 that is implemented.
// WP-07b implements the OS, backup, log and network and decoy commands (contract_os_test.go checks the list
// against the spec); the container commands follow in later slices. Sorted.
var documentedCommands = []string{
	"backup.create", "backup.purge", "backup.restore", "container.pull", "container.rollback", "container.start", "container.stop", "decoy_ip.add", "decoy_ip.remove", "logs.export", "net.apply", "net.confirm", "net.revert",
	"os.auto_security.set", "os.check", "os.install", "os.reboot", "os.reboot.cancel",
}

// netArgs mirrors how a real command validates: name regex, netip for IPs, enum, HH:MM.
type netArgs struct {
	Name  string `json:"name"`
	IP    string `json:"ip"`
	Scope string `json:"scope"`
	At    string `json:"at"`
}

type fixture struct {
	ran     atomic.Int64
	release chan struct{}
	started chan struct{}
	cmds    []server.Command
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{release: make(chan struct{}), started: make(chan struct{}, 8)}
	t.Cleanup(func() {
		select {
		case <-f.release:
		default:
			close(f.release)
		}
	})
	f.cmds = []server.Command{
		server.Define(server.Spec[netArgs]{
			Name: "test.set", Write: true, Timeout: 5 * time.Second,
			Validate: func(a *netArgs) error {
				if !validName(a.Name) {
					return server.Invalid("name", "must match ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
				}
				if ip, err := netip.ParseAddr(a.IP); err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
					return server.Invalid("ip", "must be an IPv4 unicast address")
				}
				if a.Scope != "security" && a.Scope != "all" {
					return server.Invalid("scope", "must be security or all")
				}
				if len(a.At) != 5 || a.At[2] != ':' {
					return server.Invalid("at", "must be HH:MM")
				}
				if _, err := time.Parse("15:04", a.At); err != nil {
					return server.Invalid("at", "must be HH:MM")
				}
				return nil
			},
			Run: func(context.Context, *server.RunContext, netArgs) (any, error) {
				f.ran.Add(1)
				return nil, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.slow", Write: true, Timeout: 10 * time.Second,
			Run: func(ctx context.Context, _ *server.RunContext, _ struct{}) (any, error) {
				f.ran.Add(1)
				f.started <- struct{}{}
				select {
				case <-f.release:
				case <-ctx.Done():
				}
				return nil, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.stuck", Write: true, Timeout: 50 * time.Millisecond,
			Run: func(ctx context.Context, _ *server.RunContext, _ struct{}) (any, error) {
				<-ctx.Done() // a command that honours its deadline
				return nil, ctx.Err()
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.deaf", Write: true, Timeout: 50 * time.Millisecond,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				f.ran.Add(1)
				<-f.release // ignores cancellation: the lock must stay held
				return nil, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.ok", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) { f.ran.Add(1); return nil, nil },
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.fail", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return nil, errors.New("boom")
			},
		}),
	}
	return f
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || !strings.ContainsRune("_.-", rune(c))) {
			return false
		}
	}
	return true
}

func hdr(id string) map[string]string {
	return map[string]string{"Content-Type": "application/json", api.HeaderProto: "1", api.HeaderActor: "admin@example.com", api.HeaderRequestID: id}
}

func rawReq(t *testing.T, h *servertest.Harness, path string, headers map[string]string, body string) (int, []byte) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", h.Socket)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://host"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func errCode(b []byte) string {
	var eb api.ErrorBody
	_ = json.Unmarshal(b, &eb)
	return eb.Error.Code
}

func waitDone(t *testing.T, c *client.Client, runID string) api.Run {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // 61 forks of a fake podman take a while on a loaded machine
	defer cancel()
	s := c.Events(ctx, runID, 0)
	defer s.Close()
	for {
		if _, err := s.Next(); err != nil {
			break
		}
	}
	r, err := c.GetRun(ctx, runID)
	if err != nil || !r.Status.Terminal() {
		t.Fatalf("run %s: %+v %v", runID, r, err)
	}
	return r
}

func audit(t *testing.T, h *servertest.Harness) []api.AuditRecord {
	t.Helper()
	p, err := h.Client.Audit(context.Background(), 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	return p.Records
}

// --- INV-1 -------------------------------------------------------------------------------------

func TestContract_INV1_UnknownCommandIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	names := []string{"os.install", "os.check", "exec", "sh", "run", "shell.exec", "apt.install", "TEST.OK", "test.ok ", "test.ok;id", "container.pull"}
	for i, n := range names {
		st, body := rawReq(t, h, "/v1/commands/"+strings.ReplaceAll(n, " ", "%20")+"", hdr(fmt.Sprintf("%08d-1111-4111-8111-111111111111", i)), `{"args":{}}`)
		if st != http.StatusNotFound || errCode(body) != api.CodeUnknownCommand {
			t.Errorf("%q: %d %s", n, st, body)
		}
	}
	if f.ran.Load() != 0 {
		t.Fatal("a command ran")
	}
	runs, _ := h.Client.ListRuns(context.Background(), 100)
	if len(runs) != len(names) {
		t.Fatalf("%d runs for %d unknown commands", len(runs), len(names))
	}
	for _, r := range runs {
		if r.Status != api.StatusRefused || r.Error.Code != api.CodeUnknownCommand {
			t.Fatalf("run = %+v", r)
		}
	}
	if n := len(audit(t, h)); n != len(names) {
		t.Fatalf("%d audit lines for %d refusals", n, len(names))
	}
}

func TestContract_INV1_CommandTableIsClosedAndMatchesTheSpec(t *testing.T) {
	t.Parallel()
	// The table is built once; the type has no way to add or remove a command.
	var methods []string
	typ := reflect.TypeFor[*server.Registry]()
	for i := range typ.NumMethod() {
		methods = append(methods, typ.Method(i).Name)
	}
	slices.Sort(methods)
	if !slices.Equal(methods, []string{"Lookup", "Names"}) {
		t.Fatalf("Registry methods = %v", methods)
	}
	sysReg, err := server.NewRegistry(opstest.NewMachine(t).Ops(nil).Commands()...)
	if err != nil {
		t.Fatal(err)
	}
	if got := sysReg.Names(); !slices.Equal(got, documentedCommands) {
		t.Fatalf("the system registry has %v, the documented list is %v (change docs/specs/host-api.md, CONTRACT.md and this list together)", got, documentedCommands)
	}
	// What the server advertises is exactly the table.
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	info, err := h.Client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := server.NewRegistry(f.cmds...)
	if !slices.Equal(info.Commands, reg.Names()) {
		t.Fatalf("info.commands = %v, table = %v", info.Commands, reg.Names())
	}
}

func TestContract_INV1_NothingTakesABinaryArgvOrPathFromTheRequest(t *testing.T) {
	t.Parallel()
	// The wire type carries arguments only.
	typ := reflect.TypeFor[api.CommandRequest]()
	if typ.NumField() != 1 || typ.Field(0).Name != "Args" {
		t.Fatalf("CommandRequest has fields beyond Args: %v", typ)
	}
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	good := `"args":{"name":"x","ip":"192.168.1.5","scope":"all","at":"10:30"}`
	for _, extra := range []string{
		`"binary":"/bin/sh"`, `"argv":["sh","-c","id"]`, `"exec":"id"`, `"path":"/etc/shadow"`, `"cmd":"id"`,
		`"env":{"LD_PRELOAD":"/tmp/x"}`, `"shell":true`, `"stdin":"x"`,
	} {
		st, body := rawReq(t, h, "/v1/commands/test.set", hdr(rid1), "{"+good+","+extra+"}")
		if st != http.StatusBadRequest || errCode(body) != api.CodeInvalidArgs {
			t.Errorf("%s: %d %s", extra, st, body)
		}
	}
	// And in the args object itself: fields the command does not declare.
	for _, k := range []string{"binary", "argv", "path", "command", "args", "env", "cwd"} {
		body := fmt.Sprintf(`{"args":{"name":"x","ip":"192.168.1.5","scope":"all","at":"10:30",%q:"x"}}`, k)
		if st, b := rawReq(t, h, "/v1/commands/test.set", hdr(rid1), body); st != http.StatusBadRequest {
			t.Errorf("args field %s: %d %s", k, st, b)
		}
	}
	if f.ran.Load() != 0 {
		t.Fatal("a command ran")
	}
}

// --- INV-2 -------------------------------------------------------------------------------------

func TestContract_INV2_BadArgsAreRefusedBeforeAnythingRuns(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	send := func(a netArgs) (int, []byte) {
		b, _ := json.Marshal(map[string]any{"args": a})
		return rawReq(t, h, "/v1/commands/test.set", hdr(rid1), string(b))
	}
	okArgs := netArgs{Name: "eth0", IP: "192.168.1.5", Scope: "all", At: "10:30"}
	nasty := []string{
		"; id", "a;b", "a|b", "a&b", "a&&b", "$(id)", "${HOME}", "`id`", "a b", "a\nb", "a\x00b", "../etc/passwd", "..", "a/b", "-rf", "'a'", `"a"`, "a>b", "a<b", "*", "~", "a\tb", strings.Repeat("a", 65), "",
		";", "é", "a;\u0000",
	}
	for _, n := range nasty {
		a := okArgs
		a.Name = n
		if st, b := send(a); st != http.StatusBadRequest || errCode(b) != api.CodeInvalidArgs {
			t.Errorf("name %q: %d %s", n, st, b)
		}
	}
	for _, ip := range []string{"", "1.2.3", "1.2.3.4.5", "1.2.3.4; id", "256.1.1.1", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "1.2.3.4/24", " 1.2.3.4", "$(id)", "1.2.3.4\n"} {
		a := okArgs
		a.IP = ip
		if st, b := send(a); st != http.StatusBadRequest {
			t.Errorf("ip %q: %d %s", ip, st, b)
		}
	}
	for _, s := range []string{"", "ALL", "everything", "all;id", "security,all"} {
		a := okArgs
		a.Scope = s
		if st, _ := send(a); st != http.StatusBadRequest {
			t.Errorf("scope %q accepted", s)
		}
	}
	for _, at := range []string{"", "24:00", "1:30", "10:60", "10-30", "10:30:00", "ab:cd"} {
		a := okArgs
		a.At = at
		if st, _ := send(a); st != http.StatusBadRequest {
			t.Errorf("at %q accepted", at)
		}
	}
	if f.ran.Load() != 0 {
		t.Fatalf("a command ran %d times on bad args", f.ran.Load())
	}
	// Control: the good arguments do run.
	if st, b := send(okArgs); st != http.StatusAccepted {
		t.Fatalf("good args: %d %s", st, b)
	}
}

// --- INV-3, POST-4 -----------------------------------------------------------------------------

func TestContract_INV3_OneWriteAtATime(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	first, err := h.Client.Run(context.Background(), "test.slow", nil, rid1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	<-f.started
	var wg sync.WaitGroup
	var busy atomic.Int64
	for i := range 8 { // concurrent attempts: none gets in
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("%08d-2222-4222-8222-222222222222", i)
			_, err := h.NewClient(t).Run(context.Background(), "test.ok", nil, id, "admin")
			var e *client.Error
			if errors.As(err, &e) && e.Status == http.StatusConflict && e.Code == api.CodeBusy && e.RunID == first.RunID {
				busy.Add(1)
			}
		}()
	}
	wg.Wait()
	if busy.Load() != 8 || f.ran.Load() != 1 {
		t.Fatalf("busy %d, ran %d", busy.Load(), f.ran.Load())
	}
	close(f.release)
	waitDone(t, h.Client, first.RunID)
	if _, err := h.Client.Run(context.Background(), "test.ok", nil, rid2, "admin"); err != nil {
		t.Fatalf("after the first run ended: %v", err)
	}
}

func TestContract_INV3_ACommandThatIgnoresItsDeadlineStillHoldsTheLock(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	deaf, err := h.Client.Run(context.Background(), "test.deaf", nil, rid1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if done := waitDone(t, h.Client, deaf.RunID); done.Error.Code != api.CodeTimeout {
		t.Fatalf("done = %+v", done)
	}
	_, err = h.Client.Run(context.Background(), "test.ok", nil, rid2, "admin")
	var e *client.Error
	if !errors.As(err, &e) || e.Code != api.CodeBusy || e.RunID != deaf.RunID {
		t.Fatalf("a second write started while the first still runs: %v", err)
	}
	close(f.release) // let the command return so Shutdown does not wait for it
	waitIdleLock(t, h)
}

// waitIdleLock retries a write until the lock is free.
func waitIdleLock(t *testing.T, h *servertest.Harness) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for i := 0; ; i++ {
		_, err := h.Client.Run(context.Background(), "test.ok", nil, fmt.Sprintf("%08d-4444-4444-8444-444444444444", i), "admin")
		if err == nil || !client.IsCode(err, api.CodeBusy) {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the lock never freed")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestContract_POST4_TimeoutReleasesTheLock(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds) // KillGrace 100 ms in the harness
	stuck, err := h.Client.Run(context.Background(), "test.stuck", nil, rid1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, h.Client, stuck.RunID)
	if done.Status != api.StatusFailed || done.Error.Code != api.CodeTimeout {
		t.Fatalf("done = %+v", done)
	}
	// A stall longer than KillGrace when the deadline passes can make the host judge the run abandoned (INV-3): the
	// lock is then freed when the command returns, just after (see INV-12 below). Wait for that, bounded by a real hang.
	eventually(t, "the write lock is free", func() bool { return !h.Server.WriteActive() })
	if _, err := h.Client.Run(context.Background(), "test.ok", nil, rid2, "admin"); err != nil {
		t.Fatalf("lock still held: %v", err)
	}
}

// --- INV-4 -------------------------------------------------------------------------------------

type fakeProc struct {
	mu     sync.Mutex
	uid    int
	cgroup string
	err    error
}

func (p *fakeProc) check(net.Conn) (peer.Info, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return peer.Decide(peer.Cred{UID: p.uid, PID: 4242}, 10001, "vedette-core.service", "", func(int) ([]byte, error) {
		return []byte(p.cgroup), p.err
	})
}

func (p *fakeProc) set(uid int, cgroup string, err error) {
	p.mu.Lock()
	p.uid, p.cgroup, p.err = uid, cgroup, err
	p.mu.Unlock()
}

func TestContract_INV4_EachPeerLayerDeniesAndIsAudited(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	proc := &fakeProc{}
	proc.set(10001, "0::/system.slice/vedette-core.service/libpod-1\n", nil)
	h := servertest.Start(t, f.cmds, func(o *server.Options) { o.PeerCheck = proc.check; o.AuditThrottle = time.Nanosecond })

	call := func() error {
		_, err := h.NewClient(t).Run(context.Background(), "test.ok", nil, rid1, "admin")
		return err
	}
	if err := call(); err != nil {
		t.Fatalf("core itself: %v", err)
	}
	waitIdle(t, h)
	ran := f.ran.Load()

	layers := map[string]func(){
		"layer 2: uid is not core's":        func() { proc.set(1000, "0::/system.slice/vedette-core.service\n", nil) },
		"layer 2: root is not core":         func() { proc.set(0, "0::/system.slice/vedette-core.service\n", nil) },
		"layer 3: core's uid, other cgroup": func() { proc.set(10001, "0::/user.slice/user-10001.slice/session-1.scope\n", nil) },
		"layer 3: sibling unit":             func() { proc.set(10001, "0::/system.slice/vedette-sensor.service\n", nil) },
		"layer 3: cgroup unreadable":        func() { proc.set(10001, "", errors.New("process gone")) },
	}
	for name, deny := range layers {
		before := len(audit(t, h)) // read while allowed
		deny()
		h.Clock.Advance(time.Minute) // the test clock is fixed; the throttle needs time to pass
		for range 2 {
			c := h.NewClient(t)
			if _, err := c.Info(context.Background()); err == nil {
				t.Errorf("%s: the peer got an answer", name)
			}
			if _, err := c.Run(context.Background(), "test.ok", nil, rid2, "admin"); err == nil {
				t.Errorf("%s: the peer ran a command", name)
			}
		}
		proc.set(10001, "0::/system.slice/vedette-core.service\n", nil)
		var denied int
		for _, a := range audit(t, h)[before:] {
			if a.Code != nil && *a.Code == api.CodePeerNotAllowed && a.Result == "refused" {
				denied++
			}
		}
		if denied == 0 {
			t.Errorf("%s: no peer_not_allowed audit line", name)
		}
	}
	if f.ran.Load() != ran {
		t.Fatal("a command ran for a denied peer")
	}
	// Layer 1: the socket file and its directory.
	if st, err := os.Stat(h.Socket); err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Dir(h.Socket)); err != nil || st.Mode().Perm() != 0o750 {
		t.Fatalf("socket dir mode: %v %v", st, err)
	}
}

// waitIdle blocks until the write lock is free (the last run has fully ended).
func waitIdle(t *testing.T, h *servertest.Harness) {
	t.Helper()
	runs, err := h.Client.ListRuns(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		if !r.Status.Terminal() {
			waitDone(t, h.Client, r.RunID)
		}
	}
}

func TestContract_INV4_NoRealCheckOffLinux(t *testing.T) {
	t.Parallel()
	_, err := peer.New(10001, "vedette-core.service", "")
	if err == nil {
		return // Linux: the real checker exists
	}
	if !errors.Is(err, peer.ErrUnsupportedOS) {
		t.Fatalf("err = %v", err)
	}
}

// --- INV-12 ------------------------------------------------------------------------------------

func TestContract_INV12_EveryCommandLeavesOneChainedAuditLine(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	id := func(i int) string { return fmt.Sprintf("%08d-3333-4333-8333-333333333333", i) }
	do := func(i int, command, body string) {
		rawReq(t, h, "/v1/commands/"+command, hdr(id(i)), body)
		waitIdle(t, h)
		// A terminal run normally frees the write lock in the same step, but not one the host judged abandoned (INV-3):
		// test.stuck honours its 50 ms deadline, yet a stall of the process longer than KillGrace (100 ms) at that moment
		// makes the grace timer and the command's return ready together, and execute's select takes either. The run is
		// then failed/timeout as usual, and the lock is freed only when the goroutine returns, just after. The next command
		// must not meet that lock: it would be refused busy and write no accepted line (CI: 4 accepted lines, not 5).
		eventually(t, "the write lock is free", func() bool { return !h.Server.WriteActive() })
	}
	good := `{"args":{"name":"x","ip":"192.168.1.5","scope":"all","at":"10:30"}}`
	do(1, "test.ok", `{}`)                                    // succeeded
	do(2, "test.fail", `{}`)                                  // failed
	do(3, "test.set", good)                                   // succeeded
	do(4, "nope.nope", `{}`)                                  // unknown command
	do(5, "test.set", `{"args":{"name":"; id"}}`)             // bad args
	do(6, "test.ok", `{"binary":"x"}`)                        // bad envelope
	do(7, "test.stuck", `{}`)                                 // timeout
	do(8, "test.set", strings.Replace(good, `"x"`, `"y"`, 1)) // succeeded
	rawReq(t, h, "/v1/commands/test.ok", hdr(id(1)), `{}`)    // idempotent replay: not a new command, no new line
	runs, _ := h.Client.ListRuns(context.Background(), 100)
	if len(runs) != 8 {
		t.Fatalf("%d runs", len(runs))
	}
	// Every line is on file once its run is terminal: the accepted line before the 202, a result line before the run is
	// recorded terminal (finish) or refused (refuse). No wait: a missing line here is a bug, not timing.
	var recs []api.AuditRecord
	accepted := 0
	for _, a := range audit(t, h) {
		if a.Result == "accepted" { // written when a run starts, before the result line
			accepted++
			continue
		}
		recs = append(recs, a)
	}
	// 5 commands ran (ok, fail, set, stuck, set): each has an accepted line and a result line; the 3 refusals only a result line.
	if len(recs) != 8 || accepted != 5 {
		t.Fatalf("%d result lines and %d accepted lines for 8 commands (5 ran)", len(recs), accepted)
	}
	byRun := map[string]api.AuditRecord{}
	for _, a := range recs {
		if a.RunID == nil || a.Command == "" || a.Actor != "admin@example.com" || a.ArgsDigest == "" || a.Result == "" || a.Peer.UID != 10001 || a.Peer.Unit != "vedette-core.service" {
			t.Fatalf("incomplete audit record: %+v", a)
		}
		byRun[*a.RunID] = a
	}
	for _, r := range runs {
		a, ok := byRun[r.RunID]
		if !ok || a.ID != r.AuditID || a.RequestID != r.RequestID {
			t.Fatalf("run %s has no matching audit line (%+v)", r.RunID, a)
		}
	}
	// The lines are chained (D-57 (14)) and the file verifies independently of the server.
	data, err := os.ReadFile(h.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	v := chain.NewVerifier("")
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		hash, prev := m["hash"].(string), m["prev_hash"].(string)
		delete(m, "hash")
		again, err := chain.HashCanonical(prev, numbers(m).(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		v.Add(m["id"].(string), prev, hash, again)
	}
	if res := v.Result(); !res.OK || res.Count != 13 {
		t.Fatalf("chain: %+v", res)
	}
	// Secrets in args never reach the file.
	rawReq(t, h, "/v1/commands/test.set", hdr(id(9)), `{"args":{"name":"vdt_osquery_0123456789abcdef","password":"hunter2"}}`)
	data, _ = os.ReadFile(h.AuditPath)
	if bytes.Contains(data, []byte("vdt_osquery_0123456789abcdef")) || bytes.Contains(data, []byte("hunter2")) {
		t.Fatal("a secret reached audit.jsonl")
	}
}

func numbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, _ := strconv.ParseInt(x.String(), 10, 64)
		return n
	case map[string]any:
		for k, e := range x {
			x[k] = numbers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = numbers(e)
		}
	}
	return v
}

// --- FORBID-1, FORBID-2 (source rules) ---------------------------------------------------------

// hostSources parses every non-test Go file of the host framework and of cmd/vedette-host.
func hostSources(t *testing.T) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, root := range []string{"../../host", "../../cmd/vedette-host"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files[p] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 15 {
		t.Fatalf("only %d host source files found: wrong working directory?", len(files))
	}
	return files
}

func TestContract_FORBID1_NoShellNoGenericExec(t *testing.T) {
	t.Parallel()
	for path, f := range hostSources(t) {
		for _, imp := range f.Imports {
			switch imp.Path.Value {
			case `"os/exec"`:
				t.Errorf("%s imports os/exec: processes start only through core/exec", path)
			case `"github.com/knt048/vedette/host/server/servertest"`:
				if !strings.Contains(path, "servertest") {
					t.Errorf("%s imports test support", path)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "syscall" && slices.Contains([]string{"Exec", "ForkExec", "StartProcess"}, x.Sel.Name) {
					t.Errorf("%s calls syscall.%s", path, x.Sel.Name)
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && slices.Contains([]string{`"sh"`, `"/bin/sh"`, `"bash"`, `"/bin/bash"`, `"-c"`, `"/bin/sh -c"`}, x.Value) {
					t.Errorf("%s contains the shell literal %s", path, x.Value)
				}
			}
			return true
		})
	}
}

// bannedNetworks are the network names no host source may mention, split or not.
var bannedNetworks = []string{"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "unixgram"}

// networkLiteralExceptions are the reviewed places where a banned word is an argv word or a binary name, never a
// socket network: "<file>:<top-level declaration>" -> why. Nothing else may carry one (D-268).
var networkLiteralExceptions = map[string]string{
	"host/ops/conntrack.go:argsConntrackSyslog": `"-p", "udp" of the one fixed conntrack argv`,
	"host/ops/bins.go:binIP":                    `"ip" is the name of iproute2's binary in the command runner`,
	"host/ops/decoy.go:fieldIP":                 `"ip" names the ip argument in errors and audit lines`,
	"cmd/vedette-host/notify.go:unixDatagram":   `the sd_notify client sends one datagram on the unix socket systemd gave (no listener, no IP network)`,
}

// foldString evaluates a string literal or a "+" chain of them, so that "ud"+"p" is seen as "udp".
func foldString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, lok := foldString(x.X)
		r, rok := foldString(x.Y)
		return l + r, lok && rok
	case *ast.ParenExpr:
		return foldString(x.X)
	}
	return "", false
}

type declUnit struct {
	name string // the function, or the first name of one const/var spec ("" for others)
	node ast.Node
}

// declUnits splits a file into functions and, for const/var/type groups, one unit per spec, so an exception for one
// name never covers its neighbours in the same group.
func declUnits(f *ast.File) []declUnit {
	var out []declUnit
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			out = append(out, declUnit{x.Name.Name, x})
		case *ast.GenDecl:
			for _, s := range x.Specs {
				name := ""
				switch sp := s.(type) {
				case *ast.ValueSpec:
					if len(sp.Names) > 0 {
						name = sp.Names[0].Name
					}
				case *ast.TypeSpec:
					name = sp.Name.Name
				}
				out = append(out, declUnit{name, s})
			}
		}
	}
	return out
}

// networkProblems lists what is wrong in one host source file: a banned network word (after folding concatenations)
// outside the reviewed exceptions, and any listen that is not the unix-only one. file is the path below the repo root.
func networkProblems(file string, f *ast.File) []string {
	var out []string
	for _, u := range declUnits(f) {
		d, name := u.node, u.name
		_, excepted := networkLiteralExceptions[file+":"+name]
		check := func(s string) {
			if slices.Contains(bannedNetworks, s) && !excepted {
				out = append(out, fmt.Sprintf("%s (%s) mentions network %q", file, name, s))
			}
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit, *ast.BinaryExpr:
				if s, ok := foldString(x.(ast.Expr)); ok {
					check(s)
					return false
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || !strings.HasPrefix(sel.Sel.Name, "Listen") {
					return true
				}
				pkg, _ := sel.X.(*ast.Ident)
				onPackage := pkg != nil && slices.Contains([]string{"net", "http", "tls", "quic"}, pkg.Name)
				// The only allowed way to listen: (&net.ListenConfig{}).Listen(ctx, "unix", path).
				unixListen := sel.Sel.Name == "Listen" && len(x.Args) == 3 && isLit(x.Args[1], `"unix"`)
				switch {
				case unixListen && !onPackage:
				case sel.Sel.Name == "Listen" && !onPackage && len(x.Args) <= 1:
					// our own Server.Listen(ctx), which itself is checked by the rule above
				default:
					out = append(out, fmt.Sprintf("%s: %s is not a unix-only listen", file, sel.Sel.Name))
				}
			}
			return true
		})
	}
	return out
}

func TestContract_FORBID2_NoNetworkListener(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for path, f := range hostSources(t) {
		file := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		for _, p := range networkProblems(file, f) {
			t.Error(p)
		}
		for _, u := range declUnits(f) {
			seen[file+":"+u.name] = true
		}
	}
	for k := range networkLiteralExceptions {
		if !seen[k] {
			t.Errorf("the reviewed exception %s no longer exists: remove it", k)
		}
	}
}

// The guard has teeth: a new dial, a split literal, or a listen on a network is reported wherever it is, and an
// exception covers only its own file and declaration.
func TestContract_FORBID2_TheGuardCatchesDialsSplitsAndMisplacedExceptions(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	for name, tc := range map[string]struct{ file, src string }{
		"dial udp":    {"host/ops/other.go", `func f() { net.Dial("udp", "10.0.0.1:514") }`},
		"dial tcp":    {"host/ops/other.go", `func f() { net.Dial("tcp", "10.0.0.1:514") }`},
		"split udp":   {"host/ops/other.go", `func f() { net.Dial("ud"+"p", "x") }`},
		"split ip":    {"host/ops/other.go", `var n = "i" + "p"`},
		"three parts": {"host/ops/other.go", `var n = "u" + "d" + "p"`},
		"the exception's literal elsewhere in its file":    {"host/ops/conntrack.go", `func g() { net.Dial("udp", "x") }`},
		"the exception's declaration name in another file": {"host/ops/other.go", `var argsConntrackSyslog = []string{"udp"}`},
		"listen on tcp": {"host/ops/other.go", `func f() { net.Listen("tcp", ":1") }`},
	} {
		if got := networkProblems(tc.file, parse(tc.src)); len(got) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	for name, tc := range map[string]struct{ file, src string }{
		"the reviewed conntrack argv": {"host/ops/conntrack.go", `var argsConntrackSyslog = []string{"-p", "udp"}`},
		"the reviewed binary name":    {"host/ops/bins.go", `const binIP = "ip"`},
		"an ordinary word":            {"host/ops/other.go", `func f() { net.Dial("unix", "/run/x") ; _ = "up" + "date" }`},
	} {
		if got := networkProblems(tc.file, parse(tc.src)); len(got) != 0 {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func isLit(e ast.Expr, want string) bool {
	l, ok := e.(*ast.BasicLit)
	return ok && l.Value == want
}

func TestContract_FORBID2_TheListenerIsAUnixSocket(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Prepare(t, f.cmds)
	ln, err := h.Server.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if ln.Addr().Network() != "unix" {
		t.Fatalf("listener network = %q", ln.Addr().Network())
	}
	if _, ok := ln.(*net.UnixListener); !ok {
		t.Fatalf("listener is %T", ln)
	}
}
