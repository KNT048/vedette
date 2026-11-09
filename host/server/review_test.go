package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// Tests that came out of the security review of WP-07a (M1-M3, L1-L5, info items). Each fails
// against the code as first committed.

// overlap tracks how many write handlers run at the same moment.
type overlap struct {
	inflight, max atomic.Int64
	release       chan struct{}
	returned      chan struct{}
}

func newOverlap(t *testing.T) *overlap {
	t.Helper()
	o := &overlap{release: make(chan struct{}), returned: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-o.release:
		default:
			close(o.release)
		}
	})
	return o
}

func (o *overlap) enter() func() {
	n := o.inflight.Add(1)
	for {
		m := o.max.Load()
		if n <= m || o.max.CompareAndSwap(m, n) {
			break
		}
	}
	return func() { o.inflight.Add(-1) }
}

func (o *overlap) commands() []server.Command {
	return []server.Command{
		server.Define(server.Spec[struct{}]{Name: "rv.hang", Write: true, Timeout: 50 * time.Millisecond,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				defer close(o.returned)
				defer o.enter()()
				<-o.release // does not honour its context
				return nil, nil
			}}),
		server.Define(server.Spec[struct{}]{Name: "rv.probe", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				defer o.enter()()
				return nil, nil
			}}),
	}
}

func TestReviewM1_AbandonedCommandKeepsTheWriteLock(t *testing.T) {
	t.Parallel()
	o := newOverlap(t)
	h := servertest.Start(t, o.commands())
	hang, err := h.Client.Run(context.Background(), "rv.hang", nil, rid1, "a")
	if err != nil {
		t.Fatal(err)
	}
	done := finish(t, h.Client, hang.RunID) // timeout 50 ms + grace 100 ms
	if done.Status != api.StatusFailed || done.Error.Code != api.CodeTimeout {
		t.Fatalf("the client must see the timeout: %+v", done)
	}
	// The goroutine is still running, so no other write may start.
	_, err = h.Client.Run(context.Background(), "rv.probe", nil, rid2, "a")
	var e *client.Error
	if !errors.As(err, &e) || e.Code != api.CodeBusy || e.RunID != hang.RunID {
		t.Fatalf("second write while the first still runs: %v", err)
	}
	if o.max.Load() != 1 {
		t.Fatalf("%d write handlers ran at once", o.max.Load())
	}
	// Once it really returns the lock frees.
	close(o.release)
	<-o.returned
	deadline := time.After(5 * time.Second)
	for {
		_, err = h.Client.Run(context.Background(), "rv.probe", nil, rid3, "a")
		if err == nil {
			break
		}
		if !client.IsCode(err, api.CodeBusy) {
			t.Fatal(err)
		}
		select {
		case <-deadline:
			t.Fatalf("lock never freed: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if o.max.Load() != 1 {
		t.Fatalf("%d write handlers ran at once", o.max.Load())
	}
}

func TestReviewM1_HardCeilingAuditsAndExits(t *testing.T) {
	t.Parallel()
	o := newOverlap(t)
	h := servertest.Start(t, o.commands(), func(opt *server.Options) { opt.AbandonCeiling = 100 * time.Millisecond })
	hang, err := h.Client.Run(context.Background(), "rv.hang", nil, rid1, "a")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-h.Exited:
		if code == 0 {
			t.Fatal("exit code 0: systemd would not restart the host")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the host did not exit for a command that never returns")
	}
	var found bool
	for _, a := range auditLines(t, h) {
		found = found || (a.RunID != nil && *a.RunID == hang.RunID && a.Code != nil && *a.Code == api.CodeHostWedged)
	}
	if !found {
		t.Fatal("no host_wedged audit line")
	}
}

func TestReviewL1_CheckPanicOrHangDoesNotHoldTheLock(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	ok := server.Define(server.Spec[struct{}]{Name: "rv.ok", Write: true, Timeout: time.Second,
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }})
	cmds := []server.Command{ok,
		server.Define(server.Spec[struct{}]{Name: "rv.checkpanic", Write: true, Timeout: time.Second,
			Check: func(context.Context, struct{}) error { panic("check blew up") },
			Run:   func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }}),
		server.Define(server.Spec[struct{}]{Name: "rv.checkhang", Write: true, Timeout: time.Second,
			Check: func(context.Context, struct{}) error { <-release; return nil }, // ignores ctx
			Run:   func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }}),
	}
	h := servertest.Start(t, cmds, func(o *server.Options) { o.CheckTimeout = 50 * time.Millisecond })
	for i, name := range []string{"rv.checkpanic"} {
		_, err := h.Client.Run(context.Background(), name, nil, uuid(i), "a")
		var e *client.Error
		if !errors.As(err, &e) || e.Status != http.StatusInternalServerError {
			t.Fatalf("%s: err = %v", name, err)
		}
		r, err := h.Client.Run(context.Background(), "rv.ok", nil, uuid(100+i), "a")
		if err != nil {
			t.Fatalf("after %s the write lock is stuck: %v", name, err)
		}
		finish(t, h.Client, r.RunID)
	}
}

func TestReviewL2_DeniedPeersAreThrottledPerUID(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	for i := range 30 {
		uid := 1000 // noisy
		if i == 5 {
			uid = 2000 // the one that matters
		}
		h.Peer.Deny(peer.Info{UID: uid, PID: 100 + i}, errors.New("no"))
		_, _ = h.NewClient(t).Info(context.Background())
		h.Clock.Advance(time.Second) // inside the 10 s throttle interval of uid 1000
	}
	h.Peer.Allow(servertest.CoreInfo)
	seen := map[int]int{}
	var skippedPIDs bool
	for _, r := range auditLines(t, h) {
		if r.Code != nil && *r.Code == api.CodePeerNotAllowed {
			seen[r.Peer.UID]++
			skippedPIDs = skippedPIDs || strings.Contains(string(r.ArgsRedacted), `"pids":[1`)
		}
	}
	if seen[2000] != 1 {
		t.Fatalf("uid 2000 was hidden by uid 1000's flood: %v", seen)
	}
	if seen[1000] < 2 || seen[1000] > 8 { // a first line and a summary per 10 s window over 30 s
		t.Fatalf("uid 1000 lines = %d", seen[1000])
	}
	if !skippedPIDs {
		t.Fatal("a throttled line does not list the pids it skipped")
	}
}

func TestReviewL3_CaseOnlyDuplicateKeysAreRejected(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	for name, body := range map[string]string{
		"case dup in args":   `{"args":{"name":"shown","NAME":"executed"}}`,
		"exact dup in args":  `{"args":{"name":"a","name":"b"}}`,
		"dup in envelope":    `{"args":{"name":"x"},"ARGS":{"name":"y"}}`,
		"nested case dup":    `{"args":{"name":"x","count":1,"Count":2}}`,
		"dup after an array": `{"args":{"name":"x","count":[1],"COUNT":2}}`,
	} {
		st, eb := post(t, h, "test.echo", goodHeaders(rid1), body)
		if st != http.StatusBadRequest || eb.Error.Code != api.CodeInvalidArgs {
			t.Errorf("%s: %d %+v", name, st, eb)
		}
	}
	if f.ran.Load() != 0 {
		t.Fatal("an ambiguous request ran")
	}
	// What is audited is what runs: a single differently-cased key is accepted and recorded by its decoded form.
	st, _ := raw(t, h, http.MethodPost, "/v1/commands/test.echo", goodHeaders(rid2), `{"args":{"NAME":"x"}}`)
	if st != http.StatusAccepted {
		t.Fatalf("status %d", st)
	}
	var accepted string
	for _, a := range auditLines(t, h) {
		if a.Result == "accepted" {
			accepted = string(a.ArgsRedacted)
		}
	}
	if accepted != `{"count":0,"name":"x"}` {
		t.Fatalf("accepted line records %s, not the decoded args", accepted)
	}
}

func TestReviewL4_SecretKeysAreRedacted(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	st, _ := raw(t, h, http.MethodPost, "/v1/commands/test.echo", goodHeaders(rid1), `{"args":{"vdt_live_9fQ2xLm7Rt8Kp3Zw":1}}`)
	if st != http.StatusBadRequest { // unknown field: refused, and the refusal is audited
		t.Fatalf("status %d", st)
	}
	data, err := os.ReadFile(h.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "vdt_live_9fQ2xLm7Rt8Kp3Zw") {
		t.Fatalf("a secret used as a key reached the audit file: %s", data)
	}
}

func TestReviewL5_AcceptedLineSurvivesACrash(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	r := run(t, h.Client, "test.slow", nil, rid1)
	<-f.started
	var accepted *api.AuditRecord
	for _, a := range auditLines(t, h) {
		if a.Result == "accepted" && a.RunID != nil && *a.RunID == r.RunID {
			accepted = &a
		}
	}
	if accepted == nil || accepted.Peer.UID != 10001 || accepted.Command != "test.slow" || accepted.Actor != "admin@example.com" || accepted.ID == r.AuditID {
		t.Fatalf("no usable accepted line while the run is in progress: %+v", accepted)
	}
	// Crash: copy the files as they are now and start a new host on them.
	crash := t.TempDir()
	copyTree(t, h.StateDir, filepath.Join(crash, "state"))
	copyTree(t, filepath.Dir(h.AuditPath), filepath.Join(crash, "log"))
	h2 := servertest.Prepare(t, newFixture(t).cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = filepath.Join(crash, "state"), filepath.Join(crash, "log", "audit.jsonl"), h.Socket+"2"
	})
	h2.Serve(t)
	var recovery *api.AuditRecord
	for _, a := range auditLines(t, h2) {
		if a.Code != nil && *a.Code == api.CodeHostRestarted {
			recovery = &a
		}
	}
	if recovery == nil {
		t.Fatal("no recovery line")
	}
	var detail struct {
		Accepted string `json:"accepted_audit_id"`
	}
	if err := json.Unmarshal(recovery.ArgsRedacted, &detail); err != nil || detail.Accepted != accepted.ID {
		t.Fatalf("recovery line %s does not reference the accepted line %s", recovery.ArgsRedacted, accepted.ID)
	}
	close(f.release)
}

func TestReviewInfo_StateAndAuditMustBeOwnedByTheHostUser(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Prepare(t, f.cmds) // creates the state and log directories, owned by us
	reg, _ := server.NewRegistry(f.cmds...)
	for name, mod := range map[string]func(*server.Options){
		"state dir": func(o *server.Options) { o.AuditPath = filepath.Join(filepath.Dir(o.StateDir), "log2", "a.jsonl") },
		"log dir":   func(o *server.Options) { o.StateDir = filepath.Join(filepath.Dir(o.StateDir), "state2") },
	} {
		// Directories that exist and belong to uid 0 (the host user in production) but not to us.
		o := server.Options{SocketPath: h.Socket, StateDir: h.StateDir, AuditPath: h.AuditPath, Registry: reg, PeerCheck: denyAll, OwnerUID: os.Getuid() + 1}
		mod(&o)
		if _, err := server.New(o); err == nil {
			t.Errorf("%s: a directory owned by another uid was accepted", name)
		}
	}
}

func TestReviewInfo_AuditFileIsNotFollowedThroughASymlink(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir, err := os.MkdirTemp("", "vh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logdir := filepath.Join(dir, "log")
	if err := os.Mkdir(logdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(logdir, "audit.jsonl")); err != nil {
		t.Fatal(err)
	}
	reg, _ := server.NewRegistry(f.cmds...)
	_, err = server.New(server.Options{
		SocketPath: filepath.Join(dir, "s.sock"), StateDir: filepath.Join(dir, "state"), AuditPath: filepath.Join(logdir, "audit.jsonl"),
		Registry: reg, PeerCheck: denyAll, OwnerUID: os.Getuid(),
	})
	if err == nil {
		t.Fatal("an audit log reached through a symlink was opened")
	}
}

func TestReviewInfo_UnknownPathsCountAgainstTheRateLimit(t *testing.T) {
	t.Parallel()
	h, _ := start(t, func(o *server.Options) { o.RequestsPerMinute, o.WritesPerMinute = 0, 0 })
	var last int
	for range 61 {
		last, _ = raw(t, h, http.MethodGet, "/v1/nothing", goodHeaders(rid1), "")
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("the 61st probe of an unknown path got %d", last)
	}
	h.Clock.Advance(2 * time.Minute)
	for _, a := range auditLines(t, h) {
		if a.Code != nil && *a.Code == api.CodeRateLimited {
			t.Fatal("probing of unknown paths was audited")
		}
	}
}

func TestReviewInfo_DeniedPeerIsATypedClientError(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	h.Peer.Deny(peer.Info{UID: 1000, PID: 5}, errors.New("no"))
	_, err := h.NewClient(t).Info(context.Background())
	if !errors.Is(err, client.ErrDenied) || errors.Is(err, client.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	h.Peer.Allow(servertest.CoreInfo)
}

func denyAll(net.Conn) (peer.Info, error) { return peer.Info{}, errors.New("no") }

func TestReviewL1b_AHungCheckKeepsTheWriteLockUntilItReturns(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	returned := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	var ranDuringCheck atomic.Int64
	var checking atomic.Bool
	cmds := []server.Command{
		server.Define(server.Spec[struct{}]{Name: "rv.checkhang", Write: true, Timeout: time.Second,
			Check: func(context.Context, struct{}) error {
				checking.Store(true)
				defer close(returned)
				defer checking.Store(false)
				<-release // ignores ctx
				return nil
			},
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }}),
		server.Define(server.Spec[struct{}]{Name: "rv.ok", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				if checking.Load() {
					ranDuringCheck.Add(1)
				}
				return nil, nil
			}}),
	}
	h := servertest.Start(t, cmds, func(o *server.Options) { o.CheckTimeout = 50 * time.Millisecond })
	_, err := h.Client.Run(context.Background(), "rv.checkhang", nil, rid1, "a")
	var e *client.Error
	if !errors.As(err, &e) || e.Status != http.StatusInternalServerError {
		t.Fatalf("hung check: %v", err)
	}
	_, err = h.Client.Run(context.Background(), "rv.ok", nil, rid2, "a")
	if !client.IsCode(err, api.CodeBusy) {
		t.Fatalf("a write started while the Check goroutine still runs: %v", err)
	}
	close(release)
	<-returned
	deadline := time.After(5 * time.Second)
	for {
		_, err = h.Client.Run(context.Background(), "rv.ok", nil, rid3, "a")
		if err == nil {
			break
		}
		if !client.IsCode(err, api.CodeBusy) {
			t.Fatal(err)
		}
		select {
		case <-deadline:
			t.Fatal("lock never freed")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if ranDuringCheck.Load() != 0 {
		t.Fatal("a Run executed during a Check")
	}
}

func TestReviewL2b_SummaryIsWrittenWithoutTheSameUIDKnockingAgain(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	for i := range 3 {
		h.Peer.Deny(peer.Info{UID: 1000, PID: 100 + i}, errors.New("no"))
		_, _ = h.NewClient(t).Info(context.Background())
	}
	h.Clock.Advance(11 * time.Second)
	h.Peer.Deny(peer.Info{UID: 3, PID: 9}, errors.New("no")) // a different uid triggers the flush
	_, _ = h.NewClient(t).Info(context.Background())
	h.Peer.Allow(servertest.CoreInfo)
	var found bool
	for _, r := range auditLines(t, h) {
		found = found || (r.Peer.UID == 1000 && strings.Contains(string(r.ArgsRedacted), `"skipped":2`))
	}
	if !found {
		t.Fatal("the skipped count of uid 1000 was never written")
	}
}

func TestReviewL2b_ManyUIDsCannotHideATarget(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	deny := func(uid int) {
		h.Peer.Deny(peer.Info{UID: uid, PID: uid}, errors.New("no"))
		_, _ = h.NewClient(t).Info(context.Background())
	}
	for uid := 1; uid <= 258; uid++ { // fills the 256-entry table inside one window
		deny(uid)
	}
	deny(9998) // overflow: first event of the shared entry
	deny(9999) // the target: skipped inside the overflow window
	h.Clock.Advance(11 * time.Second)
	deny(5) // flush
	h.Peer.Allow(servertest.CoreInfo)
	var found bool
	for _, r := range auditLines(t, h) {
		found = found || strings.Contains(string(r.ArgsRedacted), "9999")
	}
	if !found {
		recs := auditLines(t, h)
		t.Logf("%d lines; last: %+v %s", len(recs), recs[len(recs)-1].Peer, recs[len(recs)-1].ArgsRedacted)
		t.Fatal("uid 9999 does not appear in any audit line")
	}
}

func TestReviewInfo_ABodyThatNeverArrivesIsCutOff(t *testing.T) {
	t.Parallel()
	h, _ := start(t, func(o *server.Options) { o.BodyDeadline = 150 * time.Millisecond })
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", h.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// A GET that announces a body and sends only part of it.
	_, _ = c.Write([]byte("GET /v1/info HTTP/1.1\r\nHost: h\r\nX-Vedette-Host-Proto: 1\r\nContent-Length: 10\r\n\r\nab"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for { // read the response, then the server must close the connection by itself
		if _, err := c.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() { //nolint:errorlint // a read deadline error is a net.Error directly
				t.Fatal("the connection stayed open for a body that never completes")
			}
			return
		}
	}
}
