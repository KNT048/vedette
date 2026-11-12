package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// vedette-host -recover-core-data (D-317): the flags, the refusal beside a running daemon, the exit lines. What
// it does to core_data is tested in modules/host (TestContract_Recover_*).

type recoverBox struct {
	dir, conf, sock, state, audit, coreData string
}

func newRecoverBox(t *testing.T) recoverBox {
	t.Helper()
	dir, err := os.MkdirTemp("", "vr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	b := recoverBox{dir: dir, sock: filepath.Join(dir, "h.sock"), state: filepath.Join(dir, "state"), audit: filepath.Join(dir, "log", "audit.jsonl"), coreData: filepath.Join(dir, "core")}
	b.conf = writeConf(t, dir, b.sock)
	f, err := os.OpenFile(b.conf, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(f, "core_data = %s\n", b.coreData)
	_ = f.Close()
	return b
}

func (b recoverBox) args(more ...string) []string {
	return append([]string{"-config", b.conf, "-socket", b.sock, "-state-dir", b.state, "-audit-log", b.audit, "-recover-core-data"}, more...)
}

// journal writes a valid journal of core marked unrecoverable.
func (b recoverBox) journal(t *testing.T) {
	t.Helper()
	d := filepath.Join(b.state, "containers")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	digest, sha := "sha256:"+strings.Repeat("1", 64), strings.Repeat("a", 64)
	j := fmt.Sprintf(`{"service":"core","op":"rollback","phase":"pending","digest":%q,"prev_sha256":%q,"new_sha256":%q,"was_active":true,"at":"2026-11-10T08:00:00Z","run_id":"rn_0123456789abcdef","db_revert":"aside","aside":["vedette.db"],"unrecoverable":true}`, digest, sha, sha)
	if err := os.WriteFile(filepath.Join(d, "transition-core.json"), []byte(j), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverFlags(t *testing.T) {
	t.Parallel()
	b := newRecoverBox(t)
	env, _ := testEnv(t)
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"-use alone", []string{"-config", b.conf, "-use", "current"}, "belong to -recover-core-data"},
		{"-yes alone", []string{"-config", b.conf, "-yes"}, "belong to -recover-core-data"},
		{"with bootstrap", b.args("-bootstrap"), "separate commands"},
		{"with a bootstrap flag", b.args("-force-units"), "belong to -bootstrap"},
	} {
		err := run(context.Background(), c.args, io.Discard, env)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, c := range []struct {
		name string
		more []string
	}{
		{"a choice that does not exist", []string{"-use", "everything"}},
		{"yes without a choice", []string{"-yes"}},
	} {
		err := run(context.Background(), b.args(c.more...), io.Discard, env)
		var ee *exitError
		if !errors.As(err, &ee) || ee.code != exitUsage || !strings.HasPrefix(ee.line, "vedette-host: recover-core-data: invalid_args: ") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := os.Stat(b.state); err == nil {
		t.Error("a misuse created the state directory")
	}
}

func TestRecoverRefusesWhileTheDaemonRuns(t *testing.T) {
	t.Parallel()
	b := newRecoverBox(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", b.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	env, _ := testEnv(t)
	err = run(context.Background(), b.args(), io.Discard, env)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitDaemonRunning || !strings.HasPrefix(ee.line, "vedette-host: recover-core-data: daemon_running: ") || strings.Contains(ee.line, "\n") {
		t.Fatalf("err = %v", err)
	}
	// The daemon's state lock is the second layer: a stale socket file, but the lock held, is a running daemon too.
	_ = ln.Close()
	b.journal(t)
	holder := lockStateOf(t, b)
	defer holder()
	err = run(context.Background(), b.args(), io.Discard, env)
	if !errors.As(err, &ee) || ee.code != exitDaemonRunning {
		t.Fatalf("with the lock held: %v", err)
	}
}

func TestRecoverWithoutAJournalSaysSoAndWritesNothing(t *testing.T) {
	t.Parallel()
	b := newRecoverBox(t)
	env, _ := testEnv(t)
	var out bytes.Buffer
	if err := run(context.Background(), b.args("-use", "rollback", "-yes"), &out, env); err != nil {
		t.Fatal(err)
	}
	if out.String() != "vedette-host: recover-core-data: nothing to recover: core has no unfinished change on record\n" {
		t.Errorf("output %q", out.String())
	}
}

func TestRecoverRefusesACoreDataThatIsALink(t *testing.T) {
	t.Parallel()
	b := newRecoverBox(t)
	b.journal(t)
	behind := b.coreData + ".real"
	if err := os.Mkdir(behind, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(behind, "vedette.db.rollback"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(behind, b.coreData); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(t)
	for _, more := range [][]string{nil, {"-use", "rollback"}, {"-use", "rollback", "-yes"}} {
		err := run(context.Background(), b.args(more...), io.Discard, env)
		var ee *exitError
		if !errors.As(err, &ee) || ee.code != exitRefused || !strings.HasPrefix(ee.line, "vedette-host: recover-core-data: core_data_invalid: ") {
			t.Fatalf("%v: %v", more, err)
		}
	}
	if _, err := os.Stat(filepath.Join(behind, "vedette.db.rollback")); err != nil {
		t.Error("a file behind the link was touched")
	}
	if st, err := os.Stat(b.audit); err == nil && st.Size() != 0 {
		t.Error("a refusal wrote a line to the audit log")
	}
}

// lockStateOf takes the state lock the way the daemon does and returns the function that lets it go.
func lockStateOf(t *testing.T, b recoverBox) func() {
	t.Helper()
	o, err := ops.New(ops.Config{StateDir: b.state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := o.LockState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return func() { unlock(); o.Close() }
}
