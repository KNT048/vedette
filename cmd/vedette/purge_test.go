package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	hostapi "github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

const purgeRID = "22222222-2222-4222-8222-222222222222"

// The adapter between the real host client and core.PurgeHost, against the client's own test host: a count on success, the typed
// error that core maps to 412 transition_pending and 409 busy when the run fails with those codes, an untouched error for any other
// failure, and an unreachable error for a socket that is not there (core makes it 502, or skips the call when the file is absent).
func TestHostPurgerAdaptsBackupPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	start := func(run func() (any, error)) hostPurger {
		h := servertest.Start(t, []server.Command{server.Define(server.Spec[struct{}]{
			Name: hostapi.CmdBackupPurge, Write: true, Timeout: time.Minute,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return run() },
		})})
		return hostPurger{h.Client}
	}

	if n, err := start(func() (any, error) { return hostapi.BackupPurgeResult{Deleted: 4}, nil }).BackupPurge(ctx, purgeRID, "admin@example.com"); err != nil || n != 4 {
		t.Fatalf("success: n %d err %v", n, err)
	}
	for _, tc := range []struct {
		code   string
		status int
	}{{hostapi.CodeTransitionPending, 412}, {hostapi.CodeBusy, 409}} {
		_, err := start(func() (any, error) { return nil, &server.Failure{Code: tc.code, Message: "no"} }).BackupPurge(ctx, purgeRID, "admin@example.com")
		var he *hostclient.Error
		if !errors.As(err, &he) || he.Code != tc.code || he.Status != tc.status {
			t.Errorf("a run that failed with %s: %v", tc.code, err)
		}
	}
	_, err := start(func() (any, error) { return nil, &server.Failure{Code: "purge_failed", Message: "no"} }).BackupPurge(ctx, purgeRID, "admin@example.com")
	var he *hostclient.Error
	if err == nil || errors.As(err, &he) {
		t.Errorf("another failure must stay a plain error: %v", err)
	}
	gone := hostPurger{hostclient.New(filepath.Join(t.TempDir(), "no-such.sock"))}
	if _, err := gone.BackupPurge(ctx, purgeRID, "admin@example.com"); !errors.Is(err, hostclient.ErrUnreachable) {
		t.Errorf("an absent socket: %v", err)
	}
}
