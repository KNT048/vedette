package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// N100: the one-shot commands keep their log lines (JSON, as the daemon writes them) for the journal, at the record's priority, and
// put only errors, readable and without the time, on the terminal.
func TestOneShotLogSendsJSONToTheJournalAndOnlyErrorsToTheTerminal(t *testing.T) {
	t.Parallel()
	var info, warn, errs, term bytes.Buffer
	log := slog.New(oneShotHandler(&info, &warn, &errs, &term)).With("module", "host").WithGroup("g")
	log.Debug("dropped")
	log.Info("an info", "k", 1)
	log.Warn("release index stored", "new_sequence", 7)
	log.Error("pull failed", "service", "core")

	for name, c := range map[string]struct {
		buf  *bytes.Buffer
		want string
	}{
		"info": {&info, `"level":"INFO","msg":"an info","module":"host","g":{"k":1}}`},
		"warn": {&warn, `"level":"WARN","msg":"release index stored","module":"host","g":{"new_sequence":7}}`},
		"err":  {&errs, `"level":"ERROR","msg":"pull failed","module":"host","g":{"service":"core"}}`},
	} {
		lines := strings.Split(strings.TrimSuffix(c.buf.String(), "\n"), "\n")
		if len(lines) != 1 || !strings.HasPrefix(lines[0], `{"time":`) || !strings.HasSuffix(lines[0], c.want) {
			t.Errorf("journal %s: %q", name, c.buf.String())
		}
	}
	if got := term.String(); got != "level=ERROR msg=\"pull failed\" module=host g.service=core\n" {
		t.Errorf("terminal: %q", got)
	}
}

// -bootstrap and -recover-core-data take the one-shot logger; -version and the flag errors do not.
func TestOneShotCommandsUseTheOneShotLogger(t *testing.T) {
	t.Parallel()
	b := newRecoverBox(t)
	for _, c := range []struct {
		args []string
		want bool
	}{
		{bootArgs(b.conf, b.sock), true}, // refused for its missing documents, after the logger is chosen
		{b.args(), true},                 // nothing to recover
		{[]string{"-version"}, false},
		{[]string{"-config", b.conf, "-index", "x"}, false},
	} {
		env, _ := testEnv(t)
		called := false
		env.oneShotLog = func() *slog.Logger { called = true; return slog.New(slog.DiscardHandler) }
		_ = run(context.Background(), c.args, io.Discard, env)
		if called != c.want {
			t.Errorf("%v: one-shot logger used = %v", c.args, called)
		}
	}
}
