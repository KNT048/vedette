package main

import (
	"context"
	"io"
	"log/slog"
	"log/syslog"
)

// oneShotLogger is the logger of the two commands a person runs in a terminal, -bootstrap (install.sh) and -recover-core-data
// (RUNBOOK 5.5): the JSON lines the daemon writes (the WARN "release index stored" among them) go to the system journal through
// its syslog socket (/dev/log), identifier vedette-host, each at its own priority (journalctl -t vedette-host), and the terminal
// gets only the errors, as readable key=value lines, beside the command's own progress (stdout) and its exit line (stderr). A
// customer's installer output had raw JSON lines in it (N100). With no syslog socket every line stays on the terminal as the
// daemon writes it, so no line is lost.
func oneShotLogger(terminal io.Writer) *slog.Logger {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "vedette-host")
	if err != nil {
		return slog.New(slog.NewJSONHandler(terminal, nil)).With("module", "host")
	}
	return slog.New(oneShotHandler(priorityWriter(w.Info), priorityWriter(w.Warning), priorityWriter(w.Err), terminal)).With("module", "host")
}

// oneShotHandler writes every record as JSON to the journal writer of its level (info, warn, err) and the errors also as text,
// without the time, to the terminal.
func oneShotHandler(info, warn, errs, terminal io.Writer) slog.Handler {
	journal := byLevel{slog.NewJSONHandler(info, nil), slog.NewJSONHandler(warn, nil), slog.NewJSONHandler(errs, nil)}
	text := slog.NewTextHandler(terminal, &slog.HandlerOptions{Level: slog.LevelError, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})
	return slog.NewMultiHandler(journal, text)
}

// priorityWriter sends each write (one record) to the journal at one priority (a method of *syslog.Writer).
type priorityWriter func(string) error

func (f priorityWriter) Write(p []byte) (int, error) { return len(p), f(string(p)) }

// byLevel sends a record to the handler of its level: error and above, warn, the rest.
type byLevel struct{ info, warn, err slog.Handler }

func (b byLevel) Enabled(ctx context.Context, l slog.Level) bool { return b.info.Enabled(ctx, l) }

func (b byLevel) Handle(ctx context.Context, r slog.Record) error {
	switch {
	case r.Level >= slog.LevelError:
		return b.err.Handle(ctx, r)
	case r.Level >= slog.LevelWarn:
		return b.warn.Handle(ctx, r)
	}
	return b.info.Handle(ctx, r)
}

func (b byLevel) WithAttrs(as []slog.Attr) slog.Handler {
	return byLevel{b.info.WithAttrs(as), b.warn.WithAttrs(as), b.err.WithAttrs(as)}
}

func (b byLevel) WithGroup(name string) slog.Handler {
	return byLevel{b.info.WithGroup(name), b.warn.WithGroup(name), b.err.WithGroup(name)}
}
