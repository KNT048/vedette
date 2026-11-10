// Command vedette-sensor is the binary of the sensor and scan containers on the appliance (D-114). The only subcommand now
// is `active`, the nmap worker of the scan container (D-113); SP-4 adds `passive`. It talks to core over the mutual-TLS
// sensor link (docs/specs/sensor-protocol.md), holds no database and no consent, and links neither database/sql, SQLite nor
// the generated API (main_test.go checks).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// version is set at build time: -ldflags "-X main.version=1.2.3". It must be SemVer: it goes into the heartbeat.
var version = "0.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("module", "sensor-active")
	if err := run(ctx, os.Args[1:], os.Stdout, logger); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "vedette-sensor:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer, logger *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("usage: vedette-sensor active --core URL --creds FILE [--nmap PATH]")
	}
	switch args[0] {
	case "active":
		return runActive(ctx, args[1:], stdout, logger)
	case "-version", "--version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	return fmt.Errorf("unknown command %q (known: active)", args[0])
}

// activeFlags are the options of `vedette-sensor active`.
type activeFlags struct{ core, creds, nmap *string }

// newActiveFlags builds the flag set of `active`. The test that checks the Exec= line of the scan Quadlet unit
// (host/ops owns the unit text, D-123) parses it with this same constructor, so a flag renamed here without the
// unit following fails a test.
func newActiveFlags(stdout io.Writer) (*flag.FlagSet, activeFlags) {
	fs := flag.NewFlagSet("vedette-sensor active", flag.ContinueOnError)
	fs.SetOutput(stdout)
	return fs, activeFlags{
		core:  fs.String("core", "https://127.0.0.1:8444", "address of core's sensor listener"),
		creds: fs.String("creds", "/var/lib/vedette-creds/sensor.pem", "credentials bundle written by core (read only)"),
		nmap:  fs.String("nmap", "/usr/bin/nmap", "the OS package's nmap"),
	}
}

func runActive(ctx context.Context, args []string, stdout io.Writer, logger *slog.Logger) error {
	fs, f := newActiveFlags(stdout)
	coreURL, creds, nmap := f.core, f.creds, f.nmap
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	link, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: *coreURL, CredsPath: *creds})
	if err != nil {
		return err
	}
	w, err := worker.New(worker.Config{Link: link, NmapPath: *nmap, Version: version, Log: logger})
	if err != nil {
		return err
	}
	return w.Run(ctx)
}
