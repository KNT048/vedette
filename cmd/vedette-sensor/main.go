// Command vedette-sensor is the binary of the sensor and scan containers on the appliance (D-114). `passive` is the packet capture
// of the sensor container (the capture half of sensor-passive, SP-4), `active` the worker of the scan container: nmap (D-113,
// SP-3) and nuclei (D-125, SP-3b). Both talk to core over the mutual-TLS sensor link (docs/specs/sensor-protocol.md), hold no database and no consent, and
// link neither database/sql, SQLite nor the generated API (main_test.go checks).
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
	"path/filepath"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// version is set at build time: -ldflags "-X main.version=1.2.3". It must be SemVer: it goes into the heartbeat.
var version = "0.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(ctx, os.Args[1:], os.Stdout, logger); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "vedette-sensor:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer, logger *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("usage: vedette-sensor passive|active|healthcheck --core URL --creds FILE [--nmap PATH]")
	}
	switch args[0] {
	case "passive":
		return runPassive(ctx, args[1:], stdout, logger.With("module", "sensor-passive"))
	case "active":
		return runActive(ctx, args[1:], stdout, logger.With("module", "sensor-active"))
	case "healthcheck": // the HealthCmd= of the sensor and scan units: no arguments, nothing to configure (health.go)
		if len(args) != 1 {
			return errors.New("healthcheck takes no arguments")
		}
		return checkHeartbeat(heartbeatPath, time.Now())
	case "-version", "--version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	return fmt.Errorf("unknown command %q (known: passive, active, healthcheck)", args[0])
}

// activeFlags are the options of `vedette-sensor active`.
type activeFlags struct{ core, creds, nmap, nuclei, nucleiIndex, nucleiHome *string }

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
		// nuclei is the pinned binary of the scan image (D-125 (4)); its home is a directory on the unit's tmpfs, emptied before
		// every run, so the read-only root file system is never written and no ~/.config of the image is read (D-136 (5)).
		nuclei:      fs.String("nuclei", "/usr/local/bin/nuclei", "the pinned nuclei of the scan image"),
		nucleiIndex: fs.String("nuclei-index", "/usr/local/share/vedette/nuclei-pack/index.json", "the index of the template pack baked into the scan image"),
		nucleiHome:  fs.String("nuclei-home", "/tmp/vedette-nuclei", "a directory on a tmpfs that becomes nuclei's HOME"),
	}
}

// validNucleiHome refuses a home that is not an absolute, clean path other than "/": the worker empties it before every run
// (os.RemoveAll), so "/" or a path with ".." must never get that far.
func validNucleiHome(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return fmt.Errorf("-nuclei-home %q must be an absolute, clean path other than /", p)
	}
	return nil
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
	if err := validNucleiHome(*f.nucleiHome); err != nil {
		return err
	}
	client, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: *coreURL, CredsPath: *creds})
	if err != nil {
		return err
	}
	// The own-IP fence of the external shape (D-514): the three public services of exposure, asked only when an external job comes.
	egress, err := egressip.New(nil, nil, 0)
	if err != nil {
		return err
	}
	w, err := worker.New(worker.Config{
		Link: withBeat(client, heartbeatPath, logger), NmapPath: *nmap, Version: version, Log: logger,
		NucleiPath: *f.nuclei, NucleiIndex: *f.nucleiIndex, NucleiHome: *f.nucleiHome, Egress: egress,
	})
	if err != nil {
		return err
	}
	return w.Run(ctx)
}
