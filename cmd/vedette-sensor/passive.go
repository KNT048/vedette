package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"regexp"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// passiveFlags are the options of `vedette-sensor passive`.
type passiveFlags struct{ core, creds *string }

// newPassiveFlags builds the flag set of `passive`. The test that checks the Exec= line of the sensor Quadlet unit (host/ops owns
// the unit text, D-123) parses it with this same constructor, so a flag renamed here without the unit following fails a test.
func newPassiveFlags(stdout io.Writer) (*flag.FlagSet, passiveFlags) {
	fs := flag.NewFlagSet("vedette-sensor passive", flag.ContinueOnError)
	fs.SetOutput(stdout)
	return fs, passiveFlags{
		core:  fs.String("core", "https://127.0.0.1:8444", "address of core's sensor listener"),
		creds: fs.String("creds", "/var/lib/vedette-creds/sensor.pem", "credentials bundle written by core (read only)"),
	}
}

// runPassive is `vedette-sensor passive --core URL --creds FILE`: the capture of the sensor container. It captures on the card
// core names in its configuration, with the filters core sends, reports what it heard, and says hello every 30 seconds with
// the cards of this machine. It opens no port and sends no frame (INV-1, INV-2).
func runPassive(ctx context.Context, args []string, stdout io.Writer, logger *slog.Logger) error {
	fs, f := newPassiveFlags(stdout)
	coreURL, creds := f.core, f.creds
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
	r, err := capture.New(capture.Config{Link: link, Interfaces: osInterfaces, Version: version, Log: logger})
	if err != nil {
		return err
	}
	return r.Run(ctx)
}

// virtualName is the name of a link that is not a card: container and virtual links, bridges, bonds, VLANs. The same rule as the
// Box network page applies (D-118 (6), modules/core/handlers_network.go): the sensor does not offer these as cards.
var virtualName = regexp.MustCompile(`^(lo|veth|podman|cni|docker|br|virbr|vdh|bond|tun|tap|wg|dummy|vnet|macvtap|ifb)|[.@]`)

// osInterfaces lists the cards of this machine (the container shares the network of the host): name, MAC, link and IPv4 prefixes.
// Loopback, virtual links and cards without a 6-byte MAC (tunnels) are not part of the LAN.
func osInterfaces(context.Context) ([]capture.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []capture.Interface
	for _, i := range all {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 || virtualName.MatchString(i.Name) {
			continue
		}
		c := capture.Interface{Name: i.Name, MAC: i.HardwareAddr.String(), Link: i.Flags&net.FlagUp != 0 && i.Flags&net.FlagRunning != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
					c.Addresses = append(c.Addresses, p)
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}
