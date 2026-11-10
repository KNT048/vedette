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
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// passiveFlags are the options of `vedette-sensor passive`.
type passiveFlags struct{ core, creds, replay *string }

// newPassiveFlags builds the flag set of `passive`. The test that checks the Exec= line of the sensor Quadlet unit (host/ops owns
// the unit text, D-123) parses it with this same constructor, so a flag renamed here without the unit following fails a test.
func newPassiveFlags(stdout io.Writer) (*flag.FlagSet, passiveFlags) {
	fs := flag.NewFlagSet("vedette-sensor passive", flag.ContinueOnError)
	fs.SetOutput(stdout)
	return fs, passiveFlags{
		core:  fs.String("core", "https://127.0.0.1:8444", "address of core's sensor listener"),
		creds: fs.String("creds", "/var/lib/vedette-creds/sensor.pem", "credentials bundle written by core (read only)"),
		// ponytail: development only (the compose dev stack, D-146), no unit passes it; a recording is read in place of a card.
		replay: fs.String("replay", "", "development only, never in a unit: read this pcap or pcapng recording (a developer's own capture or a public dev fixture, never a customer's) instead of a card, whichever card core names (or none)"),
	}
}

// nowSource moves a recording to the present: core refuses observations whose time is outside its window, and a recording is old.
// Every packet keeps its distance from the first one (the flood limiter of the capture counts packets per second, so squeezing a
// recording into one instant would be dropped as a flood).
type nowSource struct {
	capture.Source
	shift time.Duration
	set   bool
}

func (n *nowSource) Next(ctx context.Context) (capture.Packet, error) {
	p, err := n.Source.Next(ctx)
	if err == nil {
		if !n.set {
			n.shift, n.set = time.Since(p.At), true
		}
		p.At = p.At.Add(n.shift)
	}
	return p, err
}

// replayLink is the link of `passive --replay`: the same as the real one, except that a configuration which names no card is told to
// capture from "replay". The dev stack has no vedette-host, so nothing in core can choose a card; a card core does name is ignored
// as well, because the recording is opened whatever the name.
type replayLink struct{ beatLink }

func (r replayLink) Config(ctx context.Context, etag string, wait time.Duration) (sensorlink.ConfigReply, error) {
	rep, err := r.beatLink.Config(ctx, etag, wait)
	if err == nil && !rep.NotModified && rep.Config.Interface == "" {
		rep.Config.Interface = "replay"
	}
	return rep, err
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
	cfg := capture.Config{Interfaces: osInterfaces, Version: version, Log: logger}
	if rec := *f.replay; rec != "" { // fail at start, not in the capture's retry loop
		src, err := capture.OpenFile(rec)
		if err != nil {
			return err
		}
		_ = src.Close()
		cfg.Open = func(string) (capture.Source, error) {
			s, err := capture.OpenFile(rec)
			if err != nil {
				return nil, err
			}
			return &nowSource{Source: s}, nil
		}
	}
	client, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: *coreURL, CredsPath: *creds})
	if err != nil {
		return err
	}
	cfg.Link = withBeat(client, heartbeatPath, logger)
	if *f.replay != "" {
		cfg.Link = replayLink{withBeat(client, heartbeatPath, logger)}
	}
	r, err := capture.New(cfg)
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
