package sensorpassive

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// Host is what the core half needs to know about the box. Every method is read-only.
//
// ponytail: Interfaces is only for the capture job that still runs inside core (until SP-5): it is that capture's own view of
// the cards. What core believes about the sensor's cards (SetInterface, the interface list of GET /inventory/sensors) comes from
// the sensor's heartbeat, never from here (INV-9).
type Host interface {
	// Interfaces lists the cards of the machine the in-process capture runs on.
	Interfaces(ctx context.Context) ([]capture.Interface, error)
	// HostCards lists the cards vedette-host reports. ok is false only when core runs without a host socket (container-only
	// install): SetInterface then validates against the cards in the sensor's heartbeat. A configured host
	// that gives no list is an error, never ok=false.
	HostCards(ctx context.Context) (cards []capture.Interface, ok bool, err error)
	// ManagementCard is the management card vedette-host reports (the configured one, else the card of the default route),
	// where the sensor listens while no card is chosen; "" when none is known yet. ok is false only when core runs
	// without a host (container-only): the default then comes from the sensor's heartbeat.
	ManagementCard(ctx context.Context) (name string, ok bool)
	// SpanOptions returns the extraction switches and exclusion filters of the SPAN settings (Settings, Box network).
	SpanOptions(ctx context.Context) (sensorlink.Extract, []sensorlink.Filter, error)
}

// Span verdicts, the values of Sensor.span_status.verdict.
const (
	VerdictOff       = "off"
	VerdictOK        = "ok"
	VerdictOwnOnly   = "own_only"
	VerdictNoTraffic = "no_traffic"
	VerdictNoLink    = "no_link"
)

// SpanStats is the measured health of the mirrored traffic (POST-4).
type SpanStats struct {
	Verdict    string
	PPS        int
	OtherMACs  int
	LastPacket time.Time // zero when none yet
}
